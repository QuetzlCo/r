//! Line-level normalization + malformed URL reconstruction.
//!
//! v0.4.0 changes from GOLDPARSE:
//!   - QuickFormat classifier — identifies line format BEFORE reconstruct
//!   - Skip reconstruct entirely for URL-first lines (major hot-path win)
//!   - Pattern 4: leading non-alphanumeric junk before valid scheme
//!   - is_bloat_line(): fast early exit for content-free lines
//!   - try_decode_base64_field(): utility for per-field base64 probe in parser

use crate::config::PreprocessConfig;
use base64::prelude::*;
use unicode_normalization::UnicodeNormalization;

// ─── Quick format classifier ────────────────────────────────────────────────
// Based on Go regex insight: classify BEFORE expensive operations.
// Avoids reconstruct_malformed_url() for the majority of well-formed lines.

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QuickFormat {
    /// Line starts with a known scheme:// — URL is already at front, no reconstruction needed
    UrlFirst,
    /// Line starts with www. — URL is at front, no reconstruction needed
    WwwFirst,
    /// Line starts with // — scheme is missing from front, possibly at end
    SlashSlash,
    /// Line starts with . followed by what looks like a domain
    LeadingDot,
    /// No recognized prefix — check if URL is at end
    Unknown,
}

/// Classify line format using byte-level prefix checks.
/// Called BEFORE reconstruct_malformed_url — avoids reconstruction for most lines.
/// This is the Go regex insight applied: `ip`, `http`, `www`, `android` pattern families.
pub fn quick_classify(line: &str) -> QuickFormat {
    let bytes = line.as_bytes();
    if bytes.len() < 4 { return QuickFormat::Unknown; }

    // Check known scheme prefixes (case-insensitive, byte-level — fast)
    // Covers Go's: (ftp|http|https|pop3|pop|smtp|imap|irc|ssh|telnet)://
    // Plus our extended scheme list
    const URL_PREFIXES: &[&[u8]] = &[
        b"https://", b"http://",
        b"ftp://",   b"ftps://",  b"sftp://",
        b"ssh://",   b"smtp://",  b"smtps://",
        b"imap://",  b"imaps://", b"pop3://", b"pop://",
        b"irc://",   b"telnet://",
        b"android://",
        b"mysql://", b"mssql://", b"postgresql://",
        b"redis://", b"mongodb://", b"ldap://",
        b"vnc://",   b"rdp://",   b"socks5://", b"socks4://",
    ];

    // Build a lowercased prefix window (max 16 bytes — covers longest scheme)
    let window_len = bytes.len().min(16);
    let mut lower = [0u8; 16];
    for (i, &b) in bytes[..window_len].iter().enumerate() {
        lower[i] = b.to_ascii_lowercase();
    }
    let lower_window = &lower[..window_len];

    for prefix in URL_PREFIXES {
        if lower_window.starts_with(prefix) {
            return QuickFormat::UrlFirst;
        }
    }

    // WWW prefix (Go's `www` regex)
    if lower_window.starts_with(b"www.") {
        return QuickFormat::WwwFirst;
    }

    // Double-slash
    if bytes.starts_with(b"//") {
        return QuickFormat::SlashSlash;
    }

    // Leading dot before a domain-looking token
    if bytes[0] == b'.' && bytes.len() > 1 && bytes[1] != b'.' && bytes[1] != b'/' {
        return QuickFormat::LeadingDot;
    }

    QuickFormat::Unknown
}

// ─── Bloat line detection ────────────────────────────────────────────────────

/// Returns true if the line contains no recoverable credential data.
/// Called BEFORE any other processing — fast rejection saves pipeline work.
///
/// From LO's requirement: lines that are ONLY a scheme prefix bloat the file.
/// Also catches lines with zero colons (cannot have user:pass structure).
pub fn is_bloat_line(line: &str) -> bool {
    if line.is_empty() { return true; }

    // Lines that are exactly a bare scheme — zero content
    let lower = line.to_ascii_lowercase();
    const BARE_SCHEMES: &[&str] = &[
        "https://", "http://", "ftp://", "ftps://", "sftp://",
        "pop3://",  "pop://",  "smtp://", "imap://", "irc://",
        "ssh://",   "telnet://",
    ];
    for s in BARE_SCHEMES {
        if lower == *s { return true; }
    }

    // No colon in line → no url:user:pass structure possible.
    // Exception: android format uses @, but android lines always have ://
    // so they'll be caught by UrlFirst before reaching the colon check.
    if !line.contains(':') {
        return true;
    }

    false
}

// ─── Malformed URL reconstruction ────────────────────────────────────────────
// GOLDPARSE patterns 1-3 + new Pattern 4 from Go code insight.
// ONLY called for SlashSlash, LeadingDot, Unknown formats — skip for UrlFirst/WwwFirst.

/// Reconstruct malformed URL lines before parsing.
///
/// Pattern 1 — `//host:user:passhttps` → `https://host:user:pass`
/// Pattern 2 — `.domain.com:user:pass` → `https://domain.com:user:pass`
/// Pattern 3A — `user:pass:https://url` → `https://url:user:pass`
/// Pattern 3B — `user:pass:www.domain` → `https://www.domain:user:pass`
/// Pattern 4 — `>>https://host:user:pass` (leading junk) → `https://host:user:pass`
///             (Go regex: `^[^a-zA-Z0-9]*(scheme)://`)
pub fn reconstruct_malformed_url(line: &str) -> String {

    // ── Pattern 1: starts with "//" ──────────────────────────────────────
    if let Some(without_slashes) = line.strip_prefix("//") {
        let lower = without_slashes.to_ascii_lowercase();

        let (cleaned, scheme) = if lower.ends_with(":https") {
            (&without_slashes[..without_slashes.len() - 6], "https")
        } else if lower.ends_with(":http") {
            (&without_slashes[..without_slashes.len() - 5], "http")
        } else if lower.ends_with("https") {
            (&without_slashes[..without_slashes.len() - 5], "https")
        } else if lower.ends_with("http") {
            (&without_slashes[..without_slashes.len() - 4], "http")
        } else {
            (without_slashes, "https")
        };

        let first = cleaned.split(':').next().unwrap_or("");
        if first.contains('.') && !first.contains(' ') && !first.is_empty() {
            return format!("{}://{}", scheme, cleaned);
        }
        return line.to_string();
    }

    // ── Pattern 2: leading dot ────────────────────────────────────────────
    if line.starts_with('.') {
        let without_dot = &line[1..];
        let first = without_dot.split(':').next().unwrap_or("");
        if first.contains('.') && !first.contains(' ') && !first.contains('/') {
            return format!("https://{}", without_dot);
        }
    }

    // ── Pattern 3: URL is last colon-delimited token ──────────────────────
    let tokens: Vec<&str> = line.splitn(12, ':').collect();
    if tokens.len() >= 2 {
        let last = tokens[tokens.len() - 1].trim();
        let last_lower = last.to_ascii_lowercase();

        // 3A: last token is a full URL
        if last_lower.starts_with("http://")
            || last_lower.starts_with("https://")
            || last_lower.starts_with("ftp://")
        {
            let rest = tokens[..tokens.len() - 1].join(":");
            return format!("{}:{}", last, rest);
        }

        // 3B: last token is a bare domain (www.x.y or x.y)
        if last.contains('.')
            && !last.contains(' ')
            && !last.starts_with('/')
            && last.len() > 3
            && !last.starts_with('-')
        {
            let rest = tokens[..tokens.len() - 1].join(":");
            return format!("https://{}:{}", last, rest);
        }
    }

    // ── Pattern 4: leading non-alphanumeric junk before valid scheme ──────
    // Go regex: `(?i)^[^a-zA-Z0-9]*(ftp|http|https|pop3|pop|smtp|imap|irc|ssh|telnet)://`
    if !line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        let stripped = line.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
        if let Some(sep) = stripped.find("://") {
            let scheme_bytes = &stripped[..sep];
            if is_known_scheme(scheme_bytes) {
                return stripped.to_string();
            }
        }
    }

    line.to_string()
}

fn is_known_scheme(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp" | "ftps" | "sftp" | "pop3" | "pop"
            | "smtp" | "smtps" | "imap" | "imaps" | "irc" | "ssh"
            | "telnet" | "android" | "mysql" | "mssql" | "postgresql"
            | "redis" | "mongodb" | "ldap" | "vnc" | "rdp"
    )
}

// ─── Per-field base64 probe ──────────────────────────────────────────────────

/// Attempt to decode a single token as base64.
/// Only succeeds if the decoded bytes are valid UTF-8 AND contain
/// a credential-like structure (`:` or `@` = sub-fields to re-tokenize).
///
/// Called per-token in parser.rs tokenization phase.
/// Cheap rejection tests first to avoid decode attempts on normal tokens.
pub fn try_decode_base64_field(token: &str) -> Option<String> {
    let len = token.len();

    // Quick rejection: too short, not multiple of 4, not base64 char set
    if len < 16 { return None; }
    if len % 4 != 0 { return None; }
    if !token.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }) { return None; }

    // Try decode
    BASE64_STANDARD.decode(token).ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|decoded| {
            // Must look like a credential sub-string — contains structure
            (decoded.contains(':') || decoded.contains('@'))
            // And must have printable content (not binary garbage)
            && decoded.bytes().all(|b| b >= 0x20 && b < 0x80)
            && decoded.len() >= 4
        })
}

// ─── Main normalize entry point ──────────────────────────────────────────────

#[derive(Debug)]
pub enum PreprocessReject {
    TooLong { len: usize, max: usize },
    SkippedPrefix(String),
    Bloat,
    Empty,
}

pub enum PreprocResult {
    Ok(String),
    Reject(PreprocessReject),
}

pub fn normalize(raw: &str, cfg: &PreprocessConfig) -> PreprocResult {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return PreprocResult::Reject(PreprocessReject::Empty);
    }

    // ── Fast bloat check — before ANY other processing ────────────────────
    if is_bloat_line(trimmed) {
        return PreprocResult::Reject(PreprocessReject::Bloat);
    }

    // ── Byte-length guard ─────────────────────────────────────────────────
    if trimmed.len() > cfg.max_line_bytes {
        return PreprocResult::Reject(PreprocessReject::TooLong {
            len: trimmed.len(),
            max: cfg.max_line_bytes,
        });
    }

    // ── Skip comment/header prefixes ──────────────────────────────────────
    for prefix in &cfg.skip_prefixes {
        if trimmed.starts_with(prefix.as_str()) {
            return PreprocResult::Reject(PreprocessReject::SkippedPrefix(prefix.clone()));
        }
    }

    // ── URL reconstruction — SKIPPED for URL-first lines (major perf win) ─
    let format = quick_classify(trimmed);
    let working = match format {
        QuickFormat::UrlFirst | QuickFormat::WwwFirst => {
            // Already well-formed — skip ALL reconstruction logic
            trimmed.to_string()
        }
        _ => {
            // Needs reconstruction attempt
            reconstruct_malformed_url(trimmed)
        }
    };

    // ── Unquote fields ────────────────────────────────────────────────────
    let working = if cfg.unquote_fields {
        strip_surrounding_quotes(&working)
    } else {
        working
    };

    // ── Unicode NFC normalization ─────────────────────────────────────────
    let working = if cfg.unicode_normalize {
        working.nfc().collect::<String>()
    } else {
        working
    };

    PreprocResult::Ok(working)
}

pub fn normalize_line_endings(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', '\n')
}

fn strip_surrounding_quotes(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    if n >= 2
        && ((b[0] == b'"' && b[n-1] == b'"')
            || (b[0] == b'\'' && b[n-1] == b'\''))
    {
        return s[1..n-1].to_string();
    }
    s.to_string()
}
