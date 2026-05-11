//! Heuristic ULP parser.
//!
//! v0.4.0 changes from GOLDPARSE:
//!   - LineFormat enum (Go code insight applied)
//!   - Tokenizer returns Vec<String> (owned) to support base64 re-tokenization
//!   - Per-field base64 probe integrated into tokenization
//!   - Fast-path hint for UrlFirst lines

use crate::config::{AppConfig, FieldOrderMode};
use crate::error::{NormalizerError, ParseResult};
use crate::preprocessor::{quick_classify, try_decode_base64_field, QuickFormat};
use once_cell::sync::Lazy;
use regex::Regex;

// ─── Runtime regex cache ─────────────────────────────────────────────────────

pub struct RegexSet {
    pub url:      Regex,
    pub email:    Regex,
    pub username: Regex,
}

pub fn build_regex_set(
    overrides: &crate::config::RegexOverrides,
    url_schemes: &[String],
) -> anyhow::Result<RegexSet> {
    let schemes = url_schemes.join("|");
    let default_url = format!(
        r"(?i)(?:{})://[^\s:@,|{{}}\\\]{{1,2048}}",
        schemes
    );
    let url_pat   = overrides.url_pattern.as_deref().unwrap_or(&default_url);
    let email_pat = overrides.email_pattern.as_deref()
        .unwrap_or(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}");
    let user_pat  = overrides.username_pattern.as_deref()
        .unwrap_or(r"^[a-zA-Z0-9._\-]{1,128}$");

    Ok(RegexSet {
        url:      Regex::new(url_pat)?,
        email:    Regex::new(email_pat)?,
        username: Regex::new(user_pat)?,
    })
}

// ─── Line format classifier (Go code insight) ────────────────────────────────

/// Describes how a line is structured.
/// Go's regexes: `ip`, `http`, `www`, `android`, `ulp` — translated to Rust enum.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineFormat {
    /// URL at front with known scheme — fastest parse path
    UrlFirst,
    /// Starts with www. — URL at front
    WwwFirst,
    /// IP address at front (possibly with scheme)
    IpFirst,
    /// android://hash@host format
    AndroidFormat,
    /// URL was at end, moved to front by reconstructor
    ReconstructedUrlFirst,
    /// Unknown — needs full heuristic
    Unknown,
}

pub fn classify_line_format(line: &str) -> LineFormat {
    use QuickFormat::*;
    match quick_classify(line) {
        UrlFirst => {
            // Distinguish android from others
            if line.len() > 10 && line[..10].eq_ignore_ascii_case("android://") {
                LineFormat::AndroidFormat
            } else {
                LineFormat::UrlFirst
            }
        }
        WwwFirst => LineFormat::WwwFirst,
        // After reconstruction, SlashSlash/LeadingDot/Unknown become UrlFirst
        // But since normalize() already called reconstruct, by the time
        // parse_line() sees the line, it should look like UrlFirst.
        // If it doesn't, fall through to Unknown.
        _ => {
            // Check if it looks like IP-first (Go's `ip` regex)
            // `^(?:[a-z]+://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
            let first = line.split(|c| c == ':' || c == '/').next().unwrap_or("");
            if looks_like_ipv4(first) {
                return LineFormat::IpFirst;
            }
            LineFormat::Unknown
        }
    }
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ─── Output record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UlpRecord {
    pub url:      String,
    pub username: String,
    pub password: String,
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

// ─── CSV injection sanitizer ─────────────────────────────────────────────────

pub fn sanitize(raw: &str) -> String {
    let trimmed = raw.trim();
    let s = if trimmed.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{}", trimmed)
    } else {
        trimmed.to_string()
    };
    s.chars()
        .filter(|&c| c != '\0' && (c == '\t' || !c.is_control()))
        .collect()
}

// ─── Tokenizer with per-field base64 probe ───────────────────────────────────

/// Tokenize remainder string, then probe each token for base64 encoding.
/// If a token decodes to a credential-like string, re-tokenize the decoded value.
/// Returns Vec<String> (owned) to support decoded sub-tokens.
fn tokenize(s: &str, delimiters: &[String]) -> Vec<String> {
    // First pass: raw tokenization
    let raw_tokens = raw_tokenize(s, delimiters);

    // Second pass: base64 probe
    let mut result: Vec<String> = Vec::with_capacity(raw_tokens.len() + 2);
    for tok in raw_tokens {
        if let Some(decoded) = try_decode_base64_field(&tok) {
            log::debug!("Base64 decoded field: {} chars → {} chars", tok.len(), decoded.len());
            // Re-tokenize the decoded value
            let sub = raw_tokenize_owned(&decoded, delimiters);
            if sub.len() >= 2 {
                result.extend(sub);
            } else {
                result.push(decoded);
            }
        } else {
            result.push(tok);
        }
    }
    result
}

fn raw_tokenize<'a>(s: &'a str, delimiters: &[String]) -> Vec<String> {
    for delim in delimiters {
        let parts: Vec<String> = if delim.len() == 1 {
            let ch = delim.chars().next().unwrap();
            s.split(ch).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
        } else {
            s.split(delim.as_str()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
        };
        if parts.len() >= 2 {
            return parts;
        }
    }
    vec![s.trim().to_string()]
}

fn raw_tokenize_owned(s: &str, delimiters: &[String]) -> Vec<String> {
    raw_tokenize(s, delimiters)
}

// ─── Main parse entry point ───────────────────────────────────────────────────

pub fn parse_line(raw: &str, cfg: &AppConfig, regexes: &RegexSet) -> ParseResult<UlpRecord> {
    let line = raw.trim();
    if line.is_empty() {
        return Err(NormalizerError::MalformedRecord { raw: line.into() });
    }

    let format = classify_line_format(line);

    // Extract URL
    let (url, remainder) = match regexes.url.find(line) {
        Some(m) => {
            let u = m.as_str().to_string();
            let r = format!("{}{}", &line[..m.start()], &line[m.end()..]);
            (u, r)
        }
        None => {
            return Err(NormalizerError::MalformedRecord { raw: line.into() });
        }
    };

    // Tokenize remainder (with base64 probe)
    let tokens = tokenize(&remainder, &cfg.parser.delimiters);

    // Classify tokens into username + password
    let (username, password) = match &cfg.parser.field_order {
        FieldOrderMode::Explicit(order) => classify_explicit(&tokens, order)?,
        FieldOrderMode::Auto(_) => classify_heuristic(&tokens, regexes, cfg.parser.entropy_threshold)?,
    };

    Ok(UlpRecord {
        url:      sanitize(&url),
        username: sanitize(&username),
        password: sanitize(&password),
    })
}

fn classify_explicit(tokens: &[String], order: &[String]) -> ParseResult<(String, String)> {
    let mut username = String::new();
    let mut password = String::new();
    let non_url: Vec<&str> = order.iter()
        .filter(|f| f.as_str() != "url")
        .map(|s| s.as_str())
        .collect();
    for (i, field) in non_url.iter().enumerate() {
        if let Some(tok) = tokens.get(i) {
            match *field {
                "username" => username = tok.clone(),
                "password" => password = tok.clone(),
                _ => {}
            }
        }
    }
    if username.is_empty() { username = tokens.get(0).cloned().unwrap_or_default(); }
    if password.is_empty() { password = tokens.get(1).cloned().unwrap_or_default(); }
    Ok((username, password))
}

fn classify_heuristic(
    tokens: &[String],
    regexes: &RegexSet,
    entropy_threshold: f64,
) -> ParseResult<(String, String)> {
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;

    for tok in tokens {
        if tok.is_empty() { continue; }

        if regexes.email.is_match(tok) && username.is_none() {
            username = Some(tok.clone());
            continue;
        }
        let entropy = shannon_entropy(tok);
        if entropy >= entropy_threshold && password.is_none() && username.is_some() {
            password = Some(tok.clone());
            continue;
        }
        if regexes.username.is_match(tok) && username.is_none() {
            username = Some(tok.clone());
        } else if password.is_none() && username.is_some() {
            password = Some(tok.clone());
        } else if username.is_none() {
            username = Some(tok.clone());
        }
    }

    match (username, password) {
        (Some(u), Some(p)) => Ok((u, p)),
        (Some(u), None) if tokens.len() >= 2 => {
            Ok((u, tokens.last().cloned().unwrap_or_default()))
        }
        _ => Err(NormalizerError::MalformedRecord { raw: tokens.join(":") }),
    }
}

pub fn aggressive_recover(line: &str, regexes: &RegexSet) -> Option<UlpRecord> {
    if let Some(m) = regexes.url.find(line) {
        let url = sanitize(m.as_str());
        let remainder = format!("{}{}", &line[..m.start()], &line[m.end()..]);
        let parts: Vec<&str> = remainder
            .split(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '_' && c != '-')
            .filter(|s| !s.is_empty())
            .collect();
        Some(UlpRecord {
            url,
            username: sanitize(parts.get(0).unwrap_or(&"")),
            password: sanitize(parts.get(1).unwrap_or(&"")),
        })
    } else {
        None
    }
}
