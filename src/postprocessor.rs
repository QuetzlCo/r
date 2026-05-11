//! Post-processing pipeline.
//! Runs AFTER parse + validate. Each transform is independently gated.
//! Every removal is auditable — reason is logged to errors.log.

use crate::config::PostProcessConfig;
use crate::parser::UlpRecord;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

// ───────────────────────────────────────────────────────────────────────────
// Static data
// ───────────────────────────────────────────────────────────────────────────

static PLACEHOLDER_PASSWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "password","password1","password123","passw0rd","passwd",
        "123456","1234567","12345678","123456789","1234567890",
        "qwerty","qwerty123","qwertyuiop","qazwsx","azerty",
        "admin","admin123","administrator","root","toor",
        "letmein","welcome","welcome1","changeme","change_me",
        "monkey","dragon","master","sunshine","iloveyou",
        "trustno1","superman","batman","abc123","abcdef",
        "111111","000000","654321","123123","121212",
        "login","test","test123","guest","default","pass","secret",
        "access","shadow","michael","football","baseball","soccer",
    ].iter().copied().collect()
});

static VALID_SCHEMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "http","https","ftp","ftps","sftp","android","socks5","socks4",
        "ssh","mysql","mssql","postgresql","redis","smtp","smtps",
        "imap","imaps","pop3","pop3s","ldap","ldaps","vnc","rdp",
        "telnet","mongodb","couchdb","cassandra",
    ].iter().copied().collect()
});

static RE_EMAIL_AT:  Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*@\s*").unwrap());
static RE_EMAIL_DOT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*\.\s*").unwrap());
static RE_URL_PORT:  Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(https?)://([^/:]+):(\d+)(.*)?$").unwrap()
});
static RE_URL_PATH:  Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(\w+://[^/]+)(/.*)?$").unwrap()
});

// ───────────────────────────────────────────────────────────────────────────
// Result types
// ───────────────────────────────────────────────────────────────────────────

pub enum PostProcResult {
    Keep(UlpRecord),
    Remove(RemoveReason),
}

#[derive(Debug, Clone)]
pub enum RemoveReason {
    PasswordTooShort { len: usize },
    PlaceholderPassword,
    PasswordEqualsUsername,
    Duplicate,
    InvalidScheme(String),
    AllFieldsEmpty,
}

impl std::fmt::Display for RemoveReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordTooShort { len }  => write!(f, "Password too short ({} chars)", len),
            Self::PlaceholderPassword       => write!(f, "Placeholder/common password"),
            Self::PasswordEqualsUsername    => write!(f, "Password == username"),
            Self::Duplicate                 => write!(f, "Duplicate record"),
            Self::InvalidScheme(s)          => write!(f, "Unknown URL scheme: {}", s),
            Self::AllFieldsEmpty            => write!(f, "All fields empty after processing"),
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Stateful post-processor
// ───────────────────────────────────────────────────────────────────────────

pub struct PostProcessor {
    cfg:   PostProcessConfig,
    dedup: HashSet<String>,
}

impl PostProcessor {
    pub fn new(cfg: PostProcessConfig) -> Self {
        Self { cfg, dedup: HashSet::new() }
    }

    pub fn process(&mut self, mut record: UlpRecord) -> PostProcResult {
        // 1. Strip non-printable ASCII
        if self.cfg.strip_non_ascii {
            record.url      = strip_non_printable(&record.url);
            record.username = strip_non_printable(&record.username);
            record.password = strip_non_printable(&record.password);
        }
        if record.url.is_empty() || record.username.is_empty() {
            return PostProcResult::Remove(RemoveReason::AllFieldsEmpty);
        }

        // 2. URL scheme normalization
        if self.cfg.clean_url_schemes {
            match normalize_url_scheme(&record.url) {
                Some(clean_url) => record.url = clean_url,
                None if self.cfg.reject_unknown_schemes => {
                    let scheme = extract_scheme(&record.url).unwrap_or_else(|| "unknown".into());
                    return PostProcResult::Remove(RemoveReason::InvalidScheme(scheme));
                }
                None => {}
            }
        }

        // 3. Strip default ports
        if self.cfg.strip_default_ports {
            record.url = strip_default_ports(&record.url);
        }

        // 4. Strip URL path
        if self.cfg.strip_url_paths {
            record.url = strip_url_path(&record.url);
        }

        // 5. Lowercase URL domain
        record.url = lowercase_url_domain(&record.url);

        // 6. Email normalization
        if self.cfg.normalize_emails && record.username.contains('@') {
            record.username = normalize_email(&record.username);
        }

        // 7. Lowercase username
        if self.cfg.lowercase_usernames {
            record.username = record.username.to_lowercase();
        }

        // 8. Minimum password length
        let plen = record.password.chars().count();
        if plen <= self.cfg.min_password_len {
            return PostProcResult::Remove(RemoveReason::PasswordTooShort { len: plen });
        }

        // 9. Placeholder password
        if self.cfg.filter_placeholder_passwords
            && PLACEHOLDER_PASSWORDS.contains(record.password.to_lowercase().as_str())
        {
            return PostProcResult::Remove(RemoveReason::PlaceholderPassword);
        }

        // 10. Password == username
        if self.cfg.remove_pass_equals_user
            && record.password.to_lowercase() == record.username.to_lowercase()
        {
            return PostProcResult::Remove(RemoveReason::PasswordEqualsUsername);
        }

        // 11. Case-insensitive deduplication on host + username
        if self.cfg.deduplicate {
            let host = extract_host(&record.url).to_lowercase();
            let key  = format!("{}::{}", host, record.username.to_lowercase());
            if !self.dedup.insert(key) {
                return PostProcResult::Remove(RemoveReason::Duplicate);
            }
        }

        PostProcResult::Keep(record)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Transform functions
// ───────────────────────────────────────────────────────────────────────────

pub fn strip_non_printable(s: &str) -> String {
    s.chars().filter(|&c| c >= '\x20' && c <= '\x7E').collect()
}

pub fn normalize_email(email: &str) -> String {
    let step1 = RE_EMAIL_AT.replace_all(email.trim(), "@");
    let parts: Vec<&str> = step1.splitn(2, '@').collect();
    if parts.len() == 2 {
        let domain = RE_EMAIL_DOT.replace_all(parts[1], ".").to_lowercase();
        format!("{}@{}", parts[0], domain)
    } else {
        step1.to_lowercase().to_string()
    }
}

pub fn normalize_url_scheme(url: &str) -> Option<String> {
    url.find("://").map(|sep| {
        let scheme = url[..sep].to_lowercase();
        let rest   = &url[sep..];
        if VALID_SCHEMES.contains(scheme.as_str()) {
            Some(format!("{}{}", scheme, rest))
        } else {
            None
        }
    }).flatten()
}

pub fn extract_scheme(url: &str) -> Option<String> {
    url.find("://").map(|i| url[..i].to_lowercase())
}

pub fn extract_host(url: &str) -> String {
    if let Some(after) = url.find("://").map(|i| &url[i+3..]) {
        let host_end = after.find('/').unwrap_or(after.len());
        let host_part = &after[..host_end];
        if let Some(colon) = host_part.rfind(':') {
            if host_part[colon+1..].chars().all(|c| c.is_ascii_digit()) {
                return host_part[..colon].to_lowercase();
            }
        }
        return host_part.to_lowercase();
    }
    url.to_lowercase()
}

pub fn strip_default_ports(url: &str) -> String {
    if let Some(m) = RE_URL_PORT.captures(url) {
        let scheme = m.get(1).map_or("", |m| m.as_str()).to_lowercase();
        let host   = m.get(2).map_or("", |m| m.as_str());
        let port   = m.get(3).map_or("", |m| m.as_str());
        let path   = m.get(4).map_or("", |m| m.as_str());
        let strip  = matches!(
            (scheme.as_str(), port),
            ("http","80") | ("https","443") | ("ftp","21") | ("smtp","25") | ("imap","143") | ("pop3","110")
        );
        if strip { return format!("{}://{}{}", scheme, host, path); }
    }
    url.to_string()
}

pub fn strip_url_path(url: &str) -> String {
    RE_URL_PATH.captures(url)
        .and_then(|m| m.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| url.to_string())
}

pub fn lowercase_url_domain(url: &str) -> String {
    if let Some(sep) = url.find("://") {
        let scheme = &url[..sep+3];
        let rest   = &url[sep+3..];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let (host, path) = rest.split_at(host_end);
        return format!("{}{}{}", scheme, host.to_lowercase(), path);
    }
    url.to_string()
}
