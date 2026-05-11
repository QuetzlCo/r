//! Strict-mode field validation.
//! Runs after parsing. All thresholds come from ValidationConfig.

use crate::config::ValidationConfig;
use crate::error::{NormalizerError, ParseResult};
use crate::parser::UlpRecord;
use once_cell::sync::Lazy;
use regex::Regex;

static RE_VALID_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^\w+://[a-zA-Z0-9.\-]+(:\d{1,5})?(/.*)?$")
        .expect("RE_VALID_URL compile")
});

pub fn validate(record: &UlpRecord, cfg: &ValidationConfig) -> ParseResult<()> {
    // URL
    if record.url.len() > cfg.url_max_length {
        return Err(NormalizerError::ValidationFailure {
            field:  "url".into(),
            value:  record.url[..64.min(record.url.len())].to_string(),
            reason: format!("exceeds max length {}", cfg.url_max_length),
        });
    }
    if !RE_VALID_URL.is_match(&record.url) {
        return Err(NormalizerError::ValidationFailure {
            field:  "url".into(),
            value:  record.url.clone(),
            reason: "does not match URL pattern".into(),
        });
    }

    // Username
    let ulen = record.username.len();
    if ulen < cfg.username_min_length || ulen > cfg.username_max_length {
        return Err(NormalizerError::ValidationFailure {
            field:  "username".into(),
            value:  record.username.clone(),
            reason: format!("length {} outside [{}, {}]", ulen, cfg.username_min_length, cfg.username_max_length),
        });
    }

    // Password — never log value even in error output
    let plen = record.password.len();
    if plen < cfg.password_min_length || plen > cfg.password_max_length {
        return Err(NormalizerError::ValidationFailure {
            field:  "password".into(),
            value:  "REDACTED".into(),
            reason: format!("length {} outside [{}, {}]", plen, cfg.password_min_length, cfg.password_max_length),
        });
    }

    Ok(())
}
