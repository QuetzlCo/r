//! Configuration — loaded from ulp_normalizer.toml.
//! Every field has a Default so a missing / empty config file is fine.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

// ───────────────────────────────────────────────────────────────────────────
// Top-level
// ───────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AppConfig {
    pub io:            IoConfig,
    pub performance:   PerfConfig,
    pub encoding:      EncodingConfig,
    pub preprocessing: PreprocessConfig,
    pub parser:        ParserConfig,
    pub validation:    ValidationConfig,
    pub output:        OutputConfig,
    pub post_process:  PostProcessConfig,
}

// ───────────────────────────────────────────────────────────────────────────
// Sub-configs
// ───────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct IoConfig {
    pub input_file:  String,
    pub output_file: String,
    pub error_log:   String,
    pub chunk_size:  usize,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PerfConfig {
    pub threads:    usize,
    pub csv_buffer: usize,
    pub err_buffer: usize,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct EncodingConfig {
    pub mode:                 String,
    pub sample_bytes:         usize,
    pub confidence_threshold: f32,
    pub fallback_encoding:    String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PreprocessConfig {
    pub strip_bom:              bool,
    pub normalize_line_endings: bool,
    pub skip_prefixes:          Vec<String>,
    pub max_line_bytes:         usize,
    pub try_base64_decode:      bool,
    pub unquote_fields:         bool,
    pub unicode_normalize:      bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ParserConfig {
    pub delimiters:        Vec<String>,
    pub url_schemes:       Vec<String>,
    pub entropy_threshold: f64,
    pub field_order:       FieldOrderMode,
    pub recovery_mode:     RecoveryMode,
    pub regex_overrides:   RegexOverrides,
}

/// How we interpret field order when a line is tokenised.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum FieldOrderMode {
    /// `"auto"` — use heuristic classification
    Auto(String),
    /// `["url", "username", "password"]` — explicit positional order
    Explicit(Vec<String>),
}

impl Default for FieldOrderMode {
    fn default() -> Self {
        FieldOrderMode::Auto("auto".into())
    }
}

/// What to do when a line partially fails to parse.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryMode {
    Skip,
    Partial,
    Aggressive,
}

impl Default for RecoveryMode {
    fn default() -> Self { RecoveryMode::Skip }
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RegexOverrides {
    pub url_pattern:      Option<String>,
    pub email_pattern:    Option<String>,
    pub username_pattern: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ValidationConfig {
    pub strict_mode:         bool,
    pub url_max_length:      usize,
    pub username_min_length: usize,
    pub username_max_length: usize,
    pub password_min_length: usize,
    pub password_max_length: usize,
    pub deduplicate:         bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct OutputConfig {
    pub write_headers: bool,
    pub csv_delimiter: String,
    pub force_quote:   bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PostProcessConfig {
    pub deduplicate:                  bool,
    pub normalize_emails:             bool,
    pub strip_non_ascii:              bool,
    /// Passwords with char-count <= this value are removed.
    pub min_password_len:             usize,
    pub clean_url_schemes:            bool,
    pub strip_default_ports:          bool,
    pub strip_url_paths:              bool,
    pub filter_placeholder_passwords: bool,
    pub remove_pass_equals_user:      bool,
    pub lowercase_usernames:          bool,
    pub reject_unknown_schemes:       bool,
    pub export_stats:                 bool,
}

// ───────────────────────────────────────────────────────────────────────────
// Default implementations
// ───────────────────────────────────────────────────────────────────────────

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            io:            IoConfig::default(),
            performance:   PerfConfig::default(),
            encoding:      EncodingConfig::default(),
            preprocessing: PreprocessConfig::default(),
            parser:        ParserConfig::default(),
            validation:    ValidationConfig::default(),
            output:        OutputConfig::default(),
            post_process:  PostProcessConfig::default(),
        }
    }
}
impl Default for IoConfig {
    fn default() -> Self { Self {
        input_file:  "dump.txt".into(),
        output_file: "output.csv".into(),
        error_log:   "errors.log".into(),
        chunk_size:  8 * 1024 * 1024,
    }}
}
impl Default for PerfConfig {
    fn default() -> Self { Self {
        threads:    0,
        csv_buffer: 1 << 20,
        err_buffer: 1 << 16,
    }}
}
impl Default for EncodingConfig {
    fn default() -> Self { Self {
        mode:                 "auto".into(),
        sample_bytes:         8192,
        confidence_threshold: 0.75,
        fallback_encoding:    "utf-8".into(),
    }}
}
impl Default for PreprocessConfig {
    fn default() -> Self { Self {
        strip_bom:              true,
        normalize_line_endings: true,
        skip_prefixes:          vec!["#".into(), "//".into(), "--".into()],
        max_line_bytes:         4096,
        try_base64_decode:      false,
        unquote_fields:         true,
        unicode_normalize:      true,
    }}
}
impl Default for ParserConfig {
    fn default() -> Self { Self {
        delimiters:        vec![":".into(), "|".into(), "\t".into(), ";".into(), " ".into()],
        url_schemes:       vec![
            "http".into(), "https".into(), "ftp".into(), "ftps".into(),
            "sftp".into(), "android".into(), "socks5".into(), "socks4".into(),
            "ssh".into(), "mysql".into(), "mssql".into(), "postgresql".into(),
            "redis".into(), "smtp".into(), "imap".into(), "pop3".into(),
            "ldap".into(), "vnc".into(), "rdp".into(), "telnet".into(),
            "mongodb".into(),
        ],
        entropy_threshold: 3.2,
        field_order:       FieldOrderMode::default(),
        recovery_mode:     RecoveryMode::default(),
        regex_overrides:   RegexOverrides::default(),
    }}
}
impl Default for ValidationConfig {
    fn default() -> Self { Self {
        strict_mode:         true,
        url_max_length:      2048,
        username_min_length: 1,
        username_max_length: 128,
        password_min_length: 1,
        password_max_length: 256,
        deduplicate:         false,
    }}
}
impl Default for OutputConfig {
    fn default() -> Self { Self {
        write_headers: true,
        csv_delimiter: ",".into(),
        force_quote:   false,
    }}
}
impl Default for PostProcessConfig {
    fn default() -> Self { Self {
        deduplicate:                  true,
        normalize_emails:             true,
        strip_non_ascii:              true,
        min_password_len:             4,
        clean_url_schemes:            true,
        strip_default_ports:          true,
        strip_url_paths:              false,
        filter_placeholder_passwords: true,
        remove_pass_equals_user:      true,
        lowercase_usernames:          true,
        reject_unknown_schemes:       false,
        export_stats:                 true,
    }}
}

// ───────────────────────────────────────────────────────────────────────────
// Loader
// ───────────────────────────────────────────────────────────────────────────

/// Load config from `path`. If file not found, returns silent defaults.
pub fn load(path: &str) -> Result<AppConfig> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let cfg: AppConfig = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config: {}", path))?;
            log::info!("Config loaded: {}", path);
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::warn!("Config '{}' not found — using defaults", path);
            Ok(AppConfig::default())
        }
        Err(e) => Err(e).with_context(|| format!("Cannot read config: {}", path)),
    }
}
