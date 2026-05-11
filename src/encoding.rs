//! Encoding detection (chardetng) + transcoding (encoding_rs).
//! Handles UTF-8, Latin-1, Windows-1252, UTF-16 LE/BE, and anything
//! chardetng can identify from legacy byte streams.

use crate::config::EncodingConfig;
use chardetng::EncodingDetector;
use encoding_rs::Encoding;

// BOM byte sequences checked before chardetng runs.
const BOM_UTF8:     &[u8] = &[0xEF, 0xBB, 0xBF];
const BOM_UTF16_LE: &[u8] = &[0xFF, 0xFE];
const BOM_UTF16_BE: &[u8] = &[0xFE, 0xFF];

pub struct DetectedEncoding {
    pub encoding:  &'static Encoding,
    pub had_bom:   bool,
    pub bom_bytes: usize,
    pub confident: bool,
}

/// Probe the file header and determine encoding.
/// BOM detection takes priority over chardetng statistical detection.
pub fn detect(raw: &[u8], cfg: &EncodingConfig) -> DetectedEncoding {
    // --- BOM first (highest confidence) ---
    if raw.starts_with(BOM_UTF8) {
        return DetectedEncoding { encoding: encoding_rs::UTF_8, had_bom: true, bom_bytes: 3, confident: true };
    }
    if raw.starts_with(BOM_UTF16_LE) {
        return DetectedEncoding { encoding: encoding_rs::UTF_16LE, had_bom: true, bom_bytes: 2, confident: true };
    }
    if raw.starts_with(BOM_UTF16_BE) {
        return DetectedEncoding { encoding: encoding_rs::UTF_16BE, had_bom: true, bom_bytes: 2, confident: true };
    }

    // --- Forced encoding (user override in config) ---
    let mode = cfg.mode.to_lowercase();
    if mode != "auto" {
        let enc = Encoding::for_label(mode.as_bytes()).unwrap_or(encoding_rs::UTF_8);
        return DetectedEncoding { encoding: enc, had_bom: false, bom_bytes: 0, confident: true };
    }

    // --- chardetng statistical detection ---
    let sample_len = cfg.sample_bytes.min(raw.len());
    let mut detector = EncodingDetector::new();
    detector.feed(&raw[..sample_len], true);
    let (encoding, confident) = detector.guess_assess(None, true);

    let use_encoding = if !confident {
        log::warn!("Encoding detection low confidence — falling back to '{}'", cfg.fallback_encoding);
        Encoding::for_label(cfg.fallback_encoding.as_bytes()).unwrap_or(encoding_rs::UTF_8)
    } else {
        encoding
    };

    log::info!("Detected encoding: {} (confident: {})", use_encoding.name(), confident);
    DetectedEncoding { encoding: use_encoding, had_bom: false, bom_bytes: 0, confident }
}

/// Transcode raw bytes from detected encoding → UTF-8 String.
/// Uses lossy decoding — unmappable bytes become U+FFFD rather than erroring.
pub fn transcode_to_utf8(raw: &[u8], detected: &DetectedEncoding) -> anyhow::Result<String> {
    let payload = &raw[detected.bom_bytes..];

    if detected.encoding == encoding_rs::UTF_8 {
        // Fast path — validate only, no copy if already valid
        return Ok(String::from_utf8_lossy(payload).into_owned());
    }

    let (cow, _enc, had_errors) = detected.encoding.decode(payload);
    if had_errors {
        log::warn!("Encoding '{}' had unmappable bytes — replaced with U+FFFD", detected.encoding.name());
    }
    Ok(cow.into_owned())
}
