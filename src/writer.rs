//! Thread-safe CSV output writer and error log writer.
//! Both are Arc<Mutex<...>> — any Rayon worker can write without blocking others.

use crate::config::AppConfig;
use crate::error::ParseResult;
use crate::parser::UlpRecord;
use anyhow::Context;
use csv::Writer;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};

pub type SharedCsvWriter = Arc<Mutex<Writer<BufWriter<File>>>>;
pub type SharedErrWriter = Arc<Mutex<BufWriter<File>>>;

/// Initialise the CSV writer at `path`, writing headers if configured.
pub fn init_csv_writer_path(path: &str, cfg: &AppConfig) -> anyhow::Result<SharedCsvWriter> {
    let file = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(path)
        .with_context(|| format!("Cannot create CSV output: {}", path))?;
    let buf = BufWriter::with_capacity(cfg.performance.csv_buffer, file);
    let mut wtr = Writer::from_writer(buf);
    if cfg.output.write_headers {
        wtr.write_record(["url", "username", "password"])
            .context("Failed to write CSV headers")?;
    }
    Ok(Arc::new(Mutex::new(wtr)))
}

/// Initialise the error log writer at `path`.
pub fn init_err_writer_path(path: &str, cfg: &AppConfig) -> anyhow::Result<SharedErrWriter> {
    let file = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(path)
        .with_context(|| format!("Cannot create error log: {}", path))?;
    Ok(Arc::new(Mutex::new(BufWriter::with_capacity(cfg.performance.err_buffer, file))))
}

/// Write a clean ULP record to the CSV output.
pub fn write_record(writer: &SharedCsvWriter, record: &UlpRecord) -> ParseResult<()> {
    let mut guard = writer.lock().unwrap();
    guard.write_record([&record.url, &record.username, &record.password])?;
    Ok(())
}

/// Write a malformed or rejected line to the error log.
pub fn write_error(writer: &SharedErrWriter, line_no: usize, raw: &str, reason: &str) {
    let mut guard = writer.lock().unwrap();
    let _ = writeln!(guard, "[LINE {}] {} | raw: {}", line_no, reason, raw);
}

/// Flush the CSV writer — call after all processing is done.
pub fn flush_csv(writer: &SharedCsvWriter) -> anyhow::Result<()> {
    let mut guard = writer.lock().unwrap();
    guard.flush().context("CSV flush failed")?;
    Ok(())
}

/// Flush the error log writer.
pub fn flush_err(writer: &SharedErrWriter) {
    let mut guard = writer.lock().unwrap();
    let _ = guard.flush();
}
