//! Background processing orchestrator.
//!
//! v0.4.0 PERFORMANCE ARCHITECTURE (from GOLDPARSE):
//!   - Local Rayon ThreadPool per job (user-configurable thread count from GUI)
//!   - crossbeam::bounded channel replaces Arc<Mutex<csv::Writer>> on hot path
//!   - Writer thread owns CSV + DashMap dedup — no cross-thread lock contention
//!   - for_each_with() — sender cloned per Rayon thread, zero Arc overhead in loop
//!   - Dynamic chunk size based on file size + thread count
//!   - PostProcessor dedup disabled per-chunk (global dedup in writer thread)
//!   - Batch sends: workers accumulate BATCH_SIZE records before sending

use crate::config::{AppConfig, PostProcessConfig, RecoveryMode};
use crate::postprocessor::{PostProcessor, PostProcResult, RemoveReason};
use crate::{encoding, parser, preprocessor, validator, writer};
use anyhow::Context;
use crossbeam_channel::Sender;
use memmap2::MmapOptions;
use native_windows_gui as nwg;
use rayon::prelude::*;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ─── Tuning constants ────────────────────────────────────────────────────────

/// Records per batch sent from worker → writer channel.
/// Larger = fewer channel sends, lower overhead. Smaller = lower latency on UI.
const BATCH_SIZE: usize = 512;

/// Bounded channel capacity (in batches).
/// 4096 batches * 512 records = ~2M records max buffered between workers and writer.
/// At 200 bytes/record = 400MB peak. Fine on 256GB machine.
const CHANNEL_CAPACITY: usize = 4096;

/// Auto thread count: 75% of logical CPUs, minimum 1.
/// Leaves ~25% for OS, GUI thread, writer thread, notice thread.
pub fn auto_thread_count() -> usize {
    (num_cpus::get() * 3 / 4).max(1)
}

/// Dynamic chunk size based on file size + thread count.
/// Targets each thread processing ~64 chunks for good load balancing.
/// Clamped: min 4MB (avoid overhead on small files), max 256MB (memory pressure on huge files).
fn optimal_chunk_size(file_size: u64, thread_count: usize) -> usize {
    let target_chunks = (thread_count * 64).max(32);
    let raw = (file_size as usize / target_chunks).max(1);
    raw.clamp(4 * 1024 * 1024, 256 * 1024 * 1024)
}

// ─── Message types (worker → GUI) ────────────────────────────────────────────

#[derive(Debug)]
pub enum UiMessage {
    Progress {
        processed:   u64,
        total_lines: u64,
        accepted:    u64,
        rejected:    u64,
        duplicates:  u64,
        filtered:    u64,
        file_name:   String,
        file_idx:    usize,
        file_count:  usize,
    },
    Speed {
        lines_per_sec: f64,
        eta_secs:      u64,
        elapsed_secs:  u64,
    },
    Log(String),
    Done(FinalStats),
    Error(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct FinalStats {
    pub total_input:          u64,
    pub accepted:             u64,
    pub rejected:             u64,
    pub duplicates:           u64,
    pub filtered_short:       u64,
    pub filtered_placeholder: u64,
    pub filtered_passequser:  u64,
    pub elapsed_secs:         f64,
    pub output_path:          String,
}

// ─── Shared message queue ─────────────────────────────────────────────────────

pub type MsgQueue = Arc<Mutex<VecDeque<UiMessage>>>;

pub fn new_queue() -> MsgQueue {
    Arc::new(Mutex::new(VecDeque::new()))
}

fn push(queue: &MsgQueue, msg: UiMessage) {
    if let Ok(mut q) = queue.lock() { q.push_back(msg); }
}

// ─── Worker state (cloned per Rayon thread via for_each_with) ─────────────────

struct WorkerState {
    tx:    Sender<Vec<parser::UlpRecord>>,
    batch: Vec<parser::UlpRecord>,
}

// Manual Clone — sender is Clone, batch starts empty on clone
impl Clone for WorkerState {
    fn clone(&self) -> Self {
        WorkerState {
            tx:    self.tx.clone(),
            batch: Vec::with_capacity(BATCH_SIZE),
        }
    }
}

// ─── File collection ──────────────────────────────────────────────────────────

pub fn collect_input_files(path: &str) -> Vec<PathBuf> {
    let p = Path::new(path);
    if p.is_file() { return vec![p.to_path_buf()]; }
    if p.is_dir() {
        let mut files: Vec<PathBuf> = fs::read_dir(p)
            .into_iter().flatten().flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e.to_ascii_lowercase().as_str(), "txt"|"csv"|"log"|"dat"))
                .unwrap_or(false))
            .collect();
        files.sort();
        return files;
    }
    vec![]
}

/// Newline-aligned chunk splitter.
fn build_line_aligned_chunks(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut start  = 0;
    let total      = data.len();
    while start < total {
        let mut end = (start + chunk_size).min(total);
        if end < total {
            while end < total && data[end] != b'\n' { end += 1; }
            if end < total { end += 1; }
        }
        chunks.push(&data[start..end]);
        start = end;
    }
    chunks
}

// ─── Main processing entry point ──────────────────────────────────────────────

pub fn run_processing(
    mut cfg:      AppConfig,        // mut so GUI values can override TOML values
    pp_cfg:       PostProcessConfig,
    input_path:   String,
    output_path:  String,
    thread_count: usize,            // from GUI txt_threads field
    pass_min:     usize,            // from GUI txt_pass_min
    pass_max:     usize,            // from GUI txt_pass_max
    queue:        MsgQueue,
    cancel:       Arc<AtomicBool>,
    notice_tx:    nwg::NoticeSender,
) {
    let start_time = Instant::now();

    // Apply GUI overrides to config
    cfg.validation.password_min_length = pass_min;
    cfg.validation.password_max_length = pass_max;

    macro_rules! log_ui {
        ($msg:expr) => {{
            push(&queue, UiMessage::Log($msg.to_string()));
            let _ = notice_tx.notice();
        }};
    }
    macro_rules! err_ui {
        ($msg:expr) => {{
            push(&queue, UiMessage::Error($msg.to_string()));
            let _ = notice_tx.notice();
            return;
        }};
    }

    // ── Build Rayon thread pool ───────────────────────────────────────────
    let n_threads = if thread_count == 0 { auto_thread_count() } else { thread_count };
    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .thread_name(|i| format!("ulp-worker-{}", i))
        .build()
    {
        Ok(p)  => p,
        Err(e) => { err_ui!(format!("Thread pool init failed: {}", e)); }
    };
    log_ui!(format!("Thread pool: {} workers", n_threads));

    // ── Collect files ─────────────────────────────────────────────────────
    let files = collect_input_files(&input_path);
    if files.is_empty() {
        err_ui!(format!("No processable files found at: {}", input_path));
    }
    log_ui!(format!("Found {} file(s) to process", files.len()));

    // ── Init writers ──────────────────────────────────────────────────────
    let csv_writer = match writer::init_csv_writer_path(&output_path, &cfg) {
        Ok(w)  => w,
        Err(e) => { err_ui!(format!("Cannot create output: {}", e)); }
    };
    let err_log = format!("{}.errors.log", output_path);
    let err_writer = match writer::init_err_writer_path(&err_log, &cfg) {
        Ok(w)  => w,
        Err(e) => { err_ui!(format!("Cannot create error log: {}", e)); }
    };

    // ── Counters ──────────────────────────────────────────────────────────
    let processed  = Arc::new(AtomicU64::new(0));
    let rejected   = Arc::new(AtomicU64::new(0));
    let accepted   = Arc::new(AtomicU64::new(0));   // updated by writer thread
    let duplicates = Arc::new(AtomicU64::new(0));   // updated by writer thread
    let filt_short = Arc::new(AtomicU64::new(0));
    let filt_ph    = Arc::new(AtomicU64::new(0));
    let filt_peu   = Arc::new(AtomicU64::new(0));

    // ── Channel between workers and writer ────────────────────────────────
    let (tx, rx) = crossbeam_channel::bounded::<Vec<parser::UlpRecord>>(CHANNEL_CAPACITY);

    // ── Spawn dedicated writer thread ─────────────────────────────────────
    let writer_handle = writer::spawn_writer_thread(
        rx,
        csv_writer,
        pp_cfg.deduplicate,
        accepted.clone(),
        duplicates.clone(),
    );

    // ── Build regex set once ──────────────────────────────────────────────
    let regexes = match parser::build_regex_set(
        &cfg.parser.regex_overrides,
        &cfg.parser.url_schemes,
    ) {
        Ok(r)  => Arc::new(r),
        Err(e) => { err_ui!(format!("Regex compile failed: {}", e)); }
    };

    let file_count = files.len();

    // ── Process each file ─────────────────────────────────────────────────
    for (file_idx, file_path) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            push(&queue, UiMessage::Cancelled);
            let _ = notice_tx.notice();
            // Drop tx to signal writer thread, then wait
            drop(tx);
            writer_handle.join().unwrap_or(());
            writer::flush_err(&err_writer);
            return;
        }

        let fname = file_path.file_name()
            .and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
        log_ui!(format!("[{}/{}] {}", file_idx + 1, file_count, fname));

        let file = match File::open(file_path) {
            Ok(f)  => f,
            Err(e) => { log_ui!(format!("  SKIP: {}", e)); continue; }
        };

        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mmap = unsafe {
            match MmapOptions::new().map(&file) {
                Ok(m)  => m,
                Err(e) => { log_ui!(format!("  MMAP error: {}", e)); continue; }
            }
        };

        let detected = encoding::detect(&mmap, &cfg.encoding);
        log_ui!(format!("  Encoding: {}", detected.encoding.name()));

        let utf8_content = match encoding::transcode_to_utf8(&mmap, &detected) {
            Ok(s)  => s,
            Err(e) => { log_ui!(format!("  Transcode error: {}", e)); continue; }
        };

        let normalized = if cfg.preprocessing.normalize_line_endings {
            preprocessor::normalize_line_endings(&utf8_content)
        } else {
            utf8_content
        };

        let total_lines_est = normalized.lines().count() as u64;
        log_ui!(format!("  ~{} lines", total_lines_est));

        let data       = normalized.as_bytes();
        let chunk_size = optimal_chunk_size(file_size, n_threads);
        let chunks     = build_line_aligned_chunks(data, chunk_size);
        log_ui!(format!("  {} chunks @ {}MB each", chunks.len(), chunk_size / 1024 / 1024));

        // ── Clone Arcs for Rayon closure ──────────────────────────────────
        let cfg_arc    = Arc::new(cfg.clone());
        let pp_arc     = Arc::new(pp_cfg.clone());
        let cancel_arc = cancel.clone();
        let rej_arc    = rejected.clone();
        let fs_arc     = filt_short.clone();
        let fp_arc     = filt_ph.clone();
        let fe_arc     = filt_peu.clone();
        let proc_arc   = processed.clone();
        let acc_arc    = accepted.clone();
        let dup_arc    = duplicates.clone();
        let err_arc    = err_writer.clone();
        let reg_arc    = regexes.clone();
        let q_arc      = queue.clone();
        let tx_clone   = notice_tx.clone();

        let speed_tracker = Arc::new(Mutex::new((Instant::now(), 0u64)));

        // ── PARALLEL DISPATCH ─────────────────────────────────────────────
        // for_each_with: each Rayon THREAD gets one WorkerState clone.
        // The batch accumulates records; sender flushes per-chunk.
        pool.install(|| {
            chunks.par_iter().for_each_with(
                WorkerState {
                    tx:    tx.clone(),  // NOT consuming tx — original kept for drop signal
                    batch: Vec::with_capacity(BATCH_SIZE),
                },
                |state, &raw_chunk| {
                    if cancel_arc.load(Ordering::Relaxed) { return; }

                    // Decode chunk as UTF-8 (chunks are byte-aligned to line boundaries)
                    let chunk_str = match std::str::from_utf8(raw_chunk) {
                        Ok(s)  => s,
                        Err(_) => return,
                    };

                    // Per-thread PostProcessor with dedup DISABLED
                    // Global dedup lives in the writer thread and sees ALL records
                    let mut pp = PostProcessor::new(crate::config::PostProcessConfig {
                        deduplicate: false,
                        ..(*pp_arc).clone()
                    });

                    let chunk_line_base = proc_arc.load(Ordering::Relaxed);

                    for (local_idx, raw_line) in chunk_str.lines().enumerate() {
                        let line_no = chunk_line_base as usize + local_idx;
                        proc_arc.fetch_add(1, Ordering::Relaxed);

                        // ── Preprocess ────────────────────────────────────
                        let prepped = match preprocessor::normalize(raw_line, &cfg_arc.preprocessing) {
                            preprocessor::PreprocResult::Ok(s) => s,
                            preprocessor::PreprocResult::Reject(r) => {
                                match r {
                                    preprocessor::PreprocessReject::Empty
                                    | preprocessor::PreprocessReject::Bloat => {}
                                    _ => {
                                        writer::write_error(&err_arc, line_no, raw_line,
                                            &format!("Preprocess: {:?}", r));
                                        rej_arc.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                continue;
                            }
                        };

                        // ── Parse ─────────────────────────────────────────
                        let record = match parser::parse_line(&prepped, &cfg_arc, &reg_arc) {
                            Ok(r)  => r,
                            Err(e) => {
                                if cfg_arc.parser.recovery_mode == RecoveryMode::Aggressive {
                                    if let Some(r) = parser::aggressive_recover(&prepped, &reg_arc) {
                                        r
                                    } else {
                                        writer::write_error(&err_arc, line_no, raw_line, &e.to_string());
                                        rej_arc.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                } else {
                                    writer::write_error(&err_arc, line_no, raw_line, &e.to_string());
                                    rej_arc.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            }
                        };

                        // ── Validate ──────────────────────────────────────
                        if cfg_arc.validation.strict_mode {
                            if let Err(e) = validator::validate(&record, &cfg_arc.validation) {
                                writer::write_error(&err_arc, line_no, raw_line, &e.to_string());
                                rej_arc.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }

                        // ── Post-process (dedup disabled — writer handles it) ──
                        match pp.process(record) {
                            PostProcResult::Keep(clean) => {
                                // Accumulate into batch, send when full
                                state.batch.push(clean);
                                if state.batch.len() >= BATCH_SIZE {
                                    let full = std::mem::replace(
                                        &mut state.batch,
                                        Vec::with_capacity(BATCH_SIZE),
                                    );
                                    let _ = state.tx.send(full);
                                }
                            }
                            PostProcResult::Remove(reason) => {
                                match &reason {
                                    RemoveReason::PasswordTooShort{..} => { fs_arc.fetch_add(1, Ordering::Relaxed); }
                                    RemoveReason::PlaceholderPassword   => { fp_arc.fetch_add(1, Ordering::Relaxed); }
                                    RemoveReason::PasswordEqualsUsername => { fe_arc.fetch_add(1, Ordering::Relaxed); }
                                    _ => {}
                                }
                                rej_arc.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // ── Progress update every 10k lines ──────────────
                        let proc_now = proc_arc.load(Ordering::Relaxed);
                        if proc_now % 10_000 == 0 {
                            let filt = fs_arc.load(Ordering::Relaxed)
                                     + fp_arc.load(Ordering::Relaxed)
                                     + fe_arc.load(Ordering::Relaxed);
                            push(&q_arc, UiMessage::Progress {
                                processed:   proc_now,
                                total_lines: total_lines_est,
                                accepted:    acc_arc.load(Ordering::Relaxed),
                                rejected:    rej_arc.load(Ordering::Relaxed),
                                duplicates:  dup_arc.load(Ordering::Relaxed),
                                filtered:    filt,
                                file_name:   fname.clone(),
                                file_idx:    file_idx + 1,
                                file_count,
                            });

                            // Speed/ETA update every ~500ms
                            if let Ok(mut sp) = speed_tracker.try_lock() {
                                let now  = Instant::now();
                                let diff = now.duration_since(sp.0);
                                if diff >= Duration::from_millis(500) {
                                    let delta = proc_now - sp.1;
                                    let lps   = delta as f64 / diff.as_secs_f64();
                                    let rem   = total_lines_est.saturating_sub(proc_now);
                                    let eta   = if lps > 0.0 { (rem as f64 / lps) as u64 } else { 0 };
                                    push(&q_arc, UiMessage::Speed {
                                        lines_per_sec: lps,
                                        eta_secs:      eta,
                                        elapsed_secs:  start_time.elapsed().as_secs(),
                                    });
                                    *sp = (now, proc_now);
                                }
                            }
                            let _ = tx_clone.notice();
                        }
                    }

                    // ── Flush remaining batch at end of chunk ─────────────
                    if !state.batch.is_empty() {
                        let remaining = std::mem::take(&mut state.batch);
                        let _ = state.tx.send(remaining);
                    }
                }
            );
        }); // pool.install
    } // for each file

    // ── Signal writer thread to finish ────────────────────────────────────
    // Drop original tx. Combined with all per-thread clone drops (on par_iter end),
    // this closes the channel and the writer thread exits its recv loop.
    drop(tx);
    writer_handle.join().unwrap_or(());
    writer::flush_err(&err_writer);

    let elapsed = start_time.elapsed().as_secs_f64();

    // ── Stats export ──────────────────────────────────────────────────────
    if pp_cfg.export_stats {
        let stats_path = format!("{}.stats.txt", output_path);
        let _ = fs::write(&stats_path, format!(
            "ULP Normalizer v0.4.0 Report\n\
             ============================\n\
             Output          : {}\n\
             Elapsed         : {:.1}s\n\
             Threads used    : {}\n\
             Pass min/max    : {}/{}\n\
             \n\
             Total Input     : {}\n\
             Accepted        : {}\n\
             Rejected        : {}\n\
             Duplicates      : {}\n\
             Short passwords : {}\n\
             Placeholder pass: {}\n\
             Pass = User     : {}\n",
            output_path, elapsed, n_threads, pass_min, pass_max,
            processed.load(Ordering::SeqCst),
            accepted.load(Ordering::SeqCst),
            rejected.load(Ordering::SeqCst),
            duplicates.load(Ordering::SeqCst),
            filt_short.load(Ordering::SeqCst),
            filt_ph.load(Ordering::SeqCst),
            filt_peu.load(Ordering::SeqCst),
        ));
    }

    push(&queue, UiMessage::Done(FinalStats {
        total_input:          processed.load(Ordering::SeqCst),
        accepted:             accepted.load(Ordering::SeqCst),
        rejected:             rejected.load(Ordering::SeqCst),
        duplicates:           duplicates.load(Ordering::SeqCst),
        filtered_short:       filt_short.load(Ordering::SeqCst),
        filtered_placeholder: filt_ph.load(Ordering::SeqCst),
        filtered_passequser:  filt_peu.load(Ordering::SeqCst),
        elapsed_secs:         elapsed,
        output_path,
    }));
    let _ = notice_tx.notice();
}
