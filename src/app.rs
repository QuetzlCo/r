//! Win32 GUI — v0.4.0
//!
//! New controls from GOLDPARSE:
//!   - txt_pass_min / txt_pass_max: password length range (replaces hardcoded 4)
//!   - txt_threads: Rayon worker thread count (0 = auto, default = 75% CPU)
//!   - lbl_threads_hint: shows detected CPU count
//!   - grp_postproc expanded by 26px to fit new row
//!   - All downstream y-positions shifted accordingly

extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;

use crate::config;
use crate::processing::{self, FinalStats, MsgQueue, UiMessage};
use nwd::NwgUi;
use nwg::NativeUi;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// ─── Window dimensions ───────────────────────────────────────────────────────
const WIN_W:         u32 = 634;
const WIN_H_COMPACT: u32 = 560;  // +26px from GOLDPARSE (new pass/thread row)
const WIN_H_VERBOSE: u32 = 760;

#[derive(Default, NwgUi)]
pub struct UlpApp {

    // ── Main Window ──────────────────────────────────────────────────────
    #[nwg_control(
        size: (WIN_W as i32, WIN_H_COMPACT as i32),
        position: (120, 80),
        title: "ULP Normalizer v0.4.0  —  CTI Data Cleaner",
        flags: "MAIN_WINDOW|VISIBLE"
    )]
    #[nwg_events(
        OnWindowClose: [UlpApp::on_exit],
        OnInit:        [UlpApp::on_init]
    )]
    pub window: nwg::Window,

    #[nwg_control()]
    #[nwg_events(OnNotice: [UlpApp::on_worker_notice])]
    pub notice: nwg::Notice,

    #[nwg_resource(family: "Tahoma", size: 15)]
    pub font: nwg::Font,

    // ═══ Group: Input ════════════════════════════════════════════════════
    #[nwg_control(text: "Input", size: (612, 68), position: (8, 5), flags: "VISIBLE")]
    pub grp_input: nwg::GroupBox,

    #[nwg_control(text: "", size: (464, 22), position: (18, 24))]
    pub txt_input: nwg::TextInput,

    #[nwg_control(text: "Browse File...", size: (92, 22), position: (488, 24))]
    #[nwg_events(OnButtonClick: [UlpApp::on_browse_file])]
    pub btn_browse_file: nwg::Button,

    #[nwg_control(text: "Browse Folder", size: (92, 22), position: (488, 50))]
    #[nwg_events(OnButtonClick: [UlpApp::on_browse_folder])]
    pub btn_browse_folder: nwg::Button,

    // ═══ Group: Output ═══════════════════════════════════════════════════
    #[nwg_control(text: "Output", size: (612, 46), position: (8, 78), flags: "VISIBLE")]
    pub grp_output: nwg::GroupBox,

    #[nwg_control(text: "output.csv", size: (464, 22), position: (18, 97))]
    pub txt_output: nwg::TextInput,

    #[nwg_control(text: "Browse...", size: (92, 22), position: (488, 97))]
    #[nwg_events(OnButtonClick: [UlpApp::on_browse_output])]
    pub btn_browse_output: nwg::Button,

    // ═══ Group: Post Processing (h=146, +26px from GOLDPARSE) ════════════
    #[nwg_control(text: "Post Processing", size: (612, 146), position: (8, 129), flags: "VISIBLE")]
    pub grp_postproc: nwg::GroupBox,

    #[nwg_control(text: "Remove duplicates (host+user)", size: (296, 18), position: (18, 148), check_state: nwg::CheckBoxState::Checked)]
    pub chk_dedup: nwg::CheckBox,

    #[nwg_control(text: "Normalize email addresses", size: (200, 18), position: (320, 148), check_state: nwg::CheckBoxState::Checked)]
    pub chk_normalize_email: nwg::CheckBox,

    #[nwg_control(text: "Strip non-ASCII chars [^\\x20-\\x7E]", size: (296, 18), position: (18, 170), check_state: nwg::CheckBoxState::Checked)]
    pub chk_strip_nonascii: nwg::CheckBox,

    #[nwg_control(text: "Enforce password length limits:", size: (200, 18), position: (320, 170), check_state: nwg::CheckBoxState::Checked)]
    pub chk_min_pass: nwg::CheckBox,

    #[nwg_control(text: "Clean & normalize URL schemes", size: (296, 18), position: (18, 192), check_state: nwg::CheckBoxState::Checked)]
    pub chk_clean_url: nwg::CheckBox,

    #[nwg_control(text: "Strip default ports (:80 :443 :21)", size: (200, 18), position: (320, 192), check_state: nwg::CheckBoxState::Checked)]
    pub chk_strip_ports: nwg::CheckBox,

    #[nwg_control(text: "Filter placeholder passwords", size: (296, 18), position: (18, 214), check_state: nwg::CheckBoxState::Checked)]
    pub chk_placeholder: nwg::CheckBox,

    #[nwg_control(text: "Remove password = username", size: (200, 18), position: (320, 214), check_state: nwg::CheckBoxState::Checked)]
    pub chk_pass_eq_user: nwg::CheckBox,

    #[nwg_control(text: "Strip URL paths (keep host only)", size: (296, 18), position: (18, 236), check_state: nwg::CheckBoxState::Unchecked)]
    pub chk_strip_paths: nwg::CheckBox,

    #[nwg_control(text: "Export stats (.stats.txt)", size: (200, 18), position: (320, 236), check_state: nwg::CheckBoxState::Checked)]
    pub chk_export_stats: nwg::CheckBox,

    // ── NEW v0.4.0: Password length + thread count row ────────────────────
    #[nwg_control(text: "Pass length:", size: (72, 16), position: (18, 262))]
    pub lbl_pass_range: nwg::Label,

    #[nwg_control(text: "6", size: (40, 20), position: (92, 260))]
    pub txt_pass_min: nwg::TextInput,

    #[nwg_control(text: "to", size: (16, 16), position: (136, 262))]
    pub lbl_pass_to: nwg::Label,

    #[nwg_control(text: "128", size: (44, 20), position: (154, 260))]
    pub txt_pass_max: nwg::TextInput,

    #[nwg_control(text: "chars     Threads:", size: (100, 16), position: (202, 262))]
    pub lbl_threads_label: nwg::Label,

    #[nwg_control(text: "0", size: (44, 20), position: (304, 260))]
    pub txt_threads: nwg::TextInput,

    #[nwg_control(text: "(0 = auto)", size: (100, 16), position: (352, 262))]
    pub lbl_threads_hint: nwg::Label,

    // ═══ Group: Progress (shifted +26px) ═════════════════════════════════
    #[nwg_control(text: "Progress", size: (612, 110), position: (8, 280), flags: "VISIBLE")]
    pub grp_progress: nwg::GroupBox,

    #[nwg_control(range: 0..1000, size: (590, 18), position: (18, 298))]
    pub progress_bar: nwg::ProgressBar,

    #[nwg_control(text: "Processed:  0", size: (140, 16), position: (18, 322))]
    pub lbl_processed: nwg::Label,

    #[nwg_control(text: "Accepted:  0", size: (140, 16), position: (162, 322))]
    pub lbl_accepted: nwg::Label,

    #[nwg_control(text: "Rejected:  0", size: (140, 16), position: (306, 322))]
    pub lbl_rejected: nwg::Label,

    #[nwg_control(text: "Dupes:  0", size: (120, 16), position: (450, 322))]
    pub lbl_dupes: nwg::Label,

    #[nwg_control(text: "Lines/sec:  --", size: (140, 16), position: (18, 342))]
    pub lbl_speed: nwg::Label,

    #[nwg_control(text: "ETA:  --", size: (140, 16), position: (162, 342))]
    pub lbl_eta: nwg::Label,

    #[nwg_control(text: "Elapsed:  00:00", size: (140, 16), position: (306, 342))]
    pub lbl_elapsed: nwg::Label,

    #[nwg_control(text: "Filtered:  0", size: (120, 16), position: (450, 342))]
    pub lbl_filtered: nwg::Label,

    #[nwg_control(text: "Ready.", size: (590, 16), position: (18, 362))]
    pub lbl_current_file: nwg::Label,

    // ═══ Controls row (shifted +26px) ════════════════════════════════════
    #[nwg_control(text: "  Start", size: (100, 28), position: (8, 400))]
    #[nwg_events(OnButtonClick: [UlpApp::on_start])]
    pub btn_start: nwg::Button,

    #[nwg_control(text: "  Stop", size: (100, 28), position: (116, 400), enabled: false)]
    #[nwg_events(OnButtonClick: [UlpApp::on_stop])]
    pub btn_stop: nwg::Button,

    #[nwg_control(text: "Verbose output", size: (150, 20), position: (232, 406), check_state: nwg::CheckBoxState::Unchecked)]
    #[nwg_events(OnButtonClick: [UlpApp::on_verbose_toggle])]
    pub chk_verbose: nwg::CheckBox,

    // ═══ Status bar ════════════════════════════════════════════════════
    #[nwg_control(text: "Ready")]
    pub status_bar: nwg::StatusBar,

    // ═══ Verbose log panel (shifted +26px) ═══════════════════════════════
    #[nwg_control(text: "Verbose Log", size: (612, 200), position: (8, 438), flags: "VISIBLE")]
    pub grp_verbose: nwg::GroupBox,

    #[nwg_control(
        text: "",
        size: (592, 175),
        position: (18, 456),
        flags: "VSCROLL|AUTOVSCROLL|VISIBLE"
    )]
    pub txt_verbose: nwg::TextBox,

    // ═══ File dialogs ════════════════════════════════════════════════════
    #[nwg_resource(
        title: "Select Input File",
        action: nwg::FileDialogAction::Open,
        filters: "Text Files (*.txt)|CSV Files (*.csv)|Log Files (*.log)|All Files (*.*)"
    )]
    pub dlg_input_file: nwg::FileDialog,

    #[nwg_resource(
        title: "Select Output CSV",
        action: nwg::FileDialogAction::Save,
        filters: "CSV Files (*.csv)|All Files (*.*)"
    )]
    pub dlg_output: nwg::FileDialog,

    // ═══ State fields (derive ignores these) ═════════════════════════════
    pub msg_queue:   RefCell<Option<MsgQueue>>,
    pub cancel_flag: RefCell<Option<Arc<AtomicBool>>>,
}

impl UlpApp {

    fn on_init(&self) {
        // Hide verbose panel on startup
        self.grp_verbose.set_visible(false);
        self.txt_verbose.set_visible(false);

        // Set detected CPU default for threads field
        let auto = processing::auto_thread_count();
        self.txt_threads.set_text(&auto.to_string());
        self.lbl_threads_hint.set_text(&format!("(0=auto, {} detected)", num_cpus::get()));

        self.status_bar.set_text(0, "Ready  |  Select input to begin.");
    }

    fn on_browse_file(&self) {
        if self.dlg_input_file.run(Some(&self.window)) {
            if let Ok(path) = self.dlg_input_file.get_selected_item() {
                let path_str = path.to_string_lossy().to_string();
                self.txt_input.set_text(&path_str);
                let out = std::path::Path::new(&path_str).with_extension("csv");
                self.txt_output.set_text(&out.to_string_lossy());
            }
        }
    }

    fn on_browse_folder(&self) {
        nwg::modal_info_message(
            &self.window,
            "Folder Input",
            "Type or paste a folder path directly into the Input field.\n\
             Processes all .txt / .csv / .log / .dat files alphabetically.",
        );
    }

    fn on_browse_output(&self) {
        if self.dlg_output.run(Some(&self.window)) {
            if let Ok(path) = self.dlg_output.get_selected_item() {
                let mut p = path.to_string_lossy().to_string();
                if !p.to_lowercase().ends_with(".csv") { p.push_str(".csv"); }
                self.txt_output.set_text(&p);
            }
        }
    }

    fn on_verbose_toggle(&self) {
        let on = self.chk_verbose.check_state() == nwg::CheckBoxState::Checked;
        self.grp_verbose.set_visible(on);
        self.txt_verbose.set_visible(on);
        self.window.set_size(WIN_W, if on { WIN_H_VERBOSE } else { WIN_H_COMPACT });
    }

    fn on_start(&self) {
        let input  = self.txt_input.text();
        let output = self.txt_output.text();

        if input.trim().is_empty() {
            nwg::modal_error_message(&self.window, "No Input",
                "Please select an input file or folder path.");
            return;
        }
        if output.trim().is_empty() {
            nwg::modal_error_message(&self.window, "No Output",
                "Please specify an output CSV path.");
            return;
        }

        // ── Parse GUI controls ────────────────────────────────────────────
        let pass_min = self.txt_pass_min.text().parse::<usize>().unwrap_or(6).clamp(1, 512);
        let pass_max = self.txt_pass_max.text().parse::<usize>().unwrap_or(128).clamp(1, 2048);
        let threads  = self.txt_threads.text().parse::<usize>().unwrap_or(0);

        if pass_min > pass_max {
            nwg::modal_error_message(&self.window, "Invalid Range",
                &format!("Password min ({}) cannot exceed max ({}).", pass_min, pass_max));
            return;
        }

        // ── Reset UI ──────────────────────────────────────────────────────
        self.progress_bar.set_pos(0);
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        for lbl in [
            &self.lbl_processed, &self.lbl_accepted, &self.lbl_rejected,
            &self.lbl_dupes, &self.lbl_filtered,
        ] { lbl.set_text(&lbl.text().split(':').next().unwrap_or("").to_string()
            .chars().collect::<String>() + ":  0"); }
        self.lbl_speed.set_text("Lines/sec:  --");
        self.lbl_eta.set_text("ETA:  --");
        self.lbl_elapsed.set_text("Elapsed:  00:00");
        self.lbl_current_file.set_text("Starting...");
        self.txt_verbose.set_text("");
        self.btn_start.set_enabled(false);
        self.btn_stop.set_enabled(true);
        self.status_bar.set_text(0, &format!(
            "Processing...  |  pass: {}-{}  |  threads: {}",
            pass_min, pass_max,
            if threads == 0 { "auto".to_string() } else { threads.to_string() }
        ));

        // ── Build PostProcessConfig from checkboxes ────────────────────────
        let checked = |cb: &nwg::CheckBox| cb.check_state() == nwg::CheckBoxState::Checked;
        let enforce_len = checked(&self.chk_min_pass);
        let pp_cfg = config::PostProcessConfig {
            deduplicate:                  checked(&self.chk_dedup),
            normalize_emails:             checked(&self.chk_normalize_email),
            strip_non_ascii:              checked(&self.chk_strip_nonascii),
            // If enforce_len unchecked: min=1, max=9999 (effectively no limit)
            min_password_len:             if enforce_len { pass_min } else { 1 },
            clean_url_schemes:            checked(&self.chk_clean_url),
            strip_default_ports:          checked(&self.chk_strip_ports),
            strip_url_paths:              checked(&self.chk_strip_paths),
            filter_placeholder_passwords: checked(&self.chk_placeholder),
            remove_pass_equals_user:      checked(&self.chk_pass_eq_user),
            lowercase_usernames:          true,
            reject_unknown_schemes:       false,
            export_stats:                 checked(&self.chk_export_stats),
        };

        let app_cfg = config::load("ulp_normalizer.toml").unwrap_or_default();

        let queue     = processing::new_queue();
        let cancel    = Arc::new(AtomicBool::new(false));
        let notice_tx = self.notice.sender();

        *self.msg_queue.borrow_mut()   = Some(queue.clone());
        *self.cancel_flag.borrow_mut() = Some(cancel.clone());

        // ── Spawn worker ──────────────────────────────────────────────────
        thread::spawn(move || {
            processing::run_processing(
                app_cfg, pp_cfg,
                input, output,
                threads, pass_min, pass_max,
                queue, cancel, notice_tx,
            );
        });
    }

    fn on_stop(&self) {
        if let Some(flag) = self.cancel_flag.borrow().as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
        self.status_bar.set_text(0, "Cancelling...");
    }

    fn on_worker_notice(&self) {
        let messages: Vec<UiMessage> = {
            if let Some(queue) = self.msg_queue.borrow().as_ref() {
                if let Ok(mut q) = queue.lock() {
                    q.drain(..).collect()
                } else { vec![] }
            } else { vec![] }
        };
        for msg in messages { self.handle_message(msg); }
    }

    fn handle_message(&self, msg: UiMessage) {
        match msg {
            UiMessage::Progress {
                processed, total_lines, accepted, rejected,
                duplicates, filtered, file_name, file_idx, file_count,
            } => {
                if total_lines > 0 {
                    let pct = ((processed as f64 / total_lines as f64) * 1000.0) as u32;
                    self.progress_bar.set_pos(pct.min(1000));
                }
                self.lbl_processed.set_text(&format!("Processed:  {}", fmt_num(processed)));
                self.lbl_accepted.set_text(&format!("Accepted:  {}", fmt_num(accepted)));
                self.lbl_rejected.set_text(&format!("Rejected:  {}", fmt_num(rejected)));
                self.lbl_dupes.set_text(&format!("Dupes:  {}", fmt_num(duplicates)));
                self.lbl_filtered.set_text(&format!("Filtered:  {}", fmt_num(filtered)));
                self.lbl_current_file.set_text(
                    &format!("[{}/{}]  {}", file_idx, file_count, file_name)
                );
            }
            UiMessage::Speed { lines_per_sec, eta_secs, elapsed_secs } => {
                self.lbl_speed.set_text(&format!("Lines/sec:  {}", fmt_speed(lines_per_sec)));
                self.lbl_eta.set_text(&format!("ETA:  {}", fmt_duration(eta_secs)));
                self.lbl_elapsed.set_text(&format!("Elapsed:  {}", fmt_duration(elapsed_secs)));
            }
            UiMessage::Log(text) => {
                if self.chk_verbose.check_state() == nwg::CheckBoxState::Checked {
                    self.append_log(&text);
                }
            }
            UiMessage::Done(stats) => {
                self.progress_bar.set_pos(1000);
                self.on_processing_done(&stats);
            }
            UiMessage::Error(err) => {
                self.btn_start.set_enabled(true);
                self.btn_stop.set_enabled(false);
                self.progress_bar.set_state(nwg::ProgressBarState::Error);
                self.status_bar.set_text(0, &format!("Error: {}", err));
                nwg::modal_error_message(&self.window, "Processing Error", &err);
            }
            UiMessage::Cancelled => {
                self.btn_start.set_enabled(true);
                self.btn_stop.set_enabled(false);
                self.progress_bar.set_state(nwg::ProgressBarState::Paused);
                self.status_bar.set_text(0, "Cancelled.");
                self.lbl_current_file.set_text("Cancelled.");
            }
        }
    }

    fn on_processing_done(&self, stats: &FinalStats) {
        self.btn_start.set_enabled(true);
        self.btn_stop.set_enabled(false);
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        let lps = if stats.elapsed_secs > 0.0 {
            fmt_speed(stats.total_input as f64 / stats.elapsed_secs)
        } else { "--".into() };
        self.status_bar.set_text(0, &format!(
            "Done in {:.1}s  |  Accepted: {}  |  Dupes: {}",
            stats.elapsed_secs,
            fmt_num(stats.accepted),
            fmt_num(stats.duplicates),
        ));
        self.lbl_current_file.set_text("Complete.");
        self.lbl_speed.set_text(&format!("Avg/sec:  {}", lps));
        self.lbl_eta.set_text("ETA:  Done");
        nwg::modal_info_message(
            &self.window, "Complete",
            &format!(
                "Processing Complete!\n\
                 ─────────────────────────────────\n\
                 Total Input    : {}\n\
                 Accepted       : {}\n\
                 Rejected       : {}\n\
                 Duplicates     : {}\n\
                 Short passwords: {}\n\
                 Placeholders   : {}\n\
                 Pass = User    : {}\n\
                 ─────────────────────────────────\n\
                 Elapsed        : {:.1}s\n\
                 Avg Speed      : {}/sec\n\
                 Output         : {}",
                fmt_num(stats.total_input), fmt_num(stats.accepted),
                fmt_num(stats.rejected), fmt_num(stats.duplicates),
                fmt_num(stats.filtered_short), fmt_num(stats.filtered_placeholder),
                fmt_num(stats.filtered_passequser),
                stats.elapsed_secs, lps, stats.output_path,
            ),
        );
    }

    fn append_log(&self, line: &str) {
        let current = self.txt_verbose.text();
        let lines: Vec<&str> = current.lines().collect();
        let trimmed = if lines.len() >= 500 {
            lines[lines.len()-499..].join("\r\n")
        } else { current };
        let new_text = if trimmed.is_empty() { line.to_string() }
                       else { format!("{}\r\n{}", trimmed, line) };
        self.txt_verbose.set_text(&new_text);
    }

    fn on_exit(&self) {
        if let Some(flag) = self.cancel_flag.borrow().as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        nwg::stop_thread_dispatch();
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}
fn fmt_speed(lps: f64) -> String {
    if lps >= 1_000_000.0  { format!("{:.1}M", lps / 1_000_000.0) }
    else if lps >= 1_000.0 { format!("{:.0}K", lps / 1_000.0) }
    else                   { format!("{:.0}", lps) }
}
fn fmt_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 { format!("{:02}:{:02}:{:02}", h, m, s) }
    else      { format!("{:02}:{:02}", m, s) }
}
