//! Two bounded observations of the NORMAL builder/bridge/packaged selector.
//! No alternate runtime, document, IPC command, timer, task or shutdown owner.
//! Only the existing relay drives these steps; failures cannot authorize exit.
use std::{ffi::OsStr, io::Write, sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, Ordering}},
    thread::ThreadId, time::{Duration, Instant}};
use serde_json::Value;
use tauri::Manager;
use crate::{bridge::AppInfo, error::BridgeError, supervisor::{HeldAppInfo, Supervisor}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Positive, Outstanding }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step { Bootstrap, Environment, ReadEnvironment, Credentials, OpenHelp, ReadHelp, CloseHelp, HelpGone, Close, Quit, Exit }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending { Dom(Step), Close, Gtk }

const HELP_KEYS: [&str; 8] = ["label", "requiredness", "what", "why", "where", "format", "requiredWhen", "failure"];
#[derive(PartialEq, Eq)]
struct HelpSample { values: [String; 8] }
impl HelpSample {
    fn read(field: &Value) -> Option<Self> {
        let mut values = std::array::from_fn(|_| String::new());
        for (index, key) in HELP_KEYS.iter().enumerate() {
            let text = field.get(*key)?.as_str()?;
            if text.is_empty() || text.len() > 16384 || text.encode_utf16().count() > 4096 { return None; }
            values[index] = text.to_owned();
        }
        Some(Self { values })
    }
}

struct Record {
    attached: bool, started: bool, loaded: bool,
    info: bool, methods: usize, sample: Option<HelpSample>,
    environment: bool, help: bool, help_gone: bool,
    step: Step, pending: Option<Pending>, evaluations: u16,
    close_prevented: bool, native_id: Option<u32>, activated: bool,
    responded: bool, disposal_response: bool, destroyed: bool, released: bool, gtk_returned: bool,
    relay_joined: bool, exit: bool, held: Option<HeldAppInfo>,
}
pub(super) struct Observation {
    case: Case, main: ThreadId, end: Instant, failed: AtomicBool, record: Mutex<Record>,
}
impl Observation {
    fn new(case: Case) -> Self {
        Self { case, main: std::thread::current().id(), end: Instant::now() + Duration::from_secs(45),
            failed: AtomicBool::new(false), record: Mutex::new(Record {
                attached: false, started: false, loaded: false, info: false, methods: 0, sample: None,
                environment: false, help: false, help_gone: false, step: Step::Bootstrap, pending: None, evaluations: 0,
                close_prevented: false, native_id: None, activated: false, responded: false, disposal_response: false,
                destroyed: false, released: false, gtk_returned: false, relay_joined: false, exit: false, held: None,
            }) }
    }
    fn fail(&self) { self.failed.store(true, Ordering::SeqCst); }
    fn record(&self) -> Option<MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(record) => Some(record), Err(_) => { self.fail(); None } }
    }
    pub(super) fn attach(&self, supervisor: &Supervisor) -> Result<(), BridgeError> {
        if std::thread::current().id() != self.main { self.fail(); return Err(BridgeError::invalid()); }
        // This is the supervisor just created by DesktopBridge::new in setup,
        // before the real window/bootstrap. Positive leaves all hooks unarmed.
        if self.case == Case::Outstanding { supervisor.arm_initial_app_info_shutdown()?; }
        let mut record = self.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if record.attached { self.fail(); return Err(BridgeError::invalid()); }
        record.attached = true;
        Ok(())
    }
    pub(super) fn page_load(&self, trusted: bool, finished: bool) {
        let Some(mut r) = self.record() else { return; };
        if !trusted || !r.attached || if finished { !r.started || r.loaded } else { r.started } { self.fail(); return; }
        if finished { r.loaded = true; } else { r.started = true; }
    }
    pub(super) fn app_info(&self, info: &AppInfo) {
        if self.case == Case::Outstanding {
            if info.runtime.state == "available" || info.capabilities.is_some() { self.fail(); }
            return;
        }
        let Some(methods) = info.capabilities.as_ref().and_then(|c| c.get("methods")).and_then(Value::as_array) else { self.fail(); return; };
        let Some(actions) = info.capabilities.as_ref().and_then(|c| c.get("actions")).and_then(Value::as_array) else { self.fail(); return; };
        if !(2..=64).contains(&methods.len()) || actions.is_empty() || actions.len() > 64 { self.fail(); return; }
        let available = |m: &&Value| m.get("available").and_then(Value::as_bool) == Some(true);
        let valid = info.runtime.state == "available" && info.runtime.mode == "bundled" && info.runtime.reason.is_none()
            && info.app_name == "Mobile Release Kit" && info.app_version == env!("CARGO_PKG_VERSION")
            && methods.iter().filter(available).count() == 2
            && ["capabilities", "catalog"].iter().all(|name| methods.iter().filter(available).any(|m| m.get("method").and_then(Value::as_str) == Some(*name)))
            && methods.iter().all(|m| m.get("available").and_then(Value::as_bool).is_some())
            && actions.iter().all(|a| a.get("available").and_then(Value::as_bool) == Some(false));
        let Some(mut r) = self.record() else { return; };
        if !valid || r.info { self.fail(); return; }
        r.info = true; r.methods = methods.len();
    }
    pub(super) fn catalog(&self, result: &Result<Value, BridgeError>) {
        // Eight bounded public help fields only, captured from the real reply.
        // The frontend still parses/adopts that reply itself, with no injection.
        let sample = result.as_ref().ok().and_then(|v| v.get("credentialGuide"))
            .and_then(|v| v.get("kinds")).and_then(Value::as_array).and_then(|v| v.first())
            .and_then(|v| v.get("fields")).and_then(Value::as_array).and_then(|v| v.first()).and_then(HelpSample::read);
        let Some(mut r) = self.record() else { return; };
        if self.case != Case::Positive || !r.info || r.sample.is_some() || sample.is_none() { self.fail(); return; }
        r.sample = sample;
    }
    pub(super) fn tick(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.failed.load(Ordering::SeqCst) { return; }
        if Instant::now() >= self.end || std::thread::current().id() == self.main { self.fail(); return; }
        let step = {
            let Some(mut r) = self.record() else { return; };
            if !r.attached || !r.loaded || r.pending.is_some() { return; }
            if r.step == Step::Bootstrap && self.case == Case::Positive {
                if !r.info || r.sample.is_none() { return; }
                r.step = Step::Environment;
            }
            r.step
        };
        if step == Step::Bootstrap {
            // The original J seam holds this actual initial app-info child
            // before its writer. No query, candidate constructor or resource
            // lock is introduced here. The returned token retains that owner.
            match app.state::<super::ShellState>().bridge.supervisor.retain_held_app_info() {
                Ok(Some(held)) => {
                    let Some(mut r) = self.record() else { return; };
                    if r.held.is_some() { self.fail(); return; }
                    r.held = Some(held); r.step = Step::Close;
                },
                Ok(None) => {}, Err(_) => self.fail(),
            }
            return;
        }
        if step == Step::Exit { return; }
        {
            let Some(mut r) = self.record() else { return; };
            r.pending = Some(match step {
                Step::Close => { r.step = Step::Quit; Pending::Close },
                Step::Quit => { if !r.close_prevented { self.fail(); return; } Pending::Gtk },
                _ => {
                    if r.evaluations >= 128 { self.fail(); return; }
                    r.evaluations += 1; Pending::Dom(step)
                },
            });
        }
        let Some(window) = app.get_webview_window(super::MAIN_WINDOW) else { self.fail(); return; };
        match step {
            Step::Close => { if window.close().is_err() { self.fail(); } },
            Step::Quit => {
                let q = self.clone(); let app = app.clone();
                if window.run_on_main_thread(move || {
                    let result = super::owned_gtk::activate_observed_quit(&app, &q);
                    q.gtk_returned(result);
                }).is_err() { self.fail(); }
            },
            _ => {
                let Some(script) = script(step) else { self.fail(); return; };
                let q = self.clone();
                // Outer Ok is dispatch, never an evaluation or DOM receipt.
                // An absent callback remains pending; it is never retried.
                if window.eval_with_callback(script, move |value| q.dom(step, &value)).is_err() { self.fail(); }
            },
        }
    }
    fn dom(&self, step: Step, raw: &str) {
        if raw.len() > 262144 || Instant::now() >= self.end { self.fail(); return; }
        let Ok(value) = crate::protocol::strict_json(raw.as_bytes()) else { self.fail(); return; };
        let Some(object) = value.as_object() else { self.fail(); return; };
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Dom(step)) || r.step != step { self.fail(); return; }
        match value.get("state").and_then(Value::as_str) {
            Some("wait") if object.len() == 1 => return,
            Some("ready") => {}, _ => { self.fail(); return; },
        }
        let valid = match step {
            Step::ReadEnvironment => {
                let versions = value.get("versions").and_then(Value::as_array);
                let available = value.get("available").and_then(Value::as_array);
                object.len() == 7 && value.get("title").and_then(Value::as_str) == Some("Bundled runtime")
                    && value.get("badge").and_then(Value::as_str) == Some("available")
                    && value.get("rows").and_then(Value::as_u64) == Some(r.methods as u64)
                    && value.get("unavailable").and_then(Value::as_u64) == Some((r.methods - 2) as u64)
                    && versions.is_some_and(|v| v.len() == 3 && v[0].as_str() == Some(env!("CARGO_PKG_VERSION"))
                        && v[1].as_str() == Some(crate::runtime::CORE_VERSION) && v[2].as_str() == Some("linux"))
                    && available.is_some_and(|a| a.len() == 2 && a[0].as_str() == Some("Read engine capabilities")
                        && a[1].as_str() == Some("Load schema & field help"))
            },
            Step::OpenHelp => object.len() == 3 && r.sample.as_ref().is_some_and(|sample|
                value.get("label").and_then(Value::as_str) == Some(sample.values[0].as_str())
                    && value.get("ariaLabel").and_then(Value::as_str).is_some_and(|label| label.strip_prefix("Help: ") == Some(sample.values[0].as_str()))),
            Step::ReadHelp => object.len() == 2 && value.get("help").and_then(Value::as_object).is_some_and(|h| h.len() == 8)
                && value.get("help").and_then(HelpSample::read).as_ref().is_some_and(|actual| r.sample.as_ref() == Some(actual)),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        r.step = match step {
            Step::Environment => Step::ReadEnvironment,
            Step::ReadEnvironment => { r.environment = true; Step::Credentials },
            Step::Credentials => Step::OpenHelp,
            Step::OpenHelp => Step::ReadHelp,
            Step::ReadHelp => { r.help = true; Step::CloseHelp },
            Step::CloseHelp => Step::HelpGone,
            Step::HelpGone => { r.help_gone = true; Step::Close },
            _ => { self.fail(); return; },
        };
    }
    pub(super) fn close_prevented(&self) {
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Close) || r.step != Step::Quit || r.close_prevented { self.fail(); return; }
        r.close_prevented = true;
    }
    pub(super) fn native_created(&self, id: u32, quit: bool) {
        let Some(mut r) = self.record() else { return; };
        if !quit || id == 0 || !r.close_prevented || r.step != Step::Quit || r.native_id.is_some() { self.fail(); return; }
        r.native_id = Some(id);
    }
    pub(super) fn native_activation(&self, id: u32) -> Result<(), ()> {
        let Some(mut r) = self.record() else { return Err(()); };
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= self.end || r.native_id != Some(id)
            || r.pending != Some(Pending::Gtk) || r.activated { self.fail(); return Err(()); }
        r.activated = true; Ok(())
    }
    pub(super) fn native_response(&self, id: u32, accepted: bool, disposal: bool) {
        let Some(mut r) = self.record() else { return; };
        if r.native_id != Some(id) || !r.activated || r.destroyed || r.released { self.fail(); return; }
        if accepted && !disposal && !r.responded { r.responded = true; }
        else if disposal && !accepted && r.responded && r.gtk_returned && !r.disposal_response {
            // At most one close-generated DeleteEvent, witnessed by the same
            // original close_ack/accepted/returned-None facts in shell.rs.
            r.disposal_response = true;
        } else { self.fail(); }
    }
    fn gtk_returned(&self, result: Result<bool, ()>) {
        let Some(mut r) = self.record() else { return; };
        if r.pending.take() != Some(Pending::Gtk) { self.fail(); return; }
        match result {
            Ok(false) if !r.activated => {},
            Ok(true) if r.activated && r.responded => { r.gtk_returned = true; r.step = Step::Exit; },
            _ => self.fail(),
        }
    }
    pub(super) fn native_destroyed(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record() else { return; };
        if !seen || r.native_id != Some(id) || !r.responded || r.destroyed { self.fail(); return; }
        r.destroyed = true;
    }
    pub(super) fn native_released(&self, id: u32, seen: bool) {
        let Some(mut r) = self.record() else { return; };
        if !seen || r.native_id != Some(id) || !r.destroyed || r.released { self.fail(); return; }
        r.released = true;
    }
    pub(super) fn relay_joined(&self, joined: bool) {
        let Some(mut r) = self.record() else { return; };
        if !joined || !r.released || !r.gtk_returned || r.relay_joined { self.fail(); return; }
        r.relay_joined = true;
    }
    pub(super) fn actual_exit(&self, ready: bool) {
        let Some(mut r) = self.record() else { return; };
        if !ready || !r.relay_joined || !r.released || r.exit { self.fail(); return; }
        r.exit = true;
    }
    fn finish(&self) -> bool {
        let held = match self.record() { Some(mut r) => r.held.take(), None => return false };
        let retired = match (self.case, held) {
            (Case::Positive, None) => true,
            (Case::Outstanding, Some(mut held)) => {
                // Borrow/join the same original after the NORMAL event loop
                // exits. No additional task, shutdown call, or replacement
                // settlement flag. The once-captured observation end is reused.
                tauri::async_runtime::block_on(held.observe_retired(self.end)).is_ok()
            },
            _ => false,
        };
        let Some(r) = self.record() else { return false; };
        retired && !self.failed.load(Ordering::SeqCst) && Instant::now() < self.end && r.attached && r.loaded
            && r.close_prevented && r.activated && r.responded && r.destroyed && r.released && r.gtk_returned
            && r.relay_joined && r.exit && r.pending.is_none() && r.step == Step::Exit
            && (self.case == Case::Outstanding || r.info && r.sample.is_some() && r.environment && r.help && r.help_gone)
    }
}

// Fixed synchronous DOM expressions. Click only existing UI controls, wait for
// later React/effect rendering, and return actual bounded text for comparison.
// No injected data, invoke, event emission, async Promise, or synthetic receipt.
fn script(step: Step) -> Option<String> {
    let body = match step {
        Step::Environment => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::ReadEnvironment => r#"
            const selected = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Environment"][aria-current="page"]');
            const card = document.querySelector('.runtime-card');
            if (!selected || !card) return {state:'wait'};
            card.scrollIntoView({block:'start'}); if (!visible(card)) return {state:'error'};
            const rows = [...document.querySelectorAll('.capability-list > div')];
            if (rows.length < 2 || rows.length > 64) return {state:'error'};
            const available = rows.filter(r => text(r.querySelector('.badge')) === 'Available · passive').map(r => text(r.querySelector('strong')));
            const versions = [...card.querySelectorAll('.runtime-versions strong')].map(text);
            return {state:'ready', title:text(card.querySelector('h2')), badge:text(card.querySelector('.badge')),
                versions, available, rows:rows.length, unavailable:rows.filter(r => text(r.querySelector('.badge')) === 'Unavailable').length};"#,
        Step::Credentials => r#"
            const b = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Credentials"]');
            if (!b) return {state:'wait'}; if (b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::OpenHelp => r#"
            const selected = document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="Credentials"][aria-current="page"]');
            const field = document.querySelector('.asset-guide-fields > li');
            if (!selected || !field) return {state:'wait'};
            const b = field.querySelector('.help-button');
            if (!b || b.disabled || document.querySelector('dialog')) return {state:'error'};
            b.scrollIntoView({block:'center'});
            if (!visible(b)) return {state:'error'};
            const label = text(field.querySelector('h4')); const ariaLabel = b.getAttribute('aria-label');
            if (typeof ariaLabel !== 'string' || ariaLabel.length > 4110) return {state:'error'};
            b.click(); return {state:'ready', label, ariaLabel};"#,
        Step::ReadHelp => r#"
            const dialogs = document.querySelectorAll('dialog.help-dialog');
            if (dialogs.length === 0) return {state:'wait'};
            if (dialogs.length !== 1) return {state:'error'};
            const d = dialogs[0]; if (!d.open || !visible(d)) return {state:'wait'};
            const values = [...d.querySelectorAll('.help-definitions dd')].map(text);
            if (values.length !== 6) return {state:'error'};
            return {state:'ready', help:{label:text(d.querySelector('h2')), requiredness:text(d.querySelector('.badge')),
                what:values[0], why:values[1], where:values[2], format:values[3], requiredWhen:values[4], failure:values[5]}};"#,
        Step::CloseHelp => r#"
            const d = document.querySelector('dialog.help-dialog[open]');
            const b = d && d.querySelector('button[aria-label="Close help"]');
            if (!b || b.disabled) return {state:'error'};
            b.click(); return {state:'ready'};"#,
        Step::HelpGone => r#"
            return {state:document.querySelector('dialog.help-dialog') ? 'wait' : 'ready'};"#,
        _ => return None,
    };
    Some(format!(r#"(() => {{ try {{
        if (document.querySelector('.preview-banner, .fatal-error, #main-content > .notice-danger')) return {{state:'error'}};
        const text = e => {{ if (!e) throw 0; const t = e.textContent; if (typeof t !== 'string' || t.length > 4096) throw 0; return t; }};
        const visible = e => {{ const r=e.getBoundingClientRect(); const s=getComputedStyle(e); return e.isConnected && r.width>0 && r.height>0 && s.display!=='none' && s.visibility==='visible'; }};
        {body}
    }} catch {{ return {{state:'error'}}; }} }})()"#))
}

fn route() -> bool {
    let Some(source) = option_env!("GITHUB_SHA") else { return false; };
    source.len() == 40 && source.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && [("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
            ("MRK_DESKTOP_HOSTED_CHECKS", "installed-shell-connection-v1"), ("GITHUB_SHA", source)]
            .iter().all(|(key, value)| std::env::var(key).ok().as_deref() == Some(*value))
        && rustix::process::getuid().as_raw() != 0 && rustix::process::getuid() == rustix::process::geteuid()
}
pub(crate) fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let case = match args.next().as_deref() {
        Some(value) if value == OsStr::new("positive") => Some(Case::Positive),
        Some(value) if value == OsStr::new("quit-outstanding") => Some(Case::Outstanding),
        _ => None,
    };
    let Some(case) = case.filter(|_| args.next().is_none() && route()) else {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=route-refused\n");
        return std::process::ExitCode::FAILURE;
    };
    let q = Arc::new(Observation::new(case));
    // This target has no libtest harness. Execute the same two pure contracts
    // here, before GTK; an assertion failure cannot reach the success report.
    crate::bridge::assert_native_capability_intersection_contract();
    crate::runtime::assert_packaged_shell_allowlist_contract();
    // Routing DATA is not native admission. The ordinary builder constructs
    // DesktopBridge::new / RuntimeConfig::packaged and owes every real check.
    let returned = super::run_builder(super::builder().manage(q.clone()));
    if !matches!(returned, Ok(0)) || !q.finish() {
        super::diagnostic(b"MRK_INSTALLED_SHELL_OBSERVATION=failed\n");
        return std::process::ExitCode::FAILURE;
    }
    let line: &[u8] = match case {
        Case::Positive => b"MRK_INSTALLED_SHELL_OBSERVATION=positive-verified\n",
        Case::Outstanding => b"MRK_INSTALLED_SHELL_OBSERVATION=quit-outstanding-verified\n",
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n")
        .and_then(|_| stdout.write_all(line)).is_ok() { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
}
