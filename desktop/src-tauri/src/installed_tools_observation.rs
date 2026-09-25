//! Closed installed Tools/Offline observations driven by the existing shell relay.
//! No alternate engine, runtime, owner, IPC command or shutdown authority.
use std::{fs::File, os::unix::fs::{FileExt, MetadataExt}, path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak, Condvar, atomic::{AtomicBool, AtomicU8, Ordering}}, time::{Duration, Instant}};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::Manager;
use tokio::sync::watch;
use crate::{error::BridgeError, environment_diagnostics_protocol as tools, offline_preflight_protocol as offline};
use super::{Observation, Case as ShellCase, Step as ShellStep};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case { ToolsObserved, ToolsCancel, ToolsSettlement, OfflinePass, OfflineNegative, OfflineDrift, OfflineCancel, OfflineSettlement }
impl Case {
    pub(crate) const ALL: [Self; 8] = [Self::ToolsObserved, Self::ToolsCancel, Self::ToolsSettlement, Self::OfflinePass,
        Self::OfflineNegative, Self::OfflineDrift, Self::OfflineCancel, Self::OfflineSettlement];
    pub(crate) fn name(self) -> &'static str { match self {
        Self::ToolsObserved => "tools-observed", Self::ToolsCancel => "tools-cancel", Self::ToolsSettlement => "tools-settlement",
        Self::OfflinePass => "offline-pass", Self::OfflineNegative => "offline-negative", Self::OfflineDrift => "offline-drift",
        Self::OfflineCancel => "offline-cancel", Self::OfflineSettlement => "offline-settlement",
    } }
    pub(crate) fn parse(value: &std::ffi::OsStr) -> Option<Self> { Self::ALL.into_iter().find(|case| value == std::ffi::OsStr::new(case.name())) }
    pub(super) fn failure_leaf(self) -> &'static str { match self {
        Self::ToolsObserved => "shell-tools-observed-failure.labels", Self::ToolsCancel => "shell-tools-cancel-failure.labels",
        Self::ToolsSettlement => "shell-tools-settlement-failure.labels", Self::OfflinePass => "shell-offline-pass-failure.labels",
        Self::OfflineNegative => "shell-offline-negative-failure.labels", Self::OfflineDrift => "shell-offline-drift-failure.labels",
        Self::OfflineCancel => "shell-offline-cancel-failure.labels", Self::OfflineSettlement => "shell-offline-settlement-failure.labels",
    } }
    pub(super) fn verified_line(self) -> &'static [u8] { match self {
        Self::ToolsObserved => b"MRK_INSTALLED_SHELL_OBSERVATION=tools-observed-verified\n",
        Self::ToolsCancel => b"MRK_INSTALLED_SHELL_OBSERVATION=tools-cancel-verified\n",
        Self::ToolsSettlement => b"MRK_INSTALLED_SHELL_OBSERVATION=tools-settlement-verified\n",
        Self::OfflinePass => b"MRK_INSTALLED_SHELL_OBSERVATION=offline-pass-verified\n",
        Self::OfflineNegative => b"MRK_INSTALLED_SHELL_OBSERVATION=offline-negative-verified\n",
        Self::OfflineDrift => b"MRK_INSTALLED_SHELL_OBSERVATION=offline-drift-verified\n",
        Self::OfflineCancel => b"MRK_INSTALLED_SHELL_OBSERVATION=offline-cancel-verified\n",
        Self::OfflineSettlement => b"MRK_INSTALLED_SHELL_OBSERVATION=offline-settlement-verified\n",
    } }
    pub(crate) fn tools(self) -> bool { matches!(self, Self::ToolsObserved | Self::ToolsCancel | Self::ToolsSettlement) }
    fn cancel(self) -> bool { matches!(self, Self::ToolsCancel | Self::OfflineCancel) }
    fn reciprocal(self) -> bool { matches!(self, Self::ToolsSettlement | Self::OfflineCancel | Self::OfflineSettlement) }
    fn boundary(self) -> &'static str { match self { Self::ToolsCancel => "inspection",
        Self::ToolsSettlement | Self::OfflineSettlement => "settlement", _ => "none" } }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Domain { Tools, Offline }
impl Domain { fn bit(self) -> u8 { match self { Self::Tools => 1, Self::Offline => 2 } } }
fn admit_once(admitted: &AtomicU8, domain: Domain) -> bool { admitted.fetch_or(domain.bit(), Ordering::SeqCst) & domain.bit() == 0 }
fn claim_once(case: Case, admitted: u8, claimed: &AtomicU8, domain: Domain) -> bool {
    admitted == 3 && case.tools() == (domain == Domain::Tools)
        && claimed.compare_exchange(0, domain.bit(), Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

// Non-cloneable setup tokens; only this module can construct them. They carry
// neither paths nor results, and the actual document consumes them before IPC.
pub(crate) struct ToolsAdmission { control: Arc<Control> }
pub(crate) struct OfflineAdmission { control: Arc<Control> }
impl ToolsAdmission { pub(crate) fn consume(self) -> Result<Arc<Control>, BridgeError> { self.control.consume(Domain::Tools)?; Ok(self.control) } }
impl OfflineAdmission { pub(crate) fn consume(self) -> Result<Arc<Control>, BridgeError> { self.control.consume(Domain::Offline)?; Ok(self.control) } }

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OriginalFacts {
    pub(crate) domain: &'static str, pub(crate) id: String, pub(crate) generation: String,
    pub(crate) inspection_joined: bool, pub(crate) acquisition_joined: bool, pub(crate) attempted: bool, pub(crate) no_child: bool,
    pub(crate) child_waited_success: bool, pub(crate) stdin_closed: bool, pub(crate) stdout_eof_closed: bool, pub(crate) stderr_eof_closed: bool,
    pub(crate) io_joined: bool, pub(crate) core_lifetime_settled: bool, pub(crate) runtime_ledger_settled: bool, pub(crate) runtime_settlement_joined: bool,
    pub(crate) driver_joined: bool, pub(crate) manager_joined: bool, pub(crate) observer_joined: bool, pub(crate) watchdog_joined: bool,
    pub(crate) retired_before_cutoff: bool, pub(crate) active_retained: bool, pub(crate) resource_unknown: bool,
}
impl OriginalFacts {
    fn final_for(&self, case: Case) -> bool {
        let common = self.domain == (if case.tools() { "tools" } else { "offline" })
            && self.inspection_joined && self.io_joined && self.runtime_ledger_settled && self.runtime_settlement_joined
            && self.driver_joined && self.manager_joined && self.observer_joined && self.watchdog_joined
            && self.retired_before_cutoff && !self.active_retained && !self.resource_unknown;
        common && if case == Case::ToolsCancel {
            self.no_child && !self.attempted && !self.acquisition_joined && !self.child_waited_success
                && !self.stdin_closed && !self.stdout_eof_closed && !self.stderr_eof_closed && !self.core_lifetime_settled
        } else {
            !self.no_child && self.attempted && self.acquisition_joined && self.child_waited_success
                && self.stdin_closed && self.stdout_eof_closed && self.stderr_eof_closed && self.core_lifetime_settled
        }
    }
    fn held_for(&self, case: Case) -> bool {
        let pending = self.domain == (if case.tools() { "tools" } else { "offline" })
            && self.inspection_joined && self.active_retained && !self.retired_before_cutoff && !self.resource_unknown
            && !self.runtime_ledger_settled && !self.runtime_settlement_joined
            && !self.driver_joined && !self.manager_joined && !self.observer_joined && !self.watchdog_joined;
        pending && if case == Case::ToolsCancel {
            self.no_child && !self.attempted && !self.acquisition_joined && !self.child_waited_success
        } else { matches!(case, Case::ToolsSettlement | Case::OfflineSettlement)
            && !self.no_child && self.attempted && self.acquisition_joined && self.child_waited_success
            && self.stdin_closed && self.stdout_eof_closed && self.stderr_eof_closed && self.io_joined && self.core_lifetime_settled }
    }
}
#[derive(Clone)]
pub(crate) struct Snapshot { pub(crate) facts: OriginalFacts, pub(crate) terminal: Value }
#[derive(Default)]
struct Hold { entered: bool, released: bool, failed: bool, facts: Option<OriginalFacts> }
pub(crate) struct Control {
    pub(crate) case: Case, original: Mutex<Option<Weak<Observation>>>, admitted: AtomicU8, claimed: AtomicU8,
    hold: Mutex<Hold>, release: watch::Sender<bool>, blocking: Condvar,
    failed: AtomicBool, record: Mutex<Record>,
}
impl Control {
    pub(super) fn new(case: Case) -> Arc<Self> {
        let (release, _) = watch::channel(false);
        Arc::new(Self { case, original: Mutex::new(None), admitted: AtomicU8::new(0), claimed: AtomicU8::new(0),
            hold: Mutex::new(Hold::default()), release, blocking: Condvar::new(), failed: AtomicBool::new(false), record: Mutex::new(Record::default()) })
    }
    fn original(&self) -> Result<Arc<Observation>, BridgeError> {
        self.original.lock().map_err(|_| BridgeError::cleanup_unknown())?.as_ref().and_then(Weak::upgrade).ok_or_else(BridgeError::invalid)
    }
    fn consume(&self, domain: Domain) -> Result<(), BridgeError> {
        let q = self.original()?; let r = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
        if !super::route() || !cfg!(all(target_os="linux",target_arch="x86_64",target_env="gnu"))
            || q.case != ShellCase::Commands(self.case) || !r.attached || r.started || q.failed.load(Ordering::SeqCst)
            || !q.commands.as_ref().is_some_and(|c| std::ptr::eq(c.as_ref(), self)) || !self.record().is_some_and(|r| r.issued)
            || !admit_once(&self.admitted, domain) { return Err(BridgeError::invalid()); }
        Ok(())
    }
    pub(crate) fn claim(&self, domain: Domain) -> Result<(), BridgeError> {
        let q = self.original()?;
        if q.failed.load(Ordering::SeqCst) || self.failed.load(Ordering::SeqCst)
            || !claim_once(self.case, self.admitted.load(Ordering::SeqCst), &self.claimed, domain) { return Err(BridgeError::invalid()); }
        Ok(())
    }
    fn fail(&self) { self.failed.store(true, Ordering::SeqCst); if let Ok(q) = self.original() { q.fail(); } }
    pub(crate) fn unavailable_witness(&self) { self.fail(); }
    // Called by the original owner with actual state while its resource guard
    // is held. This is pending DATA; it cannot claim worker entry or finality.
    pub(crate) fn prepare_hold(&self, facts: OriginalFacts) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.fail(); return false; };
        if self.case.boundary() == "none" || hold.facts.is_some() || hold.entered || hold.released { self.fail(); return false; }
        hold.facts = Some(facts); true
    }
    fn enter(&self) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.fail(); return false; };
        if hold.facts.is_none() || hold.entered || hold.released || hold.failed { self.fail(); return false; }
        hold.entered = true; true
    }
    pub(crate) async fn hold_inspection(&self, end: Instant) -> bool {
        let limit = end.min(Instant::now() + Duration::from_secs(2));
        if self.case != Case::ToolsCancel || !self.enter() { return false; }
        let mut released = self.release.subscribe();
        let result = tokio::time::timeout_at(limit.into(), async {
            while !*released.borrow_and_update() { if released.changed().await.is_err() { return false; } } true
        }).await.unwrap_or(false) && Instant::now() < limit;
        if !result { self.fail(); } result
    }
    // Runs only INSIDE the already registered original closer after its GO.
    // It holds no resource/registry/document lock and creates no new worker.
    pub(crate) fn hold_settlement(&self, end: Instant) -> bool {
        let limit = end.min(Instant::now() + Duration::from_secs(2));
        if !matches!(self.case, Case::ToolsSettlement | Case::OfflineSettlement) || !self.enter() { return false; }
        let Ok(mut hold) = self.hold.lock() else { self.fail(); return false; };
        while !hold.released {
            let Some(left) = limit.checked_duration_since(Instant::now()) else { hold.failed = true; self.fail(); return false; };
            let Ok((next, _)) = self.blocking.wait_timeout(hold, left) else { self.fail(); return false; }; hold = next;
        }
        if Instant::now() >= limit { hold.failed = true; self.fail(); false } else { !hold.failed }
    }
    fn release(&self) -> bool {
        let Ok(mut hold) = self.hold.lock() else { self.fail(); return false; };
        if !hold.entered || hold.released || hold.failed { self.fail(); return false; }
        hold.released = true; self.release.send_replace(true); self.blocking.notify_all(); true
    }
}

// The sole mutation is one LF through the already-open original config in the
// drift case. Other originals are observed, never replaced or repaired.
const DIRECTORIES: [&str; 9] = [".", "project", "project/.git", "project/app", "project/release", "project/release/store",
    "project/release/store/android", "project/release/store/android/en-US", "project/release/store/android/en-US/changelogs"];
const FILES: [(&str, u64, &str); 9] = [
    ("project/.gitignore",18,"09a8d562f263ab37eb0df4ec1495845139b47d52bebd88b668eb99cc39ee5f81"),
    ("project/app/build.gradle.kts",200,"3dd6f6d4deb260b4795a9f3190605fbbfeff1913b4ab66b6d44ba9eb8a59e836"),
    ("project/check.py",829,"4ff4b3b59ea27f0761881c9ab56d9478c0ce1e6f74554105917d8fcd8ea0d9e1"),
    ("project/gradlew",18,"9ccc5b3962196da108c17f57dbdfa6b8cfe235c23fbff9a829da17d3605f9884"),
    ("project/release/version.properties",35,"c73d049fd2d8df50bc9c6e00e1e9eb38bbdf658670fe90ac0f08159fc0beb12c"),
    ("project/release/store/android/en-US/title.txt",7,"413fc3ae31fc069fb24f61f6fa0e98e9a7e73c674e0901b38d3a70e7c7f3660a"),
    ("project/release/store/android/en-US/short_description.txt",29,"f70b38db6df2ab49cc90500e70a4e5ca6c0f3e645ebc3e8bc72a45f74e2bce84"),
    ("project/release/store/android/en-US/full_description.txt",32,"f33c9642eb88fc6ef94ec8099258c2aa486478817555efbfbabc49906ec7bb74"),
    ("project/release/store/android/en-US/changelogs/default.txt",26,"72b9553ff79986cec26850942d5aa6c7e737e30035c6303dddd12f7bb9faf2c0"),
];
const OBSERVED: [&str; 3] = ["project/release/mobile-release.json", "project/script.trace", "project/later.trace"];
fn config_descriptor(case: Case) -> (u64, &'static str) { match case {
    Case::OfflineNegative => (1174,"4081ee76f52e0c4f50c788a53856bd80c69b2462e2d5349318b32a4603737419"),
    Case::OfflineCancel => (1173,"e59ce7cab9b7959e217bde3054bf87ac1576f1bd1a5fe2ef880963356e2509ec"),
    _ => (1045,"5e9bbc6ceb2d3a08ac8a78a393138ea74aa996954d744ac9f2fbdc28db6ef84d"),
} }
fn expected_trace(case: Case) -> &'static [u8] { match case {
    Case::OfflinePass | Case::OfflineSettlement => b"pass\n", Case::OfflineNegative => b"exit-7\n", Case::OfflineCancel => b"active\n", _ => b"",
} }
fn file_identity(file: &File) -> Result<super::FixtureIdentity, ()> {
    let m = file.metadata().map_err(|_| ())?;
    let ns = |sec: i64, nano: i64| u64::try_from(sec).ok().and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| u64::try_from(nano).ok().filter(|n| *n < 1_000_000_000).and_then(|n| s.checked_add(n))).ok_or(());
    Ok([m.dev(),m.ino(),u64::from(m.mode()),u64::from(m.uid()),u64::from(m.gid()),m.nlink(),m.len(),ns(m.mtime(),m.mtime_nsec())?,ns(m.ctime(),m.ctime_nsec())?])
}
fn open_file(path: &Path, writable: bool) -> Result<File, ()> {
    use rustix::fs::{open, OFlags, Mode};
    open(path, (if writable { OFlags::RDWR } else { OFlags::RDONLY }) | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty()).map(File::from).map_err(|_| ())
}
fn read_bound(file: &File, path: &Path, identity: &super::FixtureIdentity, variable: bool) -> Result<Vec<u8>, ()> {
    let before = file_identity(file)?;
    if (if variable { before[..6] != identity[..6] } else { before != *identity })
        || before[6] > 2048 || super::fixture_identity(path)? != before { return Err(()); }
    let mut bytes = vec![0u8; before[6] as usize];
    file.read_exact_at(&mut bytes, 0).map_err(|_| ())?;
    let mut extra = [0u8;1]; if file.read_at(&mut extra, before[6]).map_err(|_| ())? != 0
        || file_identity(file)? != before || super::fixture_identity(path)? != before { return Err(()); }
    Ok(bytes)
}
#[derive(Debug, PartialEq, Eq)]
enum ActiveTrace { Empty, Changing, Active }
// Polling DATA only: the original configured check appends one active marker.
// A changing sample cannot prove readiness, finality or permission to reopen.
fn active_trace_sample(original: &super::FixtureIdentity, minimum_size: u64,
    samples: &[super::FixtureIdentity; 4], bytes: &[u8]) -> Result<ActiveTrace, ()> {
    const ACTIVE: &[u8] = b"active\n";
    if original[6] != 0 || minimum_size > ACTIVE.len() as u64 { return Err(()); }
    let mut size = minimum_size;
    for sample in samples {
        if sample[..6] != original[..6] || sample[6] < size || sample[6] > ACTIVE.len() as u64 { return Err(()); }
        size = sample[6];
    }
    let count = bytes.len() as u64;
    if !ACTIVE.starts_with(bytes) || count < samples[1][6] || count > samples[2][6] { return Err(()); }
    if samples.iter().all(|sample| *sample == samples[0]) {
        if count != size { return Err(()); }
        if bytes.is_empty() { Ok(ActiveTrace::Empty) }
        else if bytes == ACTIVE { Ok(ActiveTrace::Active) } else { Err(()) }
    } else { Ok(ActiveTrace::Changing) }
}
struct Fixture {
    case: Case, root: PathBuf, ancestors: Vec<(PathBuf, super::FixtureIdentity)>, originals: Vec<(&'static str, super::FixtureIdentity)>,
    handles: [Option<File>; 3], saved: Value, raw: Vec<u8>, changed: bool, change_attempted: bool, active_size_seen: u64,
}
impl Fixture {
    fn capture(project: &Path, case: Case) -> Result<Self, ()> {
        let positive = super::project_path().ok_or(())?; let namespace = positive.parent().ok_or(())?;
        let root = namespace.join(case.name());
        if root.join("project").as_path() != project || rustix::process::getuid().as_raw() == 0
            || rustix::process::getuid() != rustix::process::geteuid() || rustix::process::getgid().as_raw() == 0
            || rustix::process::getgid() != rustix::process::getegid() { return Err(()); }
        let mut ancestors = Vec::new();
        for path in namespace.ancestors() {
            if ancestors.len() >= 4 { return Err(()); }
            let id = super::fixture_identity(path)?;
            if id[0] == 0 || id[1] == 0 || id[2] & 0o170000 != 0o040000 || id[2] & 0o022 != 0 || id[3..5] != [0,0]
                || (path == namespace && (id[2] != 0o040755 || id[5] == 0 || id[5] > (super::SESSION_FIXTURE_NAMESPACE.len() as u64 + 2) || id[6] > 1 << 20))
                || id[2] & 0o005 != 0o005 { return Err(()); }
            ancestors.push((path.to_path_buf(),id));
        }
        if ancestors.len() != 4 { return Err(()); }
        super::session_fixture_directory(namespace, &super::SESSION_FIXTURE_NAMESPACE)?;
        let mut originals = Vec::with_capacity(21);
        for name in DIRECTORIES.into_iter().chain(FILES.iter().map(|v| v.0)).chain(OBSERVED) {
            let path = if name == "." { root.clone() } else { root.join(name) };
            let id = super::fixture_identity(&path)?; let directory = DIRECTORIES.contains(&name);
            if id[0] != ancestors[0].1[0] || id[1] == 0 || id[2] != (if directory { 0o040700 } else { 0o100600 })
                || id[3] != u64::from(rustix::process::getuid().as_raw()) || id[4] != u64::from(rustix::process::getgid().as_raw())
                || (if directory { id[5] == 0 || id[5] > 8 || id[6] > 1 << 20 } else { id[5] != 1 || id[6] > 2048 })
                || originals.iter().any(|(_, old): &(&str, super::FixtureIdentity)| old[..2] == id[..2]) { return Err(()); }
            originals.push((name,id));
        }
        let mut fixture = Self { case, root, ancestors, originals, handles: [None,None,None], saved: Value::Null, raw: Vec::new(), changed:false, change_attempted:false, active_size_seen:0 };
        for (index, name) in OBSERVED.iter().enumerate() {
            fixture.handles[index] = Some(open_file(&fixture.root.join(name), index == 0 && case == Case::OfflineDrift)?);
        }
        fixture.raw = fixture.read(0, false)?;
        let (size, hash) = config_descriptor(case);
        if fixture.raw.len() as u64 != size || format!("{:x}",Sha256::digest(&fixture.raw)) != hash
            || !fixture.read(1,false)?.is_empty() || !fixture.read(2,false)?.is_empty() { return Err(()); }
        fixture.saved = crate::protocol::strict_json(&fixture.raw).map_err(|_| ())?;
        fixture.verify()?; Ok(fixture)
    }
    fn content(&self) -> Value { let (bytes, sha256) = config_descriptor(self.case); json!({"bytes":bytes,"sha256":sha256}) }
    fn identity(&self, name: &str) -> Result<super::FixtureIdentity, ()> {
        self.originals.iter().find(|(n,_)| *n == name).map(|(_,id)| *id).ok_or(())
    }
    fn read(&self, index: usize, variable: bool) -> Result<Vec<u8>, ()> {
        let name = *OBSERVED.get(index).ok_or(())?;
        read_bound(self.handles.get(index).and_then(Option::as_ref).ok_or(())?, &self.root.join(name), &self.identity(name)?, variable)
    }
    fn trace(&self) -> Result<Vec<u8>, ()> {
        if !self.read(2,false)?.is_empty() { return Err(()); } self.read(1,true)
    }
    fn active_trace(&mut self) -> Result<ActiveTrace, ()> {
        if self.case != Case::OfflineCancel || !self.read(2,false)?.is_empty() { return Err(()); }
        let original = self.identity(OBSERVED[1])?; let path = self.root.join(OBSERVED[1]);
        let file = self.handles[1].as_ref().ok_or(())?;
        let before = file_identity(file)?; let named_before = super::fixture_identity(&path)?;
        // One bounded read of the retained original FD, including one excess
        // byte. Actual IO errors stay fatal, not disguised as append races.
        let mut bytes = [0u8;8]; let count = file.read_at(&mut bytes,0).map_err(|_| ())?;
        let after = file_identity(file)?; let named_after = super::fixture_identity(&path)?;
        let sample = active_trace_sample(&original,self.active_size_seen,&[before,named_before,after,named_after],&bytes[..count])?;
        self.active_size_seen = named_after[6];
        Ok(sample)
    }
    fn verify(&self) -> Result<(), ()> {
        for (index,(path,old)) in self.ancestors.iter().enumerate() {
            let now = super::fixture_identity(path)?;
            if if index == 0 { now != *old } else { now[..5] != old[..5] } { return Err(()); }
        }
        super::session_fixture_directory(&self.ancestors[0].0, &super::SESSION_FIXTURE_NAMESPACE)?;
        for (name,old) in &self.originals {
            let path = if *name == "." { self.root.clone() } else { self.root.join(name) };
            let now = super::fixture_identity(&path)?;
            let variable = *name == OBSERVED[1] || *name == OBSERVED[0] && self.changed;
            if if variable { now[..6] != old[..6] } else { now != *old } { return Err(()); }
            if DIRECTORIES.contains(name) {
                let parent = Path::new(if *name == "." { "" } else { name });
                let children: Vec<_> = self.originals.iter().filter_map(|(n,_)| {
                    let path = Path::new(n); (path.parent() == Some(parent)).then(|| path.file_name().and_then(|n| n.to_str())).flatten()
                }).collect();
                super::session_fixture_directory(&path, &children)?;
            } else if let Some((_,size,hash)) = FILES.iter().find(|(n,_,_)| n == name) {
                let file = open_file(&path,false)?;
                let result = read_bound(&file,&path,old,false).map(|bytes| bytes.len() as u64 == *size && format!("{:x}",Sha256::digest(&bytes)) == *hash);
                let closed = nix::unistd::close(file).is_ok();
                if result != Ok(true) || !closed { return Err(()); }
            }
        }
        let mut expected = self.raw.clone(); if self.changed { expected.push(b'\n'); }
        if self.read(0,self.changed)? != expected || !self.read(2,false)?.is_empty() { return Err(()); }
        Ok(())
    }
    fn drift(&mut self) -> Result<(), ()> {
        if self.case != Case::OfflineDrift || self.change_attempted { return Err(()); }
        self.change_attempted = true; self.verify()?;
        let file = self.handles[0].as_ref().ok_or(())?;
        file.write_all_at(b"\n",self.raw.len() as u64).map_err(|_| ())?; file.sync_all().map_err(|_| ())?;
        self.changed = true; self.verify()
    }
    fn finish(mut self) -> Result<Value, ()> {
        let before_close = self.verify().is_ok(); let trace = self.trace();
        let valid = before_close && trace.as_ref().is_ok_and(|bytes| bytes == expected_trace(self.case))
            && self.changed == (self.case == Case::OfflineDrift) && self.change_attempted == self.changed;
        let mut closed = true;
        for handle in &mut self.handles { match handle.take() { Some(file) => { if nix::unistd::close(file).is_err() { closed = false; } }, None => closed = false } }
        if !valid || !closed { return Err(()); }
        Ok(json!({"scriptTrace":std::str::from_utf8(trace.as_ref().map_err(|_| ())?).map_err(|_| ())?,"laterTrace":"","savedConfigChanged":self.changed}))
    }
}

pub(super) fn script(step: Step, case: Case) -> Option<String> {
    let body = match step {
        Step::Navigate | Step::Return => "return navigate(primary);",
        // Leaving Environment deliberately cancels Tools. Keep that existing
        // semantics; the reciprocal Offline Busy handler is checked by tick.
        Step::Reciprocal if case.tools() => "return {state:'ready'};",
        Step::Reciprocal => "return navigate('Environment');",
        Step::Ready => r#"if(!selected(primary))return {state:'wait'};const b=button(primary==='Environment'?'Check build tools':'Review offline checks');
            if(!b||b.disabled)return {state:'wait'};show(b);return {state:'ready',available:!b.disabled};"#,
        Step::Prepare => "return click('Review offline checks');",
        Step::Review | Step::Confirmed => r#"const group=document.querySelector('.offline-preflight .session-review');if(!group)return {state:'wait'};
            const checks=group.querySelectorAll('input[type="checkbox"]'),run=button('Run saved offline checks',group);
            if(checks.length!==1||checks[0].disabled||!run)throw 0;show(group);
            return {state:'ready',checked:checks[0].checked,runAvailable:!run.disabled};"#,
        Step::Acknowledge => r#"const c=document.querySelector('.offline-preflight .session-review input[type="checkbox"]');
            if(!c||c.disabled||c.checked)throw 0;show(c);c.click();return {state:'ready'};"#,
        Step::Start => "return click(primary==='Environment'?'Check build tools':'Run saved offline checks');",
        Step::ReadReciprocal if case.tools() => r#"if(!selected('Environment'))return {state:'wait'};
            const card=document.querySelector('[aria-label="Observed build-tool checks"]'),b=card&&button('Check build tools',card);
            if(!card||!b)return {state:'wait'};show(b);
            return {state:'ready',busy:b.disabled,pending:text(card).includes('Native finality: pending')&&!text(card).includes('Native finality: settled')};"#,
        Step::ReadReciprocal => r#"const other='Environment';if(!selected(other))return {state:'wait'};
            const b=button(other==='Environment'?'Check build tools':'Review offline checks');if(!b) return {state:'wait'};show(b);
            const retained=primary==='Environment'?document.querySelector('[aria-label="Retained build-tool diagnostics owner"]')
                :document.querySelector('[aria-label="Original saved offline-check operation"]');
            if(!retained)return {state:'wait'};
            const pending=primary==='Environment'?text(retained).includes('Native finality: pending')
                :!!button('Cancel original offline checks',retained)&&!text(retained).includes('Original operation settled');
            return {state:'ready',busy:b.disabled,pending};"#,
        Step::Cancel => "return click(primary==='Environment'?'Cancel observed run':'Cancel original offline checks');",
        Step::Terminal if case.tools() => r#"if(!selected(primary))return {state:'wait'};const card=document.querySelector('[aria-label="Observed build-tool checks"]');
            if(!card)return {state:'wait'};show(card);
            const badges=[...card.querySelectorAll('.badge')].map(text),fact=prefix=>{const rows=badges.filter(t=>t.startsWith(prefix));if(rows.length!==1)throw 0;return rows[0].slice(prefix.length);};
            if(!badges.includes('Native finality: settled'))return {state:'wait'};
            const rows=[...card.querySelectorAll('.environment-requirements > article')];if(rows.length>3)throw 0;
            const checks=rows.map(row=>{const dd=[...row.querySelectorAll('.environment-baseline dd')],badges=[...row.querySelectorAll('.badge')];
                if(dd.length<2||dd.length>3||badges.length!==2)throw 0;
                return {label:text(row.querySelector('h3')),state:text(badges[0]),version:text(dd[0]),returnCode:dd.length===3?Number(text(dd[2])):null};});
            return {state:'ready',phase:fact('Phase: '),outcome:fact('Outcome: '),finality:fact('Native finality: '),checks};"#,
        Step::Terminal => r#"if(!selected(primary))return {state:'wait'};const card=document.querySelector('.offline-preflight'),progress=card?.querySelector('.session-progress');
            if(!progress||text(progress.querySelector('.badge'))!=='Original operation settled')return {state:'wait'};show(progress);
            const p=[...progress.querySelectorAll(':scope > p')].find(p=>text(p).startsWith('Outcome: '));if(!p)throw 0;
            const report=card.querySelector('.offline-report'),rows=report?[...report.querySelectorAll('.offline-counts > div')]:null;
            if(rows&&rows.length!==9)throw 0;const counts=rows?Object.fromEntries(rows.map(row=>[text(row.querySelector('dt')),Number(text(row.querySelector('dd')))])):null;
            return {state:'ready',phase:text(progress.querySelector('.badge')),outcome:text(p).slice(9),counts};"#,
        Step::Work | Step::WaitFinal => return None,
    };
    Some(format!(r#"(() => {{try {{
        const primary={primary:?},text=node=>node?.textContent?.trim()??'';
        const selected=name=>!!document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"][aria-current="page"]');
        const show=node=>{{node.scrollIntoView({{block:'center'}});const r=node.getBoundingClientRect();if(r.width<=0||r.height<=0||getComputedStyle(node).visibility!=='visible')throw 0;}};
        const button=(name,root=document)=>{{const rows=[...root.querySelectorAll('button')].filter(b=>text(b)===name);if(rows.length>1)throw 0;return rows[0];}};
        const click=name=>{{const b=button(name);if(!b||b.disabled)return {{state:'wait'}};show(b);b.click();return {{state:'ready'}};}};
        const navigate=name=>{{const b=document.querySelector('nav[aria-label="Workspace navigation"] button[aria-label="'+name+'"]');if(!b||b.disabled)throw 0;b.click();return {{state:'ready'}};}};
        {body}
    }}catch{{return {{state:'error'}};}}}})()"#, primary=if case.tools() { "Environment" } else { "Releases" }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step { Navigate, Ready, Prepare, Review, Acknowledge, Confirmed, Start, Work,
    Reciprocal, ReadReciprocal, Cancel, WaitFinal, Return, Terminal }
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command { ToolsStart, ToolsCancel, OfflinePrepare, OfflineStart, OfflineCancel }
impl Command {
    fn index(self) -> usize { match self { Self::ToolsStart => 0, Self::ToolsCancel => 1, Self::OfflinePrepare => 2,
        Self::OfflineStart => 3, Self::OfflineCancel => 4 } }
}
#[derive(Default)]
struct Record {
    issued: bool, fixture: Option<Fixture>, fixture_report: Option<Value>, saved: Option<Value>, content: Option<Value>,
    requests: [u8; 5], replies: [u8; 5], context: Option<Value>, id: Option<String>, generation: Option<String>,
    initial: bool, ready: bool, start: bool, consent: bool, cancel: bool, reciprocal: bool,
    held_observed: bool, terminal_visible: bool, final_snapshot: Option<Snapshot>,
}
impl Control {
    fn record(&self) -> Option<std::sync::MutexGuard<'_, Record>> {
        match self.record.lock() { Ok(r) => Some(r), Err(_) => { self.fail(); None } }
    }
    pub(super) fn attach(self: &Arc<Self>, q: &Arc<Observation>, document: &crate::asset_session::DocumentBinding) -> Result<(), BridgeError> {
        {
            let shell = q.record().ok_or_else(BridgeError::cleanup_unknown)?;
            let mut r = self.record().ok_or_else(BridgeError::cleanup_unknown)?;
            if q.case != ShellCase::Commands(self.case) || !shell.attached || shell.started || r.issued { return Err(BridgeError::invalid()); }
            let mut original = self.original.lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if original.is_some() { return Err(BridgeError::invalid()); }
            let fixture = Fixture::capture(q.project_path().ok_or_else(BridgeError::invalid)?, self.case).map_err(|_| BridgeError::invalid())?;
            r.content = Some(fixture.content()); r.saved = Some(fixture.saved.clone()); r.fixture = Some(fixture); r.issued = true;
            *original = Some(Arc::downgrade(q));
        }
        document.admit_installed_commands(ToolsAdmission { control: self.clone() }, OfflineAdmission { control: self.clone() })
    }
    pub(super) fn snapshot(&self, project_id: &str, result: &Result<Value, BridgeError>) {
        let Ok(q) = self.original() else { self.fail(); return; };
        let Some(mut shell) = q.record_at(super::Boundary::Result) else { return; };
        let Some(r) = self.record() else { return; };
        let valid = result.as_ref().is_ok_and(|v| shell.project.as_ref().is_some_and(|p|
                p.id == project_id && v["root"].as_str() == Some(p.path.as_str()))
            && v["observationScope"] == "single-request-non-atomic" && v["config"]["path"] == "release/mobile-release.json"
            && v["config"]["state"] == "format-valid" && v["config"]["issues"].as_array().is_some_and(Vec::is_empty)
            && r.saved.as_ref() == v["config"].get("data") && r.content.as_ref() == v["config"].get("content")
            && v["discovery"]["state"] == "unverified" && v["discovery"]["partial"] == false
            && v["issues"].as_array().is_some_and(Vec::is_empty) && super::assurance(v, "static-text"));
        if !valid || shell.snapshot_requests != 1 || shell.snapshot || !matches!(shell.step, ShellStep::Selected | ShellStep::ReadSnapshot) {
            self.fail(); return;
        }
        shell.snapshot = true;
    }
    pub(super) fn request(&self, command: Command, body: &Value) {
        let Ok(q) = self.original() else { self.fail(); return; };
        let Some(shell) = q.record_at(super::Boundary::Request) else { return; };
        let Some(mut r) = self.record() else { return; };
        let Some(project) = &shell.project else { self.fail(); return; };
        let index = command.index();
        let start_context = || body["projectId"].as_str() == Some(project.id.as_str())
            && body["draftRevision"].as_u64().is_some_and(|v| v < u64::from(u32::MAX))
            && body["baselineGeneration"].as_u64().is_some_and(|v| v < u64::from(u32::MAX));
        let original = |id: &str| r.id.as_deref() == body[id].as_str()
            && r.generation.as_deref() == body["ownerGeneration"].as_str() && r.id.is_some() && r.generation.is_some();
        let valid = r.requests[index] == 0 && match command {
            Command::ToolsStart => self.case.tools() && matches!(shell.step, ShellStep::Commands(Step::Start | Step::Work)) && r.ready
                && start_context() && r.saved.as_ref() == body.get("draft") && body["platform"] == "android" && body["operation"] == "build",
            Command::OfflinePrepare => !self.case.tools() && matches!(shell.step, ShellStep::Commands(Step::Prepare | Step::Review)) && r.ready
                && start_context() && r.content.as_ref() == body.get("savedConfig"),
            Command::OfflineStart => !self.case.tools() && matches!(shell.step, ShellStep::Commands(Step::Start | Step::Work))
                && r.consent && r.replies[2] == 1 && original("operationId") && body["consentVersion"] == offline::CONSENT,
            Command::ToolsCancel => self.case == Case::ToolsCancel && matches!(shell.step, ShellStep::Commands(Step::Cancel | Step::WaitFinal))
                && r.held_observed && r.replies[0] == 1 && original("runId"),
            Command::OfflineCancel => self.case == Case::OfflineCancel && matches!(shell.step, ShellStep::Commands(Step::Cancel | Step::WaitFinal))
                && r.reciprocal && r.replies[3] == 1 && original("operationId"),
        };
        if !valid { self.fail(); return; }
        if matches!(command, Command::ToolsStart | Command::OfflinePrepare) {
            if r.context.is_some() { self.fail(); return; }
            let mut context = json!({"projectId":body["projectId"], "draftRevision":body["draftRevision"],
                "baselineGeneration":body["baselineGeneration"], "platform":"android", "operation":if self.case.tools() { "build" } else { "offline-preflight" }});
            if !self.case.tools() { context["savedConfig"] = body["savedConfig"].clone(); }
            r.context = Some(context);
        }
        r.requests[index] = 1;
    }
    pub(super) fn returned<T: Serialize>(&self, command: Command, result: &Result<T, BridgeError>) {
        let Some(mut r) = self.record() else { return; };
        let index = command.index();
        let Some(status) = result.as_ref().ok().and_then(|v| serde_json::to_value(v).ok()) else { self.fail(); return; };
        if r.requests[index] != 1 || r.replies[index] != 0 { self.fail(); return; }
        let projection = if self.case.tools() { if status["active"].is_object() { &status["active"] } else { &status["lastTerminal"] } }
            else { &status["operation"] };
        let key = if self.case.tools() { "runId" } else { "operationId" };
        let Some(id) = projection[key].as_str().filter(|s| crate::edit_protocol::token(s)) else { self.fail(); return; };
        let Some(generation) = projection["ownerGeneration"].as_str().filter(|s| crate::edit_protocol::token(s)) else { self.fail(); return; };
        if r.context.as_ref() != projection.get("context") { self.fail(); return; }
        if matches!(command, Command::ToolsStart | Command::OfflinePrepare) {
            if r.id.is_some() || r.generation.is_some() { self.fail(); return; }
            if command == Command::OfflinePrepare && (projection["phase"] != "awaiting-consent" || projection["intentUsable"] != true
                || projection["outcome"] != Value::Null || projection["result"] != Value::Null) { self.fail(); return; }
            r.id = Some(id.into()); r.generation = Some(generation.into());
        } else if r.id.as_deref() != Some(id) || r.generation.as_deref() != Some(generation) { self.fail(); return; }
        if matches!(command, Command::ToolsCancel | Command::OfflineCancel)
            && (projection["reason"] != "cancelled" || if self.case.tools() { projection["outcome"] != "cancelled" }
                else { projection["outcome"] != Value::Null && projection["outcome"] != "cancelled" }) { self.fail(); return; }
        r.replies[index] = 1;
    }
    fn expected_requests(&self) -> [u8; 5] {
        if self.case.tools() { [1, u8::from(self.case.cancel()), 0, 0, 0] }
        else { [0, 0, 1, 1, u8::from(self.case.cancel())] }
    }
    fn original_matches(&self, r: &Record, facts: &OriginalFacts, projection: &Value) -> bool {
        let id = if self.case.tools() { "runId" } else { "operationId" };
        r.id.as_deref() == Some(facts.id.as_str()) && r.generation.as_deref() == Some(facts.generation.as_str())
            && projection[id].as_str() == Some(facts.id.as_str()) && projection["ownerGeneration"].as_str() == Some(facts.generation.as_str())
            && r.context.as_ref() == projection.get("context")
    }
    fn terminal_valid(&self, r: &Record, snapshot: &Snapshot) -> bool {
        let p = &snapshot.terminal;
        if !snapshot.facts.final_for(self.case) || !self.original_matches(r, &snapshot.facts, p) { return false; }
        if self.case.tools() {
            if p["phase"] != "settled" || p["finality"] != "settled" { return false; }
            if self.case.cancel() { return p["outcome"] == "cancelled" && p["reason"] == "cancelled" && p["result"] == Value::Null; }
            return matches!(p["outcome"].as_str(), Some("complete" | "unavailable")) && p["reason"] == "none"
                && p["result"]["outcome"] == p["outcome"] && p["result"]["hostPlatform"] == "linux"
                && p["result"]["checks"].as_array().is_some_and(|rows| rows.len() == 3 && rows.iter().zip(["git", "java", "javac"])
                    .all(|(row, id)| row["id"] == id && matches!(row["state"].as_str(), Some("completed" | "not-run"))));
        }
        if p["phase"] != "terminal" || p["intentUsable"] != false { return false; }
        if self.case.cancel() { return p["outcome"] == "cancelled" && p["reason"] == "cancelled" && p["result"] == Value::Null; }
        if self.case == Case::OfflineDrift { return p["outcome"] == "refused" && p["reason"] == "saved-config-changed" && p["result"] == Value::Null; }
        let result = &p["result"];
        p["outcome"] == "complete" && p["reason"] == "none" && r.content.as_ref() == result.get("usedConfig")
            && result["findings"].as_array().is_some_and(|rows| rows.iter().filter(|row| row["check"] == "configured-project-check"
                && row["projectCheckIndex"] == 0 && row["status"] == (if self.case == Case::OfflineNegative { "FAIL" } else { "PASS" })).count() == 1
                && !rows.iter().any(|row| row["check"] == "configured-project-check" && row["projectCheckIndex"] == 1))
            && if self.case == Case::OfflineNegative { result["summary"]["counts"]["FAIL"].as_u64().is_some_and(|n| n > 0) }
                else { ["FAIL", "MISSING", "BLOCKED", "INVALID"].iter().all(|key| result["summary"]["counts"][*key] == 0) }
    }
    // No waiting task is added. Return true only to let the existing relay
    // dispatch this literal DOM step; false means wait/advance on that relay.
    pub(super) fn tick(&self, app: &tauri::AppHandle, step: Step) -> bool {
        let Ok(q) = self.original() else { self.fail(); return false; };
        let state = app.state::<super::super::ShellState>();
        let (Ok(tools), Ok(offline)) = (state.document.environment_diagnostics_status(), state.document.offline_preflight_status())
            else { self.fail(); return false; };
        if tools.capability.reason == tools::Availability::CleanupUnknown || offline.availability == offline::Availability::CleanupUnknown {
            self.fail(); return false;
        }
        let Some(mut r) = self.record() else { return false; };
        let mut next = None;
        match step {
            Step::Ready => {
                if !tools.capability.available || offline.availability != offline::Availability::Available { return false; }
                if tools.active.is_some() || tools.last_terminal.is_some() || offline.operation.is_some() { self.fail(); return false; }
                r.initial = true;
            },
            Step::Review | Step::Acknowledge | Step::Confirmed => {
                if r.replies[2] != 1 { return false; }
                if !offline.operation.as_ref().is_some_and(|p| p.phase == offline::Phase::AwaitingConsent && p.intent_usable
                    && r.id.as_deref() == Some(p.operation_id.as_str()) && r.generation.as_deref() == Some(p.owner_generation.as_str())) {
                    self.fail(); return false;
                }
            },
            Step::Start if self.case == Case::OfflineDrift => {
                if !r.consent || r.requests[3] != 0 { self.fail(); return false; }
                if !r.fixture.as_mut().is_some_and(|f| f.changed || f.drift().is_ok()) { self.fail(); return false; }
            },
            Step::Work => {
                if r.replies[if self.case.tools() { 0 } else { 3 }] != 1 { return false; }
                if self.case.boundary() != "none" {
                    let Ok(hold) = self.hold.lock() else { self.fail(); return false; };
                    if hold.failed { self.fail(); return false; }
                    if !hold.entered { return false; }
                    let Some(facts) = &hold.facts else { self.fail(); return false; };
                    let projection = if self.case.tools() { tools.active.as_ref().and_then(|p| serde_json::to_value(p).ok()) }
                        else { offline.operation.as_ref().and_then(|p| serde_json::to_value(p).ok()) };
                    if hold.released || !facts.held_for(self.case) || !projection.as_ref().is_some_and(|p| self.original_matches(&r, facts, p)
                        && if self.case.tools() { p["finality"] == "pending" && p["phase"] != "settled" }
                            else { !matches!(p["phase"].as_str(), Some("terminal" | "unknown")) && p["result"] == Value::Null }) {
                        self.fail(); return false;
                    }
                    r.held_observed = true;
                    next = Some(if self.case == Case::ToolsCancel { Step::Cancel } else { Step::Reciprocal });
                } else if self.case == Case::OfflineCancel {
                    let Some(fixture) = r.fixture.as_mut() else { self.fail(); return false; };
                    match fixture.active_trace() { Ok(ActiveTrace::Empty | ActiveTrace::Changing) => return false,
                        Ok(ActiveTrace::Active) => {}, Err(()) => { self.fail(); return false; } }
                    if !offline.operation.as_ref().is_some_and(|p| p.phase == offline::Phase::Running && !p.intent_usable) { return false; }
                    next = Some(Step::Reciprocal);
                } else { next = Some(Step::WaitFinal); }
            },
            Step::Reciprocal => {
                if r.reciprocal { self.fail(); return false; }
                let Some(context) = &r.context else { self.fail(); return false; };
                // Fixed negative call to the SAME document handler after its
                // ordinary status says Busy. No alternate positive runner.
                let refused = if self.case.tools() {
                    let Ok(input) = offline::prepare(&json!({"projectId":context["projectId"], "draftRevision":context["draftRevision"],
                        "baselineGeneration":context["baselineGeneration"], "savedConfig":r.content})) else { self.fail(); return false; };
                    offline.availability == offline::Availability::Busy
                        && state.document.prepare_offline_preflight(input).is_err_and(|e| e.code == "offline_preflight_busy")
                } else {
                    let Ok(input) = tools::start(&json!({"projectId":context["projectId"], "draft":r.saved,
                        "draftRevision":context["draftRevision"], "baselineGeneration":context["baselineGeneration"],
                        "platform":"android", "operation":"build"})) else { self.fail(); return false; };
                    !tools.capability.available && tools.capability.reason == tools::Availability::Busy
                        && state.document.start_environment_diagnostics(input).is_err_and(|e| e.code == "environment_diagnostics_busy")
                };
                if !refused { self.fail(); return false; } r.reciprocal = true;
            },
            Step::WaitFinal => {
                if self.case.cancel() && r.replies[if self.case.tools() { 1 } else { 4 }] != 1 { return false; }
                if self.case == Case::ToolsCancel {
                    let released = self.hold.lock().is_ok_and(|h| h.released);
                    if !released && !self.release() { return false; }
                }
                let snapshot = if self.case.tools() { state.bridge.diagnostics.installed_observation_snapshot() }
                    else { state.bridge.preflight.installed_observation_snapshot() };
                let Some(snapshot) = snapshot else { return false; };
                if snapshot.facts.resource_unknown { self.fail(); return false; }
                if !snapshot.facts.retired_before_cutoff { return false; }
                // These ordinary status reads are not an atomic document
                // snapshot: the later read may retire this same owner while
                // the earlier DTO still says Busy. Retry on the existing
                // relay; neither stale Busy nor this retry creates finality.
                if tools.capability.reason == tools::Availability::Busy || offline.availability == offline::Availability::Busy { return false; }
                if !self.terminal_valid(&r, &snapshot) || r.final_snapshot.is_some()
                    || !tools.capability.available || offline.availability != offline::Availability::Available { self.fail(); return false; }
                let Some(fixture) = r.fixture.take() else { self.fail(); return false; };
                match fixture.finish() { Ok(report) => r.fixture_report = Some(report), Err(()) => { self.fail(); return false; } }
                r.final_snapshot = Some(snapshot); next = Some(Step::Return);
            },
            _ => {},
        }
        drop(r);
        if let Some(next) = next {
            let Some(mut shell) = q.record_at(super::Boundary::Settlement) else { return false; };
            if shell.step != ShellStep::Commands(step) || shell.pending.is_some() { self.fail(); return false; }
            shell.step = ShellStep::Commands(next); return false;
        }
        true
    }
    pub(super) fn dom(&self, step: Step, value: &Value) {
        let Ok(q) = self.original() else { self.fail(); return; };
        let Some(mut shell) = q.record_at(super::Boundary::Dom) else { return; };
        if shell.step != ShellStep::Commands(step) || shell.pending.take() != Some(super::Pending::Dom(ShellStep::Commands(step))) {
            self.fail(); return;
        }
        let Some(object) = value.as_object() else { self.fail(); return; };
        if value["state"] == "wait" && object.len() == 1 { return; }
        if value["state"] != "ready" { self.fail(); return; }
        let Some(mut r) = self.record() else { return; };
        let valid = match step {
            Step::Ready => object.len() == 2 && value["available"] == true && r.initial,
            Step::Review => object.len() == 3 && value["checked"] == false && value["runAvailable"] == false && r.replies[2] == 1,
            Step::Confirmed => object.len() == 3 && value["checked"] == true && value["runAvailable"] == true && r.replies[2] == 1,
            Step::ReadReciprocal => object.len() == 3 && value["busy"] == true && value["pending"] == true && r.reciprocal,
            Step::Terminal => r.final_snapshot.as_ref().is_some_and(|s| self.terminal_dom(&s.terminal, value)),
            _ => object.len() == 1,
        };
        if !valid { self.fail(); return; }
        let next = match step {
            Step::Navigate => Step::Ready,
            Step::Ready => { r.ready = true; if self.case.tools() { Step::Start } else { Step::Prepare } },
            Step::Prepare => Step::Review, Step::Review => Step::Acknowledge, Step::Acknowledge => Step::Confirmed,
            Step::Confirmed => { r.consent = true; Step::Start },
            Step::Start => { r.start = true; Step::Work },
            Step::Reciprocal => Step::ReadReciprocal,
            Step::ReadReciprocal => if self.case == Case::OfflineCancel { Step::Cancel } else {
                if !r.held_observed || !self.release() { self.fail(); return; } Step::WaitFinal
            },
            Step::Cancel => { r.cancel = true; Step::WaitFinal },
            Step::Return => Step::Terminal,
            Step::Terminal => { r.terminal_visible = true; shell.step = ShellStep::Close; return; },
            _ => { self.fail(); return; },
        };
        shell.step = ShellStep::Commands(next);
    }
    fn terminal_dom(&self, p: &Value, value: &Value) -> bool {
        if self.case.tools() {
            if !super::keys(value, &["state", "phase", "outcome", "finality", "checks"])
                || value["phase"] != p["phase"] || value["outcome"] != p["outcome"] || value["finality"] != p["finality"] { return false; }
            let Some(rows) = value["checks"].as_array() else { return false; };
            if p["result"] == Value::Null { return rows.is_empty(); }
            let Some(expected) = p["result"]["checks"].as_array() else { return false; };
            rows.len() == expected.len() && rows.iter().zip(expected).zip(["Git version", "Java runtime version", "Java compiler version"])
                .all(|((row, original), label)| super::keys(row, &["label", "state", "version", "returnCode"])
                    && row["label"] == label && row["state"] == original["state"]
                    && row["version"].as_str() == Some(original["version"].as_str().unwrap_or("Not assessed"))
                    && row["returnCode"] == original["returnCode"])
        } else {
            super::keys(value, &["state", "phase", "outcome", "counts"])
                && value["phase"] == "Original operation settled" && value["outcome"] == p["outcome"]
                && value["counts"] == (if p["result"] == Value::Null { Value::Null } else { p["result"]["summary"]["counts"].clone() })
        }
    }
    pub(super) fn complete(&self) -> bool {
        let Some(r) = self.record() else { return false; };
        let Ok(h) = self.hold.lock() else { self.fail(); return false; };
        !self.failed.load(Ordering::SeqCst) && self.admitted.load(Ordering::SeqCst) == 3
            && self.claimed.load(Ordering::SeqCst) == (if self.case.tools() { Domain::Tools } else { Domain::Offline }).bit()
            && r.requests == self.expected_requests() && r.replies == r.requests && r.initial && r.ready && r.start
            && r.consent == !self.case.tools() && r.cancel == self.case.cancel() && r.reciprocal == self.case.reciprocal()
            && r.held_observed == (self.case.boundary() != "none") && h.entered == r.held_observed && h.released == r.held_observed && !h.failed
            && r.terminal_visible && r.fixture.is_none() && r.fixture_report.is_some()
            && r.final_snapshot.as_ref().is_some_and(|s| self.terminal_valid(&r, s))
    }
    pub(super) fn report(&self) -> Option<Vec<u8>> {
        if !self.complete() { return None; }
        let r = self.record()?; let h = self.hold.lock().ok()?; let original = r.final_snapshot.as_ref()?;
        serde_json::to_vec(&json!({"schema":"installed-tools-offline-v1", "case":self.case.name(), "qualificationOnly":true,
            "builder":"normal", "projectPicker":true, "savedObservation":true,
            "requests":{"toolsStart":r.requests[0],"toolsCancel":r.requests[1],"offlinePrepare":r.requests[2],"offlineStart":r.requests[3],"offlineCancel":r.requests[4]},
            "initial":{"toolsAvailable":r.initial,"offlineAvailable":r.initial},
            "ui":{"start":r.start,"consent":r.consent,"terminal":r.terminal_visible,"cancel":r.cancel},
            "reciprocalBusy":r.reciprocal,"hold":{"boundary":self.case.boundary(),"entered":h.entered,"released":h.released},
            "original":original.facts,"terminal":original.terminal,"fixture":r.fixture_report
        })).ok().filter(|bytes| bytes.len() < 64 * 1024)
    }
}

pub(super) fn assert_contracts() {
    // Separate inert owner: exercise ordinary Status/Prepare/Cancel without an
    // observation token, Start, runtime inspection or project IO. The real
    // native owner below retains its virgin revision and original admission.
    assert!(cfg!(feature = "custom-protocol") && crate::runtime::RuntimeConfig::packaged(std::path::PathBuf::from("/unopened-runtime"))
        .offline_preflight_installed_profile_available());
    crate::saved_command_owner::offline_tests::qualification_is_closed_without_a_runtime_or_another_owners_permit();
    // Inert DATA only. These synthetic bits/DTOs never enter an Observation,
    // original owner, fixture, report emitter or native admission.
    let empty: super::FixtureIdentity = [1,2,0o100600,1000,1000,1,0,10,10];
    let mut full = empty; full[6] = 7; full[7] = 11; full[8] = 11;
    assert_eq!(active_trace_sample(&empty,0,&[empty;4],b""),Ok(ActiveTrace::Empty));
    assert_eq!(active_trace_sample(&empty,0,&[full;4],b"active\n"),Ok(ActiveTrace::Active));
    // A read can see either side of the same one-write append. Neither is
    // ready when these original-file metadata samples straddle that write.
    for bytes in [b"".as_slice(),b"active\n".as_slice()] {
        assert_eq!(active_trace_sample(&empty,0,&[empty,empty,full,full],bytes),Ok(ActiveTrace::Changing));
    }
    assert_eq!(active_trace_sample(&empty,0,&[empty,full,full,full],b"active\n"),Ok(ActiveTrace::Changing));
    assert_eq!(active_trace_sample(&empty,0,&[empty,empty,empty,full],b""),Ok(ActiveTrace::Changing));
    let mut touched = empty; touched[7] = 11; touched[8] = 11;
    assert_eq!(active_trace_sample(&empty,0,&[empty,touched,touched,touched],b""),Ok(ActiveTrace::Changing));
    for field in 0..6 {
        let mut wrong = full; wrong[field] += 1;
        assert!(active_trace_sample(&empty,0,&[empty,empty,full,wrong],b"active\n").is_err());
    }
    let mut partial = full; partial[6] = 3;
    assert!(active_trace_sample(&empty,0,&[partial;4],b"act").is_err());
    assert!(active_trace_sample(&empty,0,&[full;4],b"actiVe\n").is_err());
    assert!(active_trace_sample(&empty,0,&[full;4],b"active\n\n").is_err());
    assert!(active_trace_sample(&empty,0,&[full;4],b"").is_err());
    assert!(active_trace_sample(&empty,0,&[full,full,empty,empty],b"").is_err());
    assert!(active_trace_sample(&empty,7,&[empty;4],b"").is_err());
    let mut oversize = full; oversize[6] = 8;
    assert!(active_trace_sample(&empty,0,&[empty,empty,full,oversize],b"active\n").is_err());
    for case in Case::ALL {
        assert_eq!(Case::parse(std::ffi::OsStr::new(case.name())), Some(case));
        assert_eq!(case.failure_leaf(), format!("shell-{}-failure.labels", case.name()));
        assert_eq!(case.verified_line(), format!("MRK_INSTALLED_SHELL_OBSERVATION={}-verified\n", case.name()).as_bytes());
        let admitted = AtomicU8::new(0); let claimed = AtomicU8::new(0);
        let domain = if case.tools() { Domain::Tools } else { Domain::Offline };
        let other = if case.tools() { Domain::Offline } else { Domain::Tools };
        assert!(!claim_once(case, 0, &claimed, domain));
        assert!(admit_once(&admitted, Domain::Tools)); assert!(!admit_once(&admitted, Domain::Tools));
        assert!(!claim_once(case, admitted.load(Ordering::SeqCst), &claimed, domain));
        assert!(admit_once(&admitted, Domain::Offline)); assert!(!admit_once(&admitted, Domain::Offline));
        assert!(!claim_once(case, admitted.load(Ordering::SeqCst), &claimed, other));
        assert_eq!(claimed.load(Ordering::SeqCst), 0);
        assert!(claim_once(case, admitted.load(Ordering::SeqCst), &claimed, domain));
        assert!(!claim_once(case, admitted.load(Ordering::SeqCst), &claimed, domain));
        assert!(!Control::new(case).complete()); // No issued tokens, original joins or normal UI/quit.
    }
    for value in ["", "tools", "offline", "offline-pass-extra", "../tools-observed", "normal"] {
        assert!(Case::parse(std::ffi::OsStr::new(value)).is_none());
    }
    let final_facts = OriginalFacts { domain:"tools", id:"a".repeat(32), generation:"b".repeat(32), inspection_joined:true,
        acquisition_joined:true, attempted:true, no_child:false, child_waited_success:true, stdin_closed:true, stdout_eof_closed:true,
        stderr_eof_closed:true, io_joined:true, core_lifetime_settled:true, runtime_ledger_settled:true, runtime_settlement_joined:true,
        driver_joined:true, manager_joined:true, observer_joined:true, watchdog_joined:true, retired_before_cutoff:true,
        active_retained:false, resource_unknown:false };
    assert!(final_facts.final_for(Case::ToolsObserved)); assert!(!final_facts.final_for(Case::OfflinePass));
    macro_rules! required {
        ($($field:ident),+ $(,)?) => {$({let mut missing=final_facts.clone();missing.$field=false;assert!(!missing.final_for(Case::ToolsObserved));})+};
    }
    required!(inspection_joined, acquisition_joined, attempted, child_waited_success, stdin_closed, stdout_eof_closed, stderr_eof_closed,
        io_joined, core_lifetime_settled, runtime_ledger_settled, runtime_settlement_joined, driver_joined, manager_joined, observer_joined,
        watchdog_joined, retired_before_cutoff);
    for field in [0,1,2] {
        let mut wrong = final_facts.clone(); match field { 0 => wrong.no_child=true, 1 => wrong.active_retained=true, _ => wrong.resource_unknown=true }
        assert!(!wrong.final_for(Case::ToolsObserved));
    }
    let mut cancelled = final_facts.clone(); cancelled.no_child=true; cancelled.attempted=false; cancelled.acquisition_joined=false;
    cancelled.child_waited_success=false; cancelled.stdin_closed=false; cancelled.stdout_eof_closed=false;
    cancelled.stderr_eof_closed=false; cancelled.core_lifetime_settled=false;
    assert!(cancelled.final_for(Case::ToolsCancel)); assert!(!cancelled.final_for(Case::ToolsObserved));
    cancelled.no_child=false; assert!(!cancelled.final_for(Case::ToolsCancel)); cancelled.no_child=true;
    for case in [Case::ToolsCancel, Case::ToolsSettlement, Case::OfflineSettlement] {
        let mut held = if case == Case::ToolsCancel { cancelled.clone() } else { final_facts.clone() };
        if case == Case::OfflineSettlement { held.domain="offline"; }
        held.runtime_ledger_settled=false; held.runtime_settlement_joined=false; held.driver_joined=false;
        held.manager_joined=false; held.observer_joined=false; held.watchdog_joined=false; held.retired_before_cutoff=false; held.active_retained=true;
        assert!(held.held_for(case)); assert!(!held.final_for(case));
        held.resource_unknown=true; assert!(!held.held_for(case)); held.resource_unknown=false;
        held.runtime_ledger_settled=true; assert!(!held.held_for(case));
    }
    let control = Control::new(Case::ToolsCancel);
    let context = json!({"projectId":"inert-project","draftRevision":1,"baselineGeneration":1,"platform":"android","operation":"build"});
    let r = Record { context:Some(context.clone()), id:Some(cancelled.id.clone()), generation:Some(cancelled.generation.clone()), ..Record::default() };
    let terminal = json!({"runId":cancelled.id,"ownerGeneration":cancelled.generation,"context":context,
        "phase":"settled","finality":"settled","outcome":"cancelled","reason":"cancelled","result":null});
    let mut snapshot = Snapshot { facts:cancelled, terminal };
    assert!(control.terminal_valid(&r,&snapshot));
    snapshot.terminal["runId"] = json!("c".repeat(32)); assert!(!control.terminal_valid(&r,&snapshot));
    snapshot.terminal["runId"] = json!(snapshot.facts.id); snapshot.terminal["finality"] = json!("pending");
    assert!(!control.terminal_valid(&r,&snapshot));
    snapshot.terminal["finality"] = json!("settled"); snapshot.terminal["result"] = json!({"outcome":"complete"});
    assert!(!control.terminal_valid(&r,&snapshot));
    let names: Vec<_> = DIRECTORIES.into_iter().chain(FILES.iter().map(|v| v.0)).chain(OBSERVED).collect();
    assert_eq!(names.len(),21); let mut unique=names.clone(); unique.sort();unique.dedup();assert_eq!(unique.len(),21);
    assert!(FILES.iter().all(|(_,n,hash)| *n < 2048 && hash.len()==64));
    for case in Case::ALL { let (size,hash)=config_descriptor(case); assert!(size<2048 && hash.len()==64); }
}
