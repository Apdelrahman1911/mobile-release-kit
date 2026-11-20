//! Nonshipping removal lab (cargo feature `removal-lab`). Runs ONLY on a
//! disposable GitHub-hosted macOS runner: it creates the real fixed install and
//! request paths as root, then drives the production removal peer (compiled
//! verbatim, see tests/removal_lab.m) as two real processes:
//!   Parent: root, under sudo or inside a real Installer postinstall (the
//!           production remover context), selected by the workflow.
//!   App:    the runner's console user, like the running app.
//! Covered with production code: constructor and confirmation windows, the
//! readiness notice (root post, user run-loop observer), OPEN (socket, flags,
//! bind, mode, listen, every post-check), CONNECT (accept/connect), the census
//! of the request directory through the production decoder at every
//! checkpoint, exact borrowed-original rechecks, and the peer credentials
//! (LOCAL_PEERTOKEN) at AUTHENTICATE. Identity starts right after that
//! (SecCodeCopyGuestWithAttributes and the dynamic signature checks): an
//! unsigned lab process must be refused there, so reaching it is the expected
//! end of the lab. SOURCE, identity, frames, the confirmation sheet, app exit
//! and file removal need the signed product and stay in the hosted E2E check.
use mrk_macos_installed_native::removal_coordinator::{parent_monotonic, post_removal_ready, RemovalNotice,
    RemovalNoticeInbox, RemovalNoticeStart};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{chown, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const WORK_NS: u64 = 290_000_000_000;
const HARD_NS: u64 = 300_000_000_000;
const ROOT: &str = "/Library/Application Support/MobileReleaseKit";
const REQUESTS: &str = "/Library/Application Support/MobileReleaseKit-RemovalRequests";
const OUTER: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app";
const PAYLOAD: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app";

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct StatData { device: u64, inode: u64, links: u64, size: u64, modified_seconds: i64, changed_seconds: i64,
    mode: u32, uid: u32, gid: u32, flags: u32, modified_nanoseconds: u32, changed_nanoseconds: u32 }
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct Report { version: u32, role: u32, operation: u32, failed: u32, unknown: u32, calls: u32, returned: u32,
    stage: u32, frame_index: u32, frame_started: u32, frame_size: u32, frame_offset: u32,
    token_ready: u32, watch_ready: u32, exit_observed: u32, eof: u32, closed: u32, bind_returned: u32,
    fd_states: [u32; 3], cf_states: [u32; 24], peer_pid: u32, peer_uid: u32, peer_gid: u32, first_code: u32,
    last: u64, first_failure: u64, request_directory: StatData, socket_name: StatData }
#[repr(C)]
struct Inputs { version: u32, role: u32, start: u64, work: u64, hard: u64, request_id: [u8; 16], code_sha256: [[u8; 32]; 3],
    installed_sha256: [u8; 32], remove_sha256: [u8; 32], request_sha256: [u8; 32], borrowed: [i32; 20],
    installed: *const u8, installed_signature: *const u8, remove: *const u8, remove_signature: *const u8,
    installed_size: usize, installed_signature_size: usize, remove_size: usize, remove_signature_size: usize }
const _: [(); 72] = [(); std::mem::size_of::<StatData>()];
const _: [(); 360] = [(); std::mem::size_of::<Report>()];
const _: [(); 384] = [(); std::mem::size_of::<Inputs>()];
type Gate = unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, *const Report) -> i32;
unsafe extern "C" {
    fn mrk_removal_peer_new(inputs: *const Inputs) -> *mut c_void;
    fn mrk_removal_peer_run(original: *mut c_void, operation: u32, frame: *const u8, size: usize, gate: Gate,
        context: *mut c_void, out: *mut Report) -> i32;
    fn mrk_removal_confirmation_reserve(start: u64, work: u64, hard: u64) -> *mut c_void;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: *const c_void;
    fn CFRunLoopRunInMode(mode: *const c_void, seconds: f64, return_after_source: u8) -> i32;
}
const OPEN: u32 = 2; const CONNECT: u32 = 3; const AUTHENTICATE: u32 = 4; const CLOSE: u32 = 9;
const PHASE_BIND: u32 = 14;

/// Production checkpoint stand-in: census of the request directory through the
/// production decoder (`directory_block`) with the production roster rule
/// (only request.json as a file and, once bound, "s" as a socket).
struct Census { directory: File, role: &'static str, first: Option<String>, checkpoints: u32, bound: bool }
unsafe extern "C" fn gate(context: *mut c_void, before: u32, phase: u32, _slot: u32, _cleanup: u32, facts: *const Report) -> i32 {
    let census = unsafe { &mut *(context as *mut Census) };
    let facts = unsafe { &*facts };
    census.checkpoints += 1;
    if before == 0 && phase == PHASE_BIND && facts.bind_returned == 1 { census.bound = true; }
    if let Err(error) = census_once(census) {
        census.first.get_or_insert(format!("{} census at phase {phase} before={before}: {error}", census.role));
        return 0;
    }
    1
}
fn census_once(census: &Census) -> Result<(), String> {
    let fd = census.directory.as_raw_fd();
    if unsafe { nix::libc::lseek(fd, 0, nix::libc::SEEK_SET) } != 0 { return Err("seek".into()); }
    let mut block = vec![0u8; 65536];
    let (mut json, mut socket) = (false, false);
    loop {
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let used = mrk_macos_installed_native::directory_block(fd, &mut block).map_err(|e| format!("read: {e}"))?;
        if used == 0 { break; }
        let mut at = 0;
        while at < used {
            let kind = block[at + 8];
            let length = usize::from(u16::from_ne_bytes([block[at + 9], block[at + 10]]));
            let name = &block[at + 11..at + 11 + length];
            at += 11 + length;
            match name {
                b"." | b".." => {}
                b"request.json" if kind == nix::libc::DT_REG => json = true,
                b"s" if kind == nix::libc::DT_SOCK => socket = true,
                _ => return Err(format!("unexpected entry {:?} kind {kind}", String::from_utf8_lossy(name))),
            }
        }
    }
    if !json { return Err("request.json missing".into()); }
    if census.bound && !socket { return Err("socket missing after bind".into()); }
    Ok(())
}

fn hex(id: &[u8; 16]) -> String { id.iter().map(|b| format!("{b:02x}")).collect() }
fn unhex(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if text.len() != 32 { return None; }
    for i in 0..16 { out[i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?; }
    Some(out)
}
fn open_ro(path: &str, directory: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW | if directory { nix::libc::O_DIRECTORY } else { 0 });
    options.open(path).map_err(|e| format!("open {path}: {e}"))
}
/// The 20 borrowed originals in production slot order (removal_coordinator.m).
fn borrowed(request_dir: &str) -> Result<Vec<File>, String> {
    let dirs = ["/", "/Library", "/Library/Application Support", ROOT, OUTER];
    let mut files = Vec::new();
    for d in dirs { files.push(open_ro(d, true)?); }
    for d in [format!("{OUTER}/Contents"), format!("{OUTER}/Contents/Helpers"), PAYLOAD.into(),
        format!("{PAYLOAD}/Contents"), format!("{PAYLOAD}/Contents/MacOS"), format!("{PAYLOAD}/Contents/Helpers"),
        format!("{OUTER}/Contents/MacOS")] { files.push(open_ro(&d, true)?); }
    for f in [format!("{OUTER}/Contents/MacOS/mrk-macos-entry"), format!("{PAYLOAD}/Contents/MacOS/mobile-release-kit-desktop"),
        format!("{PAYLOAD}/Contents/Helpers/mrk-macos-remove"), format!("{ROOT}/lab-installed-producer.json"),
        format!("{ROOT}/lab-installed-producer.sig")] { files.push(open_ro(&f, false)?); }
    files.push(open_ro(REQUESTS, true)?);
    files.push(open_ro(request_dir, true)?);
    files.push(open_ro(&format!("{request_dir}/request.json"), false)?);
    Ok(files)
}
fn inputs(role: u32, start: u64, id: [u8; 16], fds: &[File], bytes: &(Vec<u8>, Vec<u8>)) -> Inputs {
    let mut borrowed = [-1; 20];
    for (slot, file) in fds.iter().enumerate() { borrowed[slot] = file.as_raw_fd(); }
    Inputs { version: 1, role, start, work: start + WORK_NS, hard: start + HARD_NS, request_id: id,
        code_sha256: [[1; 32]; 3], installed_sha256: [2; 32], remove_sha256: [3; 32], request_sha256: [4; 32], borrowed,
        installed: bytes.0.as_ptr(), installed_signature: bytes.1.as_ptr(), remove: bytes.0.as_ptr(), remove_signature: bytes.1.as_ptr(),
        installed_size: bytes.0.len(), installed_signature_size: bytes.1.len(), remove_size: bytes.0.len(), remove_signature_size: bytes.1.len() }
}
/// After the peer credentials are read, AUTHENTICATE's only remaining work is
/// identity: a refused Security call (native code 10) or the signature,
/// requirement and cdhash checks (19..=31). Anything else is lab-reachable.
fn identity_code(code: u32) -> bool { code == 10 || (19..=31).contains(&code) }

struct Stage { name: &'static str, result: i32, report: Report }
fn run(peer: *mut c_void, operation: u32, census: &mut Census, name: &'static str, stages: &mut Vec<Stage>) -> i32 {
    let mut report = Report::default();
    let result = unsafe { mrk_removal_peer_run(peer, operation, std::ptr::null(), 0, gate, (census as *mut Census).cast(), &mut report) };
    stages.push(Stage { name, result, report });
    result
}
/// OPEN, CONNECT (bounded), AUTHENTICATE up to the identity boundary, CLOSE.
fn drive(peer: *mut c_void, census: &mut Census, done_path: &str) -> (Vec<Stage>, Result<String, String>) {
    let mut stages = Vec::new();
    if run(peer, OPEN, census, "open", &mut stages) != 1 { return (stages, Err("OPEN refused".into())); }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match run(peer, CONNECT, census, "connect", &mut stages) {
            1 => break,
            0 if Instant::now() < deadline => { stages.pop(); std::thread::sleep(Duration::from_millis(50)); }
            _ => return (stages, Err("CONNECT refused or timed out".into())),
        }
    }
    let auth = run(peer, AUTHENTICATE, census, "authenticate", &mut stages);
    let r = stages.last().unwrap().report;
    let verdict = if auth == 1 { Err("AUTHENTICATE passed without the signed product (identity not enforced?)".into()) }
        else if r.token_ready != 1 { Err(format!("peer credentials refused before identity (native code {})", r.first_code)) }
        else if !identity_code(r.first_code) { Err(format!("refused before the identity boundary (native code {})", r.first_code)) }
        else { Ok(format!("identity boundary reached as expected (native code {}, peer uid {} pid {})", r.first_code, r.peer_uid, r.peer_pid)) };
    // Production's App waits for the Parent's frames and never closes first;
    // hold the connection until the Parent has finished (it releases our
    // done marker after its own CLOSE, or on any earlier exit).
    let deadline = Instant::now() + Duration::from_secs(120);
    while !Path::new(done_path).exists() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(50)); }
    run(peer, CLOSE, census, "close", &mut stages);
    let _ = File::create(format!("{done_path}.app"));
    (stages, verdict)
}
fn summary(role: &str, stages: &[Stage], verdict: &Result<String, String>, census: &Census, extra: &[(String, String)]) -> String {
    let mut out = format!("{{\"role\":\"{role}\",\"pass\":{},\"verdict\":{:?},\"censusCheckpoints\":{},\"censusFirstError\":{:?},\"stages\":[",
        verdict.is_ok() && census.first.is_none(), verdict.as_ref().map_or_else(|e| e.clone(), |o| o.clone()),
        census.checkpoints, census.first.clone().unwrap_or_default());
    for (i, s) in stages.iter().enumerate() {
        let r = &s.report;
        out += &format!("{}{{\"op\":\"{}\",\"result\":{},\"stage\":{},\"failed\":{},\"unknown\":{},\"firstCode\":{},\"bind\":{},\"token\":{},\"dirLinks\":{},\"socketMode\":\"{:o}\"}}",
            if i > 0 { "," } else { "" }, s.name, s.result, r.stage, r.failed, r.unknown, r.first_code, r.bind_returned, r.token_ready,
            r.request_directory.links, r.socket_name.mode);
    }
    out += "]";
    for (k, v) in extra { out += &format!(",\"{k}\":{v:?}"); }
    out + "}"
}

fn mkdir(path: &str, mode: u32) -> Result<(), String> {
    fs::create_dir(path).map_err(|e| format!("mkdir {path}: {e}"))?;
    chown(path, Some(0), Some(0)).map_err(|e| format!("chown {path}: {e}"))?; // Darwin inherits the parent group.
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {path}: {e}"))
}
fn file(path: &str, mode: u32, bytes: &[u8]) -> Result<(), String> {
    File::create(path).and_then(|mut f| f.write_all(bytes)).map_err(|e| format!("write {path}: {e}"))?;
    chown(path, Some(0), Some(0)).map_err(|e| format!("chown {path}: {e}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod {path}: {e}"))
}
/// Fixed install/request layout with production owners and modes.
fn build_tree(request_dir: &str) -> Result<(), String> {
    mkdir(ROOT, 0o755)?; mkdir(OUTER, 0o755)?;
    let dirs = [format!("{OUTER}/Contents"), format!("{OUTER}/Contents/Helpers"), format!("{OUTER}/Contents/MacOS"),
        PAYLOAD.into(), format!("{PAYLOAD}/Contents"), format!("{PAYLOAD}/Contents/MacOS"), format!("{PAYLOAD}/Contents/Helpers")];
    for d in &dirs { mkdir(d, 0o755)?; }
    for f in [format!("{OUTER}/Contents/MacOS/mrk-macos-entry"), format!("{PAYLOAD}/Contents/MacOS/mobile-release-kit-desktop"),
        format!("{PAYLOAD}/Contents/Helpers/mrk-macos-remove")] { file(&f, 0o555, b"lab")?; }
    file(&format!("{ROOT}/lab-installed-producer.json"), 0o444, b"{}")?;
    file(&format!("{ROOT}/lab-installed-producer.sig"), 0o444, &[0u8; 256])?;
    for d in dirs.iter().rev().chain([OUTER.to_string()].iter()) {
        fs::set_permissions(d, fs::Permissions::from_mode(0o555)).map_err(|e| format!("chmod {d}: {e}"))?;
    }
    mkdir(REQUESTS, 0o755)?; mkdir(request_dir, 0o755)?;
    file(&format!("{request_dir}/request.json"), 0o444, b"{\"lab\":true}")
}

/// Parent: root, started by the workflow either through sudo or from the
/// postinstall of a payload-free package run by the real Installer (the
/// production remover's context). The App was started first by the workflow.
fn parent(id_text: &str, user: &str, out_path: &str, done_path: &str) -> Result<bool, String> {
    let hosted = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted");
    if !hosted { return Err("refusing: the removal lab runs only on a disposable GitHub-hosted runner".into()); }
    if unsafe { nix::libc::getuid() } != 0 { return Err("refusing: Parent must be root".into()); }
    if user.is_empty() || user == "root" { return Err("refusing: App user must be the non-root console user".into()); }
    if Path::new(ROOT).exists() || Path::new(REQUESTS).exists() { return Err("refusing: fixed paths already exist (not a fresh runner)".into()); }
    let id = unhex(id_text).ok_or("bad id")?;
    let request_dir = format!("{REQUESTS}/r-{}", hex(&id));
    let result = parent_run(id, &request_dir);
    // Release the App (it holds its connection until now), let it CLOSE with
    // the tree intact, then remove only the lab's own fixed tree.
    let _ = File::create(done_path);
    let app_closed = format!("{done_path}.app");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !Path::new(&app_closed).exists() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(50)); }
    for d in [ROOT, REQUESTS] { let _ = Command::new("/bin/chmod").args(["-R", "u+w", d]).status(); let _ = fs::remove_dir_all(d); }
    let line = match &result { Ok(line) => line.clone(), Err(e) => format!("{{\"role\":\"parent\",\"pass\":false,\"verdict\":{e:?}}}") };
    let context = format!("{{\"ppid\":{},\"sid\":{},\"euid\":{}}}", unsafe { nix::libc::getppid() },
        unsafe { nix::libc::getsid(0) }, unsafe { nix::libc::geteuid() });
    let pass = line.contains("\"pass\":true");
    let _ = fs::write(out_path, format!("{line}\n{{\"parentContext\":{context:?}}}\nREMOVAL_LAB_PARENT={}\n", if pass { "pass" } else { "fail" }));
    println!("{line}");
    Ok(pass)
}
fn parent_run(id: [u8; 16], request_dir: &str) -> Result<String, String> {
    build_tree(request_dir)?;
    let start = parent_monotonic().ok_or("monotonic")?;
    let fds = borrowed(request_dir)?;
    let bytes = (b"{}".to_vec(), vec![0u8; 256]);
    let peer = unsafe { mrk_removal_peer_new(&inputs(1, start, id, &fds, &bytes)) };
    let mut census = Census { directory: open_ro(request_dir, true)?, role: "parent", first: None, checkpoints: 0, bound: false };
    let mut posted = None;
    let (stages, verdict) = if peer.is_null() {
        (Vec::new(), Err("Parent constructor refused the protocol window/inputs".to_string()))
    } else if unsafe { mrk_macos_installed_native::mrk_removal_lab_enter_open(peer) } != 1 {
        (Vec::new(), Err("lab entry refused".to_string()))
    } else {
        // Production posts the readiness hint once its socket is published.
        let mut stages = Vec::new();
        if run(peer, OPEN, &mut census, "open", &mut stages) != 1 {
            (stages, Err("OPEN refused".to_string()))
        } else {
            posted = Some(post_removal_ready(&hex(&id)));
            let (mut rest, verdict) = drive_after_open(peer, &mut census);
            stages.append(&mut rest);
            (stages, verdict)
        }
    };
    Ok(summary("parent", &stages, &verdict, &census, &[("posted".into(), format!("{posted:?}"))]))
}
fn drive_after_open(peer: *mut c_void, census: &mut Census) -> (Vec<Stage>, Result<String, String>) {
    // Same as drive() minus OPEN, which the Parent ran before posting.
    let mut stages = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match run(peer, CONNECT, census, "connect", &mut stages) {
            1 => break,
            0 if Instant::now() < deadline => { stages.pop(); std::thread::sleep(Duration::from_millis(50)); }
            _ => return (stages, Err("CONNECT refused or timed out".into())),
        }
    }
    let auth = run(peer, AUTHENTICATE, census, "authenticate", &mut stages);
    let r = stages.last().unwrap().report;
    let verdict = if auth == 1 { Err("AUTHENTICATE passed without the signed product".into()) }
        else if r.token_ready != 1 { Err(format!("peer credentials refused before identity (native code {})", r.first_code)) }
        else if !identity_code(r.first_code) { Err(format!("refused before the identity boundary (native code {})", r.first_code)) }
        else { Ok(format!("identity boundary reached as expected (native code {}, peer uid {} pid {})", r.first_code, r.peer_uid, r.peer_pid)) };
    run(peer, CLOSE, census, "close", &mut stages);
    (stages, verdict)
}

fn app(id_text: &str, done_path: &str) -> Result<bool, String> {
    if unsafe { nix::libc::getuid() } == 0 { return Err("refusing: App must not be root".into()); }
    let id = unhex(id_text).ok_or("bad id")?;
    let start = parent_monotonic().ok_or("monotonic")?;
    let mut extra = Vec::new();
    // Confirmation sheet original on the main thread with the protocol window.
    let sheet = unsafe { mrk_removal_confirmation_reserve(start, start + WORK_NS, start + HARD_NS) };
    extra.push(("confirmationWindow".to_string(), if sheet.is_null() { "refused".into() } else { "admitted".into() }));
    // Readiness notice: production observer on this main run loop.
    let inbox = RemovalNoticeInbox::reserved();
    let mut notice = RemovalNotice::reserve(&inbox).ok_or("notice reserve")?;
    let started = notice.start();
    println!("notice-ready {started:?}");
    std::io::stdout().flush().ok();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut hint = None;
    while started == RemovalNoticeStart::Registered && Instant::now() < deadline {
        unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 1) };
        if let Poll::Ready(value) = inbox.poll_hint(&mut cx) { hint = value; break; }
    }
    extra.push(("notice".into(), match hint { Some(h) if h == id => "delivered".into(), Some(_) => "wrong id".into(),
        None => format!("not delivered ({started:?})") }));
    // Proceed to the socket either way so one run reports both facts.
    let request_dir = format!("{REQUESTS}/r-{}", hex(&id));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !Path::new(&format!("{request_dir}/s")).exists() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(50)); }
    let fds = borrowed(&request_dir)?;
    let bytes = (b"{}".to_vec(), vec![0u8; 256]);
    let peer = unsafe { mrk_removal_peer_new(&inputs(2, start, id, &fds, &bytes)) };
    let mut census = Census { directory: open_ro(&request_dir, true)?, role: "app", first: None, checkpoints: 0, bound: true };
    let (stages, verdict) = if peer.is_null() { (Vec::new(), Err("App constructor refused".to_string())) }
        else if unsafe { mrk_macos_installed_native::mrk_removal_lab_enter_open(peer) } != 1 { (Vec::new(), Err("lab entry refused".to_string())) }
        else { drive(peer, &mut census, done_path) };
    let _ = File::create(format!("{done_path}.app")); // also on early refusal
    let notice_ok = matches!(hint, Some(h) if h == id);
    let pass = verdict.is_ok() && census.first.is_none() && !sheet.is_null() && notice_ok;
    let mut line = summary("app", &stages, &verdict, &census, &extra);
    if !pass { line = line.replacen("\"pass\":true", "\"pass\":false", 1); }
    println!("{line}");
    Ok(pass)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let label = if args.get(1).map(String::as_str) == Some("app") { "REMOVAL_LAB_APP" } else { "REMOVAL_LAB" };
    let result = match args.get(1).map(String::as_str) {
        Some("parent") if args.len() == 6 => parent(&args[2], &args[3], &args[4], &args[5]),
        Some("app") if args.len() == 4 => app(&args[2], &args[3]),
        _ => Err("usage: removal_lab app ID DONE | removal_lab parent ID APP_USER OUT DONE (root, hosted runner only)".into()),
    };
    match result {
        Ok(true) => { eprintln!("{label}=pass"); }
        Ok(false) => { eprintln!("{label}=fail"); std::process::exit(1); }
        Err(error) => { eprintln!("{label}=error {error}"); std::process::exit(2); }
    }
}
