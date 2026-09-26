//! The existing retained synthetic TLS peer owner, shared by the two explicit
//! test-only profiles. Not a generic process runner or shipping entry point.
//! Original Child/control/readers/wait remain here through finality.
use super::*;
use std::{future::Future, path::PathBuf, task::Poll};
use serde_json::json;

type Check<T> = Result<T, &'static str>;
pub(super) const PEER_TIME: Duration = Duration::from_secs(16);
pub(super) const PEER_OUTPUT_LIMIT: usize = 8 * 1024;
fn require(value: bool, code: &'static str) -> Check<()> { if value { Ok(()) } else { Err(code) } }
fn deadline_case(name: &str) -> bool {
    matches!(name, "T4-owner-clear" | "T4-ambient-fixed" | "T4-ambient-no-rescue"
        | "T5-dns" | "T5-handshake" | "T5-read" | "T5-helper-read" | "G-header-withhold" | "G-dns-withhold")
}

#[derive(Default)]
pub(super) struct Arrivals {
    pub(super) frames: Vec<(usize, Instant)>, pub(super) observed_bytes: usize, pub(super) invalid: bool,
    pub(super) installed_first_get: Option<Instant>,
    pub(super) installed_first_dns: Option<(Value,Instant)>,
}
impl Arrivals {
    pub(super) fn observe(&mut self, bytes: &[u8], previous: usize, at: Instant) {
        // Called only by the normally driven original stdout reader,
        // immediately after its read. Store LF offsets/times, not a
        // second stream, peer timestamps or later parsing/wait times.
        if previous != self.observed_bytes || previous > bytes.len() || bytes.len() > PEER_OUTPUT_LIMIT {
            self.invalid = true; return;
        }
        for (offset, byte) in bytes[previous..].iter().enumerate() {
            if *byte == b'\n' {
                if self.frames.len() == 26 { self.invalid = true; break; }
                let start = self.frames.last().map_or(0, |(end, _)| *end);
                let end = previous + offset;
                // Only the bounded original reader sees this progress event.
                // It is an early control rendezvous, not a finality receipt.
                if let Ok(value) = protocol::strict_json(&bytes[start..end]) {
                    if value["scope"] == "github-installed-tls-peer-v1" && value["case"] == "T5-read"
                        && value["event"] == "first-get" {
                        if !installed_first_get_frame(&value) || self.frames.len() != 1 || self.installed_first_get.is_some() {
                            self.invalid = true;
                        } else { self.installed_first_get = Some(at); }
                    }
                    if value["scope"] == "github-installed-tls-peer-v1" && value["case"] == "G-dns-withhold"
                        && value["event"] == "dns-question" {
                        if !installed_dns_progress_frame(&value) || !(1..=8).contains(&self.frames.len())
                            || value["sequence"] != self.frames.len() {
                            self.invalid = true;
                        } else if self.frames.len() == 1 && self.installed_first_dns.is_none() {
                            self.installed_first_dns = Some((value["dnsSource"].clone(),at));
                        } else if self.installed_first_dns.as_ref().is_none_or(|(source,_)|*source!=value["dnsSource"]) {
                            self.invalid = true;
                        }
                    }
                }
                self.frames.push((previous + offset + 1, at));
            }
        }
        self.observed_bytes = bytes.len();
    }
}
fn installed_first_get_frame(value: &Value) -> bool {
    let names = ["schemaVersion", "scope", "case", "state", "event", "sequence", "requests", "bodyBytes",
        "wireReadBytes", "wireWriteBytes", "dnsQuestions", "dnsA", "dnsAAAA", "clientStop"];
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
        && value["schemaVersion"] == 1 && value["scope"] == "github-installed-tls-peer-v1"
        && value["case"] == "T5-read" && value["state"] == "progress" && value["event"] == "first-get"
        && value["sequence"] == 1 && value["requests"] == 1 && value["bodyBytes"] == 0
        && value["wireReadBytes"].as_u64().is_some_and(|n| (1..=128*1024).contains(&n))
        && value["wireWriteBytes"].as_u64().is_some_and(|n| (1..=128*1024).contains(&n))
        && value["dnsQuestions"] == 0 && value["dnsA"] == 0 && value["dnsAAAA"] == 0 && value["clientStop"].is_null()
}


fn installed_dns_source(value: &Value) -> Option<(std::net::Ipv4Addr,u16)> {
    let fields=["address","port","questionId","questionType"];
    let object=value.as_object()?;
    if object.len()!=fields.len() || !fields.iter().all(|field|object.contains_key(*field)) {return None;}
    let text=value["address"].as_str()?;
    let address=text.parse::<std::net::Ipv4Addr>().ok()?;
    let port=u16::try_from(value["port"].as_u64()?).ok()?;
    if !address.is_loopback() || address.to_string()!=text || port==0
        || value["questionId"].as_u64().is_none_or(|n|n>65535)
        || !matches!(value["questionType"].as_u64(),Some(1|28)) {return None;}
    Some((address,port))
}
fn installed_dns_progress_frame(value: &Value) -> bool {
    let fields=["schemaVersion","scope","case","state","event","sequence","requests","bodyBytes",
        "wireReadBytes","wireWriteBytes","dnsQuestions","dnsA","dnsAAAA","clientStop","dnsSource"];
    let Some(questions)=value["dnsQuestions"].as_u64() else{return false;};
    let Some(a)=value["dnsA"].as_u64() else{return false;};
    let Some(aaaa)=value["dnsAAAA"].as_u64() else{return false;};
    value.as_object().is_some_and(|v|v.len()==fields.len()&&fields.iter().all(|field|v.contains_key(*field)))
        && value["schemaVersion"]==1 && value["scope"]=="github-installed-tls-peer-v1"
        && value["case"]=="G-dns-withhold" && value["state"]=="progress" && value["event"]=="dns-question"
        && (1..=8).contains(&questions) && a<=8 && aaaa<=8 && a+aaaa==questions && value["sequence"]==questions
        && value["requests"]==0 && value["bodyBytes"]==0 && value["wireReadBytes"]==0 && value["wireWriteBytes"]==0
        && value["clientStop"].is_null() && installed_dns_source(&value["dnsSource"]).is_some()
        && (questions!=1 || (value["dnsSource"]["questionType"]==1)==(a==1))
}

pub(super) fn ready(bytes: &[u8], name: &str) -> bool {
    bytes.len() <= 1024 && protocol::strict_json(bytes).ok() == Some(json!({
        "schemaVersion":1,"scope":"github-tls-peer-v1","case":name,"state":"ready"}))
}
fn bound_ready(bytes: &[u8], name: &str, installed: Option<&Value>) -> bool {
    match installed {
        None => ready(bytes, name),
        Some(expected) => bytes.len() <= 1024 && expected["case"] == name
            && expected["scope"] == "github-installed-tls-peer-v1"
            && protocol::strict_json(bytes).ok().as_ref() == Some(expected),
    }
}
async fn peer_stdout<R: AsyncRead + Unpin>(mut reader: R, name: &'static str, ready_tx: oneshot::Sender<bool>,
    progress: Option<Arc<Mutex<Arrivals>>>, ready_binding: Option<Value>) -> ReadEnd {
    let mut ready_tx = Some(ready_tx);
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => return ReadEnd { bytes, eof: true, overflow },
            Ok(length) => {
                let original_read_at = Instant::now();
                let keep = length.min(PEER_OUTPUT_LIMIT.saturating_sub(bytes.len()));
                let previous = bytes.len();
                bytes.extend_from_slice(&buffer[..keep]);
                overflow |= keep != length;
                if let Some(progress) = &progress { lock(progress).observe(&bytes, previous, original_read_at); }
                if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                    if let Some(tx) = ready_tx.take() { let _ = tx.send(bound_ready(&bytes[..end], name, ready_binding.as_ref())); }
                } else if bytes.len() > 1024 || overflow {
                    if let Some(tx) = ready_tx.take() { let _ = tx.send(false); }
                }
                // Discard excess, but retain this original reader to real EOF.
            }
            Err(_) => return ReadEnd { bytes, eof: false, overflow },
        }
    }
}
// This guard is TLS-local; it changes neither the original owner fixture nor
// product scheduling. Catch each cleanup independently, including its drop.
pub(super) async fn guarded<F: Future>(future: F) -> Check<F::Output> {
    let mut future = Box::pin(future);
    let result = std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(_) => Poll::Ready(Err("tls_case_unwind")),
        }
    }).await;
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future))).is_err() { return Err("tls_case_drop_unwind"); }
    result
}

pub(super) struct ControlOriginal<W = tokio::process::ChildStdin> {
    pub(super) stdin: Option<W>, pub(super) completion: Option<oneshot::Receiver<()>>,
}
#[derive(Default)]
pub(super) struct ControlEnd {
    pub(super) product_settled: bool, pub(super) write_complete: bool, pub(super) shutdown_complete: bool, pub(super) released: bool, pub(super) failed: bool,
    pub(super) completed_at: Option<Instant>,
}
pub(super) struct PeerControl {
    pub(super) original: Arc<AsyncMutex<ControlOriginal>>, pub(super) writer: Option<JoinHandle<ControlEnd>>,
    pub(super) acquired: bool, pub(super) started: bool, pub(super) joined: bool, pub(super) join_failed: bool, pub(super) failed: bool,
    pub(super) joined_at: Option<Instant>, pub(super) end: Option<ControlEnd>,
}
impl PeerControl {
    pub(super) fn new(completion: oneshot::Receiver<()>) -> Self {
        Self { original: Arc::new(AsyncMutex::new(ControlOriginal { stdin: None, completion: Some(completion) })),
            writer: None, acquired: false, started: false, joined: false, join_failed: false, failed: false,
            joined_at: None, end: None }
    }
    pub(super) fn settled(&self) -> bool {
        self.acquired && self.started && self.joined && !self.join_failed
            && self.end.as_ref().is_some_and(|end| end.released)
    }
    pub(super) fn evidence(&self, endpoint: Option<Instant>) -> Value {
        json!({"acquired":self.acquired,"started":self.started,"joined":self.joined,
            "writeComplete":self.end.as_ref().is_some_and(|end| end.write_complete),
            "shutdownComplete":self.end.as_ref().is_some_and(|end| end.shutdown_complete),
            "productSettled":self.end.as_ref().is_some_and(|end| end.product_settled),
            "withinEndpoint":self.joined_at.zip(endpoint).is_some_and(|(done, limit)| done < limit)
                && self.end.as_ref().and_then(|end| end.completed_at).zip(endpoint).is_some_and(|(done, limit)| done < limit),
            "released":self.end.as_ref().is_some_and(|end| end.released),"failed":self.failed})
    }
}
async fn control_writer<W: tokio::io::AsyncWrite + Unpin>(original: Arc<AsyncMutex<ControlOriginal<W>>>, endpoint: Instant) -> ControlEnd {
    // Borrow from the pre-acquisition retained slot. Unwind/cancellation can
    // lose neither the original stdin nor its one original receiver.
    let mut original = original.lock().await;
    let mut end = ControlEnd::default();
    if let Some(completion) = original.completion.as_mut() {
        end.product_settled = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), completion)).await, Ok(Ok(Ok(()))));
    }
    original.completion.take(); // No second receiver or replacement signal.
    if end.product_settled && Instant::now() < endpoint {
        if let Some(stdin) = original.stdin.as_mut() {
            end.write_complete = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), stdin.write_all(b"S"))).await, Ok(Ok(Ok(()))));
        }
    }
    // Missing/false/unwound completion never writes S. Independently try
    // the same original shutdown even after a failed/unwound write or deadline;
    // there is no renewed allowance and no replacement descriptor/task.
    if let Some(stdin) = original.stdin.as_mut() {
        end.shutdown_complete = matches!(guarded(tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), stdin.shutdown())).await, Ok(Ok(Ok(()))));
    }
    if end.shutdown_complete {
        drop(original.stdin.take());
        end.released = true;
    }
    end.completed_at = Some(Instant::now());
    end.failed = !end.product_settled || !end.write_complete || !end.shutdown_complete || !end.released
        || end.completed_at.is_some_and(|done| done >= endpoint);
    end
}

#[cfg(test)]
mod control_models {
    // Exercise the actual writer with inert memory only. No Child, native
    // pipe, listener, process, filesystem, peer import or test hook is used.
    use super::*;
    use std::{io, pin::Pin, task::Context};

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Fault { None, WriteError, WriteUnwind, ShutdownError, ShutdownUnwind, ShutdownPending }
    #[derive(Default)]
    struct Trace { writes: Vec<Vec<u8>>, shutdowns: usize, drops: usize }
    struct MemoryWriter { original: Arc<Mutex<Trace>>, fault: Fault }
    impl tokio::io::AsyncWrite for MemoryWriter {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            lock(&self.original).writes.push(bytes.to_vec());
            match self.fault {
                Fault::WriteError => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Fault::WriteUnwind => panic!("inert control writer unwind"),
                _ => Poll::Ready(Ok(bytes.len())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            lock(&self.original).shutdowns += 1;
            match self.fault {
                Fault::ShutdownError => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Fault::ShutdownUnwind => panic!("inert control shutdown unwind"),
                Fault::ShutdownPending => Poll::Pending,
                _ => Poll::Ready(Ok(())),
            }
        }
    }
    impl Drop for MemoryWriter {
        fn drop(&mut self) { lock(&self.original).drops += 1; }
    }

    fn runtime() -> tokio::runtime::Runtime {
        match tokio::runtime::Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => panic!("inert current-thread timer unavailable"),
        }
    }
    fn original(fault: Fault, completion: Option<oneshot::Receiver<()>>)
        -> (Arc<AsyncMutex<ControlOriginal<MemoryWriter>>>, Arc<Mutex<Trace>>) {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let slot = ControlOriginal { stdin: Some(MemoryWriter { original: trace.clone(), fault }), completion };
        (Arc::new(AsyncMutex::new(slot)), trace)
    }

    #[test]
    fn original_completion_and_endpoint_gate_the_only_success_byte() {
        for mode in ["confirmed", "absent", "closed", "pending-expired", "queued-expired"] {
            let (sender, receiver) = oneshot::channel();
            let mut retained_sender = Some(sender);
            if matches!(mode, "confirmed" | "queued-expired") {
                let Some(sender) = retained_sender.take() else { panic!("original sender missing"); };
                assert!(sender.send(()).is_ok());
            } else if mode == "closed" { drop(retained_sender.take()); }
            let completion = if mode == "absent" { drop(receiver); None } else { Some(receiver) };
            let (slot, trace) = original(Fault::None, completion);
            let expired = mode.ends_with("expired");
            let endpoint = if expired { Instant::now() - Duration::from_secs(1) }
                else { Instant::now() + Duration::from_secs(10) };
            let end = runtime().block_on(control_writer(slot.clone(), endpoint));
            let facts = lock(&trace);
            assert_eq!(facts.writes, if mode == "confirmed" { vec![b"S".to_vec()] } else { vec![] }, "{mode}");
            assert_eq!(facts.shutdowns, 1, "{mode}");
            assert_eq!(facts.drops, 1, "{mode}");
            assert!(end.shutdown_complete && end.released, "{mode}");
            assert_eq!(end.write_complete, mode == "confirmed", "{mode}");
            assert_eq!(end.failed, mode != "confirmed", "{mode}");
            assert_eq!(end.product_settled, matches!(mode, "confirmed" | "queued-expired"), "{mode}");
            assert_eq!(end.completed_at.is_some_and(|at| at >= endpoint), expired, "{mode}");
            drop(facts);
            let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
            assert!(original.stdin.is_none() && original.completion.is_none(), "{mode}");
            // Pending completion is not manufactured by the writer; a late
            // original publication cannot resurrect the consumed receiver.
            if mode == "pending-expired" {
                let Some(sender) = retained_sender.take() else { panic!("pending original sender missing"); };
                assert!(sender.send(()).is_err());
            }
        }
    }

    #[test]
    fn failed_or_unwound_write_still_shuts_down_the_same_original() {
        for fault in [Fault::WriteError, Fault::WriteUnwind] {
            let (sender, receiver) = oneshot::channel();
            assert!(sender.send(()).is_ok());
            let (slot, trace) = original(fault, Some(receiver));
            let endpoint = Instant::now() + Duration::from_secs(10);
            let end = runtime().block_on(control_writer(slot.clone(), endpoint));
            let facts = lock(&trace);
            assert_eq!(facts.writes, [b"S".to_vec()]);
            assert_eq!((facts.shutdowns, facts.drops), (1, 1));
            assert!(end.product_settled && !end.write_complete && end.shutdown_complete && end.released && end.failed);
            drop(facts);
            let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
            assert!(original.stdin.is_none() && original.completion.is_none());
        }
    }

    #[test]
    fn uncertain_shutdown_retains_the_same_original_without_renewal() {
        for fault in [Fault::ShutdownError, Fault::ShutdownUnwind, Fault::ShutdownPending] {
            let (sender, receiver) = oneshot::channel();
            assert!(sender.send(()).is_ok());
            let (slot, trace) = original(fault, Some(receiver));
            let endpoint = Instant::now() + if fault == Fault::ShutdownPending {
                Duration::from_millis(100)
            } else { Duration::from_secs(10) };
            let end = runtime().block_on(control_writer(slot.clone(), endpoint));
            let facts = lock(&trace);
            assert_eq!(facts.writes, [b"S".to_vec()]);
            assert!(facts.shutdowns > 0);
            assert_eq!(facts.drops, 0);
            assert!(end.product_settled && end.write_complete && !end.shutdown_complete && !end.released && end.failed);
            assert_eq!(end.completed_at.is_some_and(|at| at >= endpoint), fault == Fault::ShutdownPending);
            drop(facts);
            let Ok(original) = slot.try_lock() else { panic!("original slot remained borrowed"); };
            assert!(original.stdin.as_ref().is_some_and(|writer| Arc::ptr_eq(&writer.original, &trace)));
            assert!(original.completion.is_none());
            // Only an inert Rust value is dropped when this model ends;
            // no native close or producer finality is claimed by the test.
        }
    }
}

#[derive(Default)]
pub(crate) struct Peer {
    pub(super) endpoint: Option<Instant>, pub(super) completed_at: Option<Instant>,
    pub(super) acquisition: Option<JoinHandle<std::io::Result<Child>>>, pub(super) acquisition_joined: bool, pub(super) acquisition_failed: bool,
    pub(super) child: Option<Child>, pub(super) spawned: bool, pub(super) spawn_refused: bool, pub(super) pipes_retained: bool,
    pub(super) stdout_original: Arc<AsyncMutex<Option<tokio::process::ChildStdout>>>,
    pub(super) stderr_original: Arc<AsyncMutex<Option<tokio::process::ChildStderr>>>,
    pub(super) stdout: Option<JoinHandle<ReadEnd>>, pub(super) stderr: Option<JoinHandle<ReadEnd>>,
    pub(super) stdout_started: bool, pub(super) stderr_started: bool, pub(super) stdout_joined: bool, pub(super) stderr_joined: bool, pub(super) stdout_failed: bool, pub(super) stderr_failed: bool,
    pub(super) out: Option<ReadEnd>, pub(super) err: Option<ReadEnd>, pub(super) ready_rx: Option<oneshot::Receiver<bool>>, pub(super) ready: bool,
    pub(super) control: Option<PeerControl>,
    pub(super) progress: Option<Arc<Mutex<Arrivals>>>,
    pub(super) ready_binding: Option<Value>,
    pub(super) waited: Option<ExitStatus>, pub(super) wait_failed: bool, pub(super) stop_attempted: bool, pub(super) expired: bool,
    pub(super) settled: bool, pub(super) protocol_checked: bool, pub(super) terminal: Option<Value>,
}
enum PeerEvent {
    Wait(std::io::Result<ExitStatus>), Out(Result<ReadEnd, tokio::task::JoinError>),
    Err(Result<ReadEnd, tokio::task::JoinError>), Control(Result<ControlEnd, tokio::task::JoinError>), Deadline,
}
impl Peer {
    pub(super) fn begin_paths(&mut self, python: PathBuf, script: PathBuf, environment: BTreeMap<String, String>, name: &'static str) -> Check<()> {
        require(self.endpoint.is_none(), "tls_peer_already_started")?;
        let cwd = script.parent().ok_or("tls_peer_layout")?.to_path_buf();
        let controlled = self.control.is_some();
        let endpoint = Instant::now() + PEER_TIME;
        self.endpoint = Some(endpoint); // Includes queue, spawn and readiness.
        let (release, enter) = oneshot::channel();
        self.acquisition = Some(tokio::task::spawn_blocking(move || {
            // The same original acquisition handle is registered before creation.
            // A lost release/returned opaque creation error is never retried.
            if enter.blocking_recv().is_err() {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "TLS peer original release unavailable"));
            }
            if Instant::now() >= endpoint { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS peer admission expired")); }
            let mut command = Command::new(python);
            command.args(["-I", "-S", "-B"]).arg(script).arg(name).current_dir(cwd)
                .env_clear().env("LC_ALL", "C").env("LANG", "C").envs(environment)
                .stdin(if controlled { Stdio::piped() } else { Stdio::null() })
                .stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(false);
            if Instant::now() >= endpoint { return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS peer admission expired")); }
            command.spawn()
        }));
        let _ = release.send(());
        Ok(())
    }
    pub(super) fn retain_pipes(&mut self) -> Check<()> {
        if self.pipes_retained { return Ok(()); }
        let mut input = match self.control.as_ref() {
            Some(control) => Some(control.original.try_lock().map_err(|_| "tls_peer_control_slot_busy")?),
            None => None,
        };
        let mut stdout = self.stdout_original.try_lock().map_err(|_| "tls_peer_stdout_slot_busy")?;
        let mut stderr = self.stderr_original.try_lock().map_err(|_| "tls_peer_stderr_slot_busy")?;
        let child = self.child.as_mut().ok_or("tls_peer_child_missing")?;
        require(stdout.is_none() && stderr.is_none() && input.as_ref().map_or(true, |original| original.stdin.is_none()),
            "tls_peer_original_pipe_replacement")?;
        // No await, allocation or fallible step between taking the original
        // pipes and storing ALL of them in pre-acquisition retained slots.
        *stdout = child.stdout.take();
        *stderr = child.stderr.take();
        let acquired = if let Some(original) = input.as_mut() {
            original.stdin = child.stdin.take();
            original.stdin.is_some()
        } else { false };
        self.pipes_retained = true;
        drop(input);
        if let Some(control) = self.control.as_mut() { control.acquired = acquired; }
        Ok(())
    }
    pub(super) fn start_stdout(&mut self, name: &'static str) -> Check<()> {
        if self.stdout_started { return require(self.stdout.is_some() || self.stdout_joined, "tls_peer_stdout_task_missing"); }
        self.stdout_started = true; // An uncertain allocation is never retried.
        require(self.stdout_original.try_lock().is_ok_and(|original| original.is_some()), "tls_peer_stdout_missing")?;
        let (ready_tx, ready_rx) = oneshot::channel();
        self.ready_rx = Some(ready_rx);
        let original = self.stdout_original.clone();
        let progress = self.progress.clone();
        let ready_binding = self.ready_binding.clone();
        self.stdout = Some(tokio::spawn(async move {
            let mut original = original.lock().await;
            let Some(stdout) = original.as_mut() else { return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; };
            let end = peer_stdout(stdout, name, ready_tx, progress, ready_binding).await;
            if end.eof { drop(original.take()); }
            end
        }));
        Ok(())
    }
    pub(super) fn start_stderr(&mut self) -> Check<()> {
        if self.stderr_started { return require(self.stderr.is_some() || self.stderr_joined, "tls_peer_stderr_task_missing"); }
        self.stderr_started = true;
        require(self.stderr_original.try_lock().is_ok_and(|original| original.is_some()), "tls_peer_stderr_missing")?;
        let (faults, _receiver) = mpsc::channel(2);
        let original = self.stderr_original.clone();
        self.stderr = Some(tokio::spawn(async move {
            let mut original = original.lock().await;
            let Some(stderr) = original.as_mut() else { return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; };
            let end = read_bounded(stderr, PEER_OUTPUT_LIMIT, faults).await;
            if end.eof { drop(original.take()); }
            end
        }));
        Ok(())
    }
    pub(super) fn start_control(&mut self) -> Check<()> {
        let Some(control) = self.control.as_mut() else { return Ok(()); };
        if control.started { return require(control.writer.is_some() || control.joined, "tls_peer_control_task_missing"); }
        control.started = true;
        let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
        require(control.acquired && control.original.try_lock().is_ok_and(|original| original.stdin.is_some() && original.completion.is_some()),
            "tls_peer_control_missing")?;
        control.writer = Some(tokio::spawn(control_writer(control.original.clone(), endpoint)));
        Ok(())
    }
    pub(super) async fn prepare_pipes(&mut self, name: &'static str) -> Check<()> {
        // Each original gets its own attempt even if another allocation or
        // setup unwinds. Already-started or uncertain tasks are not replaced.
        let kept = guarded(async { self.retain_pipes() }).await.unwrap_or_else(Err);
        let out = guarded(async { self.start_stdout(name) }).await.unwrap_or_else(Err);
        let err = guarded(async { self.start_stderr() }).await.unwrap_or_else(Err);
        let control = guarded(async { self.start_control() }).await.unwrap_or_else(Err);
        if out.is_err() { self.stdout_failed = true; }
        if err.is_err() { self.stderr_failed = true; }
        if control.is_err() { if let Some(control) = self.control.as_mut() { control.failed = true; } }
        kept.and(out).and(err).and(control)
    }
    pub(super) async fn acquire(&mut self, name: &'static str) -> Check<()> {
        require(!self.acquisition_failed, "tls_peer_acquisition_unknown")?;
        let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
        if !self.acquisition_joined {
            let task = self.acquisition.as_mut().ok_or("tls_peer_acquisition_missing")?;
            let result = match tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), task).await {
                Ok(result) => result,
                Err(_) => { self.expired = true; return Err("tls_peer_acquisition_deadline"); },
            };
            let result = match result {
                Ok(result) => { self.acquisition_joined = true; self.acquisition.take(); result },
                Err(_) => { self.acquisition_failed = true; return Err("tls_peer_acquisition_unknown"); },
            };
            match result {
                Ok(child) => { self.child = Some(child); self.spawned = true; },
                Err(_) => {
                    self.spawn_refused = true;
                    self.acquisition_failed = true; // Opaque error is not no-child/pipe evidence.
                    return Err("tls_peer_spawn_refused");
                },
            }
        }
        require(self.spawned, "tls_peer_spawn_refused")?;
        self.prepare_pipes(name).await?;
        require(Instant::now() < endpoint, "tls_peer_acquisition_deadline")
    }
    pub(super) async fn readiness(&mut self, name: &'static str) -> Check<()> {
        self.acquire(name).await?;
        let endpoint = self.endpoint.ok_or("tls_peer_not_started")?;
        let receiver = self.ready_rx.as_mut().ok_or("tls_peer_readiness_missing")?;
        let admitted = tokio::time::timeout_at(tokio::time::Instant::from_std(endpoint), receiver).await
            .map_err(|_| "tls_peer_readiness_deadline")?.map_err(|_| "tls_peer_readiness_closed")?;
        self.ready_rx.take();
        require(admitted && Instant::now() < endpoint, "tls_peer_readiness_invalid")?;
        self.ready = true;
        Ok(())
    }
    pub(super) fn stop_original(&mut self) {
        if self.stop_attempted || self.waited.is_some() || self.wait_failed { return; }
        let Some(child) = self.child.as_mut() else { return; };
        match child.try_wait() {
            Ok(Some(status)) => self.waited = Some(status),
            Ok(None) => {
                self.stop_attempted = true;
                // Even a rejected stop request cannot suppress the original
                // wait. Only that wait and both reader joins prove finality.
                let _ = child.start_kill();
            },
            Err(_) => self.wait_failed = true,
        }
    }
    pub(super) async fn settle(&mut self, name: &'static str, failed: bool) -> bool {
        let Some(endpoint) = self.endpoint else { self.settled = true; return true; };
        if !self.acquisition_joined && !self.acquisition_failed { let _ = guarded(self.acquire(name)).await; }
        if self.spawned { let _ = self.prepare_pipes(name).await; }
        // New cases wait for the positive original product result, not the
        // projection assertion. A projection failure can still dispose with
        // S, but cannot turn the case into success. False/unwind/missing
        // completion instead returns the close-only writer's failure.
        // Failed literal deadline cases dispose their own original peer
        // promptly, including after late acquisition; T6 still waits for S.
        if (failed && (self.control.is_none() || deadline_case(name)))
            || self.control.as_ref().is_some_and(|control| control.failed) { self.stop_original(); }
        loop {
            let wait_pending = self.child.is_some() && self.waited.is_none() && !self.wait_failed;
            let out_pending = self.stdout.is_some() && !self.stdout_failed;
            let err_pending = self.stderr.is_some() && !self.stderr_failed;
            let control_pending = self.control.as_ref().is_some_and(|control| control.writer.is_some() && !control.join_failed && !control.joined);
            if !wait_pending && !out_pending && !err_pending && !control_pending {
                self.completed_at = Some(Instant::now());
                self.expired |= Instant::now() >= endpoint;
                self.settled = !self.expired && self.acquisition_joined && !self.acquisition_failed
                    && (self.spawn_refused || self.spawned && self.waited.is_some() && !self.wait_failed
                        && self.stdout_joined && self.stderr_joined && !self.stdout_failed && !self.stderr_failed
                        && self.out.as_ref().is_some_and(|end| end.eof) && self.err.as_ref().is_some_and(|end| end.eof)
                        && self.control.as_ref().map_or(true, PeerControl::settled));
                if self.settled { self.child.take(); }
                return self.settled;
            }
            let event = {
                let Self { child, stdout, stderr, control, .. } = self;
                tokio::select! {
                    result = wait_original(child), if wait_pending => PeerEvent::Wait(result),
                    result = join_slot(stdout), if out_pending => PeerEvent::Out(result),
                    result = join_slot(stderr), if err_pending => PeerEvent::Err(result),
                    result = async {
                        match control.as_mut() { Some(control) => join_slot(&mut control.writer).await, None => pending().await }
                    }, if control_pending => PeerEvent::Control(result),
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(endpoint)) => PeerEvent::Deadline,
                }
            };
            match event {
                PeerEvent::Wait(Ok(status)) => self.waited = Some(status),
                PeerEvent::Wait(Err(_)) => self.wait_failed = true,
                PeerEvent::Out(Ok(end)) => { self.stdout_joined = true; self.stdout.take(); self.out = Some(end); },
                PeerEvent::Err(Ok(end)) => { self.stderr_joined = true; self.stderr.take(); self.err = Some(end); },
                // Keep each failed consumed handle without polling it again;
                // still attempt the OTHER reader and original child wait.
                PeerEvent::Out(Err(_)) => self.stdout_failed = true,
                PeerEvent::Err(Err(_)) => self.stderr_failed = true,
                PeerEvent::Control(Ok(end)) => {
                    let failed = end.failed;
                    if let Some(control) = self.control.as_mut() {
                        control.joined = true; control.joined_at = Some(Instant::now()); control.writer.take();
                        control.failed |= failed; control.end = Some(end);
                    }
                    if failed { self.stop_original(); }
                },
                PeerEvent::Control(Err(_)) => {
                    if let Some(control) = self.control.as_mut() { control.join_failed = true; control.failed = true; }
                    self.stop_original();
                },
                PeerEvent::Deadline => {
                    self.expired = true;
                    if let Some(control) = self.control.as_mut() { control.failed = true; }
                    self.stop_original();
                    return false;
                },
            }
        }
    }
    pub(super) fn evidence(&self) -> Value {
        let mut value = json!({"acquisitionJoined":self.acquisition_joined,"spawned":self.spawned,"waited":self.waited.is_some(),
            "exitCode":self.waited.as_ref().and_then(ExitStatus::code),"exitSuccess":self.waited.as_ref().map(ExitStatus::success),
            "stopAttempted":self.stop_attempted,"stdoutJoined":self.stdout_joined,"stderrJoined":self.stderr_joined,
            "stdoutEof":self.out.as_ref().is_some_and(|end| end.eof),"stderrEof":self.err.as_ref().is_some_and(|end| end.eof),
            "stdoutBytes":self.out.as_ref().map_or(0, |end| end.bytes.len()),"stderrBytes":self.err.as_ref().map_or(0, |end| end.bytes.len()),
            "stdoutOverflow":self.out.as_ref().is_some_and(|end| end.overflow),"stderrOverflow":self.err.as_ref().is_some_and(|end| end.overflow),
            "ready":self.ready,"settled":self.settled,"withinEndpoint":self.settled && !self.expired && self.completed_at.zip(self.endpoint).is_some_and(|(done, end)| done < end),
            "protocolChecked":self.protocol_checked,"terminal":self.terminal});
        if let Some(control) = self.control.as_ref() { value["control"] = control.evidence(self.endpoint); }
        value
    }
}

// Installed adapter around the SAME retained peer. It supplies closed input
// admission and receipt checks, not another Child, wait, task or cleanup owner.
#[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub(crate) mod installed {
    use super::*;
    use std::{fs, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::Path};
    use sha2::{Digest, Sha256};
    use crate::runtime::GitHubReadOnlyObservationProfile as RuntimeProfile;

    pub(crate) const N: &str = "8ef2fefe057a1773acb8d5d514adc08c28baebc98d4178f448ad2b74be204d66";
    pub(crate) const PEER_SHA: &str = "85fb9f73077426672efdc64a08de41baf9b117753b59f4a87b4b4c591c8561da";
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Case { ConnectRefresh, RealCa, WrongName, Expired, Ragged, Length, Chunk,
        HeaderLimit, BodyLimit, ChunkLimit, Unauthorized, Rate, Identity, Redirect,
        AmbientFixed, AmbientNoRescue, HandshakeDeadline, HeaderDeadline, BodyDeadline,
        Cancel, Quit, Unknown, NormalNegative, DnsDeadline, ConnectDeadline }
    impl Case {
        pub(crate) const ALL: [Self;25] = [Self::ConnectRefresh,Self::RealCa,Self::WrongName,Self::Expired,
            Self::Ragged,Self::Length,Self::Chunk,Self::HeaderLimit,Self::BodyLimit,Self::ChunkLimit,
            Self::Unauthorized,Self::Rate,Self::Identity,Self::Redirect,Self::AmbientFixed,Self::AmbientNoRescue,
            Self::HandshakeDeadline,Self::HeaderDeadline,Self::BodyDeadline,Self::Cancel,Self::Quit,Self::Unknown,Self::NormalNegative,Self::DnsDeadline,Self::ConnectDeadline];
        pub(crate) fn name(self) -> &'static str { match self {
            Self::ConnectRefresh=>"github-connect-refresh",Self::RealCa=>"github-real-ca-refusal",
            Self::WrongName=>"github-wrong-name",Self::Expired=>"github-expired",Self::Ragged=>"github-ragged",
            Self::Length=>"github-length",Self::Chunk=>"github-chunk",Self::HeaderLimit=>"github-header-limit",
            Self::BodyLimit=>"github-body-limit",Self::ChunkLimit=>"github-chunk-limit",Self::Unauthorized=>"github-unauthorized",
            Self::Rate=>"github-rate",Self::Identity=>"github-identity",Self::Redirect=>"github-redirect",
            Self::AmbientFixed=>"github-ambient-fixed",Self::AmbientNoRescue=>"github-ambient-no-rescue",
            Self::HandshakeDeadline=>"github-handshake-deadline",Self::HeaderDeadline=>"github-header-deadline",
            Self::BodyDeadline=>"github-body-deadline",Self::Cancel=>"github-cancel",Self::Quit=>"github-quit",
            Self::Unknown=>"github-unknown",Self::NormalNegative=>"github-normal-negative",
            Self::DnsDeadline=>"github-dns-deadline",Self::ConnectDeadline=>"github-connect-deadline",
        }}
        pub(crate) fn parse(value: &std::ffi::OsStr) -> Option<Self> {
            Self::ALL.into_iter().find(|case| value == std::ffi::OsStr::new(case.name()))
        }
        pub(crate) fn script(self) -> Option<&'static str> { Some(match self {
            Self::ConnectRefresh=>"G-connect-refresh",Self::RealCa=>"T2-root",Self::WrongName=>"T2-name",Self::Expired=>"T2-expired",
            Self::Ragged=>"T3-ragged",Self::Length=>"T3-length",Self::Chunk=>"T3-chunk",Self::HeaderLimit=>"T6-header",
            Self::BodyLimit=>"T6-body",Self::ChunkLimit=>"T6-chunk-metadata",Self::Unauthorized=>"T6-unauthorized",
            Self::Rate=>"T6-rate-expiry",Self::Identity=>"T6-target",Self::Redirect=>"T6-redirect",
            Self::AmbientFixed=>"T4-ambient-fixed",Self::AmbientNoRescue=>"T4-ambient-no-rescue",
            Self::HandshakeDeadline=>"T5-handshake",Self::HeaderDeadline=>"G-header-withhold",
            Self::BodyDeadline|Self::Cancel|Self::Quit|Self::Unknown=>"T5-read",Self::DnsDeadline=>"G-dns-withhold",
            Self::NormalNegative|Self::ConnectDeadline=>return None,
        })}
        pub(crate) fn profile(self) -> RuntimeProfile { match self {
            Self::NormalNegative|Self::DnsDeadline|Self::ConnectDeadline=>RuntimeProfile::Normal,
            Self::RealCa|Self::AmbientNoRescue=>RuntimeProfile::DialRealCa,
            _=>RuntimeProfile::DialSyntheticCa,
        }}
        pub(crate) fn manifest(self) -> &'static str { self.profile().manifest_sha256() }
        pub(crate) fn connections(self) -> u64 { match self {
            Self::ConnectRefresh=>8,Self::Identity|Self::AmbientFixed=>4,Self::DnsDeadline|Self::ConnectDeadline=>0,_=>1,
        }}
        pub(crate) fn reads(self) -> usize { if self == Self::ConnectRefresh { 2 } else { 1 } }
        pub(crate) fn deadline(self) -> bool { matches!(self,Self::HandshakeDeadline|Self::HeaderDeadline|Self::BodyDeadline|Self::DnsDeadline|Self::ConnectDeadline) }
        pub(crate) fn no_peer(self) -> bool { matches!(self,Self::NormalNegative|Self::ConnectDeadline) }
        pub(crate) fn normal_boundary(self) -> bool { matches!(self,Self::DnsDeadline|Self::ConnectDeadline) }
        pub(crate) fn not_proven(self) -> &'static [&'static str] { match self {
            Self::DnsDeadline=>&["real-stalled-tcp-connect"],Self::ConnectDeadline=>&["normal-resolver-withholding"],
            _=>&["normal-resolver-withholding","real-stalled-tcp-connect"],
        }}
        pub(crate) fn active_control(self) -> bool { matches!(self,Self::Cancel|Self::Quit|Self::Unknown) }
        pub(crate) fn ambient(self) -> bool { matches!(self,Self::AmbientFixed|Self::AmbientNoRescue) }
        pub(crate) fn refused_tls(self) -> bool { matches!(self,Self::RealCa|Self::WrongName|Self::Expired|Self::AmbientNoRescue) }
        pub(crate) fn reason(self) -> &'static str { match self {
            Self::ConnectRefresh|Self::AmbientFixed=>"none",
            Self::RealCa|Self::WrongName|Self::Expired|Self::Ragged|Self::AmbientNoRescue=>"tls-failed",
            Self::HeaderLimit|Self::BodyLimit|Self::ChunkLimit=>"response-limit",
            Self::Unauthorized|Self::NormalNegative=>"unauthorized",Self::Rate=>"response-invalid",
            Self::Identity=>"target-changed",Self::Redirect=>"response-invalid",
            Self::HandshakeDeadline|Self::HeaderDeadline|Self::BodyDeadline|Self::DnsDeadline|Self::ConnectDeadline=>"query_timeout",
            Self::Cancel|Self::Quit=>"cancelled",Self::Unknown=>"cleanup_unknown",
            _=>"response-invalid",
        }}
    }
    fn keys(value: &Value, expected: &[&str]) -> bool {
        value.as_object().is_some_and(|v| v.len()==expected.len() && expected.iter().all(|key|v.contains_key(*key)))
    }
    fn identity(st: &fs::Metadata) -> (u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64) {
        (st.dev(),st.ino(),st.mode(),st.uid(),st.gid(),st.nlink(),st.len(),st.mtime(),st.mtime_nsec(),st.ctime(),st.ctime_nsec())
    }
    fn protected_parents(path: &Path) -> Check<()> {
        require(path.is_absolute(), "installed_peer_path")?;
        for path in path.ancestors().skip(1) {
            let st=fs::symlink_metadata(path).map_err(|_|"installed_peer_parent")?;
            require(st.is_dir() && st.uid()==0 && st.gid()==0 && st.mode()&0o7022==0,"installed_peer_parent")?;
        }
        Ok(())
    }
    fn fixed_input(path: &Path, size: u64, hash: &str, mode: u32, end: Instant) -> Check<()> {
        protected_parents(path)?;
        let before=fs::symlink_metadata(path).map_err(|_|"installed_peer_input")?;
        require(before.is_file() && before.uid()==0 && before.gid()==0 && before.nlink()==1
            && before.mode()&0o7777==mode && before.len()==size && Instant::now()<end,"installed_peer_input")?;
        let file=fs::OpenOptions::new().read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC|rustix::fs::OFlags::NONBLOCK).bits() as i32)
            .open(path).map_err(|_|"installed_peer_input")?;
        let checked=(||{
            require(identity(&file.metadata().map_err(|_|"installed_peer_input")?)==identity(&before),"installed_peer_input")?;
            let mut digest=Sha256::new();let mut reader=&file;let mut buffer=[0u8;16384];let mut count=0u64;
            loop {
                require(Instant::now()<end,"installed_peer_input_deadline")?;
                let length=reader.read(&mut buffer).map_err(|_|"installed_peer_input")?;
                if length==0 {break;} count+=length as u64;require(count<=size,"installed_peer_input")?;digest.update(&buffer[..length]);
            }
            require(count==size && format!("{:x}",digest.finalize())==hash
                && identity(&file.metadata().map_err(|_|"installed_peer_input")?)==identity(&before)
                && identity(&fs::symlink_metadata(path).map_err(|_|"installed_peer_input")?)==identity(&before),"installed_peer_input")
        })();
        let closed=nix::unistd::close(file).is_ok();
        if !closed {return Err("installed_peer_input_close");} checked
    }
    fn proc_bytes(path: &str, maximum: u64) -> Check<Vec<u8>> {
        let file=fs::OpenOptions::new().read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC).bits() as i32).open(path).map_err(|_|"installed_peer_domain")?;
        let read=(||{let mut raw=Vec::new();(&file).take(maximum+1).read_to_end(&mut raw).map_err(|_|"installed_peer_domain")?;
            require(raw.len() as u64<=maximum,"installed_peer_domain")?;Ok(raw)})();
        if nix::unistd::close(file).is_err(){return Err("installed_peer_domain_close");}read
    }

    type NamespacePairs = BTreeMap<&'static str, (u64, u64)>;
    fn namespace_pairs(value: &Value, roles: &[&'static str]) -> Check<NamespacePairs> {
        require(keys(value, roles), "installed_peer_namespace_witness")?;
        let mut pairs = BTreeMap::new();
        for &role in roles {
            let pair = value[role].as_array().ok_or("installed_peer_namespace_witness")?;
            require(pair.len() == 2, "installed_peer_namespace_witness")?;
            let device = pair[0].as_u64().filter(|n| *n > 0).ok_or("installed_peer_namespace_witness")?;
            let inode = pair[1].as_u64().filter(|n| *n > 0).ok_or("installed_peer_namespace_witness")?;
            pairs.insert(role, (device, inode));
        }
        Ok(pairs)
    }
    fn lower_hex(value: &str, length: usize) -> bool {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }
    fn peer_namespace_witness(raw: &[u8], source: &str, service: &str, cgroup: &str,
        uid: u32, gid: u32) -> Check<NamespacePairs> {
        require(!raw.is_empty() && raw.len() <= 1024 * 1024 && lower_hex(source, 40)
            && uid != 0 && gid != 0, "installed_peer_namespace_witness")?;
        let run = service.strip_prefix("mrk-ubuntu-native-").and_then(|name| name.strip_suffix(".service"))
            .and_then(|name| name.split_once('-'));
        require(run.is_some_and(|(run, attempt)| [run, attempt].into_iter().all(|part|
            (1..=20).contains(&part.len()) && !part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())))
            && cgroup == format!("/system.slice/{service}"), "installed_peer_namespace_witness")?;
        // The existing protocol decoder rejects duplicate keys at every depth.
        let value = protocol::strict_json(raw).map_err(|_| "installed_peer_namespace_witness")?;
        let invocation = value["invocationId"].as_str().ok_or("installed_peer_namespace_witness")?;
        require(value["sourceSha"].as_str() == Some(source) && lower_hex(invocation, 32)
            && value["unit"]["Id"].as_str() == Some(service)
            && value["unit"]["InvocationID"].as_str() == Some(invocation)
            && value["unit"]["ControlGroup"].as_str() == Some(cgroup)
            && value["runnerUid"].as_u64() == Some(u64::from(uid))
            && value["runnerGid"].as_u64() == Some(u64::from(gid)), "installed_peer_namespace_witness")?;
        let witness = namespace_pairs(&value["githubPeerNamespaces"], &["user", "pid", "mnt", "net"])?;
        let legacy = namespace_pairs(&value["namespaces"], &["user", "pid", "mnt"])?;
        require(legacy.iter().all(|(role, pair)| witness.get(role) == Some(pair)),
            "installed_peer_namespace_witness")?;
        Ok(witness)
    }
    fn root_start_receipt(path: &Path, end: Instant) -> Check<Vec<u8>> {
        protected_parents(path)?;
        let before = fs::symlink_metadata(path).map_err(|_| "installed_peer_start_receipt")?;
        require(before.is_file() && before.uid() == 0 && before.gid() == 0 && before.nlink() == 1
            && before.mode() & 0o7777 == 0o444 && (1..=1024 * 1024).contains(&before.len())
            && Instant::now() < end, "installed_peer_start_receipt")?;
        // The nonroot reader does not own this file: NOATIME would fail.
        let file = fs::OpenOptions::new().read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK).bits() as i32)
            .open(path).map_err(|_| "installed_peer_start_receipt")?;
        let read = (|| {
            require(identity(&file.metadata().map_err(|_| "installed_peer_start_receipt")?) == identity(&before),
                "installed_peer_start_receipt")?;
            let mut bytes = Vec::with_capacity(before.len() as usize);
            let mut reader = &file;
            let mut buffer = [0u8; 8192];
            loop {
                require(Instant::now() < end, "installed_peer_start_receipt_deadline")?;
                let count = reader.read(&mut buffer).map_err(|_| "installed_peer_start_receipt")?;
                if count == 0 { break; }
                bytes.extend_from_slice(&buffer[..count]);
                require(bytes.len() as u64 <= before.len(), "installed_peer_start_receipt")?;
            }
            require(bytes.len() as u64 == before.len(), "installed_peer_start_receipt")?;
            Ok(bytes)
        })();
        // Recheck and consume the original on failure too; no replacement open.
        let post = (|| {
            require(identity(&file.metadata().map_err(|_| "installed_peer_start_receipt")?) == identity(&before)
                && identity(&fs::symlink_metadata(path).map_err(|_| "installed_peer_start_receipt")?) == identity(&before),
                "installed_peer_start_receipt")?;
            protected_parents(path)
        })();
        let closed = nix::unistd::close(file).is_ok();
        require(closed, "installed_peer_start_receipt_close")?;
        post?;
        require(Instant::now() < end, "installed_peer_start_receipt_deadline")?;
        read
    }
    fn namespace_labels(expected: &NamespacePairs, observed: &NamespacePairs) -> Check<BTreeMap<String, String>> {
        require(expected == observed && expected.len() == 4, "installed_peer_initial_domain")?;
        let mut labels = BTreeMap::new();
        for (kind, role) in [("net", "NETNS"), ("mnt", "MNTNS"), ("user", "USERNS"), ("pid", "PIDNS")] {
            let (_, inode) = expected.get(kind).ok_or("installed_peer_initial_domain")?;
            let label = format!("{kind}:[{inode}]");
            labels.insert(format!("MRK_TLS_PARENT_{role}"), label.clone());
            labels.insert(format!("MRK_TLS_{role}"), label);
        }
        Ok(labels)
    }
    fn original_namespace_labels(expected: &NamespacePairs, end: Instant) -> Check<BTreeMap<String, String>> {
        let mut observed = BTreeMap::new();
        for kind in ["user", "pid", "mnt", "net"] {
            require(Instant::now() < end, "installed_peer_namespace_deadline")?;
            // Only these fixed self nsfs magiclinks are intentionally followed.
            let file = fs::OpenOptions::new().read(true).custom_flags(
                (rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK).bits() as i32)
                .open(format!("/proc/self/ns/{kind}")).map_err(|_| "installed_peer_domain")?;
            let mut baseline = None;
            let pair: Check<(u64, u64)> = (|| {
                let before = file.metadata().map_err(|_| "installed_peer_domain")?;
                baseline = Some(identity(&before));
                require(before.is_file() && before.uid() == 0 && before.gid() == 0 && before.nlink() == 1,
                    "installed_peer_domain")?;
                Ok((before.dev(), before.ino()))
            })();
            let stable = baseline.is_none_or(|before|
                file.metadata().is_ok_and(|after| identity(&after) == before));
            let closed = nix::unistd::close(file).is_ok();
            require(closed, "installed_peer_domain_close")?;
            require(stable && Instant::now() < end, "installed_peer_namespace_deadline")?;
            observed.insert(kind, pair?);
        }
        namespace_labels(expected, &observed)
    }

    #[derive(Clone,Debug,PartialEq,Eq)]
    struct SocketRow {
        inode:u64, uid:u32, family:&'static str, protocol:&'static str,
        local:std::net::IpAddr, local_port:u16, remote:std::net::IpAddr, remote_port:u16, state:u8,
    }
    fn socket_endpoint(text:&str,ipv6:bool)->Check<(std::net::IpAddr,u16)> {
        let (address,port)=text.split_once(':').ok_or("installed_github_socket_endpoint")?;
        require(address.len()==(if ipv6{32}else{8}) && port.len()==4
            && address.bytes().chain(port.bytes()).all(|b|b.is_ascii_hexdigit()),"installed_github_socket_endpoint")?;
        let port=u16::from_str_radix(port,16).map_err(|_|"installed_github_socket_endpoint")?;
        let ip=if ipv6 {
            let mut bytes=[0u8;16];
            for (index,word) in address.as_bytes().chunks_exact(8).enumerate() {
                let word=std::str::from_utf8(word).map_err(|_|"installed_github_socket_endpoint")?;
                bytes[index*4..index*4+4].copy_from_slice(&u32::from_str_radix(word,16)
                    .map_err(|_|"installed_github_socket_endpoint")?.to_le_bytes());
            }
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_str_radix(address,16)
                .map_err(|_|"installed_github_socket_endpoint")?.to_le_bytes()))
        };
        Ok((ip,port))
    }
    fn socket_rows(raw:&[u8],ipv6:bool,protocol:&'static str,owned:&BTreeMap<u32,u64>)->Check<Vec<SocketRow>> {
        require(raw.len()<=1<<20 && matches!(protocol,"udp"|"tcp"),"installed_github_socket_table")?;
        let text=std::str::from_utf8(raw).map_err(|_|"installed_github_socket_table")?;
        let mut lines=text.lines();
        let header=lines.next().ok_or("installed_github_socket_table")?.split_whitespace().collect::<Vec<_>>();
        require(header.len()>=4 && header[0]=="sl" && header[1]=="local_address"
            && matches!(header[2],"rem_address"|"remote_address") && header[3]=="st","installed_github_socket_table")?;
        let mut result=Vec::new();
        for (index,line) in lines.enumerate() {
            require(index<4096 && line.len()<=1024,"installed_github_socket_table")?;
            let fields=line.split_whitespace().collect::<Vec<_>>();
            require((10..=32).contains(&fields.len()),"installed_github_socket_table")?;
            let inode=fields[9].parse::<u64>().map_err(|_|"installed_github_socket_table")?;
            // These tables belong to the namespace. Only exact original FD
            // inodes may enter the product observation or public receipt.
            if inode==0 || !owned.values().any(|original|*original==inode) {continue;}
            let (local,local_port)=socket_endpoint(fields[1],ipv6)?;
            let (remote,remote_port)=socket_endpoint(fields[2],ipv6)?;
            require(fields[3].len()==2,"installed_github_socket_table")?;
            let state=u8::from_str_radix(fields[3],16).map_err(|_|"installed_github_socket_table")?;
            let uid=fields[7].parse::<u32>().map_err(|_|"installed_github_socket_table")?;
            require(result.len()<256,"installed_github_socket_table")?;
            result.push(SocketRow{inode,uid,family:if ipv6{"ipv6"}else{"ipv4"},protocol,local,local_port,remote,remote_port,state});
        }
        Ok(result)
    }
    fn original_socket_fds(id:u32,end:Instant)->Check<BTreeMap<u32,u64>> {
        let path=format!("/proc/{id}/fd");
        let before=fs::symlink_metadata(&path).map_err(|_|"installed_github_socket_fds")?;
        require(before.is_dir() && before.uid()==rustix::process::getuid().as_raw() && Instant::now()<end,
            "installed_github_socket_fds")?;
        let directory=fs::OpenOptions::new().read(true).custom_flags(
            (rustix::fs::OFlags::DIRECTORY|rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::CLOEXEC).bits() as i32)
            .open(&path).map_err(|_|"installed_github_socket_fds")?;
        let read=(|| {
            require(identity(&directory.metadata().map_err(|_|"installed_github_socket_fds")?)==identity(&before),
                "installed_github_socket_fds")?;
            let mut buffer=[std::mem::MaybeUninit::uninit();4096];
            // RawDir borrows this same descriptor; it neither duplicates the
            // original nor hides a second unchecked directory close.
            let mut rows=rustix::fs::RawDir::new(&directory,&mut buffer);
            let mut result=BTreeMap::new();let mut count=0usize;
            while let Some(entry)=rows.next() {
                require(Instant::now()<end && count<258,"installed_github_socket_fds")?;count+=1;
                let entry=entry.map_err(|_|"installed_github_socket_fds")?;
                let name=entry.file_name().to_bytes();
                if matches!(name,b"."|b".."){continue;}
                let text=std::str::from_utf8(name).map_err(|_|"installed_github_socket_fds")?;
                let fd=text.parse::<u32>().map_err(|_|"installed_github_socket_fds")?;
                require(text==fd.to_string() && entry.file_type()==rustix::fs::FileType::Symlink,"installed_github_socket_fds")?;
                let mut link=[0u8;4097];
                let length=match rustix::fs::readlinkat_raw(&directory,entry.file_name(),&mut link[..]) {
                    Ok(length)=>length,
                    Err(rustix::io::Errno::NOENT)=>continue, // A vanishing FD cannot match both snapshots.
                    Err(_)=>return Err("installed_github_socket_fds"),
                };
                require(length<=4096,"installed_github_socket_fds")?;
                let link=&link[..length];
                if let Some(number)=link.strip_prefix(b"socket:[").and_then(|v|v.strip_suffix(b"]")) {
                    let text=std::str::from_utf8(number).map_err(|_|"installed_github_socket_fds")?;
                    let inode=text.parse::<u64>().map_err(|_|"installed_github_socket_fds")?;
                    require(inode>0 && text==inode.to_string() && result.insert(fd,inode).is_none(),"installed_github_socket_fds")?;
                }
            }
            require(identity(&directory.metadata().map_err(|_|"installed_github_socket_fds")?)==identity(&before)
                && identity(&fs::symlink_metadata(&path).map_err(|_|"installed_github_socket_fds")?)==identity(&before),
                "installed_github_socket_fds")?;
            Ok(result)
        })();
        if nix::unistd::close(directory).is_err(){return Err("installed_github_socket_fds_close");}read
    }
    fn normal_connect_address(address:std::net::IpAddr)->bool {
        match address {
            std::net::IpAddr::V4(ip)=>!ip.is_loopback()&&!ip.is_unspecified()&&!ip.is_private()
                &&!ip.is_link_local()&&!ip.is_multicast()&&!ip.is_broadcast()&&ip.octets()[0]!=0,
            std::net::IpAddr::V6(ip)=>!ip.is_loopback()&&!ip.is_unspecified()&&!ip.is_multicast()
                &&!ip.is_unique_local()&&!ip.is_unicast_link_local()&&ip.to_ipv4_mapped().is_none(),
        }
    }
    fn boundary_matches(case:Case,row:&SocketRow,source:Option<&Value>,uid:u32)->bool {
        if row.uid!=uid || row.local_port==0 || row.local.is_unspecified() {return false;}
        match case {
            Case::DnsDeadline=>source.and_then(installed_dns_source).is_some_and(|(address,port)|
                row.family=="ipv4" && row.protocol=="udp" && row.local==std::net::IpAddr::V4(address) && row.local_port==port
                && (row.remote==std::net::IpAddr::V4(std::net::Ipv4Addr::new(127,0,0,53)) && row.remote_port==53 && row.state==1
                    || row.remote.is_unspecified() && row.remote_port==0 && row.state==7)),
            Case::ConnectDeadline=>source.is_none() && row.protocol=="tcp" && row.state==2
                && row.remote_port==443 && normal_connect_address(row.remote),
            _=>false,
        }
    }
    fn joined_boundary(case:Case,rows:&[SocketRow],before:&BTreeMap<u32,u64>,after:&BTreeMap<u32,u64>,
        source:Option<&Value>,uid:u32)->Check<Option<(u32,SocketRow)>> {
        require(rows.len()<=256 && before.len()<=256 && after.len()<=256,"installed_github_boundary_bound")?;
        if before!=after{return Ok(None);}
        let mut selected=None;
        for row in rows {
            if !boundary_matches(case,row,source,uid){continue;}
            for (fd,inode) in before {
                if *inode==row.inode && after.get(fd)==Some(inode) {
                    require(selected.is_none(),"installed_github_boundary_ambiguous")?;
                    selected=Some((*fd,row.clone()));
                }
            }
        }
        Ok(selected)
    }
    fn dns_protocol(peer:&Peer,terminal:&Value,lines:&[&[u8]],product_endpoint:Option<Instant>)->Check<()> {
        let fields=["schemaVersion","scope","case","installedCase","ownerTag","manifestSha256","peerSha256","primaryPort",
            "state","status","code","connections","handshakes","requests","decryptedBytes","authBytes","closeNotify","tlsRefused",
            "wireReadBytes","wireWriteBytes","replyBytes","allSocketsClosed","completion","sni","phase","withheldWireBytes",
            "bodyBytes","incompleteBody","clientStop","progressCount","dnsQuestions","dnsA","dnsAAAA","dnsReplies","dnsSource"];
        require(keys(terminal,&fields) && terminal["phase"]=="dns" && terminal["tlsRefused"]==false
            && terminal["incompleteBody"]==false && terminal["clientStop"].is_null(),"installed_peer_dns_terminal")?;
        for key in ["connections","handshakes","requests","decryptedBytes","authBytes","closeNotify","sni","withheldWireBytes","bodyBytes","dnsReplies"] {
            require(terminal[key]==0,"installed_peer_dns_no_reply")?;
        }
        for key in ["wireReadBytes","wireWriteBytes","replyBytes"] {require(terminal[key]==json!([]),"installed_peer_dns_no_reply")?;}
        let completion=&terminal["completion"];
        require(keys(completion,&["bytes","eof","closed","primaryEmpty","primaryUnexpected","primaryClosed","proxy","dnsEmpty","dnsClosed"])
            && completion["primaryEmpty"].is_null() && completion["primaryClosed"].is_null() && completion["primaryUnexpected"]==0
            && completion["proxy"].is_null() && completion["dnsEmpty"]==true && completion["dnsClosed"]==true,"installed_peer_dns_completion")?;
        let progress=peer.progress.as_ref().ok_or("installed_peer_progress")?;let arrivals=lock(progress);
        let (source,first_at)=arrivals.installed_first_dns.as_ref().ok_or("installed_peer_dns_progress")?;
        require(!arrivals.invalid && arrivals.frames.len()==lines.len()-1 && (4..=11).contains(&lines.len())
            && terminal["dnsSource"]==*source && installed_dns_source(source).is_some(),"installed_peer_dns_progress")?;
        let mut last:Option<Value>=None;
        for (index,line) in lines[1..lines.len()-2].iter().enumerate() {
            let value=protocol::strict_json(line).map_err(|_|"installed_peer_dns_progress")?;
            require(installed_dns_progress_frame(&value) && value["sequence"]==index+1 && value["dnsSource"]==*source,
                "installed_peer_dns_progress")?;
            if let Some(previous)=last.as_ref() {
                require(value["dnsA"].as_u64()>=previous["dnsA"].as_u64()
                    && value["dnsAAAA"].as_u64()>=previous["dnsAAAA"].as_u64(),"installed_peer_dns_progress")?;
            }
            last=Some(value);
        }
        let last=last.ok_or("installed_peer_dns_progress")?;
        for key in ["dnsQuestions","dnsA","dnsAAAA"] {require(terminal[key]==last[key],"installed_peer_dns_progress")?;}
        require(terminal["progressCount"]==last["sequence"],"installed_peer_dns_progress")?;
        let endpoint=product_endpoint.ok_or("installed_peer_product_endpoint")?;
        let control=peer.control.as_ref().ok_or("installed_peer_control")?;
        require(*first_at<endpoint && control.end.as_ref().and_then(|end|end.completed_at)
            .is_some_and(|at|at>=endpoint && peer.endpoint.is_some_and(|end|at<end)),"installed_peer_dns_timing")
    }

    pub(crate) struct InstalledPeer {
        case: Case, original: Peer, completion: Option<oneshot::Sender<()>>,
        root: Option<PathBuf>, environment: BTreeMap<String,String>, ready_frame: Option<Value>,
        materials_checked: bool, post_checked: bool, failed: bool,
    }
    impl InstalledPeer {
        pub(crate) fn new(case: Case) -> Self {
            let (sender,receiver)=oneshot::channel();
            let mut original=Peer::default();
            original.control=Some(PeerControl::new(receiver));
            original.progress=Some(Arc::new(Mutex::new(Arrivals::default())));
            Self {case,original,completion:Some(sender),root:None,environment:BTreeMap::new(),
                ready_frame:None,materials_checked:false,post_checked:false,failed:false}
        }
        fn inputs(&self, root:&Path, end:Instant)->Check<()> {
            fixed_input(&PathBuf::from("/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu").join(N).join("python/bin/python3"),
                8247616,"9d13da55c5e3ec27d0e6a18e3960fa6af4ced7628afe2e63830e7e66d8c80d4f",0o555,end)?;
            if self.case.no_peer() {return Ok(());}
            let staged=root.join("github-peer");
            fixed_input(&staged.join("github_tls_peer.py"),61665,PEER_SHA,0o444,end)?;
            for (name,size,hash) in [
                ("api-valid.pem",786,"33f6acd10b8d466078525b80464a1c5938266b1084ea5aabf43b348bd7dca6f2"),
                ("wrong-san.pem",786,"8d9b1bcc7c3ca1a9118af18993d2cd01a45439e76c0b1407103f1e6689ee9108"),
                ("api-expired.pem",790,"d0613acb9ef97d2b421d13a279e9f6b5674688210a5cb80441bcd89a183b4c0f"),
                ("server-key.pem",241,"33332bb26fd6e394d067f7e2df563d496f934e0a098de1e3039169fb8d4ee109"),
                ("root-ca.pem",761,"3d785e2a47139241c55b340b4d07a5de79aed18b9c28157f9dbe9f694b461025"),
                ("other-root-ca.pem",778,"69b4eda8770c518de6e83caa5037bcf5d38f9f9ec16ef3c1e7c11023627a018c"),
            ] {fixed_input(&staged.join("github_tls").join(name),size,hash,0o444,end)?;}
            Ok(())
        }
        pub(crate) fn prepare(&mut self, root:PathBuf, end:Instant)->Check<()> {
            require(self.root.is_none() && !self.materials_checked && self.original.endpoint.is_none(),"installed_peer_repeated_setup")?;
            self.root=Some(root.clone()); // Failed setup is never retried under a replacement context.
            let uname=rustix::system::uname();
            require(uname.sysname().to_bytes()==b"Linux" && uname.machine().to_bytes()==b"x86_64"
                && uname.release().to_bytes()==b"6.17.0-1022-azure","installed_peer_domain")?;
            let uid=rustix::process::getuid().as_raw();let gid=rustix::process::getgid().as_raw();
            require(uid!=0 && gid!=0 && rustix::process::geteuid().as_raw()==uid && rustix::process::getegid().as_raw()==gid,
                "installed_peer_identity")?;
            require(root.parent()==Some(Path::new("/var/lib")),"installed_peer_domain")?;
            let name=root.file_name().and_then(|v|v.to_str()).ok_or("installed_peer_domain")?;
            require(proc_bytes("/proc/self/cgroup",4096)?==format!("0::/system.slice/{name}.service\n").as_bytes(),"installed_peer_domain")?;
            let status=String::from_utf8(proc_bytes("/proc/self/status",16384)?).map_err(|_|"installed_peer_domain")?;
            for (key,wanted) in [("NoNewPrivs","1"),("CapInh","0000000000000000"),("CapPrm","0000000000000000"),
                ("CapEff","0000000000000000"),("CapBnd","0000000000000000"),("CapAmb","0000000000000000"),("Groups","")] {
                let rows=status.lines().filter_map(|s|s.split_once(':')).filter(|(k,_)|*k==key).map(|(_,v)|v.trim()).collect::<Vec<_>>();
                require(rows==[wanted],"installed_peer_domain")?;
            }
            let mut environment=BTreeMap::from([
                ("MRK_DESKTOP_HOSTED_CHECKS".into(),"github-readonly-installed-tls-v1".into()),
                ("GITHUB_ACTIONS".into(),"true".into()),("RUNNER_ENVIRONMENT".into(),"github-hosted".into()),
                ("MRK_TLS_ORIGINAL_UID".into(),uid.to_string()),("MRK_TLS_ORIGINAL_GID".into(),gid.to_string()),
                ("MRK_TLS_PEER_SHA256".into(),PEER_SHA.into()),("MRK_TLS_INSTALLED_CASE".into(),self.case.name().into()),
                ("MRK_TLS_RUNTIME_MANIFEST_SHA256".into(),self.case.manifest().into()),
            ]);
            let source = option_env!("GITHUB_SHA").ok_or("installed_peer_namespace_witness")?;
            let receipt = root_start_receipt(&root.join("public/unit-start.json"), end)?;
            let service = format!("{name}.service");
            let witness = peer_namespace_witness(&receipt, source, &service, &format!("/system.slice/{service}"), uid, gid)?;
            environment.extend(original_namespace_labels(&witness, end)?);
            self.inputs(&root,end)?;
            if self.case.ambient() {
                for key in ["http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"] {
                    require(std::env::var(key).ok().as_deref()==Some("http://127.0.0.1:18888"),"installed_peer_ambient")?;
                }
                let ca=root.join("github-peer/github_tls/root-ca.pem");
                for key in ["SSL_CERT_FILE","REQUESTS_CA_BUNDLE","CURL_CA_BUNDLE"] {
                    require(std::env::var_os(key).as_deref()==Some(ca.as_os_str()),"installed_peer_ambient")?;
                }
                require(std::env::var_os("SSLKEYLOGFILE").as_deref()==Some(root.join(format!("shell-{}-keylog.log",self.case.name())).as_os_str()),
                    "installed_peer_ambient")?;
            }
            // Correlation only: authority comes from the exact retained Child,
            // exclusive bind and its original stdout, never this public label.
            let tag=format!("{:x}",Sha256::digest(format!("{}:{name}:{}:{}",self.case.name(),std::process::id(),
                option_env!("GITHUB_SHA").unwrap_or("")).as_bytes()))[..16].to_owned();
            environment.insert("MRK_TLS_PEER_OWNER_TAG".into(),tag.clone());
            let ready=json!({"schemaVersion":1,"scope":"github-installed-tls-peer-v1","case":self.case.script(),
                "state":"ready","installedCase":self.case.name(),"ownerTag":tag,"manifestSha256":self.case.manifest(),
                "peerSha256":PEER_SHA,"primaryPort":if self.case==Case::DnsDeadline{18553}else{18443}});
            self.original.ready_binding=Some(ready.clone());self.ready_frame=Some(ready);self.environment=environment;
            self.materials_checked=true;Ok(())
        }
        pub(crate) async fn start(&mut self)->Check<()> {
            require(self.materials_checked && self.original.endpoint.is_none(),"installed_peer_setup")?;
            if self.case.no_peer() {return Ok(());}
            let root=self.root.as_ref().ok_or("installed_peer_setup")?;
            let script=self.case.script().ok_or("installed_peer_setup")?;
            let python=PathBuf::from("/var/lib/mobile-release-kit/versions/x86_64-unknown-linux-gnu").join(N).join("python/bin/python3");
            self.original.begin_paths(python,root.join("github-peer/github_tls_peer.py"),self.environment.clone(),script)?;
            self.original.readiness(script).await
        }
        pub(crate) fn first_get(&self)->bool {
            self.original.progress.as_ref().is_some_and(|p|{let p=lock(p);!p.invalid&&p.installed_first_get.is_some()})
        }
        pub(crate) async fn settle(&mut self, product_final:bool, end:Instant)->bool {
            if self.post_checked {return self.original.settled || self.case.no_peer();}
            if product_final {if let Some(sender)=self.completion.take(){let _=sender.send(());}}
            else {drop(self.completion.take());self.failed=true;}
            let settled=if let Some(script)=self.case.script(){self.original.settle(script,!product_final).await}else{true};
            self.failed|=!settled;
            if settled {
                let result=self.root.as_ref().ok_or("installed_peer_setup").and_then(|root|self.inputs(root,end));
                self.post_checked=true;self.failed|=result.is_err();
            }
            // Physical disposal is separate from the positive protocol result:
            // a failed case may exit only after the same original peer is final.
            settled && self.post_checked
        }
        pub(crate) fn validate(&mut self, product_endpoint:Option<Instant>)->Check<()> {
            if self.case.no_peer() {return require(self.materials_checked&&self.post_checked&&!self.failed,"installed_peer_normal");}
            let peer=&mut self.original;
            require(peer.settled && peer.ready && peer.spawned && !peer.expired && !peer.stop_attempted
                && peer.waited.as_ref().is_some_and(ExitStatus::success) && self.post_checked && !self.failed,"installed_peer_final")?;
            let out=peer.out.as_ref().ok_or("installed_peer_output")?;let err=peer.err.as_ref().ok_or("installed_peer_output")?;
            require(out.eof && err.eof && !out.overflow && !err.overflow && err.bytes.is_empty(),"installed_peer_output")?;
            let lines=out.bytes.split(|b|*b==b'\n').collect::<Vec<_>>();
            require((3..=27).contains(&lines.len()) && lines.last()==Some(&&b""[..])
                && protocol::strict_json(lines[0]).ok()==self.ready_frame,"installed_peer_frames")?;
            let terminal=protocol::strict_json(lines[lines.len()-2]).map_err(|_|"installed_peer_terminal")?;
            let binding=self.ready_frame.as_ref().ok_or("installed_peer_binding")?;
            for key in ["schemaVersion","scope","case","installedCase","ownerTag","manifestSha256","peerSha256","primaryPort"] {
                require(terminal.get(key)==binding.get(key),"installed_peer_binding")?;
            }
            require(terminal["state"]=="finished" && terminal["status"]=="passed" && terminal["code"].is_null()
                && terminal["allSocketsClosed"]==true && terminal["connections"]==self.case.connections(),"installed_peer_terminal")?;
            let completion=&terminal["completion"];
            require(completion["bytes"]==1 && completion["eof"]==true && completion["closed"]==true,"installed_peer_completion")?;
            let control=peer.control.as_ref().ok_or("installed_peer_control")?;
            require(control.settled() && !control.failed && control.end.as_ref().is_some_and(|e|
                e.product_settled && e.write_complete && e.shutdown_complete && e.released),"installed_peer_control")?;
            if self.case==Case::DnsDeadline {
                dns_protocol(peer,&terminal,&lines,product_endpoint)?;
                peer.terminal=Some(terminal);peer.protocol_checked=true;return Ok(());
            }
            require(completion["primaryEmpty"]==true && completion["primaryUnexpected"]==0 && completion["primaryClosed"]==true,
                "installed_peer_completion")?;
            let deadline=self.case.deadline() || self.case.active_control();
            let framed=deadline || self.case.ambient();
            let mut fields=vec!["schemaVersion","scope","case","installedCase","ownerTag","manifestSha256","peerSha256","primaryPort",
                "state","status","code","connections","handshakes","requests","decryptedBytes","authBytes","closeNotify","tlsRefused",
                "wireReadBytes","wireWriteBytes","replyBytes","allSocketsClosed","completion"];
            if framed {fields.extend(["sni","phase","withheldWireBytes","bodyBytes","incompleteBody","clientStop","progressCount",
                "dnsQuestions","dnsA","dnsAAAA","dnsReplies"]);}else {fields.push("replyStops");}
            require(keys(&terminal,&fields),"installed_peer_terminal_fields")?;
            let refused=self.case.refused_tls();let handshake=self.case==Case::HandshakeDeadline;
            let requests=if refused||handshake{0}else{self.case.connections()};
            require(terminal["requests"]==requests && terminal["handshakes"]==requests
                && terminal["authBytes"]==requests*b"Bearer INERT_NOT_A_CREDENTIAL".len() as u64
                && terminal["tlsRefused"]==refused
                && terminal["decryptedBytes"].as_u64().is_some_and(|n|n>=requests*27&&n<=requests*8192),"installed_peer_requests")?;
            if refused {require(terminal["decryptedBytes"]==0 && terminal["closeNotify"]==0,"installed_peer_no_authorization")?;}
            require(terminal["closeNotify"].as_u64().is_some_and(|n|n<=self.case.connections()),"installed_peer_notify_bound")?;
            let wire_max=if self.case==Case::BodyLimit{512*1024}else{128*1024};
            for key in ["wireReadBytes","wireWriteBytes","replyBytes"] {
                let values=terminal[key].as_array().ok_or("installed_peer_wire")?;
                require(values.len()==self.case.connections() as usize && values.iter().all(|v|v.as_u64().is_some_and(|n|n<=wire_max)),
                    "installed_peer_wire")?;
            }
            let progress=peer.progress.as_ref().ok_or("installed_peer_progress")?;let arrivals=lock(progress);
            require(!arrivals.invalid && arrivals.frames.len()==lines.len()-1,"installed_peer_progress")?;
            let mut body_times=Vec::new();let mut phase_at=None;let mut stop_at=None;let mut count=0;
            for (index,line) in lines[1..lines.len()-2].iter().enumerate() {
                let value=protocol::strict_json(line).map_err(|_|"installed_peer_progress")?;
                require(framed && keys(&value,&["schemaVersion","scope","case","state","event","sequence","requests","bodyBytes",
                    "wireReadBytes","wireWriteBytes","dnsQuestions","dnsA","dnsAAAA","clientStop"])
                    && value["schemaVersion"]==1 && value["scope"]=="github-installed-tls-peer-v1"
                    && value["case"]==binding["case"] && value["state"]=="progress" && value["sequence"]==index+1
                    && value["dnsQuestions"]==0 && value["dnsA"]==0 && value["dnsAAAA"]==0,"installed_peer_progress")?;
                let at=arrivals.frames[index+1].1;count+=1;
                match value["event"].as_str() {
                    Some("first-get") if !handshake && phase_at.is_none() && value["requests"]==1=>phase_at=Some(at),
                    Some("client-hello") if handshake && phase_at.is_none() && value["requests"]==0=>phase_at=Some(at),
                    Some("body-byte") if matches!(self.case,Case::BodyDeadline|Case::Cancel|Case::Quit|Case::Unknown)
                        && phase_at.is_some() && value["bodyBytes"]==body_times.len()+1=>body_times.push(at),
                    Some("client-stop") if deadline && phase_at.is_some() && stop_at.is_none()=>stop_at=Some(at),
                    _=>return Err("installed_peer_progress_event"),
                }
            }
            if framed {
                require(terminal["progressCount"]==count && terminal["dnsQuestions"]==0 && terminal["dnsA"]==0
                    && terminal["dnsAAAA"]==0 && terminal["dnsReplies"]==0,"installed_peer_progress")?;
                require(keys(completion,&["bytes","eof","closed","primaryEmpty","primaryUnexpected","primaryClosed","proxy","dnsEmpty","dnsClosed"])
                    && completion["dnsEmpty"].is_null() && completion["dnsClosed"].is_null(),"installed_peer_completion_fields")?;
                if self.case.ambient(){require(completion["proxy"]==json!({"empty":true,"unexpected":0,"closed":true}),"installed_peer_proxy")?;}
                else{require(completion["proxy"].is_null(),"installed_peer_proxy")?;}
            } else {
                require(lines.len()==3 && keys(completion,&["bytes","eof","closed","primaryEmpty","primaryUnexpected","primaryClosed","redirect"]),
                    "installed_peer_completion_fields")?;
                let redirect=if self.case==Case::Redirect{json!({"empty":true,"unexpected":0,"closed":true})}else{Value::Null};
                require(completion["redirect"]==redirect,"installed_peer_redirect")?;
                let stops=terminal["replyStops"].as_array().ok_or("installed_peer_reply_stops")?;
                require(stops.len()==self.case.connections() as usize && stops.iter().all(|s|matches!(s.as_str(),
                    Some("none"|"notify:broken-pipe"|"notify:connection-reset"|"notify:tls-eof"|"notify:tls-close-notify"
                        |"reply:broken-pipe"|"reply:connection-reset"|"reply:tls-eof"|"reply:tls-close-notify"))),"installed_peer_reply_stops")?;
                let streaming:Option<(&[u64],&[u64])>=match self.case {
                    Case::HeaderLimit=>Some((&[40630],&[32768])),Case::BodyLimit=>Some((&[262215],&[262215])),
                    Case::ChunkLimit=>Some((&[35803],&[33143])),Case::Unauthorized=>Some((&[99],&[80])),
                    Case::Rate=>Some((&[175],&[156])),Case::Identity=>Some((&[95,222,102,222],&[95,222,102,222])),
                    Case::Redirect=>Some((&[136],&[117])),_=>None,
                };
                if let Some((scripted,minima))=streaming {
                    let mut notified=0;
                    for (i,stop) in stops.iter().enumerate() {
                        let stop=stop.as_str().ok_or("installed_peer_reply_stops")?;
                        let whole=if stop=="none"{notified+=1;true}else{stop.starts_with("notify:")};
                        let minimum=if whole{scripted[i]}else{minima[i]};
                        require((self.case!=Case::Identity||stop=="none")
                            && terminal["replyBytes"][i].as_u64().is_some_and(|n|(minimum..=scripted[i]).contains(&n))
                            && terminal["wireWriteBytes"][i].as_u64().is_some_and(|n|n>=minimum),"installed_peer_streaming_floor")?;
                    }
                    require(terminal["closeNotify"]==notified,"installed_peer_streaming_notify")?;
                } else {
                    let notify=match self.case{Case::ConnectRefresh=>8,Case::Length|Case::Chunk=>1,_=>0};
                    require(terminal["closeNotify"]==notify,"installed_peer_framing_notify")?;
                    if !refused {require(terminal["replyBytes"].as_array().is_some_and(|v|
                        v.iter().all(|n|n.as_u64().is_some_and(|n|n>0&&n<=65536))),"installed_peer_framing_body")?;}
                }
            }
            if deadline {
                require(terminal["sni"]==1 && phase_at.is_some() && stop_at.is_some()
                    && matches!(terminal["clientStop"].as_str(),Some("tcp-eof"|"connection-reset"|"tls-close-notify"|"broken-pipe")),"installed_peer_withholding")?;
                if handshake {
                    require(terminal["phase"]=="handshake" && terminal["withheldWireBytes"].as_u64().is_some_and(|n|n>0)
                        && terminal["wireWriteBytes"]==json!([0]) && terminal["replyBytes"]==json!([0]),"installed_peer_handshake")?;
                } else if self.case==Case::HeaderDeadline {
                    require(terminal["phase"]=="headers" && terminal["bodyBytes"]==0 && terminal["replyBytes"]==json!([0]),"installed_peer_headers")?;
                } else {
                    require(terminal["phase"]=="read" && terminal["incompleteBody"]==true && !body_times.is_empty()
                        && terminal["bodyBytes"]==body_times.len() && body_times.len()<14,"installed_peer_body")?;
                }
                if self.case.deadline() {
                    let endpoint=product_endpoint.ok_or("installed_peer_product_endpoint")?;
                    require(phase_at.is_some_and(|at|at+Duration::from_secs(5)<endpoint)
                        && stop_at.is_some_and(|at|at>=endpoint && at<endpoint+CLEANUP_TIME),"installed_peer_deadline_timing")?;
                    if self.case==Case::BodyDeadline {
                        require(body_times.len()>=7 && body_times.windows(2).all(|p|
                            p[1].saturating_duration_since(p[0])>=Duration::from_millis(500)
                            && p[1].saturating_duration_since(p[0])<Duration::from_secs(2))
                            && body_times.last().is_some_and(|at|*at+Duration::from_secs(2)>endpoint),"installed_peer_body_progress")?;
                    }
                }
            }
            drop(arrivals);
            peer.terminal=Some(terminal);peer.protocol_checked=true;Ok(())
        }
        pub(crate) fn evidence(&self)->Value {
            if self.case.no_peer() {Value::Null}else{self.original.evidence()}
        }
    }

    // Observation of exact original product owners. It never acquires a child,
    // owns a replacement joiner or grants product admission/cleanup.
    pub(crate) struct ProductWitness {
        case: Case, owners: Mutex<Vec<Arc<Owner>>>, results: Mutex<Vec<Value>>,
        progress:Option<Arc<Mutex<Arrivals>>>, boundaries:Mutex<BTreeMap<u64,Value>>,
        io_checked: Mutex<std::collections::BTreeSet<u64>>, observing: AsyncMutex<()>, unknown_injected: AtomicBool, failed: AtomicBool,
    }
    impl ProductWitness {
        pub(crate) fn new(case:Case,peer:&InstalledPeer)->Arc<Self>{Arc::new(Self{case,owners:Mutex::new(Vec::new()),results:Mutex::new(Vec::new()),
            progress:peer.original.progress.clone(),boundaries:Mutex::new(BTreeMap::new()),
            io_checked:Mutex::new(std::collections::BTreeSet::new()),observing:AsyncMutex::new(()),
            unknown_injected:AtomicBool::new(false),failed:AtomicBool::new(false)})}
        pub(crate) fn profile(&self)->RuntimeProfile{self.case.profile()}

        pub(in crate::supervisor) fn observe_boundary(&self,id:u32,key:u64,profile:RuntimeProfile,end:Instant,stop:&watch::Receiver<bool>)->Check<()> {
            require(self.case.profile()==profile,"installed_github_boundary_case")?;
            let case=self.case;
            if !case.normal_boundary(){return Ok(());}
            let owner=lock(&self.owners).iter().find(|owner|owner.key==key).cloned().ok_or("installed_github_boundary_owner")?;
            require(self.original_profile(&owner)==Some(RuntimeProfile::Normal) && owner.endpoint()==end
                && !lock(&self.boundaries).contains_key(&key),"installed_github_boundary_owner")?;
            // The caller is the SAME existing observation task under the driver
            // guard, before any wait/reap of this exact retained Child. Its PID
            // is not discovered through a namespace-wide process search.
            let uid=rustix::process::getuid().as_raw();
            require(uid!=0 && id>0 && proc_bytes(&format!("/proc/{id}/cgroup"),4096)?==proc_bytes("/proc/self/cgroup",4096)?,
                "installed_github_boundary_domain")?;
            let network=fs::read_link(format!("/proc/{id}/ns/net")).map_err(|_|"installed_github_boundary_domain")?;
            require(network==fs::read_link("/proc/self/ns/net").map_err(|_|"installed_github_boundary_domain")?
                && network==fs::read_link("/proc/1/ns/net").map_err(|_|"installed_github_boundary_domain")?,
                "installed_github_boundary_domain")?;
            let status=String::from_utf8(proc_bytes(&format!("/proc/{id}/status"),16384)?).map_err(|_|"installed_github_boundary_domain")?;
            let rows=status.lines().filter_map(|line|line.strip_prefix("Uid:")).collect::<Vec<_>>();
            require(rows.len()==1 && rows[0].split_whitespace().collect::<Vec<_>>()==vec![uid.to_string();4]
                && Instant::now()<end,"installed_github_boundary_identity")?;
            while Instant::now()<end && !*stop.borrow() {
                let source=if case==Case::DnsDeadline {
                    let progress=self.progress.as_ref().ok_or("installed_github_boundary_progress")?;let arrivals=lock(progress);
                    require(!arrivals.invalid,"installed_github_boundary_progress")?;
                    let Some((source,at))=arrivals.installed_first_dns.as_ref() else {
                        drop(arrivals);std::thread::sleep(Duration::from_millis(1));continue;
                    };
                    require(*at<end && installed_dns_source(source).is_some(),"installed_github_boundary_progress")?;
                    Some(source.clone())
                } else{None};
                let before=original_socket_fds(id,end)?;
                let mut rows=Vec::new();
                let tables:&[(&str,bool,&'static str)]=if case==Case::DnsDeadline{&[("udp",false,"udp")]}
                    else{&[("tcp",false,"tcp"),("tcp6",true,"tcp")]};
                for (table,ipv6,protocol) in tables {
                    let raw=proc_bytes(&format!("/proc/{id}/net/{table}"),1<<20)?;
                    rows.extend(socket_rows(&raw,*ipv6,*protocol,&before)?);
                }
                let after=original_socket_fds(id,end)?;
                // A table row alone is never process ownership. Every positive
                // candidate must be the same exact FD/inode before and after.
                if let Some((fd,row))=joined_boundary(case,&rows,&before,&after,source.as_ref(),uid)? {
                    require(Instant::now()<end && !*stop.borrow(),"installed_github_boundary_late")?;
                    let receipt=json!({"kind":if case==Case::DnsDeadline{"normal-dns"}else{"normal-connect"},
                        "childPid":id,"fd":fd,"inode":row.inode.to_string(),"uid":uid,"family":row.family,"protocol":row.protocol,
                        "localAddress":row.local.to_string(),"localPort":row.local_port,
                        "remoteAddress":row.remote.to_string(),"remotePort":row.remote_port,"state":format!("{:02X}",row.state),
                        "originalFdStable":true,"observedBeforeDeadline":true,"peerSource":source});
                    require(lock(&self.boundaries).insert(key,receipt).is_none(),"installed_github_boundary_once")?;
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err("installed_github_boundary_missing")
        }

        pub(in crate::supervisor) fn register(&self,owner:&Arc<Owner>){
            let mut owners=lock(&self.owners);
            if !matches!(owner.profile,Profile::GitHubReadOnly) || owners.len()>=self.case.reads()
                || owners.iter().any(|old|old.key==owner.key){self.failed.store(true,Ordering::SeqCst);return;}
            owners.push(owner.clone());
        }
        pub(in crate::supervisor) fn original_profile(&self, owner:&Arc<Owner>)->Option<RuntimeProfile> {
            (!self.failed.load(Ordering::SeqCst) && lock(&self.owners).iter().any(|original|Arc::ptr_eq(original,owner)))
                .then(||self.case.profile())
        }
        pub(in crate::supervisor) fn observe_settled_io(&self,owner:&Arc<Owner>,resources:&Resources) {
            // Called under the SAME driver resource guard, after its native
            // settlement and before it consumes both real reader DTOs. Retain
            // only positive bounded facts, never another reader or raw output.
            if self.original_profile(owner).is_none() || !resources.write_end.is_some_and(|w|w.complete)
                || resources.writer.is_some() || resources.stdout.is_some() || resources.stderr.is_some()
                || resources.failed_writer.is_some() || resources.failed_stdout.is_some() || resources.failed_stderr.is_some()
                || resources.waited.is_none() || resources.child.is_none()
                || !resources.out_end.as_ref().is_some_and(|r|r.eof&&!r.overflow)
                || !resources.err_end.as_ref().is_some_and(|r|r.eof&&!r.overflow&&r.bytes.is_empty())
                || !lock(&self.io_checked).insert(owner.key) {self.failed.store(true,Ordering::SeqCst);}
        }
        pub(crate) fn attach(self:&Arc<Self>,supervisor:&Supervisor)->Check<()> {
            require(supervisor.can_exit() && !supervisor.disabled() && !supervisor.stopping()
                && lock(&self.owners).is_empty(),"installed_github_witness_setup")?;
            let mut slot=lock(&supervisor.inner.native_test.github);
            require(slot.is_none(),"installed_github_witness_setup")?;*slot=Some(self.clone());Ok(())
        }
        pub(crate) fn inject_unknown(&self,supervisor:&Supervisor)->Check<()> {
            require(self.case==Case::Unknown && !self.unknown_injected.swap(true,Ordering::SeqCst),"installed_github_unknown_once")?;
            let owners=lock(&self.owners).clone();require(owners.len()==1,"installed_github_unknown_owner")?;
            let owner=&owners[0];
            require(lock(&supervisor.inner.owners).get(&owner.key).is_some_and(|o|Arc::ptr_eq(o,owner))
                && owner.github_receipt.as_ref().is_some_and(|r|matches!(*lock(r),GitHubReadReceipt::Pending))
                && !lock(&owner.state).terminal,"installed_github_unknown_pending")?;
            // The ordinary sticky Unknown entry records failure BEFORE STOP.
            // Actual driver/native/management settlement still must follow.
            owner.unknown(&supervisor.inner);
            require(supervisor.disabled() && lock(&owner.state).unknown,"installed_github_unknown_latch")
        }
        pub(crate) fn endpoint(&self)->Option<Instant>{lock(&self.owners).first().map(|o|o.endpoint())}
        pub(crate) async fn observe_retired(&self,supervisor:&Supervisor,end:Instant)->Check<bool>{
            // The existing relay and exit observer can overlap. Serialize their
            // observations of the SAME retained final handle, not another task
            // or replacement join chain. Resample completed rows after entry.
            let _observing=self.observing.lock().await;
            let result=self.observe_retired_inner(supervisor,end).await;
            if result.is_err(){self.failed.store(true,Ordering::SeqCst);}
            result
        }
        async fn observe_retired_inner(&self,_supervisor:&Supervisor,end:Instant)->Check<bool>{
            require(!self.failed.load(Ordering::SeqCst),"installed_github_witness_failed")?;
            let owners=lock(&self.owners).clone();
            let completed=lock(&self.results).len();
            for owner in owners.iter().skip(completed){
                let receipt=owner.github_receipt.as_ref().map(|r|lock(r).clone()).ok_or("installed_github_receipt")?;
                let GitHubReadReceipt::Settled{outcome,settled_at,was_unknown}=receipt else{return Ok(false);};
                let mut observer=owner.observer.lock().await;
                let handle=observer.as_mut().ok_or("installed_github_original_observer")?;
                let joined=tokio::time::timeout_at(end.into(),handle).await.map_err(|_|"installed_github_observer_deadline")?;
                if joined.is_err(){self.failed.store(true,Ordering::SeqCst);return Err("installed_github_observer_join");}
                observer.take();drop(observer);
                let resources=owner.resources.try_lock().map_err(|_|"installed_github_original_resources")?;
                let state=lock(&owner.state);
                require(state.terminal && state.unknown==was_unknown && state.driver_join==ManagementJoin::Returned
                    && state.watchdog_join==ManagementJoin::Returned && matches!(state.watchdog_end,Some(WatchdogEnd::DriverObserved(ManagementJoin::Returned)))
                    && lock(&owner.permit).is_none() && owner.driver.try_lock().is_ok_and(|s|s.is_none())
                    && owner.watchdog.try_lock().is_ok_and(|s|s.is_none()),"installed_github_management_final")?;
                require(resources.inspection_return==Some(ManagementJoin::Returned) && resources.inspection.is_none()
                    && resources.inspection_error.is_none() && resources.acquisition_return==Some(ManagementJoin::Returned)
                    && resources.acquisition.is_none() && resources.acquisition_error.is_none() && resources.child.is_none()
                    && resources.writer.is_none() && resources.stdout.is_none() && resources.stderr.is_none()
                    && resources.failed_writer.is_none() && resources.failed_stdout.is_none() && resources.failed_stderr.is_none()
                    && resources.passive.is_none() && resources.github_readonly.as_ref().is_some_and(|s|lock(s).settled())
                    && resources.native_started && resources.native_settlement.is_none()
                    && matches!(resources.native_return,Some(Ok(CloseOutcome::Settled)))
                    && resources.native_observation.is_none() && resources.native_observation_return==Some(ManagementJoin::Returned)
                    && resources.native_observation_failure.is_none() && resources.native_snapshots.len()==1
                    && installed_native_fixture::snapshot_clear(&resources.native_snapshots[0])
                    && resources.waited.is_some() && resources.write_end.is_some_and(|w|w.complete)
                    && resources.out_end.is_none() && resources.err_end.is_none()
                    && lock(&self.io_checked).contains(&owner.key),"installed_github_native_final")?;
                let reason=match &outcome{
                    Ok(outcome)=>serde_json::to_value(outcome.control.reason).map_err(|_|"installed_github_result")?,
                    Err(error)=>Value::String(error.code.clone()),
                };
                require(outcome_shape(self.case,outcome.is_ok(),reason.as_str(),state.error.as_ref().map(|e|e.code.as_str()))
                    && was_unknown==(self.case==Case::Unknown)
                    && (if self.case.deadline(){settled_at>=state.endpoint && state.error.as_ref().is_some_and(|e|e.code=="query_timeout")}
                        else{settled_at<state.endpoint})
                    && state.cleanup_endpoint.is_some()==(self.case.deadline()||self.case.active_control())
                    && state.cleanup_endpoint.is_none_or(|limit|settled_at<limit),"installed_github_product_result")?;
                if outcome.is_ok(){require(resources.waited.as_ref().is_some_and(ExitStatus::success),"installed_github_product_exit")?;}
                if let Ok(outcome)=&outcome { self.check_projection(outcome)?; }
                let maps=installed_native_fixture::snapshot_value(&resources.native_snapshots[0]);
                let mut value=json!({"operationId":owner.id,"manifestSha256":self.case.manifest(),
                    "receiptKind":if outcome.is_ok(){"typed-outcome"}else{"native-error"},"reason":reason,
                    "terminal":true,"unknownLatched":was_unknown,"firstError":state.error.as_ref().map(|e|e.code.clone()),
                    "originalObserverJoined":true,"nativeSettled":true,"environmentClear":true,"maps":maps,
                    "cleanupWithinOriginalEndpoint":state.cleanup_endpoint.is_none_or(|limit|settled_at<limit),
                    "elapsedMs":settled_at.saturating_duration_since(state.endpoint-OPERATION_TIME).as_millis()});
                if self.case.normal_boundary() {
                    value["boundary"]=lock(&self.boundaries).get(&owner.key).cloned().ok_or("installed_github_boundary_missing")?;
                }
                lock(&self.results).push(value);
            }
            Ok(lock(&self.results).len()==owners.len() && !owners.is_empty())
        }
        fn check_projection(&self,outcome:&crate::github_connection_protocol::GitHubReadOutcome)->Check<()> {
            use crate::github_connection_protocol::{Reason,FactState,Permission,Visibility,Coverage,Presence,WorkflowState};
            require(outcome.facts.schema_version==1 && outcome.control.credential_expires_at.is_none()
                && outcome.control.cooldown_seconds==(if self.case==Case::Rate{Some(120)}else{None})
                && !outcome.control.cooldown_blocked,"installed_github_product_control")?;
            let f=&outcome.facts;
            if outcome.control.reason==Reason::None {
                require(f.account.state==FactState::Observed && f.account.reason==Reason::None
                    && f.account.value.as_ref().is_some_and(|a|a.id=="11"&&a.login=="owner")
                    && f.repository.state==FactState::Observed && f.repository.reason==Reason::None
                    && f.repository.value.as_ref().is_some_and(|r|r.id=="22"&&r.full_name=="owner/app"&&r.default_branch=="main"
                        &&r.visibility==Visibility::Private&&!r.archived&&r.permissions.pull==Permission::ReportedAllowed
                        &&r.permissions.push==Permission::ReportedDenied&&r.permissions.admin==Permission::ReportedDenied)
                    && f.automation.state==FactState::Observed && f.automation.reason==Reason::None
                    && f.automation.value.as_ref().is_some_and(|a|a.coverage==Coverage::Complete&&a.workflows.len()==4
                        &&a.workflows.iter().all(|w|w.presence==Presence::NotListed&&w.remote_id.is_none()&&w.state==WorkflowState::Unknown))
                    && f.account.observed_at.is_some() && f.account.observed_at==f.repository.observed_at
                    && f.account.observed_at==f.automation.observed_at,"installed_github_success_projection")
            } else {
                let identity=self.case==Case::Identity;
                require((if identity {f.account.state==FactState::Observed && f.account.reason==Reason::None
                        && f.account.value.as_ref().is_some_and(|a|a.id=="11"&&a.login=="owner") && f.account.observed_at.is_some()}
                    else{f.account.state==FactState::Unavailable&&f.account.value.is_none()&&f.account.observed_at.is_none()
                        &&f.account.reason==outcome.control.reason})
                    && f.repository.state==FactState::Unavailable && f.repository.value.is_none() && f.repository.observed_at.is_none()
                    && f.repository.reason==outcome.control.reason && f.automation.state==FactState::Unavailable
                    && f.automation.value.is_none() && f.automation.observed_at.is_none()
                    && f.automation.reason==outcome.control.reason,"installed_github_refusal_projection")
            }
        }
        pub(crate) fn complete(&self,supervisor:&Supervisor)->bool {
            !self.failed.load(Ordering::SeqCst) && lock(&self.results).len()==self.case.reads()
                && lock(&self.boundaries).len()==usize::from(self.case.normal_boundary())
                && lock(&self.owners).len()==self.case.reads() && lock(&self.io_checked).len()==self.case.reads() && supervisor.can_exit()
                && supervisor.disabled()==(self.case==Case::Unknown)
                && self.unknown_injected.load(Ordering::SeqCst)==(self.case==Case::Unknown)
        }
        pub(crate) fn evidence(&self)->Vec<Value>{lock(&self.results).clone()}
    }
    fn outcome_shape(case:Case,typed:bool,reason:Option<&str>,first_error:Option<&str>)->bool {
        let native_error=case.deadline()||case.active_control();
        typed!=native_error && reason==Some(case.reason())
            && first_error==native_error.then(||case.reason())
    }
    fn assert_namespace_witness_contracts() {
        let source = "a".repeat(40);
        let service = "mrk-ubuntu-native-10-2.service";
        let cgroup = "/system.slice/mrk-ubuntu-native-10-2.service";
        let valid = json!({"sourceSha":source,"invocationId":"b".repeat(32),
            "unit":{"Id":service,"InvocationID":"b".repeat(32),"ControlGroup":cgroup},
            "runnerUid":1001,"runnerGid":1002,
            "namespaces":{"user":[4,11],"pid":[4,12],"mnt":[4,13]},
            "githubPeerNamespaces":{"user":[4,11],"pid":[4,12],"mnt":[4,13],"net":[4,14]}});
        let decode = |value: &Value| peer_namespace_witness(&serde_json::to_vec(value).unwrap(),
            &source, service, cgroup, 1001, 1002);
        let witness = decode(&valid).unwrap();
        let labels = namespace_labels(&witness, &witness).unwrap();
        assert_eq!(labels.len(), 8);
        assert_eq!(labels["MRK_TLS_PARENT_NETNS"], "net:[14]");
        assert_eq!(labels["MRK_TLS_MNTNS"], "mnt:[13]");
        for (key, value) in [("sourceSha", json!("c".repeat(40))), ("sourceSha", Value::Null),
            ("invocationId", json!("B".repeat(32))), ("invocationId", json!("c".repeat(32))),
            ("runnerUid", json!(1002)), ("runnerGid", json!(1001)), ("runnerUid", json!(0)),
            ("runnerUid", json!(true)), ("runnerGid", json!(1002.0))] {
            let mut invalid = valid.clone(); invalid[key] = value; assert!(decode(&invalid).is_err());
        }
        for (key, value) in [("Id", "mrk-ubuntu-native-11-2.service"), ("InvocationID", "bad"),
            ("ControlGroup", "/system.slice/other.service")] {
            let mut invalid = valid.clone(); invalid["unit"][key] = json!(value); assert!(decode(&invalid).is_err());
        }
        for field in ["namespaces", "githubPeerNamespaces"] {
            for malformed in [json!([0,11]), json!([4,0]), json!([true,11]), json!([4,11.0]),
                json!([4,-1]), json!([4,18446744073709551616.0]), json!([4]), json!([4,11,12]),
                json!(["4",11]), Value::Null] {
                let mut invalid = valid.clone(); invalid[field]["user"] = malformed; assert!(decode(&invalid).is_err());
            }
            let mut missing = valid.clone(); missing[field].as_object_mut().unwrap().remove("user");
            assert!(decode(&missing).is_err());
            let mut extra = valid.clone(); extra[field]["other"] = json!([4,15]); assert!(decode(&extra).is_err());
        }
        let mut mismatch = valid.clone(); mismatch["namespaces"]["mnt"] = json!([4,15]);
        assert!(decode(&mismatch).is_err());
        let raw = serde_json::to_string(&valid).unwrap();
        let duplicate = raw.replace("\"runnerUid\":1001", "\"runnerUid\":1001,\"runnerUid\":1001");
        assert_ne!(duplicate, raw);
        assert!(peer_namespace_witness(duplicate.as_bytes(), &source, service, cgroup, 1001, 1002).is_err());
        for bad_source in ["", "A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaG"] {
            assert!(peer_namespace_witness(raw.as_bytes(), bad_source, service, cgroup, 1001, 1002).is_err());
        }
        assert!(peer_namespace_witness(raw.as_bytes(), &source, service, cgroup, 0, 1002).is_err());
        assert!(peer_namespace_witness(raw.as_bytes(), &source, service, "/system.slice/other.service", 1001, 1002).is_err());
        for role in ["user", "pid", "mnt", "net"] {
            let mut other = witness.clone(); other.insert(role, (4,99));
            assert!(namespace_labels(&witness, &other).is_err());
            other.remove(role); assert!(namespace_labels(&witness, &other).is_err());
        }
        let mut extra = witness.clone(); extra.insert("other", (4,99));
        assert!(namespace_labels(&witness, &extra).is_err());
    }
    pub(crate) fn assert_contracts() {
        // Inert DATA only: real command/peer execution is a separate gate.
        assert_namespace_witness_contracts();
        let mut names=std::collections::BTreeSet::new();
        for case in Case::ALL {
            assert!(names.insert(case.name()));
            assert_eq!(Case::parse(std::ffi::OsStr::new(case.name())),Some(case));
            assert_eq!(case.script().is_none(),case.no_peer());
            assert_eq!(case.manifest()==N,case==Case::NormalNegative||case.normal_boundary());
            let native_error=case.deadline()||case.active_control();
            let first_error=native_error.then(||case.reason());
            assert!(outcome_shape(case,!native_error,Some(case.reason()),first_error));
            assert!(!outcome_shape(case,native_error,Some(case.reason()),first_error));
            assert!(!outcome_shape(case,!native_error,Some(case.reason()),Some("io_error")));
        }
        assert_eq!(Case::Identity.connections(),4);
        assert_eq!(Case::ConnectRefresh.connections(),8);
        assert_eq!(Case::ConnectRefresh.reads(),2);
        assert_eq!(Case::HeaderDeadline.script(),Some("G-header-withhold"));
        assert_eq!(Case::AmbientNoRescue.profile(),RuntimeProfile::DialRealCa);
        assert!(Case::parse(std::ffi::OsStr::new("github-connect-refresh-extra")).is_none());
        let progress=json!({"schemaVersion":1,"scope":"github-installed-tls-peer-v1","case":"T5-read",
            "state":"progress","event":"first-get","sequence":1,"requests":1,"bodyBytes":0,
            "wireReadBytes":1000,"wireWriteBytes":1000,"dnsQuestions":0,"dnsA":0,"dnsAAAA":0,"clientStop":null});
        assert!(installed_first_get_frame(&progress));
        for (name,value) in [("scope",json!("github-tls-peer-v1")),("sequence",json!(2)),("requests",json!(2)),
            ("bodyBytes",json!(1)),("wireReadBytes",json!(0)),("clientStop",json!("tcp-eof")),("extra",json!(true))] {
            let mut invalid=progress.clone();invalid[name]=value;assert!(!installed_first_get_frame(&invalid));
        }
        let at=Instant::now();let mut bytes=b"{\"state\":\"ready\"}\n".to_vec();
        let mut arrivals=Arrivals::default();arrivals.observe(&bytes,0,at);
        let previous=bytes.len();bytes.extend(serde_json::to_vec(&progress).unwrap());
        arrivals.observe(&bytes,previous,at);assert!(arrivals.installed_first_get.is_none());
        let previous=bytes.len();bytes.push(b'\n');arrivals.observe(&bytes,previous,at);
        assert_eq!(arrivals.installed_first_get,Some(at));assert!(!arrivals.invalid);
        let previous=bytes.len();bytes.extend(serde_json::to_vec(&progress).unwrap());bytes.push(b'\n');
        arrivals.observe(&bytes,previous,at);assert!(arrivals.invalid); // Duplicate cannot authorize active controls.

        let dns_source=json!({"address":"127.0.0.7","port":32123,"questionId":19,"questionType":1});
        let dns_progress=json!({"schemaVersion":1,"scope":"github-installed-tls-peer-v1","case":"G-dns-withhold",
            "state":"progress","event":"dns-question","sequence":1,"requests":0,"bodyBytes":0,"wireReadBytes":0,"wireWriteBytes":0,
            "dnsQuestions":1,"dnsA":1,"dnsAAAA":0,"clientStop":null,"dnsSource":dns_source});
        assert!(installed_dns_progress_frame(&dns_progress));
        for (field,value) in [("state",json!("ready")),("state",json!("finished")),("event",json!("other")),
            ("scope",json!("github-tls-peer-v1")),("case",json!("T5-dns")),
            ("sequence",json!(2)),("wireWriteBytes",json!(1)),("dnsQuestions",json!(0)),
            ("dnsAAAA",json!(1)),("clientStop",json!("tcp-eof")),("extra",json!(true))] {
            let mut invalid=dns_progress.clone();invalid[field]=value;assert!(!installed_dns_progress_frame(&invalid));
        }
        for (field,value) in [("address",json!("127.000.0.7")),("address",json!("192.0.2.1")),("port",json!(0)),
            ("questionId",json!(65536)),("questionType",json!(15)),("extra",json!(false))] {
            let mut invalid=dns_source.clone();invalid[field]=value;assert!(installed_dns_source(&invalid).is_none());
        }
        // Actual installed ready/finished shapes share the case and scope with
        // progress. They must not be mistaken for its early rendezvous.
        let dns_ready=json!({"schemaVersion":1,"scope":"github-installed-tls-peer-v1","case":"G-dns-withhold",
            "state":"ready","installedCase":"github-dns-deadline","ownerTag":"0123456789abcdef",
            "manifestSha256":N,"peerSha256":PEER_SHA,"primaryPort":18553});
        let dns_finished=json!({"schemaVersion":1,"scope":"github-installed-tls-peer-v1","case":"G-dns-withhold",
            "installedCase":"github-dns-deadline","ownerTag":"0123456789abcdef",
            "manifestSha256":N,"peerSha256":PEER_SHA,"primaryPort":18553,"state":"finished","status":"passed","code":null,
            "connections":0,"handshakes":0,"requests":0,"decryptedBytes":0,"authBytes":0,"closeNotify":0,"tlsRefused":false,
            "wireReadBytes":[],"wireWriteBytes":[],"replyBytes":[],"allSocketsClosed":true,
            "completion":{"bytes":1,"eof":true,"closed":true,"primaryEmpty":null,"primaryUnexpected":0,
                "primaryClosed":null,"proxy":null,"dnsEmpty":true,"dnsClosed":true},
            "sni":0,"phase":"dns","withheldWireBytes":0,"bodyBytes":0,"incompleteBody":false,"clientStop":null,
            "progressCount":1,"dnsQuestions":1,"dnsA":1,"dnsAAAA":0,"dnsReplies":0,"dnsSource":dns_source});
        assert!(!installed_dns_progress_frame(&dns_ready));
        assert!(!installed_dns_progress_frame(&dns_finished));
        let mut ready_bytes=serde_json::to_vec(&dns_ready).unwrap();ready_bytes.push(b'\n');
        assert!(bound_ready(&ready_bytes[..ready_bytes.len()-1],"G-dns-withhold",Some(&dns_ready)));
        let mut arrivals=Arrivals::default();let mut bytes=ready_bytes.clone();arrivals.observe(&bytes,0,at);
        assert!(!arrivals.invalid);assert!(arrivals.installed_first_dns.is_none());
        let previous=bytes.len();bytes.extend(serde_json::to_vec(&dns_progress).unwrap());
        arrivals.observe(&bytes,previous,at);
        assert!(!arrivals.invalid);assert!(arrivals.installed_first_dns.is_none()); // No LF yet.
        let dns_at=at+Duration::from_millis(1);let previous=bytes.len();bytes.push(b'\n');
        arrivals.observe(&bytes,previous,dns_at);assert!(!arrivals.invalid);
        assert_eq!(arrivals.installed_first_dns,Some((dns_source.clone(),dns_at)));
        let finished_start=bytes.len();bytes.extend(serde_json::to_vec(&dns_finished).unwrap());bytes.push(b'\n');
        arrivals.observe(&bytes,finished_start,dns_at+Duration::from_millis(1));
        assert!(!arrivals.invalid);assert_eq!(arrivals.frames.len(),3);
        assert_eq!(arrivals.installed_first_dns,Some((dns_source.clone(),dns_at)));
        let mut coalesced=Arrivals::default();coalesced.observe(&bytes,0,dns_at);
        assert!(!coalesced.invalid);assert_eq!(coalesced.frames.len(),3);
        assert_eq!(coalesced.installed_first_dns,Some((dns_source.clone(),dns_at)));
        let mut duplicate=Arrivals::default();let mut repeated=bytes[..finished_start].to_vec();
        duplicate.observe(&repeated,0,dns_at);
        let previous=repeated.len();repeated.extend(serde_json::to_vec(&dns_progress).unwrap());repeated.push(b'\n');
        duplicate.observe(&repeated,previous,dns_at);assert!(duplicate.invalid);
        assert_eq!(duplicate.installed_first_dns,Some((dns_source.clone(),dns_at)));
        let mut missing_ready=Arrivals::default();let mut only_progress=serde_json::to_vec(&dns_progress).unwrap();
        only_progress.push(b'\n');missing_ready.observe(&only_progress,0,dns_at);
        assert!(missing_ready.invalid);assert!(missing_ready.installed_first_dns.is_none());
        assert_eq!(socket_endpoint("0700007F:7D7B",false).unwrap(),("127.0.0.7".parse().unwrap(),32123));
        assert_eq!(socket_endpoint("00000000000000000000000001000000:01BB",true).unwrap(),("::1".parse().unwrap(),443));
        assert!(socket_endpoint("0700007F:10000",false).is_err());
        let owned=BTreeMap::from([(9,123u64)]);
        let udp=b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
 0: 0700007F:7D7B 3500007F:0035 01 00000000:00000000 00:00000000 00000000 1001 0 123 2 0 0\n\
 1: 0700007F:7D7B 3500007F:0035 01 00000000:00000000 00:00000000 00000000 1001 0 456 2 0 0\n";
        let rows=socket_rows(udp,false,"udp",&owned).unwrap();assert_eq!(rows.len(),1);
        assert!(joined_boundary(Case::DnsDeadline,&rows,&owned,&owned,Some(&dns_source),1001).unwrap().is_some());
        assert!(joined_boundary(Case::DnsDeadline,&rows,&owned,&BTreeMap::from([(9,456)]),Some(&dns_source),1001).unwrap().is_none());
        let duplicated=BTreeMap::from([(9,123),(10,123)]);
        assert!(joined_boundary(Case::DnsDeadline,&rows,&duplicated,&duplicated,Some(&dns_source),1001).is_err());
        let other=BTreeMap::from([(9,456)]);
        assert!(joined_boundary(Case::DnsDeadline,&rows,&other,&other,Some(&dns_source),1001).unwrap().is_none());
        let dns=rows[0].clone();assert!(boundary_matches(Case::DnsDeadline,&dns,Some(&dns_source),1001));
        assert!(!boundary_matches(Case::DnsDeadline,&dns,Some(&dns_source),1002));
        assert!(socket_rows(udp,false,"udp",&BTreeMap::from([(9,789u64)])).unwrap().is_empty());
        for changed in [SocketRow{remote_port:18553,..dns.clone()},SocketRow{state:2,..dns.clone()},
            SocketRow{local_port:32124,..dns.clone()},SocketRow{local:"0.0.0.0".parse().unwrap(),..dns.clone()}] {
            assert!(!boundary_matches(Case::DnsDeadline,&changed,Some(&dns_source),1001));
        }
        let unconnected=SocketRow{remote:"0.0.0.0".parse().unwrap(),remote_port:0,state:7,..dns.clone()};
        assert!(boundary_matches(Case::DnsDeadline,&unconnected,Some(&dns_source),1001));
        let connect=SocketRow{protocol:"tcp",local:"10.0.0.2".parse().unwrap(),remote:"140.82.112.6".parse().unwrap(),
            remote_port:443,state:2,..dns};
        assert!(boundary_matches(Case::ConnectDeadline,&connect,None,1001));
        for changed in [SocketRow{state:1,..connect.clone()},SocketRow{remote_port:18443,..connect.clone()},
            SocketRow{remote:"127.0.0.1".parse().unwrap(),..connect.clone()},SocketRow{uid:1002,..connect.clone()}] {
            assert!(!boundary_matches(Case::ConnectDeadline,&changed,None,1001));
        }
        assert!(!boundary_matches(Case::ConnectDeadline,&connect,Some(&dns_source),1001));
        assert_eq!(Case::DnsDeadline.profile(),RuntimeProfile::Normal);
        assert_eq!(Case::ConnectDeadline.profile(),RuntimeProfile::Normal);
        assert_eq!(Case::DnsDeadline.script(),Some("G-dns-withhold"));
        assert!(!Case::DnsDeadline.no_peer() && Case::ConnectDeadline.no_peer());
        assert!(Case::DnsDeadline.deadline() && Case::ConnectDeadline.deadline());
        assert_eq!(Case::DnsDeadline.connections(),0);
        assert_eq!(Case::ConnectDeadline.connections(),0);

        installed_native_fixture::assert_github_observation_roles();
    }
}
