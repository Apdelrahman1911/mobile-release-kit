//! Fixed Installer Parent namespace and private copier protocol. Not registered
//! until the executing Source, SELF signer and sole child route are joined.
//! A record is recovery DATA, never evidence that an old process closed.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const RECORD_LIMIT: usize = 4096;
const PRIVATE_LIMIT: usize = 4096;
const NS_SLOTS: usize = 10;
const CHILD_FDS: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Clock,
    Access,
    Bounds,
    State,
    Binding,
    Present,
    Read,
    Write,
    Sync,
    Close,
    Child,
    Unknown,
}
type Result<T> = std::result::Result<T, Failure>;

// Diagnostic DATA only: no field participates in admission, clocks or finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Input,
    Source,
    SelfCheck,
    Carrier,
    Selection,
    SourceApple,
    StagedApple,
    FinalApple,
    Facts,
    Census,
    Copy,
    Record,
    RetireTree,
    Current,
    SourcePost,
    FilesSettle,
    SourceSettle,
    LoansSettle,
    Reply,
    EndpointSettle,
    Namespace,
    Reservation,
    Child,
    Publication,
    NamespaceSettle,
    Finality,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiagnosticScope {
    Public,
    Child,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Diagnostic {
    pub(crate) stage: Stage,
    pub(crate) failure: Failure,
}
impl Diagnostic {
    pub(crate) fn line(self, scope: DiagnosticScope) -> String {
        let scope = match scope {
            DiagnosticScope::Public => "public",
            DiagnosticScope::Child => "child",
        };
        let stage = match self.stage {
            Stage::Input => "input",
            Stage::Source => "source",
            Stage::SelfCheck => "self",
            Stage::Carrier => "carrier",
            Stage::Selection => "selection",
            Stage::SourceApple => "source-apple",
            Stage::StagedApple => "staged-apple",
            Stage::FinalApple => "final-apple",
            Stage::Facts => "facts",
            Stage::Census => "census",
            Stage::Copy => "copy",
            Stage::Record => "record",
            Stage::RetireTree => "retire-tree",
            Stage::Current => "current",
            Stage::SourcePost => "source-post",
            Stage::FilesSettle => "files-settle",
            Stage::SourceSettle => "source-settle",
            Stage::LoansSettle => "loans-settle",
            Stage::Reply => "reply",
            Stage::EndpointSettle => "endpoint-settle",
            Stage::Namespace => "namespace",
            Stage::Reservation => "reservation",
            Stage::Child => "child",
            Stage::Publication => "publication",
            Stage::NamespaceSettle => "namespace-settle",
            Stage::Finality => "finality",
        };
        let failure = match self.failure {
            Failure::Clock => "clock",
            Failure::Access => "access",
            Failure::Bounds => "bounds",
            Failure::State => "state",
            Failure::Binding => "binding",
            Failure::Present => "present",
            Failure::Read => "read",
            Failure::Write => "write",
            Failure::Sync => "sync",
            Failure::Close => "close",
            Failure::Child => "child",
            Failure::Unknown => "unknown",
        };
        format!("MRK_XCODE_SETUP_REFUSED=scope={scope};stage={stage};reason={failure}\n")
    }
}
#[derive(Clone, Copy)]
struct Trace {
    stage: Stage,
    first: Option<Diagnostic>,
}
impl Trace {
    fn new(stage: Stage) -> Self {
        Self { stage, first: None }
    }
    fn at(&mut self, stage: Stage) {
        self.stage = stage;
    }
    fn note(&mut self, failure: Failure) {
        self.first.get_or_insert(Diagnostic {
            stage: self.stage,
            failure,
        });
    }
    fn record<T>(&mut self, result: &Result<T>) {
        if let Err(failure) = result {
            self.note(*failure);
        }
    }
    fn refused(&mut self, refused: bool, failure: Failure) {
        if refused {
            self.note(failure);
        }
    }
    fn fallback(&mut self, refused: bool) {
        if refused && self.first.is_none() {
            self.at(Stage::Finality);
            self.note(Failure::Unknown);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupOutcome {
    Prepared,
    NeedsRerun,
    CarrierChecked,
}
pub(crate) struct CallResult {
    pub(crate) diagnostic: Option<Diagnostic>,
    pub(crate) outcome: Option<SetupOutcome>,
    pub(crate) first_failure: Option<Instant>,
    pub(crate) unknown: bool,
    pub(crate) settled: bool,
    pub(crate) safe_to_settle_source: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Current {
    Fresh,
    Pending,
    Attempt,
    Final,
    FinalAttempt,
    FinalPending,
}
impl Current {
    fn observed(final_present: bool, pending: bool, attempt: bool) -> Result<Self> {
        match (final_present, pending, attempt) {
            (false, false, false) => Ok(Self::Fresh),
            (false, true, true) => Ok(Self::Pending),
            (false, false, true) => Ok(Self::Attempt),
            (true, false, false) => Ok(Self::Final),
            (true, false, true) => Ok(Self::FinalAttempt),
            (true, true, true) => Ok(Self::FinalPending),
            _ => Err(Failure::Binding),
        }
    }
    fn has_final(self) -> bool {
        matches!(self, Self::Final | Self::FinalAttempt | Self::FinalPending)
    }
    fn has_pending(self) -> bool {
        matches!(self, Self::Pending | Self::FinalPending)
    }
    fn has_attempt(self) -> bool {
        !matches!(self, Self::Fresh | Self::Final)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    device: u64,
    inode: u64,
}
impl Node {
    fn valid(self) -> bool {
        self.device > 0 && self.inode > 0
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reserved {
    id: String,
    kind: String,
    namespace: Node,
    pending: Node,
    staged: Node,
    source_sha256: String,
    version: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Copied {
    id: String,
    kind: String,
    staged: Node,
    tree_sha256: String,
    version: u32,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Exactly two possible appends, on one original0600 file. Canonical field
/// order is this closed schema's serialization order; LF is part of the record.
/// No third line, duplicate field, whitespace alternative or incomplete line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    reserved: Reserved,
    copied: Option<Copied>,
}
impl Record {
    fn reserved(
        id: String,
        namespace: Node,
        pending: Node,
        staged: Node,
        source_sha256: String,
    ) -> Result<Self> {
        let out = Self {
            reserved: Reserved {
                id,
                kind: "reserved".into(),
                namespace,
                pending,
                staged,
                source_sha256,
                version: 1,
            },
            copied: None,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        let r = &self.reserved;
        if !hex(&r.id, 32)
            || r.kind != "reserved"
            || r.version != 1
            || !r.namespace.valid()
            || !r.pending.valid()
            || !r.staged.valid()
            || r.namespace.device != r.pending.device
            || r.namespace.device != r.staged.device
            || r.pending == r.namespace
            || r.staged == r.pending
            || r.staged == r.namespace
            || !hex(&r.source_sha256, 64)
        {
            return Err(Failure::Binding);
        }
        if let Some(c) = &self.copied {
            if c.id != r.id
                || c.kind != "copied"
                || c.version != 1
                || !c.staged.valid()
                || c.staged != r.staged
                || !hex(&c.tree_sha256, 64)
            {
                return Err(Failure::Binding);
            }
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(&self.reserved).map_err(|_| Failure::Bounds)?;
        bytes.push(b'\n');
        if let Some(c) = &self.copied {
            bytes.extend(serde_json::to_vec(c).map_err(|_| Failure::Bounds)?);
            bytes.push(b'\n');
        }
        if bytes.len() > RECORD_LIMIT {
            return Err(Failure::Bounds);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > RECORD_LIMIT || bytes.last() != Some(&b'\n') {
            return Err(Failure::Bounds);
        }
        let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
        let reserved = serde_json::from_slice(lines.next().ok_or(Failure::State)?)
            .map_err(|_| Failure::Binding)?;
        let copied = lines
            .next()
            .map(|line| serde_json::from_slice(line).map_err(|_| Failure::Binding))
            .transpose()?;
        if lines.next().is_some() {
            return Err(Failure::State);
        }
        let out = Self { reserved, copied };
        out.validate()?;
        if out.encode()? != bytes {
            return Err(Failure::Binding);
        }
        Ok(out)
    }
    fn binds_originals(&self, namespace: Node, pending: Node, source_sha256: &str) -> bool {
        self.validate().is_ok()
            && self.reserved.namespace == namespace
            && self.reserved.pending == pending
            && self.reserved.source_sha256 == source_sha256
    }
    fn binds_current(
        &self,
        namespace: Node,
        source_sha256: &str,
        final_node: Option<Node>,
        pending: Option<Node>,
    ) -> bool {
        self.validate().is_ok()
            && self.reserved.namespace == namespace
            && self.reserved.source_sha256 == source_sha256
            && final_node.is_none_or(|node| self.copied.is_some() && node == self.reserved.staged)
            && pending.is_none_or(|node| node == self.reserved.pending)
    }
    fn add_copied(&mut self, staged: Node, tree_sha256: String) -> Result<()> {
        if self.copied.is_some() {
            return Err(Failure::State);
        }
        let next = Copied {
            id: self.reserved.id.clone(),
            kind: "copied".into(),
            staged,
            tree_sha256,
            version: 1,
        };
        let mut proposed = self.clone();
        proposed.copied = Some(next);
        proposed.validate()?;
        *self = proposed;
        Ok(())
    }
}

/// The actual child tail is entered once. Losing wait custody is sticky;
/// a numeric PID is not a grant to signal again during later finalizers.
struct ChildTail {
    entered: bool,
    result: Option<Result<()>>,
    custody: bool,
    term: bool,
    kill: bool,
}
impl ChildTail {
    fn new() -> Self {
        Self {
            entered: false,
            result: None,
            custody: true,
            term: false,
            kill: false,
        }
    }
    fn begin(&mut self) -> bool {
        if self.entered {
            false
        } else {
            self.entered = true;
            true
        }
    }
    fn cached(&self) -> Result<()> {
        self.result.unwrap_or(Err(Failure::Unknown))
    }
    fn lose_wait(&mut self) {
        self.custody = false;
    }
    fn signal(&mut self, now: Instant, hard: Instant, kill: bool) -> bool {
        if !self.entered || self.result.is_some() || !self.custody || now >= hard {
            return false;
        }
        let attempted = if kill { &mut self.kill } else { &mut self.term };
        if *attempted {
            return false;
        }
        *attempted = true;
        true
    }
    fn finish(&mut self, result: Result<()>) -> Result<()> {
        self.result = Some(result);
        result
    }
}
#[derive(Clone, Copy)]
struct Clock {
    work: Instant,
    finish: Instant,
    hard: Instant,
    last: Instant,
    first: Option<Instant>,
    regressed: bool,
}
impl Clock {
    fn new(work: Instant, finish: Instant, hard: Instant) -> Result<Self> {
        let now = Instant::now();
        if !(now < work && work < finish && finish < hard) {
            return Err(Failure::Clock);
        }
        Ok(Self {
            work,
            finish,
            hard,
            last: now,
            first: None,
            regressed: false,
        })
    }
    fn fail(&mut self) {
        self.fail_at(Instant::now());
    }
    fn fail_at(&mut self, at: Instant) {
        let at = self.first.map_or(at, |old| old.min(at));
        self.first = Some(at);
        if let Some(cut) = at.checked_add(Duration::from_secs(120)) {
            self.finish = self.finish.min(cut);
        }
        // Failure contraction also bounds the final process-reap tail. Keeping
        // original H here could otherwise wait almost the whole setup window
        // after the original first-failure cleanup interval had expired.
        if let Some(tail) = self.finish.checked_add(Duration::from_secs(10)) {
            self.hard = self.hard.min(tail);
        }
    }
    /// Merge a subordinate's ORIGINAL first failure before starting any
    /// independent cleanup. A later return cannot buy a fresh 120 seconds.
    fn absorb(&mut self, first: Option<Instant>, failed: bool) {
        if let Some(at) = first {
            self.fail_at(at);
        }
        if failed && self.first.is_none() {
            self.fail();
        }
    }
    fn point(&mut self, cleanup: bool) -> Result<()> {
        let now = Instant::now();
        self.regressed |= now < self.last;
        self.last = self.last.max(now);
        if self.regressed
            || now >= if cleanup { self.finish } else { self.work }
            || (!cleanup && self.first.is_some())
        {
            return Err(Failure::Clock);
        }
        Ok(())
    }
}

/// Child reports are not close authority. Parent must independently observe its
/// own spawned PID's exit, EOF and all own controls consumed before Copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Reserved,
    Running,
    Joined,
    Copied,
    Published,
    Retired,
    Unknown,
}
#[derive(Clone, Copy)]
struct Lifecycle {
    phase: Phase,
    output_complete: bool,
    eof: bool,
    exit_zero: bool,
    controls_closed: bool,
}
impl Lifecycle {
    fn new() -> Self {
        Self {
            phase: Phase::New,
            output_complete: false,
            eof: false,
            exit_zero: false,
            controls_closed: false,
        }
    }
    fn reserve(&mut self) -> Result<()> {
        if self.phase != Phase::New {
            return Err(Failure::State);
        }
        self.phase = Phase::Reserved;
        Ok(())
    }
    fn spawned(&mut self) -> Result<()> {
        if self.phase != Phase::Reserved {
            return Err(Failure::State);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    fn joined(&mut self) -> Result<()> {
        if self.phase != Phase::Running
            || !self.output_complete
            || !self.eof
            || !self.exit_zero
            || !self.controls_closed
        {
            return Err(Failure::Child);
        }
        self.phase = Phase::Joined;
        Ok(())
    }
    fn copied(&mut self) -> Result<()> {
        if self.phase != Phase::Joined {
            return Err(Failure::State);
        }
        self.phase = Phase::Copied;
        Ok(())
    }
    fn published(&mut self) -> Result<()> {
        if self.phase != Phase::Copied {
            return Err(Failure::State);
        }
        self.phase = Phase::Published;
        Ok(())
    }
    fn retired(&mut self) -> Result<()> {
        if self.phase != Phase::Published {
            return Err(Failure::State);
        }
        self.phase = Phase::Retired;
        Ok(())
    }
    fn unknown(&mut self) {
        self.phase = Phase::Unknown;
    }
    fn may_remove_empty_reservation(&self) -> bool {
        self.phase == Phase::Reserved
    }
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
mod native {
    use super::*;
    use crate as abi;
    use crate::{macos_xcode_copy as copy, macos_xcode_setup as profile};
    use nix::{libc, mount::MntFlags, sys::statfs};
    use std::{
        ffi::{CStr, CString},
        os::fd::{AsRawFd, BorrowedFd},
    };
    const ROOT: usize = 0;
    const LIBRARY: usize = 1;
    const NAMESPACE: usize = 2;
    const LOCK: usize = 3;
    const PENDING: usize = 4;
    const ATTEMPT: usize = 5;
    const STAGED: usize = 6;
    #[derive(Clone, Copy)]
    enum Slot {
        Vacant,
        Acquiring,
        Owned(libc::c_int),
        Closed,
        Unknown,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Stat {
        node: Node,
        mode: libc::mode_t,
        uid: u32,
        gid: u32,
        links: libc::nlink_t,
        size: i64,
        flags: u32,
        mt: i64,
        mn: i64,
        ct: i64,
        cn: i64,
    }
    impl Stat {
        fn from(s: libc::stat) -> Result<Self> {
            if s.st_dev <= 0 || s.st_ino == 0 || s.st_size < 0 {
                return Err(Failure::Binding);
            }
            Ok(Self {
                node: Node {
                    device: s.st_dev as u64,
                    inode: s.st_ino,
                },
                mode: s.st_mode,
                uid: s.st_uid,
                gid: s.st_gid,
                links: s.st_nlink,
                size: s.st_size,
                flags: s.st_flags,
                mt: s.st_mtime,
                mn: s.st_mtime_nsec,
                ct: s.st_ctime,
                cn: s.st_ctime_nsec,
            })
        }
        fn directory(self, mode: Option<u16>) -> bool {
            // Apple sys/stat.h: SF_RESTRICTED, SF_NOUNLINK, SF_FIRMLINK.
            // These protection flags occur on real / and /Library originals;
            // they are not permission to alter those ancestors. Managed nodes
            // retain the existing zero-flags policy, including every POST.
            const ANCESTOR_PROTECTION: u32 = 0x00080000 | 0x00100000 | 0x00800000;
            self.mode & libc::S_IFMT == libc::S_IFDIR
                && self.uid == 0
                && self.mode & 0o7022 == 0
                && match mode {
                    None => self.flags & !ANCESTOR_PROTECTION == 0,
                    Some(mode) => self.flags == 0 && self.mode & 0o7777 == mode && self.gid == 0,
                }
        }
        fn created_private(self) -> bool {
            self.mode & libc::S_IFMT == libc::S_IFDIR
                && self.mode & 0o7777 & !0o700 == 0
                && self.uid == 0 && self.gid == 0 && self.flags == 0
        }
        fn sealed_creation(self, actual: Self, named: Self, mode: u16) -> bool {
            self.created_private() && actual == named && actual.directory(Some(mode))
                && self.node == actual.node && self.links == actual.links
                && self.size == actual.size && self.mt == actual.mt && self.mn == actual.mn
                && self.uid == actual.uid && self.gid == actual.gid && self.flags == actual.flags
        }
        fn control(self) -> bool {
            self.mode == (libc::S_IFREG | 0o600)
                && self.uid == 0
                && self.gid == 0
                && self.links == 1
                && self.flags == 0
                && self.size <= RECORD_LIMIT as i64
        }
        /// Parent directory revisions legitimately change only via admitted
        /// own entry effects. All security fields and original identity remain.
        fn same_directory(self, other: Self) -> bool {
            self.node == other.node
                && self.mode == other.mode
                && self.uid == other.uid
                && self.gid == other.gid
                && self.flags == other.flags
        }
    }
    fn c(value: &str) -> Result<CString> {
        CString::new(value).map_err(|_| Failure::Binding)
    }
    fn fstat(fd: BorrowedFd<'_>) -> Result<Stat> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), s.as_mut_ptr()) } != 0 {
            return Err(Failure::Read);
        }
        Stat::from(unsafe { s.assume_init() })
    }
    fn named(parent: BorrowedFd<'_>, name: &CStr) -> Result<Option<Stat>> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                s.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(Failure::Read)
            };
        }
        Ok(Some(Stat::from(unsafe { s.assume_init() })?))
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Purpose {
        Carrier,
        Copy,
        RetirePending,
        ObserveFinal,
        ObserveAttempt,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "purpose", deny_unknown_fields)]
    enum Loans {
        #[serde(rename = "carrier")]
        Carrier { fds: [i32; 2], nodes: [Node; 2] },
        #[serde(rename = "copy")]
        Copy {
            fds: [i32; 7],
            nodes: [Node; 7],
            staged: Node,
        },
        #[serde(rename = "retire-pending")]
        RetirePending {
            fds: [i32; 7],
            nodes: [Node; 7],
            record: Record,
            attempt: Node,
        },
        #[serde(rename = "observe-final")]
        ObserveFinal {
            fds: [i32; 7],
            nodes: [Node; 7],
            record: Option<Record>,
            attempt: Option<Node>,
            pending: Option<Node>,
        },
        #[serde(rename = "observe-attempt")]
        ObserveAttempt {
            fds: [i32; 6],
            nodes: [Node; 6],
            record: Record,
            attempt: Node,
        },
    }
    impl Loans {
        fn fds(&self) -> &[i32] {
            match self {
                Self::Carrier { fds, .. } => fds,
                Self::Copy { fds, .. }
                | Self::RetirePending { fds, .. }
                | Self::ObserveFinal { fds, .. } => fds,
                Self::ObserveAttempt { fds, .. } => fds,
            }
        }
        fn nodes(&self) -> &[Node] {
            match self {
                Self::Carrier { nodes, .. } => nodes,
                Self::Copy { nodes, .. }
                | Self::RetirePending { nodes, .. }
                | Self::ObserveFinal { nodes, .. } => nodes,
                Self::ObserveAttempt { nodes, .. } => nodes,
            }
        }
        fn staged(&self) -> Option<Node> {
            match self {
                Self::Copy { staged, .. } => Some(*staged),
                Self::RetirePending { record, .. } => Some(record.reserved.staged),
                Self::Carrier { .. } | Self::ObserveFinal { .. } | Self::ObserveAttempt { .. } => {
                    None
                }
            }
        }
        fn purpose(&self) -> Purpose {
            match self {
                Self::Carrier { .. } => Purpose::Carrier,
                Self::Copy { .. } => Purpose::Copy,
                Self::RetirePending { .. } => Purpose::RetirePending,
                Self::ObserveFinal { .. } => Purpose::ObserveFinal,
                Self::ObserveAttempt { .. } => Purpose::ObserveAttempt,
            }
        }
        fn copy(fds: [i32; 7], staged: Node) -> Result<Self> {
            if !staged.valid() {
                return Err(Failure::Binding);
            }
            let mut nodes = [Node {
                device: 0,
                inode: 0,
            }; 7];
            for (n, fd) in fds.iter().enumerate() {
                nodes[n] = fstat(unsafe { BorrowedFd::borrow_raw(*fd) })?.node;
            }
            Ok(Self::Copy { fds, nodes, staged })
        }
        fn retirement(&self) -> Option<(Record, Node)> {
            match self {
                Self::RetirePending {
                    record, attempt, ..
                } => Some((record.clone(), *attempt)),
                _ => None,
            }
        }
        fn retire(fds: [i32; 7], record: Record, attempt: Node) -> Result<Self> {
            record.validate()?;
            if !attempt.valid() {
                return Err(Failure::Binding);
            }
            let Self::Copy { fds, nodes, .. } = Self::copy(fds, record.reserved.staged)? else {
                return Err(Failure::State);
            };
            if nodes[2] != record.reserved.namespace || nodes[4] != record.reserved.pending {
                return Err(Failure::Binding);
            }
            Ok(Self::RetirePending {
                fds,
                nodes,
                record,
                attempt,
            })
        }
        fn current(&self) -> Option<(Option<Record>, Option<Node>, Option<Node>)> {
            match self {
                Self::ObserveFinal {
                    record,
                    attempt,
                    pending,
                    ..
                } => Some((record.clone(), *attempt, *pending)),
                Self::ObserveAttempt {
                    record, attempt, ..
                } => Some((Some(record.clone()), Some(*attempt), None)),
                _ => None,
            }
        }
        fn observe(
            fds: [i32; 7],
            record: Option<Record>,
            attempt: Option<Node>,
            pending: Option<Node>,
        ) -> Result<Self> {
            if record.is_some() != attempt.is_some() || pending.is_some() && record.is_none() {
                return Err(Failure::Binding);
            }
            if let Some(r) = record.as_ref() {
                r.validate()?;
            }
            let mut nodes = [Node {
                device: 0,
                inode: 0,
            }; 7];
            for (at, fd) in fds.iter().enumerate() {
                nodes[at] = fstat(unsafe { BorrowedFd::borrow_raw(*fd) })?.node;
            }
            Ok(Self::ObserveFinal {
                fds,
                nodes,
                record,
                attempt,
                pending,
            })
        }
        fn observe_attempt(fds: [i32; 6], record: Record, attempt: Node) -> Result<Self> {
            record.validate()?;
            if !attempt.valid() {
                return Err(Failure::Binding);
            }
            let mut nodes = [Node {
                device: 0,
                inode: 0,
            }; 6];
            for (at, fd) in fds.iter().enumerate() {
                nodes[at] = fstat(unsafe { BorrowedFd::borrow_raw(*fd) })?.node;
            }
            Ok(Self::ObserveAttempt {
                fds,
                nodes,
                record,
                attempt,
            })
        }
        fn carrier(fds: [i32; 2]) -> Result<Self> {
            let mut nodes = [Node {
                device: 0,
                inode: 0,
            }; 2];
            for (n, fd) in fds.iter().enumerate() {
                nodes[n] = fstat(unsafe { BorrowedFd::borrow_raw(*fd) })?.node;
            }
            Ok(Self::Carrier { fds, nodes })
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Start {
        finish_ns: u64,
        hard_ns: u64,
        loans: Loans,
        nonce: String,
        parent: i32,
        version: u32,
        work_ns: u64,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "outcome", deny_unknown_fields)]
    enum Proof {
        #[serde(rename = "carrier-checked")]
        Carrier,
        #[serde(rename = "pending-empty-needs-rerun")]
        PendingEmpty,
        #[serde(rename = "current-final")]
        CurrentFinal,
        #[serde(rename = "attempt-only-needs-rerun")]
        AttemptOnly,
        #[serde(rename = "copied")]
        Copied { staged: Node, tree_sha256: String },
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report {
        nonce: String,
        proof: Proof,
        version: u32,
    }
    fn monotonic() -> Result<u64> {
        let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } != 0 {
            return Err(Failure::Clock);
        }
        let t = unsafe { t.assume_init() };
        if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
            return Err(Failure::Clock);
        }
        (t.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(t.tv_nsec as u64))
            .ok_or(Failure::Clock)
    }
    fn wire_endpoints(clock: &Clock) -> Result<(u64, u64, u64)> {
        // Raw observation BEFORE Instant: adding only the later remaining
        // interval is conservative. Child reverses the bracket, not the budget.
        let raw = monotonic()?;
        let now = Instant::now();
        let endpoint = |end: Instant| -> Result<u64> {
            let left = end
                .checked_duration_since(now)
                .ok_or(Failure::Clock)?
                .as_nanos();
            raw.checked_add(u64::try_from(left).map_err(|_| Failure::Clock)?)
                .ok_or(Failure::Clock)
        };
        Ok((
            endpoint(clock.work)?,
            endpoint(clock.finish)?,
            endpoint(clock.hard)?,
        ))
    }
    fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        // Every caller uses a fixed schema with prebounded scalar fields.
        let bytes = serde_json::to_vec(value).map_err(|_| Failure::Bounds)?;
        if bytes.is_empty() || bytes.len() > PRIVATE_LIMIT {
            return Err(Failure::Bounds);
        }
        let mut out = Vec::with_capacity(PRIVATE_LIMIT + 4);
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
        Ok(out)
    }
    /// Exactly one own child process, one duplex private original. No process
    /// group, retries, arbitrary command callback or second lease acquisition.
    struct Copier {
        pid: libc::pid_t,
        endpoint: Slot,
        clock: Clock,
        reaped: bool,
        exit_zero: bool,
        eof: bool,
        sent: bool,
        request: Vec<u8>,
        incoming: [u8; PRIVATE_LIMIT + 5],
        used: usize,
        nonce: String,
        purpose: Purpose,
        report: Option<Report>,
        unknown: bool,
        tail: ChildTail,
    }
    impl Copier {
        fn spawn(executable: &str, loans: Loans, clock: Clock, nonce: String) -> Result<Self> {
            let purpose = loans.purpose();
            let mut inherited = [-1; 7];
            if !hex(&nonce, 32) || loans.fds().iter().any(|fd| *fd < 3) {
                return Err(Failure::Binding);
            }
            for (n, fd) in loans.fds().iter().enumerate() {
                if loans.fds()[..n].contains(fd) {
                    return Err(Failure::Binding);
                }
                inherited[n] = *fd;
            }
            let (work_ns, finish_ns, hard_ns) = wire_endpoints(&clock)?;
            let request = frame(&Start {
                loans,
                hard_ns,
                finish_ns,
                nonce: nonce.clone(),
                parent: unsafe { libc::getpid() },
                version: 1,
                work_ns,
            })?;
            let path = c(executable)?;
            // Preallocate every child-side byte BEFORE fork. The child makes
            // only async-signal-safe FD/exec syscalls and then immediate _exit.
            let role = c("--private-copier")?;
            let mut sockets = [-1; 2];
            if unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr())
            } != 0
            {
                return Err(Failure::Child);
            }
            let mut own = [Slot::Owned(sockets[0]), Slot::Owned(sockets[1])];
            let mut spawned = 0;
            let prepared = (|| -> Result<Self> {
                for fd in sockets {
                    let no_sigpipe: libc::c_int = 1;
                    if unsafe {
                        libc::setsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_NOSIGPIPE,
                            (&no_sigpipe as *const libc::c_int).cast(),
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        )
                    } != 0
                    {
                        return Err(Failure::Child);
                    }
                    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
                        || unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } != 0
                    {
                        return Err(Failure::Child);
                    }
                }
                let channel = c(&sockets[1].to_string())?;
                let args = [
                    path.as_ptr(),
                    role.as_ptr(),
                    channel.as_ptr(),
                    std::ptr::null(),
                ];
                let e1 = c("PATH=/usr/bin:/bin:/usr/sbin:/sbin")?;
                let e2 = c("LANG=C")?;
                let e3 = c("LC_ALL=C")?;
                let env = [e1.as_ptr(), e2.as_ptr(), e3.as_ptr(), std::ptr::null()];
                if Instant::now() >= clock.work {
                    return Err(Failure::Clock);
                }
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe {
                        if libc::close(sockets[0]) != 0 {
                            libc::_exit(74);
                        }
                        if libc::fcntl(sockets[1], libc::F_SETFD, 0) != 0 {
                            libc::_exit(74);
                        }
                        for fd in inherited {
                            if fd >= 0 && libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                                libc::_exit(74);
                            }
                        }
                        libc::execve(path.as_ptr(), args.as_ptr(), env.as_ptr());
                        libc::_exit(74);
                    }
                }
                if pid < 0 {
                    return Err(Failure::Child);
                }
                spawned = pid;
                // No Drop/implicit close. A failed consumed endpoint cannot
                // be retried; returned owner retains PID and unknown status.
                own[1] = Slot::Unknown;
                let closed = unsafe { libc::close(sockets[1]) } == 0;
                if closed {
                    own[1] = Slot::Closed;
                }
                own[0] = Slot::Closed; // ownership transferred below, not closed
                Ok(Self {
                    pid,
                    endpoint: Slot::Owned(sockets[0]),
                    clock,
                    reaped: false,
                    exit_zero: false,
                    eof: false,
                    sent: false,
                    request,
                    incoming: [0; PRIVATE_LIMIT + 5],
                    used: 0,
                    nonce,
                    purpose,
                    report: None,
                    unknown: !closed,
                    tail: ChildTail::new(),
                })
            })();
            // All fallible allocation/setup precedes successful fork. After
            // fork success we ALWAYS return actual PID owner, even closeerror.
            if prepared.is_err() {
                let mut cleanup_failed = false;
                for cell in &mut own {
                    if let Slot::Owned(fd) = *cell {
                        *cell = Slot::Unknown;
                        if unsafe { libc::close(fd) } == 0 {
                            *cell = Slot::Closed;
                        } else {
                            cleanup_failed = true;
                        }
                    }
                }
                if spawned > 0 || cleanup_failed {
                    return Err(Failure::Unknown);
                }
            }
            prepared
        }
        fn fd(&self) -> Result<i32> {
            match self.endpoint {
                Slot::Owned(fd) => Ok(fd),
                _ => Err(Failure::Unknown),
            }
        }
        fn child_status(&mut self) -> Result<()> {
            if self.reaped {
                return Ok(());
            }
            if !self.tail.custody {
                return Err(Failure::Unknown);
            }
            let mut status = 0;
            let n = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if n == 0 {
                return Ok(());
            }
            if n != self.pid {
                self.tail.lose_wait();
                self.unknown = true;
                return Err(Failure::Unknown);
            }
            self.reaped = true;
            self.exit_zero = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            Ok(())
        }
        fn pump(&mut self) -> Result<()> {
            self.clock.point(false)?;
            if self.unknown {
                return Err(Failure::Unknown);
            }
            let mut offset = 0;
            while !self.sent {
                self.clock.point(false)?;
                let n = unsafe {
                    libc::send(
                        self.fd()?,
                        self.request[offset..].as_ptr().cast(),
                        self.request.len() - offset,
                        0,
                    )
                };
                if n > 0 {
                    offset += n as usize;
                    if offset == self.request.len() {
                        self.sent = true;
                        break;
                    }
                } else if n == 0 {
                    return Err(Failure::Child);
                } else if !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EINTR)
                ) {
                    return Err(Failure::Write);
                }
                self.child_status()?;
                if self.reaped {
                    return Err(Failure::Child);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if unsafe { libc::shutdown(self.fd()?, libc::SHUT_WR) } != 0 {
                return Err(Failure::Write);
            }
            while !self.eof || !self.reaped {
                self.clock.point(false)?;
                if !self.eof {
                    if self.used == self.incoming.len() {
                        return Err(Failure::Bounds);
                    }
                    let n = unsafe {
                        libc::read(
                            self.fd()?,
                            self.incoming[self.used..].as_mut_ptr().cast(),
                            self.incoming.len() - self.used,
                        )
                    };
                    if n > 0 {
                        self.used += n as usize;
                    } else if n == 0 {
                        self.eof = true;
                    } else if !matches!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::EAGAIN) | Some(libc::EINTR)
                    ) {
                        return Err(Failure::Read);
                    }
                }
                self.child_status()?;
                std::thread::sleep(Duration::from_millis(2));
            }
            self.clock.point(false)?;
            if !self.exit_zero || self.used < 5 {
                return Err(Failure::Child);
            }
            let size =
                u32::from_be_bytes(self.incoming[..4].try_into().map_err(|_| Failure::Bounds)?)
                    as usize;
            if size == 0 || size > PRIVATE_LIMIT || size + 4 != self.used {
                return Err(Failure::Bounds);
            }
            let report: Report = serde_json::from_slice(&self.incoming[4..self.used])
                .map_err(|_| Failure::Binding)?;
            if report.version != 1
                || report.nonce != self.nonce
                || !match (&report.proof, self.purpose) {
                    (Proof::Carrier, Purpose::Carrier) => true,
                    (Proof::PendingEmpty, Purpose::RetirePending) => true,
                    (Proof::CurrentFinal, Purpose::ObserveFinal) => true,
                    (Proof::AttemptOnly, Purpose::ObserveAttempt) => true,
                    (
                        Proof::Copied {
                            staged,
                            tree_sha256,
                        },
                        Purpose::Copy,
                    ) => staged.valid() && hex(tree_sha256, 64),
                    _ => false,
                }
                || frame(&report)? != self.incoming[..self.used]
            {
                return Err(Failure::Binding);
            }
            self.report = Some(report);
            Ok(())
        }
        fn close_endpoint(&mut self) -> Result<()> {
            match self.endpoint {
                Slot::Closed => Ok(()),
                Slot::Owned(fd) => {
                    self.clock.point(true)?;
                    self.endpoint = Slot::Unknown;
                    if unsafe { libc::close(fd) } != 0 {
                        self.unknown = true;
                        return Err(Failure::Close);
                    }
                    self.endpoint = Slot::Closed;
                    Ok(())
                }
                _ => {
                    self.unknown = true;
                    Err(Failure::Unknown)
                }
            }
        }
        fn settle(&mut self) -> Result<()> {
            if !self.tail.begin() {
                return self.tail.cached();
            }
            let mut failure = None;
            if !self.reaped {
                let now = Instant::now();
                if now < self.clock.last {
                    self.clock.regressed = true;
                }
                self.clock.last = self.clock.last.max(now);
                if !self.clock.regressed && self.tail.signal(now, self.clock.hard, false) {
                    if unsafe { libc::kill(self.pid, libc::SIGTERM) } != 0 {
                        self.clock.fail();
                        failure = Some(Failure::Unknown);
                    }
                } else {
                    failure = Some(Failure::Unknown);
                }
                let kill_at = now
                    .checked_add(Duration::from_secs(1))
                    .map_or(self.clock.finish, |v| v.min(self.clock.finish));
                while !self.reaped && self.tail.custody && !self.clock.regressed {
                    let now = Instant::now();
                    if now < self.clock.last {
                        self.clock.regressed = true;
                        break;
                    }
                    self.clock.last = now;
                    if now >= self.clock.hard {
                        break;
                    }
                    if now >= kill_at && !self.tail.kill {
                        if self.tail.signal(now, self.clock.hard, true) {
                            if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
                                self.clock.fail();
                                failure.get_or_insert(Failure::Unknown);
                            }
                        } else {
                            failure.get_or_insert(Failure::Unknown);
                            break;
                        }
                    }
                    if let Err(e) = self.child_status() {
                        failure.get_or_insert(e);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                if !self.reaped {
                    self.unknown = true;
                    self.clock.fail();
                    failure.get_or_insert(Failure::Unknown);
                }
            }
            // Independent endpoint consumption remains original-F bounded. A
            // failed wait never permits another signal/close on a later call.
            if let Err(e) = self.close_endpoint() {
                failure.get_or_insert(e);
            }
            if self.unknown {
                failure.get_or_insert(Failure::Unknown);
            }
            self.tail.finish(failure.map_or(Ok(()), Err))
        }
    }

    /// Child adopts only the original private-channel and seven exact loans.
    /// Raw descriptor numbers are nomination DATA until all original path,
    /// parent/UID/channel and immutable-start bindings pass. No callerchosenpath.
    struct ChildAdmission {
        trace: Trace,
        channel: Slot,
        loans: [Slot; 7],
        original: [Option<Stat>; 7],
        clock: Clock,
        parent: i32,
        nonce: String,
        purpose: Purpose,
        staged: Option<Node>,
        retirement: Option<(Record, Node)>,
        current: Option<(Option<Record>, Option<Node>, Option<Node>)>,
        actual_loans: usize,
        unknown: bool,
        admitted: bool,
    }
    impl ChildAdmission {
        fn receive(
            channel: i32,
            trace: &mut Trace,
            diagnostic_hard: &mut Option<Instant>,
        ) -> Result<Self> {
            if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 || channel < 3 {
                return Err(Failure::Access);
            }
            let parent = unsafe { libc::getppid() };
            if parent <= 1 {
                return Err(Failure::Child);
            }
            let mut uid = 1;
            let mut gid = 1;
            if unsafe { libc::getpeereid(channel, &mut uid, &mut gid) } != 0 || uid != 0 || gid != 0
            {
                return Err(Failure::Access);
            }
            // This finite read limit is only pre-admission. Parent already owns
            // originalH. No forward/file work occurs until ORIGINAL clocks parse.
            let limit = Instant::now()
                .checked_add(Duration::from_secs(10))
                .ok_or(Failure::Clock)?;
            let mut bytes = [0u8; PRIVATE_LIMIT + 5];
            let mut used = 0;
            loop {
                if Instant::now() >= limit || unsafe { libc::getppid() } != parent {
                    return Err(Failure::Clock);
                }
                if used == bytes.len() {
                    return Err(Failure::Bounds);
                }
                let n = unsafe {
                    libc::read(
                        channel,
                        bytes[used..].as_mut_ptr().cast(),
                        bytes.len() - used,
                    )
                };
                if n > 0 {
                    used += n as usize;
                } else if n == 0 {
                    break;
                } else if !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EINTR)
                ) {
                    return Err(Failure::Read);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if used < 5 {
                return Err(Failure::Bounds);
            }
            let n =
                u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Failure::Bounds)?) as usize;
            if n == 0 || n > PRIVATE_LIMIT || n + 4 != used {
                return Err(Failure::Bounds);
            }
            let start: Start =
                serde_json::from_slice(&bytes[4..used]).map_err(|_| Failure::Binding)?;
            if frame(&start)? != bytes[..used]
                || start.version != 1
                || start.parent != parent
                || !hex(&start.nonce, 32)
                || start.loans.fds().contains(&channel)
                || start.loans.fds().iter().any(|fd| *fd < 3)
            {
                return Err(Failure::Binding);
            }
            for (at, fd) in start.loans.fds().iter().enumerate() {
                if start.loans.fds()[..at].contains(fd) {
                    return Err(Failure::Binding);
                }
            }
            // Instant sampled BEFORE rawnow, opposite conservative bracket to
            // Parent. No duration is restarted or H inferred from a new W.
            let sampled = Instant::now();
            let raw = monotonic()?;
            if !(raw < start.work_ns
                && start.work_ns < start.finish_ns
                && start.finish_ns < start.hard_ns)
                || start.work_ns - raw > 3_600_000_000_000
                || start.finish_ns - start.work_ns > 120_000_000_000
                || start.hard_ns - start.finish_ns > 10_000_000_000
            {
                return Err(Failure::Clock);
            }
            let endpoint = |end: u64| {
                sampled
                    .checked_add(Duration::from_nanos(end - raw))
                    .ok_or(Failure::Clock)
            };
            let clock = Clock::new(
                endpoint(start.work_ns)?,
                endpoint(start.finish_ns)?,
                endpoint(start.hard_ns)?,
            )?;
            *diagnostic_hard = Some(clock.hard);
            let actual_loans = start.loans.fds().len();
            let purpose = start.loans.purpose();
            let mut slots = [Slot::Vacant; 7];
            for (n, fd) in start.loans.fds().iter().enumerate() {
                slots[n] = Slot::Owned(*fd);
            }
            let mut owner = Self {
                trace: *trace,
                channel: Slot::Owned(channel),
                loans: slots,
                original: [None; 7],
                clock,
                parent,
                nonce: start.nonce,
                purpose,
                staged: start.loans.staged(),
                retirement: start.loans.retirement(),
                current: start.loans.current(),
                actual_loans,
                unknown: false,
                admitted: false,
            };
            let admitted = (|| -> Result<()> {
                for index in 0..actual_loans {
                    let observed = fstat(owner.loan(index)?)?;
                    if observed.node != start.loans.nodes()[index] {
                        return Err(Failure::Binding);
                    }
                    owner.original[index] = Some(observed);
                }
                owner.post()?;
                owner.admitted = true;
                Ok(())
            })();
            trace.record(&admitted);
            if admitted.is_err() {
                owner.clock.fail();
                let closed = owner.settle();
                *diagnostic_hard = Some(owner.clock.hard);
                return if closed.is_err() {
                    Err(Failure::Unknown)
                } else {
                    admitted.map(|_| owner)
                };
            }
            Ok(owner)
        }
        fn loan(&self, index: usize) -> Result<BorrowedFd<'_>> {
            match self.loans.get(index) {
                Some(Slot::Owned(fd)) => Ok(unsafe { BorrowedFd::borrow_raw(*fd) }),
                _ => Err(Failure::Binding),
            }
        }
        fn point(&mut self) -> Result<()> {
            self.clock.point(false)?;
            if unsafe { libc::getppid() } != self.parent {
                return Err(Failure::Child);
            }
            Ok(())
        }
        fn post(&mut self) -> Result<()> {
            self.point()?;
            let names = if self.purpose != Purpose::Carrier {
                [
                    None,
                    Some((0, "Library")),
                    Some((1, "MobileReleaseKitDeveloper")),
                    Some((2, profile::LOCK)),
                    if self.purpose == Purpose::ObserveAttempt {
                        None
                    } else {
                        Some((
                            2,
                            if self.purpose == Purpose::ObserveFinal {
                                profile::APP
                            } else {
                                profile::PENDING
                            },
                        ))
                    },
                    None,
                    None,
                ]
            } else {
                [None; 7]
            };
            for index in 0..self.actual_loans {
                let old = self.original[index].ok_or(Failure::Binding)?;
                let held = fstat(self.loan(index)?)?;
                let stable = if old.mode & libc::S_IFMT == libc::S_IFDIR {
                    old.same_directory(held)
                } else {
                    old == held
                };
                if !stable {
                    return Err(Failure::Binding);
                }
                if let Some((parent, name)) = names[index] {
                    let current = named(self.loan(parent)?, &c(name)?)?.ok_or(Failure::Binding)?;
                    if !(if old.mode & libc::S_IFMT == libc::S_IFDIR {
                        held.same_directory(current)
                    } else {
                        held == current
                    }) {
                        return Err(Failure::Binding);
                    }
                }
                if ((self.purpose != Purpose::Carrier && index < 3)
                    || (self.purpose == Purpose::Carrier && index == 0))
                    && (!held.directory(if self.purpose != Purpose::Carrier && index == 2 {
                        Some(0o755)
                    } else {
                        None
                    }) || self.purpose == Purpose::Carrier && held.flags != 0)
                {
                    return Err(Failure::Access);
                }
                if self.purpose != Purpose::Carrier
                    && index == 3
                    && (!held.control() || held.size != 0)
                {
                    return Err(Failure::Access);
                }
                if !matches!(self.purpose, Purpose::Carrier | Purpose::ObserveAttempt)
                    && index == 4
                    && !held.directory(Some(if self.purpose == Purpose::ObserveFinal {
                        0o555
                    } else {
                        0o700
                    }))
                {
                    return Err(Failure::Access);
                }
                let acl = abi::empty_acl_observed(self.loan(index)?);
                if let Err(error) = acl {
                    if error.free_result != 0 || error.refusal_code.is_none() {
                        self.unknown = true;
                        return Err(Failure::Unknown);
                    }
                    return Err(Failure::Access);
                }
                self.point()?;
            }
            if self.purpose != Purpose::Carrier {
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe { libc::lstat(c("/")?.as_ptr(), stat.as_mut_ptr()) } != 0
                    || !self.original[0]
                        .ok_or(Failure::Binding)?
                        .same_directory(Stat::from(unsafe { stat.assume_init() })?)
                {
                    return Err(Failure::Binding);
                }
            }
            self.point()
        }
        fn bind_source(
            &mut self,
            source: &mut crate::macos_xcode_source::SetupSource,
        ) -> Result<()> {
            self.post()?;
            source.post().map_err(|_| Failure::Binding)?;
            let setup = match self.purpose {
                Purpose::Carrier => 0,
                Purpose::ObserveAttempt => 4,
                _ => 5,
            };
            if fstat(source.setup().map_err(|_| Failure::Binding)?)?
                != self.original[setup].ok_or(Failure::Binding)?
                || fstat(source.image().map_err(|_| Failure::Binding)?)?
                    != self.original[setup + 1].ok_or(Failure::Binding)?
            {
                return Err(Failure::Binding);
            }
            self.point()
        }
        /// Every loan is consumed exactly once independently. No unlock call:
        /// closing THIS inherited description cannot unlock Parent's stillheldOFD.
        fn settle(&mut self) -> Result<()> {
            let mut failed = false;
            for cell in self.loans.iter_mut().rev() {
                if let Slot::Owned(fd) = *cell {
                    if self.clock.point(true).is_err() {
                        self.unknown = true;
                        failed = true;
                        continue;
                    }
                    *cell = Slot::Unknown;
                    if unsafe { libc::close(fd) } == 0 {
                        *cell = Slot::Closed;
                    } else {
                        self.unknown = true;
                        self.clock.fail();
                        failed = true;
                    }
                } else if !matches!(cell, Slot::Closed | Slot::Vacant) {
                    self.unknown = true;
                    failed = true;
                }
            }
            if failed || self.unknown {
                Err(Failure::Unknown)
            } else {
                Ok(())
            }
        }
        fn finish(&mut self, proof: Proof) -> Result<()> {
            self.point()?;
            if !self.admitted
                || self.unknown
                || !self.loans[..self.actual_loans]
                    .iter()
                    .all(|s| matches!(s, Slot::Closed))
                || !match (&proof, self.purpose) {
                    (Proof::Carrier, Purpose::Carrier) => true,
                    (Proof::PendingEmpty, Purpose::RetirePending) => true,
                    (Proof::CurrentFinal, Purpose::ObserveFinal) => true,
                    (Proof::AttemptOnly, Purpose::ObserveAttempt) => true,
                    (
                        Proof::Copied {
                            staged,
                            tree_sha256,
                        },
                        Purpose::Copy,
                    ) => staged.valid() && hex(tree_sha256, 64),
                    _ => false,
                }
            {
                return Err(Failure::State);
            }
            let bytes = frame(&Report {
                nonce: self.nonce.clone(),
                proof,
                version: 1,
            })?;
            let fd = match self.channel {
                Slot::Owned(fd) => fd,
                _ => return Err(Failure::Unknown),
            };
            let mut at = 0;
            while at < bytes.len() {
                self.point()?;
                let n = unsafe { libc::send(fd, bytes[at..].as_ptr().cast(), bytes.len() - at, 0) };
                if n > 0 {
                    at += n as usize;
                } else if n == 0 {
                    return Err(Failure::Write);
                } else if !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EINTR)
                ) {
                    return Err(Failure::Write);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            self.trace.at(Stage::EndpointSettle);
            self.clock.point(true)?;
            self.channel = Slot::Unknown;
            if unsafe { libc::close(fd) } != 0 {
                self.unknown = true;
                return Err(Failure::Close);
            }
            self.channel = Slot::Closed;
            self.point()
        }
    }

    /// Fixed legacy source selection for provisioning ONLY. Managed destination
    /// is never recursively adopted as source, and user paths are not accepted.
    struct SourceSelection {
        applications: usize,
        alias: Option<usize>,
        app: usize,
        name: CString,
        applications_id: copy::Identity,
        alias_id: Option<copy::Identity>,
        app_id: copy::Identity,
        target: Vec<u8>,
        path: std::path::PathBuf,
    }
    impl SourceSelection {
        fn selected(
            root: BorrowedFd<'_>,
            files: &mut crate::macos_xcode_tree::CopierFiles,
            work: &copy::Work,
        ) -> Result<Self> {
            let apps_name = c("Applications")?;
            let apps_id = copy::named(root, &apps_name, work).map_err(|_| Failure::Binding)?;
            let applications = files
                .open_applications(root, apps_id, work)
                .map_err(|_| Failure::Binding)?;
            let raw = files
                .fd(applications)
                .map_err(|_| Failure::Binding)?
                .as_raw_fd();
            let apps = unsafe { BorrowedFd::borrow_raw(raw) };
            let fixed = c(profile::APP)?;
            let selected = copy::named(apps, &fixed, work).map_err(|_| Failure::Binding)?;
            let kind = selected.source_kind().map_err(|_| Failure::Access)?;
            let (alias, alias_id, target, name) = match kind {
                profile::Kind::Directory => (None, None, Vec::new(), fixed),
                profile::Kind::Symlink => {
                    let alias = files
                        .open_source(apps, &fixed, selected, work)
                        .map_err(|_| Failure::Binding)?;
                    let mut bytes = [0u8; 1025];
                    work.point().map_err(|_| Failure::Clock)?;
                    let n = unsafe {
                        libc::readlinkat(
                            apps.as_raw_fd(),
                            fixed.as_ptr(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        )
                    };
                    work.point().map_err(|_| Failure::Clock)?;
                    if !(1..=1024).contains(&n) {
                        return Err(Failure::Bounds);
                    }
                    let target = &bytes[..n as usize];
                    let text = std::str::from_utf8(target).map_err(|_| Failure::Binding)?;
                    // Same exact ios_toolchain::sibling_target SOURCE grammar.
                    // It grants selection DATA only; every actual original below
                    // remains open/named and wholecopy requires Apple signature.
                    let sibling = text.strip_prefix("/Applications/").unwrap_or(text);
                    if sibling == profile::APP
                        || sibling.len() > 255
                        || !sibling.starts_with("Xcode")
                        || !sibling.ends_with(".app")
                        || !sibling
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
                    {
                        return Err(Failure::Binding);
                    }
                    copy::exact(
                        files.fd(alias).map_err(|_| Failure::Binding)?,
                        apps,
                        &fixed,
                        selected,
                        work,
                    )
                    .map_err(|_| Failure::Binding)?;
                    (Some(alias), Some(selected), target.to_vec(), c(sibling)?)
                }
                _ => return Err(Failure::Access),
            };
            let app_id = copy::named(apps, &name, work).map_err(|_| Failure::Binding)?;
            if app_id.source_kind().map_err(|_| Failure::Access)? != profile::Kind::Directory {
                return Err(Failure::Access);
            }
            let app = files
                .open_source(apps, &name, app_id, work)
                .map_err(|_| Failure::Binding)?;
            let path = std::path::Path::new("/Applications")
                .join(name.to_str().map_err(|_| Failure::Binding)?);
            let out = Self {
                applications,
                alias,
                app,
                name,
                applications_id: apps_id,
                alias_id,
                app_id,
                target,
                path,
            };
            out.post(root, files, work)?;
            Ok(out)
        }
        fn post(
            &self,
            root: BorrowedFd<'_>,
            files: &crate::macos_xcode_tree::CopierFiles,
            work: &copy::Work,
        ) -> Result<()> {
            let apps = files.fd(self.applications).map_err(|_| Failure::Binding)?;
            copy::exact(apps, root, &c("Applications")?, self.applications_id, work)
                .map_err(|_| Failure::Binding)?;
            if let Some(index) = self.alias {
                let fixed = c(profile::APP)?;
                copy::exact(
                    files.fd(index).map_err(|_| Failure::Binding)?,
                    apps,
                    &fixed,
                    self.alias_id.ok_or(Failure::Binding)?,
                    work,
                )
                .map_err(|_| Failure::Binding)?;
                let mut bytes = [0u8; 1025];
                work.point().map_err(|_| Failure::Clock)?;
                let n = unsafe {
                    libc::readlinkat(
                        apps.as_raw_fd(),
                        fixed.as_ptr(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                work.point().map_err(|_| Failure::Clock)?;
                if n != self.target.len() as isize || bytes[..self.target.len()] != self.target[..]
                {
                    return Err(Failure::Binding);
                }
            }
            copy::exact(
                files.fd(self.app).map_err(|_| Failure::Binding)?,
                apps,
                &self.name,
                self.app_id,
                work,
            )
            .map_err(|_| Failure::Binding)
        }
    }

    fn source_signed(
        source: &mut crate::macos_xcode_source::SetupSource,
        owner: &mut ChildAdmission,
    ) -> Result<()> {
        owner.trace.at(Stage::SourcePost);
        owner.bind_source(source)?;
        // Real dynamic SELF Security invocation stays in this actual retained
        // child. No synchronous Security call runs in sole unobserved Parent.
        owner.trace.at(Stage::SelfCheck);
        let signed = {
            let path = std::path::Path::new(source.executable().map_err(|_| Failure::Binding)?);
            let mut signer =
                crate::macos_xcode_self::SelfSigner::new(owner.clock.work, owner.clock.finish);
            let observed = signer.verify(
                path,
                source.setup().map_err(|_| Failure::Binding)?,
                source.image().map_err(|_| Failure::Binding)?,
            );
            owner.trace.refused(!observed, Failure::Access);
            owner.clock.absorb(signer.first_failure(), !observed);
            let closed = signer.settle(owner.clock.first);
            owner.trace.refused(!closed, Failure::Close);
            let accepted = observed && closed && signer.accepted();
            owner.trace.refused(!accepted, Failure::Access);
            owner.clock.absorb(signer.first_failure(), !accepted);
            if signer.unknown() {
                owner.unknown = true;
            }
            accepted
        };
        // All borrowed SELF originals above remain actual Source-owned until
        // this independent original Source POST and later consuming settlement.
        owner.trace.at(Stage::SourcePost);
        owner.bind_source(source)?;
        if !signed {
            return Err(Failure::Access);
        }
        Ok(())
    }
    fn carrier_child(owner: &mut ChildAdmission) -> Result<Proof> {
        if owner.purpose != Purpose::Carrier {
            return Err(Failure::State);
        }
        owner.trace.at(Stage::Source);
        let mut source =
            crate::macos_xcode_source::SetupSource::new(owner.clock.work, owner.clock.finish)
                .map_err(|_| Failure::Binding)?;
        let result = (|| -> Result<()> {
            source.admit().map_err(|_| Failure::Binding)?;
            source_signed(&mut source, owner)?;
            owner.trace.at(Stage::Carrier);
            const TEMPLATE: &str =
                include_str!("../../../macos-xcode-setup-inputs/CarrierInfo.plist");
            const VERSION: &str = env!("MRK_XCODE_SETUP_PACKAGE_VERSION");
            if TEMPLATE.len() > 4096
                || TEMPLATE.matches("__MRK_PACKAGE_VERSION__").count() != 1
                || VERSION.len() > 64
                || !VERSION.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            {
                return Err(Failure::Binding);
            }
            let info = TEMPLATE.replacen("__MRK_PACKAGE_VERSION__", VERSION, 1);
            let checked = {
                let mut carrier = crate::macos_xcode_carrier::CarrierPreflight::new(
                    owner.clock.work,
                    owner.clock.finish,
                    source.setup().map_err(|_| Failure::Binding)?,
                )
                .map_err(|_| Failure::Binding)?;
                let admitted = carrier.check(VERSION, info.as_bytes());
                owner.trace.refused(admitted.is_err(), Failure::Access);
                owner
                    .clock
                    .absorb(carrier.first_failure(), admitted.is_err());
                let closed = carrier.settle();
                owner.trace.refused(closed.is_err(), Failure::Close);
                owner.clock.absorb(carrier.first_failure(), closed.is_err());
                // Work failure and positive cleanup are separate. No proof on
                // unknown native/FD settlement, even when receipt bytes match.
                let ok = admitted.is_ok() && closed.is_ok() && carrier.accepted();
                owner.trace.refused(!ok, Failure::Access);
                if closed.is_err() || !carrier.settled() {
                    owner.unknown = true;
                }
                ok
            };
            if !checked {
                return Err(Failure::Access);
            }
            owner.trace.at(Stage::SourcePost);
            source.post().map_err(|_| Failure::Binding)?;
            owner.bind_source(&mut source)?;
            owner.point()
        })();
        owner.trace.record(&result);
        owner.clock.absorb(source.first_failure(), result.is_err());
        owner.trace.at(Stage::SourceSettle);
        let closed = source.settle(owner.clock.first).map_err(|_| Failure::Close);
        owner.trace.refused(closed.is_err(), Failure::Close);
        owner.clock.absorb(source.first_failure(), closed.is_err());
        if !source.settled() {
            owner.unknown = true;
        }
        result?;
        closed?;
        if !source.accepted() {
            return Err(Failure::Binding);
        }
        Ok(Proof::Carrier)
    }
    fn observed_facts(
        app: BorrowedFd<'_>,
        owner: &mut ChildAdmission,
    ) -> Result<crate::macos_xcode_facts::Observed> {
        owner.trace.at(Stage::Facts);
        let mut facts = crate::macos_xcode_facts::Facts::new(owner.clock.work, owner.clock.finish)
            .map_err(|_| Failure::Binding)?;
        let observed = facts.inspect(app);
        owner.trace.refused(observed.is_err(), Failure::Binding);
        owner.clock.absorb(facts.first_failure(), observed.is_err());
        let posted = if observed.is_ok() {
            facts.post()
        } else {
            Err(crate::macos_xcode_facts::Failure::Used)
        };
        owner
            .clock
            .absorb(facts.first_failure(), observed.is_err() || posted.is_err());
        owner.trace.refused(posted.is_err(), Failure::Binding);
        let closed = facts.settle(owner.clock.first);
        owner.trace.refused(closed.is_err(), Failure::Close);
        owner.clock.absorb(facts.first_failure(), closed.is_err());
        if !facts.settled() || facts.unknown() {
            owner.unknown = true;
        }
        if posted.is_err() || closed.is_err() || !facts.accepted() {
            return Err(Failure::Binding);
        }
        observed.map_err(|_| Failure::Binding)
    }
    fn apple_checked(
        role: crate::macos_xcode_apple::Role,
        path: &std::path::Path,
        parent: BorrowedFd<'_>,
        app: BorrowedFd<'_>,
        owner: &mut ChildAdmission,
    ) -> Result<()> {
        owner.trace.at(match role {
            crate::macos_xcode_apple::Role::Source => Stage::SourceApple,
            crate::macos_xcode_apple::Role::Staged => Stage::StagedApple,
            crate::macos_xcode_apple::Role::Final => Stage::FinalApple,
        });
        let mut apple = crate::macos_xcode_apple::Apple::new(owner.clock.work, owner.clock.finish);
        let observed = apple.verify(role, path, parent, app);
        owner.trace.refused(!observed, Failure::Access);
        owner.clock.absorb(apple.first_failure(), !observed);
        let closed = apple.settle(owner.clock.first);
        owner.trace.refused(!closed, Failure::Close);
        owner.clock.absorb(apple.first_failure(), !closed);
        if apple.unknown() {
            owner.unknown = true;
        }
        if !observed || !closed || !apple.accepted() {
            return Err(Failure::Access);
        }
        owner.point()
    }
    fn copy_child_work(owner: &mut ChildAdmission) -> Result<Proof> {
        if owner.purpose != Purpose::Copy || owner.actual_loans != 7 {
            return Err(Failure::State);
        }
        owner.trace.at(Stage::Source);
        let mut source =
            crate::macos_xcode_source::SetupSource::new(owner.clock.work, owner.clock.finish)
                .map_err(|_| Failure::Binding)?;
        let mut files = None;
        let result = (|| -> Result<Proof> {
            source.admit().map_err(|_| Failure::Binding)?;
            source_signed(&mut source, owner)?;
            owner.trace.at(Stage::Record);
            // Copied source/input, all inherited originals including private
            // channel+stdio, and fixed Facts8 reserve are charged BEFORE opens.
            let inherited = owner
                .actual_loans
                .checked_add(1 + 3)
                .and_then(|n| n.checked_add(source.held_count()))
                .and_then(|n| n.checked_add(crate::macos_xcode_facts::OWNED_FDS))
                .ok_or(Failure::Bounds)?;
            if crate::macos_xcode_facts::OWNED_BYTES
                + crate::macos_xcode_self::OWNED_BYTES
                + crate::macos_xcode_apple::OWNED_BYTES
                + profile::NAME_CONTROL_LIMIT as usize
                + 24 * 1024 * 1024
                + 1024 * 1024
                > profile::OWNED_MEMORY_LIMIT
            {
                return Err(Failure::Bounds);
            }
            files = Some(
                crate::macos_xcode_tree::CopierFiles::new(owner.clock.finish, inherited)
                    .map_err(|_| Failure::Bounds)?,
            );
            let files = files.as_mut().ok_or(Failure::State)?;
            let work = copy::Work {
                end: owner.clock.work,
                parent: owner.parent,
            };
            let root_raw = owner.loan(0)?.as_raw_fd();
            let root = unsafe { BorrowedFd::borrow_raw(root_raw) };
            owner.trace.at(Stage::Selection);
            let selection = SourceSelection::selected(root, files, &work)?;
            let apps_raw = files
                .fd(selection.applications)
                .map_err(|_| Failure::Binding)?
                .as_raw_fd();
            let app_raw = files
                .fd(selection.app)
                .map_err(|_| Failure::Binding)?
                .as_raw_fd();
            let apps = unsafe { BorrowedFd::borrow_raw(apps_raw) };
            let app = unsafe { BorrowedFd::borrow_raw(app_raw) };
            apple_checked(
                crate::macos_xcode_apple::Role::Source,
                &selection.path,
                apps,
                app,
                owner,
            )?;
            owner.trace.at(Stage::Selection);
            selection.post(root, files, &work)?;
            let source_facts = observed_facts(app, owner)?;
            owner.trace.at(Stage::Selection);
            selection.post(root, files, &work)?;
            owner.trace.at(Stage::SourcePost);
            owner.bind_source(&mut source)?;
            owner.trace.at(Stage::Census);
            let mut tree = crate::macos_xcode_tree::SourceTree::original(
                app,
                apps,
                &selection.name,
                selection.app_id,
                &work,
            )
            .map_err(|_| Failure::Binding)?;
            let stage_raw = owner.loan(4)?.as_raw_fd();
            let stage = unsafe { BorrowedFd::borrow_raw(stage_raw) };
            let stage_id = copy::fstat(stage, &work).map_err(|_| Failure::Binding)?;
            copy::private_stage(stage_id).map_err(|_| Failure::Access)?;
            let fs = statfs::fstatfs(stage).map_err(|_| Failure::Read)?;
            let unit = u64::try_from(fs.block_size()).map_err(|_| Failure::Bounds)?;
            let census = tree.census(files, unit).map_err(|_| Failure::Binding)?;
            // Actual copy_to repeats full original source admission and exact
            // destination free-space quote immediately before first content.
            owner.point()?;
            owner.post()?;
            owner.trace.at(Stage::Copy);
            let copied = tree
                .copy_to(
                    files,
                    stage,
                    stage_id,
                    owner.staged.ok_or(Failure::Binding)?.device,
                    owner.staged.ok_or(Failure::Binding)?.inode,
                    &census,
                )
                .map_err(|_| Failure::Binding)?;
            let copied_raw = files
                .fd(copied.slot)
                .map_err(|_| Failure::Binding)?
                .as_raw_fd();
            let copied_fd = unsafe { BorrowedFd::borrow_raw(copied_raw) };
            let path =
                std::path::Path::new("/Library/MobileReleaseKitDeveloper/.pending/Xcode.app");
            apple_checked(
                crate::macos_xcode_apple::Role::Staged,
                path,
                stage,
                copied_fd,
                owner,
            )?;
            let copied_facts = observed_facts(copied_fd, owner)?;
            if source_facts != copied_facts {
                return Err(Failure::Binding);
            }
            copy::exact(copied_fd, stage, &c(profile::APP)?, copied.identity, &work)
                .map_err(|_| Failure::Binding)?;
            owner.trace.at(Stage::Census);
            let final_source = tree.census(files, unit).map_err(|_| Failure::Binding)?;
            if final_source.quote != census.quote || final_source.digest != census.digest {
                return Err(Failure::Binding);
            }
            owner.trace.at(Stage::Selection);
            selection.post(root, files, &work)?;
            owner.trace.at(Stage::SourcePost);
            owner.bind_source(&mut source)?;
            owner.point()?;
            Ok(Proof::Copied {
                staged: Node {
                    device: copied.identity.device() as u64,
                    inode: copied.identity.inode(),
                },
                tree_sha256: copied.digest.iter().map(|b| format!("{b:02x}")).collect(),
            })
        })();
        owner.trace.record(&result);
        owner.clock.absorb(source.first_failure(), result.is_err());
        let mut all_closed = true;
        if let Some(files) = files.as_mut() {
            owner.clock.absorb(files.first_failure(), result.is_err());
            if let Some(at) = owner.clock.first {
                files.fail_at(at);
            }
            owner.trace.at(Stage::FilesSettle);
            let files_closed = files.close_all();
            owner.trace.refused(!files_closed, Failure::Close);
            owner.clock.absorb(files.first_failure(), !files_closed);
            if !files_closed {
                owner.unknown = true;
                all_closed = false;
            }
        }
        // SOURCE is consumed independently even when copy/Apple/Facts fails.
        owner.trace.at(Stage::SourceSettle);
        let source_closed = source.settle(owner.clock.first).map_err(|_| Failure::Close);
        owner.trace.record(&source_closed);
        owner
            .clock
            .absorb(source.first_failure(), source_closed.is_err());
        if !source.settled() {
            owner.unknown = true;
            all_closed = false;
        }
        result.and_then(|proof| {
            source_closed?;
            if !all_closed || !source.accepted() || owner.unknown {
                return Err(Failure::Unknown);
            }
            owner.point()?;
            Ok(proof)
        })
    }

    fn retire_child(owner: &mut ChildAdmission) -> Result<Proof> {
        if owner.purpose != Purpose::RetirePending || owner.actual_loans != 7 {
            return Err(Failure::State);
        }
        let (record, attempt) = owner.retirement.clone().ok_or(Failure::Binding)?;
        record.validate()?;
        if record.reserved.id != owner.nonce
            || record.reserved.namespace != owner.original[2].ok_or(Failure::Binding)?.node
            || record.reserved.pending != owner.original[4].ok_or(Failure::Binding)?.node
        {
            return Err(Failure::Binding);
        }
        owner.trace.at(Stage::Source);
        let mut source =
            crate::macos_xcode_source::SetupSource::new(owner.clock.work, owner.clock.finish)
                .map_err(|_| Failure::Binding)?;
        let mut files = None;
        let result = (|| -> Result<Proof> {
            source.admit().map_err(|_| Failure::Binding)?;
            source_signed(&mut source, owner)?;
            owner.trace.at(Stage::Record);
            let hash: String = source
                .image_sha256()
                .map_err(|_| Failure::Binding)?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if hash != record.reserved.source_sha256 {
                return Err(Failure::Binding);
            }
            let inherited = source
                .held_count()
                .checked_add(owner.actual_loans + 1 + 3)
                .ok_or(Failure::Bounds)?;
            files = Some(
                crate::macos_xcode_tree::CopierFiles::new(owner.clock.finish, inherited)
                    .map_err(|_| Failure::Bounds)?,
            );
            let files = files.as_mut().ok_or(Failure::State)?;
            let work = copy::Work {
                end: owner.clock.work,
                parent: owner.parent,
            };
            let namespace_raw = owner.loan(2)?.as_raw_fd();
            let namespace = unsafe { BorrowedFd::borrow_raw(namespace_raw) };
            let pending_raw = owner.loan(4)?.as_raw_fd();
            let pending = unsafe { BorrowedFd::borrow_raw(pending_raw) };
            // No parent nomination alone authorizes deletion: inspect and
            // positively close the exact current protected attempt original.
            let info = named(namespace, &c(profile::ATTEMPT)?)?.ok_or(Failure::Binding)?;
            if !info.control() || info.node != attempt {
                return Err(Failure::Binding);
            }
            let id = copy::named(namespace, &c(profile::ATTEMPT)?, &work)
                .map_err(|_| Failure::Binding)?;
            let bytes = files
                .read_attempt(namespace, id, info.size as usize, &work)
                .map_err(|_| Failure::Binding)?;
            if Record::decode(&bytes)? != record {
                return Err(Failure::Binding);
            }
            owner.trace.at(Stage::FilesSettle);
            if !files.close_all() {
                owner.trace.note(Failure::Close);
                owner.unknown = true;
                return Err(Failure::Unknown);
            }
            owner.trace.at(Stage::SourcePost);
            owner.bind_source(&mut source)?;
            owner.post()?;
            if named(namespace, &c(profile::APP)?)?.is_some() {
                return Err(Failure::Present);
            }
            let pending_id = copy::fstat(pending, &work).map_err(|_| Failure::Binding)?;
            owner.trace.at(Stage::RetireTree);
            files
                .retire_pending(
                    pending,
                    pending_id,
                    record.reserved.staged.device,
                    record.reserved.staged.inode,
                    owner.parent,
                )
                .map_err(|_| Failure::Binding)?;
            // The old operation is still not established. This proves only
            // current cleanup by this fresh original signed helper invocation.
            owner.trace.at(Stage::SourcePost);
            owner.bind_source(&mut source)?;
            Ok(Proof::PendingEmpty)
        })();
        owner.trace.record(&result);
        owner.clock.absorb(source.first_failure(), result.is_err());
        let mut all_closed = true;
        if let Some(files) = files.as_mut() {
            owner.clock.absorb(files.first_failure(), result.is_err());
            if let Some(at) = owner.clock.first {
                files.fail_at(at);
            }
            owner.trace.at(Stage::FilesSettle);
            let files_closed = files.close_all();
            owner.trace.refused(!files_closed, Failure::Close);
            owner.clock.absorb(files.first_failure(), !files_closed);
            if !files_closed {
                all_closed = false;
                owner.unknown = true;
            }
        }
        owner.trace.at(Stage::SourceSettle);
        let source_closed = source.settle(owner.clock.first).map_err(|_| Failure::Close);
        owner.trace.record(&source_closed);
        owner
            .clock
            .absorb(source.first_failure(), source_closed.is_err());
        if !source.settled() {
            all_closed = false;
            owner.unknown = true;
        }
        result.and_then(|proof| {
            source_closed?;
            if !all_closed || owner.unknown || !source.accepted() {
                return Err(Failure::Unknown);
            }
            owner.point()?;
            Ok(proof)
        })
    }

    /// Fixed namespace roster on an already-held original. Only a bounded set
    /// of known names is admitted; no tree/path nomination or directory reopen.
    fn fixed_roster(
        fd: BorrowedFd<'_>,
        expected: &[&str],
        clock: &mut Clock,
        cleanup: bool,
    ) -> Result<()> {
        clock.point(cleanup)?;
        let before = fstat(fd)?;
        if expected.len() > 4 || unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
            return Err(Failure::Bounds);
        }
        let mut seen = [false; 4];
        let mut block = [0u8; 65536];
        loop {
            clock.point(cleanup)?;
            let used = abi::directory_block(fd, &mut block).map_err(|_| Failure::Read)?;
            clock.point(cleanup)?;
            if used == 0 {
                break;
            }
            let mut at = 0;
            while at < used {
                if used - at < 11 {
                    return Err(Failure::Binding);
                }
                let n = usize::from(u16::from_ne_bytes([block[at + 9], block[at + 10]]));
                let end = at
                    .checked_add(11 + n)
                    .filter(|v| *v <= used)
                    .ok_or(Failure::Bounds)?;
                let name = &block[at + 11..end];
                at = end;
                if matches!(name, b"." | b"..") {
                    continue;
                }
                let pos = expected
                    .iter()
                    .position(|v| v.as_bytes() == name)
                    .ok_or(Failure::Present)?;
                if seen[pos] {
                    return Err(Failure::Binding);
                }
                seen[pos] = true;
            }
        }
        if seen[..expected.len()].iter().any(|v| !*v) || fstat(fd)? != before {
            return Err(Failure::Binding);
        }
        clock.point(cleanup)
    }
    fn observe_child(owner: &mut ChildAdmission) -> Result<Proof> {
        let final_view = owner.purpose == Purpose::ObserveFinal;
        if !matches!(
            owner.purpose,
            Purpose::ObserveFinal | Purpose::ObserveAttempt
        ) || owner.actual_loans != if final_view { 7 } else { 6 }
        {
            return Err(Failure::State);
        }
        let (record, attempt, pending) = owner.current.clone().ok_or(Failure::Binding)?;
        if record.is_some() != attempt.is_some()
            || !final_view && (record.is_none() || pending.is_some())
        {
            return Err(Failure::Binding);
        }
        owner.trace.at(Stage::Source);
        let mut source =
            crate::macos_xcode_source::SetupSource::new(owner.clock.work, owner.clock.finish)
                .map_err(|_| Failure::Binding)?;
        let mut files = None;
        let result = (|| -> Result<Proof> {
            source.admit().map_err(|_| Failure::Binding)?;
            source_signed(&mut source, owner)?;
            owner.trace.at(Stage::Record);
            let inherited = owner
                .actual_loans
                .checked_add(1 + 3 + source.held_count())
                .and_then(|n| n.checked_add(crate::macos_xcode_facts::OWNED_FDS))
                .ok_or(Failure::Bounds)?;
            if crate::macos_xcode_facts::OWNED_BYTES
                + crate::macos_xcode_self::OWNED_BYTES
                + crate::macos_xcode_apple::OWNED_BYTES
                + profile::NAME_CONTROL_LIMIT as usize
                + 24 * 1024 * 1024
                + 1024 * 1024
                > profile::OWNED_MEMORY_LIMIT
            {
                return Err(Failure::Bounds);
            }
            files = Some(
                crate::macos_xcode_tree::CopierFiles::new(owner.clock.finish, inherited)
                    .map_err(|_| Failure::Bounds)?,
            );
            let files = files.as_mut().ok_or(Failure::State)?;
            let work = copy::Work {
                end: owner.clock.work,
                parent: owner.parent,
            };
            let ns_raw = owner.loan(2)?.as_raw_fd();
            let ns = unsafe { BorrowedFd::borrow_raw(ns_raw) };
            let source_sha: String = source
                .image_sha256()
                .map_err(|_| Failure::Binding)?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if let Some(r) = record.as_ref() {
                r.validate()?;
                if r.reserved.id != owner.nonce
                    || !r.binds_current(
                        fstat(ns)?.node,
                        &source_sha,
                        if final_view {
                            Some(owner.original[4].ok_or(Failure::Binding)?.node)
                        } else {
                            None
                        },
                        pending,
                    )
                {
                    return Err(Failure::Binding);
                }
                let control = named(ns, c"attempt.json")?.ok_or(Failure::Binding)?;
                if !control.control() || control.node != attempt.ok_or(Failure::Binding)? {
                    return Err(Failure::Binding);
                }
                let id = copy::named(ns, c"attempt.json", &work).map_err(|_| Failure::Binding)?;
                let raw = files
                    .read_attempt(ns, id, r.encode()?.len(), &work)
                    .map_err(|_| Failure::Binding)?;
                if Record::decode(&raw)? != *r {
                    return Err(Failure::Binding);
                }
            } else if named(ns, c"attempt.json")?.is_some() {
                return Err(Failure::Present);
            }
            let present_pending = named(ns, c".pending")?;
            match (pending, present_pending) {
                (None, None) => (),
                (Some(node), Some(id)) if id.node == node && id.directory(Some(0o700)) => (),
                _ => return Err(Failure::Binding),
            }
            let mut names = vec![profile::LOCK];
            if final_view {
                names.push(profile::APP);
            }
            if pending.is_some() {
                names.push(profile::PENDING);
            }
            if record.is_some() {
                names.push(profile::ATTEMPT);
            }
            owner.trace.at(Stage::Current);
            fixed_roster(ns, &names, &mut owner.clock, false)?;
            if final_view {
                let final_raw = owner.loan(4)?.as_raw_fd();
                let app = unsafe { BorrowedFd::borrow_raw(final_raw) };
                let id = copy::fstat(app, &work).map_err(|_| Failure::Binding)?;
                let tree =
                    crate::macos_xcode_tree::SourceTree::original(app, ns, c"Xcode.app", id, &work)
                        .and_then(|v| v.protected())
                        .map_err(|_| Failure::Binding)?;
                let unit = u64::try_from(
                    statfs::fstatfs(app)
                        .map_err(|_| Failure::Read)?
                        .block_size(),
                )
                .map_err(|_| Failure::Bounds)?;
                owner.trace.at(Stage::Census);
                let before = tree.census(files, unit).map_err(|_| Failure::Binding)?;
                apple_checked(
                    crate::macos_xcode_apple::Role::Final,
                    std::path::Path::new("/Library/MobileReleaseKitDeveloper/Xcode.app"),
                    ns,
                    app,
                    owner,
                )?;
                let _facts = observed_facts(app, owner)?;
                owner.trace.at(Stage::Census);
                let after = tree.census(files, unit).map_err(|_| Failure::Binding)?;
                if before != after {
                    return Err(Failure::Binding);
                }
            } else if named(ns, c"Xcode.app")?.is_some() {
                return Err(Failure::Present);
            }
            // Re-read exactly this control after final Apple/tree checks. This
            // does not grant old completion; it binds only current retirement.
            if let Some(r) = record.as_ref() {
                let control = named(ns, c"attempt.json")?.ok_or(Failure::Binding)?;
                if control.node != attempt.ok_or(Failure::Binding)? || !control.control() {
                    return Err(Failure::Binding);
                }
                let id = copy::named(ns, c"attempt.json", &work).map_err(|_| Failure::Binding)?;
                let raw = files
                    .read_attempt(ns, id, r.encode()?.len(), &work)
                    .map_err(|_| Failure::Binding)?;
                if Record::decode(&raw)? != *r {
                    return Err(Failure::Binding);
                }
            }
            owner.trace.at(Stage::Current);
            fixed_roster(ns, &names, &mut owner.clock, false)?;
            if named(ns, c".pending")? != present_pending {
                return Err(Failure::Binding);
            }
            owner.trace.at(Stage::SourcePost);
            owner.bind_source(&mut source)?;
            Ok(if final_view {
                Proof::CurrentFinal
            } else {
                Proof::AttemptOnly
            })
        })();
        owner.trace.record(&result);
        owner.clock.absorb(source.first_failure(), result.is_err());
        let mut known = true;
        if let Some(files) = files.as_mut() {
            owner.clock.absorb(files.first_failure(), result.is_err());
            if let Some(first) = owner.clock.first {
                files.fail_at(first);
            }
            owner.trace.at(Stage::FilesSettle);
            let closed = files.close_all();
            owner.trace.refused(!closed, Failure::Close);
            owner.clock.absorb(files.first_failure(), !closed);
            if !closed {
                known = false;
                owner.unknown = true;
            }
        }
        owner.trace.at(Stage::SourceSettle);
        let closed = source.settle(owner.clock.first);
        owner.trace.refused(closed.is_err(), Failure::Close);
        owner.clock.absorb(source.first_failure(), closed.is_err());
        if !source.settled() {
            known = false;
            owner.unknown = true;
        }
        result.and_then(|proof| {
            if closed.is_err() || !known || !source.accepted() || owner.unknown {
                return Err(Failure::Unknown);
            }
            owner.point()?;
            Ok(proof)
        })
    }

    pub(crate) fn carrier_once(
        source: &mut crate::macos_xcode_source::SetupSource,
        work: Instant,
        finish: Instant,
        hard: Instant,
    ) -> CallResult {
        let mut trace = Trace::new(Stage::SourcePost);
        let mut child = None;
        let mut attempted = false;
        let mut first = source.first_failure();
        let result = (|| -> Result<()> {
            source.post().map_err(|_| Failure::Binding)?;
            let clock = Clock::new(work, finish, hard)?;
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| Failure::Read)?;
            let nonce = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let loans = Loans::carrier([
                source.setup().map_err(|_| Failure::Binding)?.as_raw_fd(),
                source.image().map_err(|_| Failure::Binding)?.as_raw_fd(),
            ])?;
            let executable = source.executable().map_err(|_| Failure::Binding)?;
            trace.at(Stage::Child);
            attempted = true;
            child = Some(Copier::spawn(executable, loans, clock, nonce)?);
            let owner = child.as_mut().ok_or(Failure::State)?;
            let observed = owner.pump();
            owner.clock.absorb(None, observed.is_err());
            trace.record(&observed);
            let closed = owner.settle();
            trace.record(&closed);
            owner.clock.absorb(None, closed.is_err());
            observed?;
            closed?;
            if !owner.reaped
                || !owner.exit_zero
                || !owner.eof
                || !matches!(owner.endpoint, Slot::Closed)
                || owner.unknown
                || !matches!(
                    owner.report.as_ref().map(|r| &r.proof),
                    Some(Proof::Carrier)
                )
            {
                return Err(Failure::Unknown);
            }
            trace.at(Stage::SourcePost);
            source.post().map_err(|_| Failure::Binding)?;
            owner.clock.point(false)
        })();
        trace.record(&result);
        let mut settled = true;
        let mut unknown = false;
        if let Some(owner) = child.as_mut() {
            owner.clock.absorb(source.first_failure(), result.is_err());
            trace.at(Stage::Child);
            let closed = owner.settle();
            trace.record(&closed);
            owner.clock.absorb(None, closed.is_err());
            first = earliest(first, owner.clock.first);
            settled = closed.is_ok();
            unknown = owner.unknown || !owner.reaped;
        } else if attempted {
            settled = false;
            unknown = true;
        }
        first = earliest(first, source.first_failure());
        if result.is_err() {
            first = earliest(first, Some(Instant::now()));
        }
        let safe = child.as_ref().map_or(!attempted, |v| {
            v.reaped && matches!(v.endpoint, Slot::Closed)
        });
        trace.fallback(result.is_err() || !settled || unknown || !safe || first.is_some());
        CallResult {
            diagnostic: trace.first,
            outcome: if result.is_ok() && settled && !unknown && safe && first.is_none() {
                Some(SetupOutcome::CarrierChecked)
            } else {
                None
            },
            first_failure: first,
            unknown,
            settled,
            safe_to_settle_source: safe,
        }
    }
    fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }
    pub(crate) fn setup_once(
        source: &mut crate::macos_xcode_source::SetupSource,
        work: Instant,
        finish: Instant,
        hard: Instant,
    ) -> CallResult {
        let mut trace = Trace::new(Stage::Namespace);
        let mut namespace = match Namespace::new(work, finish, hard, source.held_count()) {
            Ok(v) => v,
            Err(error) => {
                trace.note(error);
                return CallResult {
                    diagnostic: trace.first,
                    outcome: None,
                    first_failure: earliest(source.first_failure(), Some(Instant::now())),
                    unknown: false,
                    settled: true,
                    safe_to_settle_source: true,
                };
            }
        };
        let result = (|| -> Result<SetupOutcome> {
            trace.at(Stage::SourcePost);
            source.post().map_err(|_| Failure::Binding)?;
            trace.at(Stage::Namespace);
            namespace.admit_namespace(false)?;
            match namespace.current.ok_or(Failure::State)? {
                Current::Fresh => {
                    let mut random = [0u8; 16];
                    getrandom::fill(&mut random).map_err(|_| Failure::Read)?;
                    let id = random.iter().map(|b| format!("{b:02x}")).collect();
                    let source_hash = source
                        .image_sha256()
                        .map_err(|_| Failure::Binding)?
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    trace.at(Stage::Reservation);
                    namespace.reserve(id, source_hash)?;
                    trace.at(Stage::Child);
                    namespace.copy_child(source)?;
                    trace.at(Stage::Publication);
                    namespace.publish()?;
                    Ok(SetupOutcome::Prepared)
                }
                Current::Pending => {
                    trace.at(Stage::RetireTree);
                    namespace.retire_interrupted(source)?;
                    Ok(SetupOutcome::NeedsRerun)
                }
                _ => {
                    trace.at(Stage::Current);
                    namespace.observe_current(source)
                }
            }
        })();
        trace.record(&result);
        namespace
            .clock
            .absorb(source.first_failure(), result.is_err());
        if result.is_err() && namespace.life.may_remove_empty_reservation() {
            trace.at(Stage::Reservation);
            let cleanup = namespace.retire_empty_refusal();
            trace.record(&cleanup);
            namespace.clock.absorb(None, cleanup.is_err());
        }
        trace.at(Stage::NamespaceSettle);
        let closed = namespace.settle(namespace.clock.first);
        trace.record(&closed);
        namespace.clock.absorb(None, closed.is_err());
        let safe = namespace.users_joined();
        let settled = closed.is_ok()
            && namespace
                .slots
                .iter()
                .all(|s| matches!(s, Slot::Vacant | Slot::Closed));
        let unknown = namespace.unknown();
        trace.fallback(
            result.is_err() || !settled || !safe || unknown || namespace.clock.first.is_some(),
        );
        CallResult {
            diagnostic: trace.first,
            outcome: if settled && safe && !unknown && namespace.clock.first.is_none() {
                result.ok()
            } else {
                None
            },
            first_failure: namespace.clock.first,
            unknown,
            settled,
            safe_to_settle_source: safe,
        }
    }

    /// Private carrier branch is callable only after actual Source/currentimage
    /// and fixed peer/fd/clock admission. Public bin remains inert until Copy and
    /// recovery are fully joined and reviewed; this is not feature activation.
    fn emit_child(diagnostic: Option<Diagnostic>, hard: Option<Instant>) {
        if let (Some(diagnostic), Some(hard)) = (diagnostic, hard) {
            let line = diagnostic.line(DiagnosticScope::Child);
            if Instant::now() < hard {
                let _ = std::io::Write::write(&mut std::io::stderr().lock(), line.as_bytes());
            }
        }
    }
    pub(crate) fn copier_entry(channel: i32) -> i32 {
        let mut trace = Trace::new(Stage::Input);
        let mut diagnostic_hard = None;
        let mut owner = match ChildAdmission::receive(channel, &mut trace, &mut diagnostic_hard) {
            Ok(v) => v,
            Err(error) => {
                trace.note(error);
                emit_child(trace.first, diagnostic_hard);
                return 74;
            }
        };
        let result = match owner.purpose {
            Purpose::Carrier => carrier_child(&mut owner),
            Purpose::Copy => copy_child_work(&mut owner),
            Purpose::RetirePending => retire_child(&mut owner),
            Purpose::ObserveFinal | Purpose::ObserveAttempt => observe_child(&mut owner),
        };
        owner.trace.record(&result);
        if result.is_err() {
            owner.clock.fail();
        }
        owner.trace.at(Stage::LoansSettle);
        let closed = owner.settle();
        owner.trace.record(&closed);
        let result = match (result, closed) {
            (Ok(proof), Ok(())) => {
                owner.trace.at(Stage::Reply);
                owner.finish(proof)
            }
            _ => Err(Failure::Unknown),
        };
        owner.trace.record(&result);
        // On refusal still consume original private endpoint once under F; no
        // success frame, no implicit Drop closure/late success after deadline.
        if result.is_err() {
            if let Slot::Owned(fd) = owner.channel {
                if owner.clock.point(true).is_ok() {
                    owner.channel = Slot::Unknown;
                    if unsafe { libc::close(fd) } == 0 {
                        owner.channel = Slot::Closed;
                    } else {
                        owner.unknown = true;
                    }
                }
            }
            emit_child(owner.trace.first, Some(owner.clock.hard));
            return 74;
        }
        0
    }

    /// Original table is deliberately small: SetupSource16 + namespace10 +
    /// original child controls4 + three standard I/O originals <=Parent32.
    /// Child must charge all descriptors inherited from this actual table.
    pub(crate) struct Namespace {
        slots: [Slot; NS_SLOTS],
        original: [Option<Stat>; NS_SLOTS],
        clock: Clock,
        unknown: bool,
        locked: bool,
        record: Option<Record>,
        record_bytes: Vec<u8>,
        life: Lifecycle,
        child: Option<Copier>,
        new_namespace: bool,
        new_lock: bool,
        own_pending: bool,
        own_attempt: bool,
        current: Option<Current>,
        spawn_attempted: bool,
    }
    impl Namespace {
        pub(crate) fn new(
            work: Instant,
            finish: Instant,
            hard: Instant,
            actual_source_originals: usize,
        ) -> Result<Self> {
            if actual_source_originals
                .checked_add(NS_SLOTS + CHILD_FDS + 3)
                .is_none_or(|n| n > profile::PARENT_ORIGINAL_LIMIT)
            {
                return Err(Failure::Bounds);
            }
            if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
                return Err(Failure::Access);
            }
            Ok(Self {
                slots: [Slot::Vacant; NS_SLOTS],
                original: [None; NS_SLOTS],
                clock: Clock::new(work, finish, hard)?,
                unknown: false,
                locked: false,
                record: None,
                record_bytes: Vec::with_capacity(RECORD_LIMIT),
                life: Lifecycle::new(),
                child: None,
                new_namespace: false,
                new_lock: false,
                own_pending: false,
                own_attempt: false,
                current: None,
                spawn_attempted: false,
            })
        }
        fn fd(&self, index: usize) -> Result<BorrowedFd<'_>> {
            match self.slots.get(index) {
                Some(Slot::Owned(fd)) => Ok(unsafe { BorrowedFd::borrow_raw(*fd) }),
                _ => Err(Failure::Binding),
            }
        }
        fn point(&mut self, cleanup: bool) -> Result<()> {
            if self.unknown {
                return Err(Failure::Unknown);
            }
            self.clock.point(cleanup)
        }
        fn store(&mut self, index: usize, fd: i32) -> Result<()> {
            self.slots[index] = if fd < 0 {
                Slot::Closed
            } else {
                Slot::Owned(fd)
            };
            if fd < 0 {
                return Err(Failure::Read);
            }
            self.original[index] = Some(fstat(self.fd(index)?)?);
            Ok(())
        }
        fn protect(&mut self, index: usize) -> Result<()> {
            self.point(false)?;
            let before = fstat(self.fd(index)?)?;
            // Policy::Empty distinguishes absent/valid-empty; native uncertain
            // objects are refused, never reinterpreted as absence.
            let checked = abi::empty_acl_observed(self.fd(index)?);
            if let Err(error) = checked {
                if error.free_result != 0 || error.refusal_code.is_none() {
                    self.unknown = true;
                    return Err(Failure::Unknown);
                }
                self.point(false)?;
                return Err(Failure::Access);
            }
            self.point(false)?;
            let fs = statfs::fstatfs(self.fd(index)?).map_err(|_| Failure::Read)?;
            self.point(false)?;
            if fs.filesystem_type_name() != "apfs"
                || !fs.flags().contains(MntFlags::MNT_LOCAL)
                || fs.flags().intersects(
                    MntFlags::MNT_UNION
                        | MntFlags::MNT_AUTOMOUNTED
                        | MntFlags::MNT_IGNORE_OWNERSHIP,
                )
                || fstat(self.fd(index)?)? != before
            {
                return Err(Failure::Access);
            }
            Ok(())
        }
        fn open(&mut self, index: usize, parent: usize, name: &str, flags: i32) -> Result<()> {
            self.point(false)?;
            if !matches!(self.slots[index], Slot::Vacant | Slot::Closed) {
                return Err(Failure::State);
            }
            let name = c(name)?;
            let before = named(self.fd(parent)?, &name)?.ok_or(Failure::Binding)?;
            self.slots[index] = Slot::Acquiring;
            let fd = unsafe {
                libc::openat(
                    self.fd(parent)?.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            self.store(index, fd)?;
            self.point(false)?;
            if self.original[index] != Some(before)
                || named(self.fd(parent)?, &name)? != Some(before)
            {
                return Err(Failure::Binding);
            }
            self.protect(index)
        }
        fn join(&mut self, index: usize, parent: usize, name: &str, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let initial = self.original[index].ok_or(Failure::Binding)?;
            let current = fstat(self.fd(index)?)?;
            let byname = named(self.fd(parent)?, &c(name)?)?.ok_or(Failure::Binding)?;
            let exact = if initial.mode & libc::S_IFMT == libc::S_IFDIR {
                initial.same_directory(current) && current.same_directory(byname)
            } else {
                initial == current && current == byname
            };
            self.point(cleanup)?;
            if !exact {
                return Err(Failure::Binding);
            }
            Ok(())
        }
        fn roots(&mut self, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let original = self.original[ROOT].ok_or(Failure::Binding)?;
            if !original.same_directory(fstat(self.fd(ROOT)?)?) {
                return Err(Failure::Binding);
            }
            // Actual named / checked again, not only the inherited former root.
            let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::lstat(c("/")?.as_ptr(), s.as_mut_ptr()) } != 0
                || !original.same_directory(Stat::from(unsafe { s.assume_init() })?)
            {
                return Err(Failure::Binding);
            }
            self.join(LIBRARY, ROOT, "Library", cleanup)?;
            self.join(NAMESPACE, LIBRARY, "MobileReleaseKitDeveloper", cleanup)?;
            if self.locked {
                self.join(LOCK, NAMESPACE, profile::LOCK, cleanup)?;
            }
            Ok(())
        }
        fn absent(&mut self, parent: usize, name: &str) -> Result<()> {
            self.point(false)?;
            if named(self.fd(parent)?, &c(name)?)?.is_some() {
                return Err(Failure::Present);
            }
            self.point(false)
        }
        fn sync(&mut self, index: usize, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let r = unsafe { libc::fsync(self.fd(index)?.as_raw_fd()) };
            self.point(cleanup)?;
            if r != 0 {
                Err(Failure::Sync)
            } else {
                Ok(())
            }
        }
        fn mkdir(&mut self, parent: usize, name: &str, index: usize, mode: u16) -> Result<()> {
            self.point(false)?;
            if !matches!(mode, 0o700 | 0o755) {
                return Err(Failure::Access);
            }
            self.absent(parent, name)?;
            // Hooks intentionally inherit umask077. Always create privately;
            // mkdir's requested bits alone cannot establish the final mode.
            if unsafe { libc::mkdirat(self.fd(parent)?.as_raw_fd(), c(name)?.as_ptr(), 0o700) } != 0
            {
                return Err(Failure::Write);
            }
            // Effect happened: a later failure never permits an eager unlink
            // using only this name. Original acquisition is required first.
            self.open(index, parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let before = self.original[index].ok_or(Failure::Binding)?;
            if !before.created_private() {
                return Err(Failure::Access);
            }
            self.join(index, parent, name, false)?;
            self.point(false)?;
            let changed = unsafe { libc::fchmod(self.fd(index)?.as_raw_fd(), mode) };
            self.point(false)?;
            if changed != 0 {
                return Err(Failure::Write);
            }
            let actual = fstat(self.fd(index)?)?;
            self.point(false)?;
            let byname = named(self.fd(parent)?, &c(name)?)?.ok_or(Failure::Binding)?;
            self.point(false)?;
            if !before.sealed_creation(actual, byname, mode) {
                return Err(Failure::Binding);
            }
            // Only the positively observed chmod of this newly created same
            // original may revise its metadata. Existing names never reach it.
            self.original[index] = Some(actual);
            self.protect(index)?;
            self.join(index, parent, name, false)?;
            self.sync(parent, false)
        }
        fn create_control(&mut self, index: usize, name: &str) -> Result<()> {
            self.point(false)?;
            self.absent(NAMESPACE, name)?;
            self.slots[index] = Slot::Acquiring;
            let fd = unsafe {
                libc::openat(
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    c(name)?.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            self.store(index, fd)?;
            self.point(false)?;
            if !self.original[index].is_some_and(|s| s.control() && s.size == 0) {
                return Err(Failure::Access);
            }
            self.protect(index)?;
            self.join(index, NAMESPACE, name, false)?;
            self.sync(NAMESPACE, false)
        }
        fn roster(&mut self, index: usize, expected: &[&str], cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let before = fstat(self.fd(index)?)?;
            if unsafe { libc::lseek(self.fd(index)?.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
                return Err(Failure::Read);
            }
            // Exact fixed namespace only: bounded sixteen names, no collected
            // arbitrary tree and no Vec allocation from mutable entry lengths.
            let mut observed = [false; 16];
            if expected.len() > observed.len() {
                return Err(Failure::Bounds);
            }
            let mut block = [0u8; 65536];
            loop {
                self.point(cleanup)?;
                let used =
                    abi::directory_block(self.fd(index)?, &mut block).map_err(|_| Failure::Read)?;
                self.point(cleanup)?;
                if used == 0 {
                    break;
                }
                let mut at = 0;
                while at < used {
                    if used - at < 11 {
                        return Err(Failure::Binding);
                    }
                    let n = usize::from(u16::from_ne_bytes([block[at + 9], block[at + 10]]));
                    let end = at
                        .checked_add(11 + n)
                        .filter(|n| *n <= used)
                        .ok_or(Failure::Bounds)?;
                    let value = &block[at + 11..end];
                    at = end;
                    if matches!(value, b"." | b"..") {
                        continue;
                    }
                    let pos = expected
                        .iter()
                        .position(|v| v.as_bytes() == value)
                        .ok_or(Failure::Present)?;
                    if observed[pos] {
                        return Err(Failure::Binding);
                    }
                    observed[pos] = true;
                }
            }
            if observed[..expected.len()].iter().any(|v| !*v) || before != fstat(self.fd(index)?)? {
                return Err(Failure::Binding);
            }
            Ok(())
        }
        /// Admit fixed protected ancestry before even the small reservation.
        /// An existing pending/attempt or final is not silently cleaned here.
        /// Recovery is a separate exact state under the same original EX.
        fn admit_namespace(&mut self, recovery: bool) -> Result<()> {
            self.point(false)?;
            self.slots[ROOT] = Slot::Acquiring;
            self.store(ROOT, unsafe {
                libc::open(
                    c("/")?.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            if !self.original[ROOT].is_some_and(|s| s.directory(None)) {
                return Err(Failure::Access);
            }
            self.protect(ROOT)?;
            self.open(LIBRARY, ROOT, "Library", libc::O_RDONLY | libc::O_DIRECTORY)?;
            if !self.original[LIBRARY].is_some_and(|s| s.directory(None)) {
                return Err(Failure::Access);
            }
            let ns = named(self.fd(LIBRARY)?, &c("MobileReleaseKitDeveloper")?)?;
            if ns.is_none() {
                if recovery {
                    return Err(Failure::Present);
                }
                // Tiny metadata reserve precedes tree census, not a full-copy
                // space promise. No user content/publication/tool execution.
                let fs = statfs::fstatfs(self.fd(LIBRARY)?).map_err(|_| Failure::Read)?;
                if (fs.blocks_available() as u128) * (fs.block_size() as u128) < 1024 * 1024 {
                    return Err(Failure::Bounds);
                }
                self.mkdir(LIBRARY, "MobileReleaseKitDeveloper", NAMESPACE, 0o755)?;
                self.new_namespace = true;
            } else {
                self.open(
                    NAMESPACE,
                    LIBRARY,
                    "MobileReleaseKitDeveloper",
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                if !self.original[NAMESPACE].is_some_and(|s| s.directory(Some(0o755))) {
                    return Err(Failure::Access);
                }
            }
            let current = self.observe_namespace()?;
            if named(self.fd(NAMESPACE)?, &c(profile::LOCK)?)?.is_none() {
                if current != Current::Fresh || recovery {
                    return Err(Failure::Present);
                }
                self.roster(NAMESPACE, &[], false)?;
                self.create_control(LOCK, profile::LOCK)?;
                self.new_lock = true;
            } else {
                self.roster_current(current)?;
                self.open(LOCK, NAMESPACE, profile::LOCK, libc::O_RDWR)?;
                if !self.original[LOCK].is_some_and(|s| s.control() && s.size == 0) {
                    return Err(Failure::Access);
                }
            }
            self.point(false)?;
            if unsafe { libc::flock(self.fd(LOCK)?.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                != 0
            {
                return Err(Failure::Present);
            }
            self.locked = true;
            // Re-admit after EX: first observation was not the exclusion cut.
            self.roots(false)?;
            if self.observe_namespace()? != current {
                return Err(Failure::Binding);
            }
            self.roster_current(current)?;
            self.current = Some(current);
            Ok(())
        }
        fn observe_namespace(&mut self) -> Result<Current> {
            self.point(false)?;
            let kind = Current::observed(
                named(self.fd(NAMESPACE)?, &c(profile::APP)?)?.is_some(),
                named(self.fd(NAMESPACE)?, &c(profile::PENDING)?)?.is_some(),
                named(self.fd(NAMESPACE)?, &c(profile::ATTEMPT)?)?.is_some(),
            )?;
            self.point(false)?;
            Ok(kind)
        }
        fn roster_current(&mut self, kind: Current) -> Result<()> {
            let mut names = vec![profile::LOCK];
            if kind.has_final() {
                names.push(profile::APP);
            }
            if kind.has_pending() {
                names.push(profile::PENDING);
            }
            if kind.has_attempt() {
                names.push(profile::ATTEMPT);
            }
            self.roster(NAMESPACE, &names, false)
        }
        pub(crate) fn reserve(&mut self, id: String, source_sha256: String) -> Result<()> {
            let result = (|| -> Result<()> {
                if self.life.phase != Phase::New || !hex(&id, 32) || !hex(&source_sha256, 64) {
                    return Err(Failure::State);
                }
                if !self.locked {
                    self.admit_namespace(false)?;
                }
                if self.current != Some(Current::Fresh) {
                    return Err(Failure::Present);
                }
                self.mkdir(NAMESPACE, profile::PENDING, PENDING, 0o700)?;
                self.own_pending = true;
                self.roster(PENDING, &[], false)?;
                // Empty root metadata only. Its genuine original identity is
                // durable BEFORE the child may write any payload content.
                self.mkdir(PENDING, profile::APP, STAGED, 0o700)?;
                self.roster(STAGED, &[], false)?;
                self.create_control(ATTEMPT, profile::ATTEMPT)?;
                self.own_attempt = true;
                let record = Record::reserved(
                    id,
                    self.original[NAMESPACE].ok_or(Failure::Binding)?.node,
                    self.original[PENDING].ok_or(Failure::Binding)?.node,
                    self.original[STAGED].ok_or(Failure::Binding)?.node,
                    source_sha256,
                )?;
                self.append_record(&record)?;
                self.record = Some(record);
                self.life.reserve()?;
                self.roster(
                    NAMESPACE,
                    &[profile::LOCK, profile::PENDING, profile::ATTEMPT],
                    false,
                )?;
                self.roots(false)
            })();
            if result.is_err() {
                self.clock.fail();
            }
            result
        }
        fn append_record(&mut self, record: &Record) -> Result<()> {
            self.point(false)?;
            self.roots(false)?;
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
            let bytes = record.encode()?;
            if !bytes.starts_with(&self.record_bytes) || bytes.len() <= self.record_bytes.len() {
                return Err(Failure::State);
            }
            let fd = self.fd(ATTEMPT)?.as_raw_fd();
            let mut at = self.record_bytes.len();
            while at < bytes.len() {
                self.point(false)?;
                let n = unsafe {
                    libc::pwrite(fd, bytes[at..].as_ptr().cast(), bytes.len() - at, at as i64)
                };
                if n <= 0 {
                    return Err(Failure::Write);
                }
                at += n as usize;
            }
            self.sync(ATTEMPT, false)?;
            let fresh = fstat(self.fd(ATTEMPT)?)?;
            if !fresh.control()
                || fresh.node != self.original[ATTEMPT].ok_or(Failure::Binding)?.node
                || fresh.size != bytes.len() as i64
            {
                return Err(Failure::Binding);
            }
            let mut check = [0u8; RECORD_LIMIT + 1];
            self.point(false)?;
            let n = unsafe { libc::pread(fd, check.as_mut_ptr().cast(), check.len(), 0) };
            self.point(false)?;
            if n != bytes.len() as isize
                || check[..bytes.len()] != bytes[..]
                || Record::decode(&check[..bytes.len()])? != *record
            {
                return Err(Failure::Binding);
            }
            if fstat(self.fd(ATTEMPT)?)? != fresh
                || named(self.fd(NAMESPACE)?, &c(profile::ATTEMPT)?)? != Some(fresh)
            {
                return Err(Failure::Binding);
            }
            self.original[ATTEMPT] = Some(fresh);
            self.record_bytes = bytes;
            self.sync(NAMESPACE, false)
        }
        /// Exact original SetupSource, no command/path nomination. The child
        /// inherits the SAME lock open-file description; it must never flock.
        pub(crate) fn copy_child(
            &mut self,
            source: &mut crate::macos_xcode_source::SetupSource,
        ) -> Result<()> {
            let result = (|| -> Result<()> {
                if self.life.phase != Phase::Reserved || self.child.is_some() {
                    return Err(Failure::State);
                }
                self.roots(false)?;
                self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
                source.post().map_err(|_| Failure::Binding)?;
                let executable = source.executable().map_err(|_| Failure::Binding)?;
                let loans = [
                    self.fd(ROOT)?.as_raw_fd(),
                    self.fd(LIBRARY)?.as_raw_fd(),
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    self.fd(LOCK)?.as_raw_fd(),
                    self.fd(PENDING)?.as_raw_fd(),
                    source.setup().map_err(|_| Failure::Binding)?.as_raw_fd(),
                    source.image().map_err(|_| Failure::Binding)?.as_raw_fd(),
                ];
                let nonce = self
                    .record
                    .as_ref()
                    .ok_or(Failure::State)?
                    .reserved
                    .id
                    .clone();
                self.spawn_attempted = true;
                let child = Copier::spawn(
                    executable,
                    Loans::copy(
                        loans,
                        self.record.as_ref().ok_or(Failure::State)?.reserved.staged,
                    )?,
                    self.clock,
                    nonce,
                )?;
                self.child = Some(child);
                self.life.spawned()?;
                let child = self.child.as_mut().ok_or(Failure::State)?;
                let worked = child.pump();
                if worked.is_err() {
                    child.clock.fail();
                }
                self.clock.absorb(child.clock.first, worked.is_err());
                let settled = child.settle();
                self.clock.absorb(child.clock.first, settled.is_err());
                // Consume independently, preserve primary error over cleanup.
                worked?;
                settled?;
                self.life.output_complete = child.report.is_some();
                self.life.eof = child.eof;
                self.life.exit_zero = child.reaped && child.exit_zero;
                self.life.controls_closed =
                    matches!(child.endpoint, Slot::Closed) && !child.unknown;
                self.life.joined()?;
                source.post().map_err(|_| Failure::Binding)?;
                self.roots(false)?;
                self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
                self.roster(PENDING, &[profile::APP], false)?;
                // Same original root was retained across the entire child.
                // Only the admitted copier may normalize 0700 to sealed 0555.
                let staged = fstat(self.fd(STAGED)?)?;
                if staged.node != self.record.as_ref().ok_or(Failure::State)?.reserved.staged
                    || named(self.fd(PENDING)?, &c(profile::APP)?)? != Some(staged)
                {
                    return Err(Failure::Binding);
                }
                self.original[STAGED] = Some(staged);
                let report = self
                    .child
                    .as_ref()
                    .and_then(|c| c.report.as_ref())
                    .ok_or(Failure::State)?;
                let Proof::Copied {
                    staged: reported,
                    tree_sha256,
                } = &report.proof
                else {
                    return Err(Failure::Binding);
                };
                if !staged.directory(Some(0o555)) || staged.node != *reported {
                    return Err(Failure::Binding);
                }
                let mut record = self.record.clone().ok_or(Failure::State)?;
                record.add_copied(staged.node, tree_sha256.clone())?;
                self.append_record(&record)?;
                self.record = Some(record);
                self.life.copied()?;
                Ok(())
            })();
            if result.is_err() {
                self.clock.fail();
                if result == Err(Failure::Unknown) {
                    self.unknown = true;
                    self.life.unknown();
                }
                if let Some(child) = self.child.as_mut() {
                    let child_closed = child.settle();
                    self.clock.absorb(child.clock.first, child_closed.is_err());
                    if child_closed.is_err() || !child.reaped || child.unknown {
                        self.unknown = true;
                        self.life.unknown();
                    }
                }
            }
            result
        }
        /// Fresh original signed-helper recovery. Existing state is only DATA
        /// until the one actual child reauthenticates SELF/source and reports
        /// positively closed pending-empty. This invocation never publishes.
        pub(crate) fn retire_interrupted(
            &mut self,
            source: &mut crate::macos_xcode_source::SetupSource,
        ) -> Result<()> {
            let result = (|| -> Result<()> {
                if self.life.phase != Phase::New || self.child.is_some() {
                    return Err(Failure::State);
                }
                source.post().map_err(|_| Failure::Binding)?;
                let source_hash: String = source
                    .image_sha256()
                    .map_err(|_| Failure::Binding)?
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if !self.locked {
                    self.admit_namespace(true)?;
                }
                if self.current != Some(Current::Pending) {
                    return Err(Failure::Present);
                }
                self.open(
                    PENDING,
                    NAMESPACE,
                    profile::PENDING,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                if !self.original[PENDING].is_some_and(|s| s.directory(Some(0o700))) {
                    return Err(Failure::Access);
                }
                self.open(ATTEMPT, NAMESPACE, profile::ATTEMPT, libc::O_RDONLY)?;
                let original = self.original[ATTEMPT].ok_or(Failure::Binding)?;
                if !original.control() || original.size == 0 {
                    return Err(Failure::Binding);
                }
                self.point(false)?;
                let mut bytes = [0u8; RECORD_LIMIT + 1];
                let n = unsafe {
                    libc::pread(
                        self.fd(ATTEMPT)?.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                };
                self.point(false)?;
                if n != original.size as isize {
                    return Err(Failure::Binding);
                }
                self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
                let record = Record::decode(&bytes[..n as usize])?;
                if !record.binds_originals(
                    self.original[NAMESPACE].ok_or(Failure::Binding)?.node,
                    self.original[PENDING].ok_or(Failure::Binding)?.node,
                    &source_hash,
                ) {
                    return Err(Failure::Binding);
                }
                if let Some(staged) = named(self.fd(PENDING)?, &c(profile::APP)?)? {
                    if staged.node != record.reserved.staged
                        || !(staged.directory(Some(0o700)) || staged.directory(Some(0o555)))
                    {
                        return Err(Failure::Binding);
                    }
                    self.roster(PENDING, &[profile::APP], false)?;
                    self.open(
                        STAGED,
                        PENDING,
                        profile::APP,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                    )?;
                } else {
                    self.roster(PENDING, &[], false)?;
                }
                self.record_bytes = bytes[..n as usize].to_vec();
                self.record = Some(record.clone());
                self.own_pending = true;
                self.own_attempt = true;
                self.life.reserve()?;
                let fds = [
                    self.fd(ROOT)?.as_raw_fd(),
                    self.fd(LIBRARY)?.as_raw_fd(),
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    self.fd(LOCK)?.as_raw_fd(),
                    self.fd(PENDING)?.as_raw_fd(),
                    source.setup().map_err(|_| Failure::Binding)?.as_raw_fd(),
                    source.image().map_err(|_| Failure::Binding)?.as_raw_fd(),
                ];
                let loans = Loans::retire(fds, record.clone(), original.node)?;
                self.spawn_attempted = true;
                self.child = Some(Copier::spawn(
                    source.executable().map_err(|_| Failure::Binding)?,
                    loans,
                    self.clock,
                    record.reserved.id,
                )?);
                self.life.spawned()?;
                let child = self.child.as_mut().ok_or(Failure::State)?;
                let observed = child.pump();
                if observed.is_err() {
                    child.clock.fail();
                }
                self.clock.absorb(child.clock.first, observed.is_err());
                let closed = child.settle();
                self.clock.absorb(child.clock.first, closed.is_err());
                observed?;
                closed?;
                self.life.output_complete = matches!(
                    child.report.as_ref().map(|r| &r.proof),
                    Some(Proof::PendingEmpty)
                );
                self.life.eof = child.eof;
                self.life.exit_zero = child.reaped && child.exit_zero;
                self.life.controls_closed =
                    matches!(child.endpoint, Slot::Closed) && !child.unknown;
                self.life.joined()?;
                source.post().map_err(|_| Failure::Binding)?;
                self.roots(false)?;
                self.close(STAGED)?;
                self.retire_empty_refusal()?;
                self.life.phase = Phase::Retired;
                Ok(())
            })();
            if result.is_err() {
                self.clock.fail();
                if let Some(child) = self.child.as_mut() {
                    let child_closed = child.settle();
                    self.clock.absorb(child.clock.first, child_closed.is_err());
                    if child_closed.is_err() || !child.reaped || child.unknown {
                        self.unknown = true;
                        self.life.unknown();
                    }
                }
            }
            result
        }

        fn read_record(&mut self, source_hash: &str) -> Result<Record> {
            self.open(ATTEMPT, NAMESPACE, profile::ATTEMPT, libc::O_RDONLY)?;
            let original = self.original[ATTEMPT].ok_or(Failure::Binding)?;
            if !original.control() || original.size <= 0 {
                return Err(Failure::Binding);
            }
            let mut bytes = [0u8; RECORD_LIMIT + 1];
            self.point(false)?;
            let n = unsafe {
                libc::pread(
                    self.fd(ATTEMPT)?.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            self.point(false)?;
            if n != original.size as isize || n <= 0 || n as usize > RECORD_LIMIT {
                return Err(Failure::Bounds);
            }
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
            let record = Record::decode(&bytes[..n as usize])?;
            if record.reserved.namespace != self.original[NAMESPACE].ok_or(Failure::Binding)?.node
                || record.reserved.source_sha256 != source_hash
            {
                return Err(Failure::Binding);
            }
            self.record_bytes = bytes[..n as usize].to_vec();
            self.record = Some(record.clone());
            Ok(record)
        }
        fn record_post(&mut self) -> Result<()> {
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
            let expected = self.record.as_ref().ok_or(Failure::Binding)?.clone();
            let mut bytes = [0u8; RECORD_LIMIT + 1];
            self.point(false)?;
            let n = unsafe {
                libc::pread(
                    self.fd(ATTEMPT)?.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            self.point(false)?;
            if n != self.record_bytes.len() as isize
                || bytes[..n.max(0) as usize] != self.record_bytes
                || Record::decode(&self.record_bytes)? != expected
            {
                return Err(Failure::Binding);
            }
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)
        }
        /// Fresh current admission, not recovery of the prior invocation's
        /// unknown success. Child observes only; Parent retires exact originals.
        fn observe_current(
            &mut self,
            source: &mut crate::macos_xcode_source::SetupSource,
        ) -> Result<SetupOutcome> {
            let result = (|| -> Result<SetupOutcome> {
                if !self.locked || self.life.phase != Phase::New || self.child.is_some() {
                    return Err(Failure::State);
                }
                let current = self.current.ok_or(Failure::State)?;
                if current == Current::Fresh || current == Current::Pending {
                    return Err(Failure::State);
                }
                source.post().map_err(|_| Failure::Binding)?;
                let source_hash: String = source
                    .image_sha256()
                    .map_err(|_| Failure::Binding)?
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if current.has_final() {
                    self.open(
                        STAGED,
                        NAMESPACE,
                        profile::APP,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                    )?;
                    if !self.original[STAGED].is_some_and(|s| s.directory(Some(0o555))) {
                        return Err(Failure::Access);
                    }
                }
                if current.has_pending() {
                    self.open(
                        PENDING,
                        NAMESPACE,
                        profile::PENDING,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                    )?;
                    if !self.original[PENDING].is_some_and(|s| s.directory(Some(0o700))) {
                        return Err(Failure::Access);
                    }
                    self.roster(PENDING, &[], false)?;
                }
                let record = if current.has_attempt() {
                    Some(self.read_record(&source_hash)?)
                } else {
                    None
                };
                if let Some(r) = record.as_ref() {
                    if !r.binds_current(
                        self.original[NAMESPACE].ok_or(Failure::Binding)?.node,
                        &source_hash,
                        if current.has_final() {
                            Some(self.original[STAGED].ok_or(Failure::Binding)?.node)
                        } else {
                            None
                        },
                        if current.has_pending() {
                            Some(self.original[PENDING].ok_or(Failure::Binding)?.node)
                        } else {
                            None
                        },
                    ) {
                        return Err(Failure::Binding);
                    }
                }
                let mut nonce = [0u8; 16];
                getrandom::fill(&mut nonce).map_err(|_| Failure::Read)?;
                let nonce = record
                    .as_ref()
                    .map(|r| r.reserved.id.clone())
                    .unwrap_or_else(|| nonce.iter().map(|b| format!("{b:02x}")).collect());
                let common = [
                    self.fd(ROOT)?.as_raw_fd(),
                    self.fd(LIBRARY)?.as_raw_fd(),
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    self.fd(LOCK)?.as_raw_fd(),
                ];
                let setup = source.setup().map_err(|_| Failure::Binding)?.as_raw_fd();
                let image = source.image().map_err(|_| Failure::Binding)?.as_raw_fd();
                let loans = if current.has_final() {
                    Loans::observe(
                        [
                            common[0],
                            common[1],
                            common[2],
                            common[3],
                            self.fd(STAGED)?.as_raw_fd(),
                            setup,
                            image,
                        ],
                        record.clone(),
                        self.original[ATTEMPT].map(|s| s.node),
                        self.original[PENDING].map(|s| s.node),
                    )?
                } else {
                    Loans::observe_attempt(
                        [common[0], common[1], common[2], common[3], setup, image],
                        record.clone().ok_or(Failure::Binding)?,
                        self.original[ATTEMPT].ok_or(Failure::Binding)?.node,
                    )?
                };
                self.life.reserve()?;
                self.spawn_attempted = true;
                self.child = Some(Copier::spawn(
                    source.executable().map_err(|_| Failure::Binding)?,
                    loans,
                    self.clock,
                    nonce,
                )?);
                self.life.spawned()?;
                let child = self.child.as_mut().ok_or(Failure::State)?;
                let observed = child.pump();
                child.clock.absorb(None, observed.is_err());
                self.clock.absorb(child.clock.first, observed.is_err());
                let closed = child.settle();
                self.clock.absorb(child.clock.first, closed.is_err());
                observed?;
                closed?;
                self.life.output_complete = matches!(
                    (
                        &child.report.as_ref().map(|r| &r.proof),
                        current.has_final()
                    ),
                    (Some(Proof::CurrentFinal), true) | (Some(Proof::AttemptOnly), false)
                );
                self.life.eof = child.eof;
                self.life.exit_zero = child.reaped && child.exit_zero;
                self.life.controls_closed =
                    matches!(child.endpoint, Slot::Closed) && !child.unknown;
                self.life.joined()?;
                source.post().map_err(|_| Failure::Binding)?;
                self.roots(false)?;
                self.roster_current(current)?;
                if current.has_final() {
                    self.join(STAGED, NAMESPACE, profile::APP, false)?;
                } else {
                    self.absent(NAMESPACE, profile::APP)?;
                }
                if current.has_pending() {
                    self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
                    self.roster(PENDING, &[], false)?;
                    self.record_post()?;
                    self.point(false)?;
                    if unsafe {
                        libc::unlinkat(
                            self.fd(NAMESPACE)?.as_raw_fd(),
                            c(profile::PENDING)?.as_ptr(),
                            libc::AT_REMOVEDIR,
                        )
                    } != 0
                    {
                        return Err(Failure::Write);
                    }
                    self.sync(NAMESPACE, false)?;
                    self.close(PENDING)?;
                    self.absent(NAMESPACE, profile::PENDING)?;
                } else {
                    self.absent(NAMESPACE, profile::PENDING)?;
                }
                if current.has_attempt() {
                    // The original record is re-read after childjoin and after
                    // any wrapper removal immediately before its own unlink.
                    self.record_post()?;
                    self.roots(false)?;
                    self.absent(NAMESPACE, profile::PENDING)?;
                    if current.has_final() {
                        self.join(STAGED, NAMESPACE, profile::APP, false)?;
                    } else {
                        self.absent(NAMESPACE, profile::APP)?;
                    }
                    self.point(false)?;
                    if unsafe {
                        libc::unlinkat(
                            self.fd(NAMESPACE)?.as_raw_fd(),
                            c(profile::ATTEMPT)?.as_ptr(),
                            0,
                        )
                    } != 0
                    {
                        return Err(Failure::Write);
                    }
                    self.sync(NAMESPACE, false)?;
                    self.close(ATTEMPT)?;
                    self.absent(NAMESPACE, profile::ATTEMPT)?;
                }
                self.roster_current(if current.has_final() {
                    Current::Final
                } else {
                    Current::Fresh
                })?;
                if current.has_final() {
                    self.join(STAGED, NAMESPACE, profile::APP, false)?;
                }
                self.life.phase = Phase::Retired;
                Ok(if current.has_final() {
                    SetupOutcome::Prepared
                } else {
                    SetupOutcome::NeedsRerun
                })
            })();
            self.clock.absorb(source.first_failure(), result.is_err());
            result
        }
        fn users_joined(&self) -> bool {
            match self.child.as_ref() {
                Some(child) => child.reaped && matches!(child.endpoint, Slot::Closed),
                None => !self.spawn_attempted,
            }
        }

        /// Parent sole publication. Neither child report nor record alone can
        /// reach this branch; actual live route must have consumed originalchild.
        pub(crate) fn publish(&mut self) -> Result<()> {
            let result = (|| -> Result<()> {
                if self.life.phase != Phase::Copied {
                    return Err(Failure::State);
                }
                self.roots(false)?;
                self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
                self.join(STAGED, PENDING, profile::APP, false)?;
                self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
                self.roster(PENDING, &[profile::APP], false)?;
                self.absent(NAMESPACE, profile::APP)?;
                let app = c(profile::APP)?;
                // RENAME_EXCL never replaces a final path, including a foreign
                // directory which appeared since the immediately preceding POST.
                if unsafe {
                    libc::renameatx_np(
                        self.fd(PENDING)?.as_raw_fd(),
                        app.as_ptr(),
                        self.fd(NAMESPACE)?.as_raw_fd(),
                        app.as_ptr(),
                        libc::RENAME_EXCL,
                    )
                } != 0
                {
                    return Err(Failure::Write);
                }
                self.life.published()?;
                self.sync(NAMESPACE, false)?;
                self.sync(PENDING, false)?;
                self.join(STAGED, NAMESPACE, profile::APP, false)?;
                self.roster(PENDING, &[], false)?;
                self.roots(false)?;
                self.retire_published()?;
                Ok(())
            })();
            if result.is_err() {
                self.clock.fail();
            }
            result
        }
        fn retire_published(&mut self) -> Result<()> {
            if self.life.phase != Phase::Published {
                return Err(Failure::State);
            }
            self.roots(false)?;
            self.join(STAGED, NAMESPACE, profile::APP, false)?;
            self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
            self.roster(PENDING, &[], false)?;
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
            // Current actual joined publication; fresh retry must independently
            // reauthenticate complete source/signature/record before this cut.
            if unsafe {
                libc::unlinkat(
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    c(profile::PENDING)?.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(Failure::Write);
            }
            self.sync(NAMESPACE, false)?;
            self.close(PENDING)?;
            self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, false)?;
            if unsafe {
                libc::unlinkat(
                    self.fd(NAMESPACE)?.as_raw_fd(),
                    c(profile::ATTEMPT)?.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(Failure::Write);
            }
            self.sync(NAMESPACE, false)?;
            self.close(ATTEMPT)?;
            self.roster(NAMESPACE, &[profile::LOCK, profile::APP], false)?;
            self.join(STAGED, NAMESPACE, profile::APP, false)?;
            self.life.retired()?;
            self.own_pending = false;
            self.own_attempt = false;
            Ok(())
        }
        pub(crate) fn pending(&mut self) -> Result<BorrowedFd<'_>> {
            self.roots(false)?;
            self.join(PENDING, NAMESPACE, profile::PENDING, false)?;
            self.fd(PENDING)
        }
        pub(crate) fn lock(&mut self) -> Result<BorrowedFd<'_>> {
            if !self.locked {
                return Err(Failure::State);
            }
            self.roots(false)?;
            self.fd(LOCK)
        }
        pub(crate) fn held_count(&self) -> usize {
            self.slots
                .iter()
                .filter(|s| !matches!(s, Slot::Vacant | Slot::Closed))
                .count()
        }
        fn close(&mut self, index: usize) -> Result<()> {
            match self.slots[index] {
                Slot::Vacant | Slot::Closed => Ok(()),
                Slot::Owned(fd) => {
                    if self.clock.point(true).is_err() {
                        self.slots[index] = Slot::Unknown;
                        self.unknown = true;
                        return Err(Failure::Unknown);
                    }
                    self.slots[index] = Slot::Unknown;
                    let r = unsafe { libc::close(fd) };
                    if r != 0 {
                        self.unknown = true;
                        return Err(Failure::Close);
                    }
                    self.slots[index] = Slot::Closed;
                    Ok(())
                }
                _ => {
                    self.unknown = true;
                    Err(Failure::Unknown)
                }
            }
        }
        /// No final or nonempty tree is ever removed here. This limited known
        /// refusal cut handles only this invocation's actually empty reservation.
        pub(crate) fn retire_empty_refusal(&mut self) -> Result<()> {
            let result = (|| -> Result<()> {
                let joined_retirement = self.life.phase == Phase::Joined
                    && self.child.as_ref().is_some_and(|child| {
                        child.purpose == Purpose::RetirePending
                            && child.reaped
                            && child.exit_zero
                            && child.eof
                            && !child.unknown
                            && matches!(child.endpoint, Slot::Closed)
                            && matches!(
                                child.report.as_ref().map(|r| &r.proof),
                                Some(Proof::PendingEmpty)
                            )
                    });
                if !(self.life.may_remove_empty_reservation() || joined_retirement)
                    || !self.own_pending
                    || !self.own_attempt
                {
                    return Err(Failure::State);
                }
                self.roots(true)?;
                self.join(PENDING, NAMESPACE, profile::PENDING, true)?;
                if self.life.phase == Phase::Reserved && self.child.is_none() {
                    let record = self.record.as_ref().ok_or(Failure::State)?;
                    if self.original[STAGED].ok_or(Failure::Binding)?.node != record.reserved.staged
                    {
                        return Err(Failure::Binding);
                    }
                    self.join(STAGED, PENDING, profile::APP, true)?;
                    self.roster(STAGED, &[], true)?;
                    self.point(true)?;
                    if unsafe {
                        libc::unlinkat(
                            self.fd(PENDING)?.as_raw_fd(),
                            c(profile::APP)?.as_ptr(),
                            libc::AT_REMOVEDIR,
                        )
                    } != 0
                    {
                        return Err(Failure::Write);
                    }
                    self.sync(PENDING, true)?;
                    self.close(STAGED)?;
                }
                self.roster(PENDING, &[], true)?;
                self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, true)?;
                // Remove pending first. An interruption with attempt alone is
                // conservatively present; no later fallback may ignore it.
                if unsafe {
                    libc::unlinkat(
                        self.fd(NAMESPACE)?.as_raw_fd(),
                        c(profile::PENDING)?.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                } != 0
                {
                    return Err(Failure::Write);
                }
                self.sync(NAMESPACE, true)?;
                self.close(PENDING)?;
                if named(self.fd(NAMESPACE)?, &c(profile::PENDING)?)?.is_some() {
                    return Err(Failure::Binding);
                }
                self.join(ATTEMPT, NAMESPACE, profile::ATTEMPT, true)?;
                if unsafe {
                    libc::unlinkat(
                        self.fd(NAMESPACE)?.as_raw_fd(),
                        c(profile::ATTEMPT)?.as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(Failure::Write);
                }
                self.sync(NAMESPACE, true)?;
                self.close(ATTEMPT)?;
                if named(self.fd(NAMESPACE)?, &c(profile::ATTEMPT)?)?.is_some() {
                    return Err(Failure::Binding);
                }
                self.own_pending = false;
                self.own_attempt = false;
                self.roster(NAMESPACE, &[profile::LOCK], true)
            })();
            if result.is_err() {
                self.clock.fail();
            }
            result
        }
        /// Independent consuming closes; holding or losing a lock never
        /// supplies old child-finality credit. Existing namespace/lock persist.
        pub(crate) fn settle(&mut self, parent_first: Option<Instant>) -> Result<()> {
            if let Some(at) = parent_first {
                self.clock.fail_at(at);
            }
            let mut failure = None;
            if let Some(child) = self.child.as_mut() {
                if let Some(at) = self.clock.first {
                    child.clock.fail_at(at);
                }
                self.clock.absorb(child.clock.first, false);
                let closed = child.settle();
                self.clock.absorb(child.clock.first, closed.is_err());
                if let Err(e) = closed {
                    self.unknown = true;
                    failure = Some(e);
                }
                if !child.reaped {
                    self.unknown = true;
                    failure.get_or_insert(Failure::Unknown);
                }
            }
            for index in (0..NS_SLOTS).rev() {
                if let Err(e) = self.close(index) {
                    failure.get_or_insert(e);
                }
            }
            self.locked = false;
            if let Some(e) = failure {
                Err(e)
            } else {
                Ok(())
            }
        }
        pub(crate) fn unknown(&self) -> bool {
            self.unknown
                || self
                    .slots
                    .iter()
                    .any(|s| matches!(s, Slot::Acquiring | Slot::Unknown))
        }
        pub(crate) fn first_failure(&self) -> Option<Instant> {
            self.clock.first
        }
    }

    #[cfg(test)]
    mod namespace_tests {
        use super::*;
        use std::{fs, os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
            panic::{catch_unwind, AssertUnwindSafe}, time::{SystemTime, UNIX_EPOCH}};

        #[test]
        #[ignore = "requires explicit disposable macOS read-only system-Xcode census"]
        fn selected_system_xcode_initial_census_is_read_only_and_reports_first_failure() {
            assert_eq!(unsafe { libc::getuid() }, 0);
            assert_eq!(unsafe { libc::geteuid() }, 0);
            // Full source census measured ~568s on ARM; Intel reached the old
            // 600s probe limit. This read-only test has its own original budget,
            // not a changed shipping setup deadline or per-node renewal.
            let start = Instant::now();
            let finish = start + Duration::from_secs(930);
            let work = copy::Work { end: start + Duration::from_secs(900),
                parent: unsafe { libc::getppid() } };
            let mut files = crate::macos_xcode_tree::CopierFiles::new(finish, 1).unwrap();
            let mut root: Option<libc::c_int> = None;
            let mut stage = "root-original";
            let observed = catch_unwind(AssertUnwindSafe(|| {
                work.point().expect("initial census original clock");
                let raw = unsafe { libc::open(c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if raw >= 0 { root = Some(raw); }
                assert!(raw >= 0, "initial census read-only root open");
                work.point().expect("initial census root-open clock");
                let root = unsafe { BorrowedFd::borrow_raw(raw) };
                let root_identity = fstat(root).expect("initial census root stat");
                assert!(root_identity.directory(None), "initial census root policy");
                stage = "source-selection";
                let selected = SourceSelection::selected(root, &mut files, &work)
                    .expect("initial census fixed original selection");
                let apps_raw = files.fd(selected.applications).unwrap().as_raw_fd();
                let app_raw = files.fd(selected.app).unwrap().as_raw_fd();
                let apps = unsafe { BorrowedFd::borrow_raw(apps_raw) };
                let app = unsafe { BorrowedFd::borrow_raw(app_raw) };
                stage = "source-tree-original";
                let tree = crate::macos_xcode_tree::SourceTree::original(
                    app, apps, &selected.name, selected.app_id, &work,
                ).expect("initial census actual source tree");
                stage = "source-allocation-unit";
                let filesystem = statfs::fstatfs(app).expect("initial census source filesystem");
                let unit = u64::try_from(filesystem.block_size()).expect("initial census allocation unit");
                stage = "initial-source-census";
                let census = tree.census(&mut files, unit).expect("initial source census refused");
                stage = "selection-post";
                selected.post(root, &files, &work).expect("initial census selection POST");
                stage = "root-post";
                assert!(fstat(root).unwrap() == root_identity, "initial census root original POST");
                work.point().expect("initial census final original clock");
                (census.quote.entries(), census.quote.logical_bytes())
            }));
            // Earliest source/copy error survives final cleanup. The root uses
            // the SAME effective F; not a renewed cleanup allowance.
            if observed.is_err() { files.note_failure(); }
            let children_closed = files.close_all();
            let cutoff = files.first_failure()
                .and_then(|at| at.checked_add(Duration::from_secs(120)))
                .map_or(finish, |at| at.min(finish));
            let root_closed = root.map_or(true, |fd| {
                Instant::now() < cutoff && unsafe { libc::close(fd) } == 0
            });
            let settled = children_closed && files.live() == 0 && root_closed && Instant::now() < cutoff;
            // No output was created and no source object may be removed.
            assert!(settled, "initial census original closure unconfirmed");
            match observed {
                Ok((entries, bytes)) => eprintln!("MRK_XCODE_INITIAL_CENSUS state=passed;entries={entries};logicalBytes={bytes};copyPerformed=false;signerVerified=false"),
                Err(error) => {
                    eprintln!("MRK_XCODE_INITIAL_CENSUS state=failed;stage={stage};originalsClosed=true;copyPerformed=false");
                    std::panic::resume_unwind(error);
                }
            }
        }

        #[test]
        #[ignore = "requires explicit disposable macOS root/APFS fixture"]
        fn namespace_creation_seals_umask077_and_preserves_existing_objects() {
            assert_eq!(unsafe { libc::getuid() }, 0);
            assert_eq!(unsafe { libc::geteuid() }, 0);
            // This exact ignored method runs alone with --test-threads=1.
            // Restore the process mask even if a fixture assertion panics.
            struct Mask(libc::mode_t);
            impl Drop for Mask { fn drop(&mut self) { unsafe { libc::umask(self.0); } } }
            let mask = Mask(unsafe { libc::umask(0o077) });
            let path = std::env::temp_dir().join(format!("mrk-xcode-namespace-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let now = Instant::now();
            let mut owner = Namespace::new(now + Duration::from_secs(30), now + Duration::from_secs(40),
                now + Duration::from_secs(50), 0).unwrap();
            let raw = unsafe { libc::open(c(path.to_str().unwrap()).unwrap().as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            assert!(raw >= 0, "exclusive fixture parent open");
            // Actual tempfile may inherit the runner parent's group. Normalize
            // only this new fixture, before supplying it to the production call.
            owner.slots[ROOT] = Slot::Owned(raw);
            let original = fs::symlink_metadata(&path).unwrap();
            let mut sources = crate::macos_xcode_tree::CopierFiles::new(
                now + Duration::from_secs(40), 4, // Namespace's three + actual / below.
            ).unwrap();
            let mut system_root: Option<libc::c_int> = None;
            let observed = catch_unwind(AssertUnwindSafe(|| {
                assert_eq!(unsafe { libc::fchown(raw, 0, 0) }, 0);
                owner.original[ROOT] = Some(fstat(owner.fd(ROOT).unwrap()).unwrap());
                owner.protect(ROOT).unwrap();
                let base = owner.original[ROOT].unwrap();
                let observed_root = Stat { mode: libc::S_IFDIR | 0o755, flags: 1048576, ..base };
                assert!(observed_root.directory(None)); // Actual macos26 root: SF_NOUNLINK.
                for flags in [0, 0x00080000, 0x00100000, 0x00800000, 0x00980000] {
                    let ancestor = Stat { flags, ..observed_root };
                    assert!(ancestor.directory(None));
                    assert_eq!(ancestor.directory(Some(0o755)), flags == 0);
                }
                assert!(!Stat { flags: 1, ..observed_root }.directory(None));
                assert!(!Stat { mode: libc::S_IFDIR | 0o777, ..observed_root }.directory(None));
                assert!(!Stat { uid: 1, ..observed_root }.directory(None));
                assert!(!Stat { flags: 0, ..observed_root }.created_private());
                for wrong in [Stat { uid: 1, ..base }, Stat { gid: 1, ..base },
                    Stat { flags: 1, ..base }, Stat { mode: libc::S_IFREG | 0o700, ..base }] {
                    assert!(!wrong.created_private());
                }
                owner.mkdir(ROOT, "managed", NAMESPACE, 0o755).unwrap();
                let created = owner.original[NAMESPACE].unwrap();
                assert!(created.directory(Some(0o755)));
                assert!(fstat(owner.fd(NAMESPACE).unwrap()).unwrap() == created);
                assert!(named(owner.fd(ROOT).unwrap(), c"managed").unwrap() == Some(created));
                owner.mkdir(NAMESPACE, "pending", PENDING, 0o700).unwrap();
                assert!(owner.original[PENDING].unwrap().directory(Some(0o700)));
                let private = Stat { mode: libc::S_IFDIR | 0o700, ..created };
                assert!(private.sealed_creation(created, created, 0o755));
                assert!(!private.sealed_creation(Stat { node: Node { inode: created.node.inode + 1, ..created.node }, ..created }, created, 0o755));
                assert!(!private.sealed_creation(Stat { flags: 1, ..created }, Stat { flags: 1, ..created }, 0o755));
                // No permission repair of preexisting objects or link targets.
                fs::DirBuilder::new().mode(0o500).create(path.join("existing")).unwrap();
                let existing = fs::symlink_metadata(path.join("existing")).unwrap();
                assert_eq!(owner.mkdir(ROOT, "existing", STAGED, 0o755), Err(Failure::Present));
                let after = fs::symlink_metadata(path.join("existing")).unwrap();
                assert_eq!((after.dev(), after.ino(), after.mode()), (existing.dev(), existing.ino(), existing.mode()));
                symlink("existing", path.join("alias")).unwrap();
                assert_eq!(owner.mkdir(ROOT, "alias", STAGED, 0o755), Err(Failure::Present));
                assert_eq!(fs::read_link(path.join("alias")).unwrap(), std::path::Path::new("existing"));
                assert_eq!(fs::symlink_metadata(path.join("existing")).unwrap().mode(), existing.mode());
                assert_eq!(owner.mkdir(ROOT, "bad-mode", STAGED, 0o777), Err(Failure::Access));
                assert!(!path.join("bad-mode").exists());
                // A system source ancestor is not copied payload: admit the
                // observed root:admin 0775/protective-flags shape without ever
                // changing /Applications. The native fixture below has no flags.
                fs::DirBuilder::new().mode(0o700).create(path.join("Applications")).unwrap();
                fs::set_permissions(path.join("Applications"), fs::Permissions::from_mode(0o775)).unwrap();
                let work = copy::Work { end: now + Duration::from_secs(30),
                    parent: unsafe { libc::getppid() } };
                let apps = copy::named(owner.fd(ROOT).unwrap(), c"Applications", &work).unwrap();
                let selected = sources.open_applications(owner.fd(ROOT).unwrap(), apps, &work).unwrap();
                copy::exact(sources.fd(selected).unwrap(), owner.fd(ROOT).unwrap(),
                    c"Applications", apps, &work).unwrap();
                let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                assert_eq!(unsafe { libc::fstat(sources.fd(selected).unwrap().as_raw_fd(), metadata.as_mut_ptr()) }, 0);
                let mut metadata = unsafe { metadata.assume_init() };
                metadata.st_gid = 80;
                for flags in [0, 0x00080000, 1048576, 0x00800000, 0x00980000] {
                    metadata.st_flags = flags;
                    let ancestor = copy::Identity::of(&metadata);
                    assert!(ancestor.applications_directory().is_ok());
                    assert_eq!(ancestor.source_kind().is_ok(), flags == 0);
                    // Managed protected files retain the stricter sealed policy.
                    let mut managed = metadata;
                    managed.st_mode = libc::S_IFDIR | 0o555;
                    managed.st_gid = 0;
                    assert_eq!(copy::Identity::of(&managed).protected_kind().is_ok(), flags == 0);
                }
                metadata.st_flags = 1;
                assert!(copy::Identity::of(&metadata).applications_directory().is_err());
                metadata.st_flags = 0;
                metadata.st_uid = 1;
                assert!(copy::Identity::of(&metadata).applications_directory().is_err());
                metadata.st_uid = 0;
                metadata.st_gid = 1;
                assert!(copy::Identity::of(&metadata).applications_directory().is_err());
                metadata.st_gid = 80;
                metadata.st_mode = libc::S_IFDIR | 0o777;
                assert!(copy::Identity::of(&metadata).applications_directory().is_err());
                // Fail fast on the real host's ancestry/ACL/mount policy too.
                // This is READ ONLY: no chmod/chown/flags changes, no Xcode walk.
                let system_fd = unsafe { libc::open(c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if system_fd >= 0 { system_root = Some(system_fd); }
                assert!(system_fd >= 0, "actual root read-only open");
                let system = unsafe { BorrowedFd::borrow_raw(system_fd) };
                assert!(fstat(system).unwrap().directory(None));
                let actual_apps = copy::named(system, c"Applications", &work).unwrap();
                let actual_slot = sources.open_applications(system, actual_apps, &work)
                    .expect("actual Applications ancestor/ACL/mount admission");
                copy::exact(sources.fd(actual_slot).unwrap(), system, c"Applications",
                    actual_apps, &work).expect("actual Applications original POST");
                // Keep the original fd: replacing its name with an alias must
                // invalidate POST and the fixed opener must not follow the alias.
                fs::rename(path.join("Applications"), path.join("Applications-original")).unwrap();
                symlink("Applications-original", path.join("Applications")).unwrap();
                assert!(copy::exact(sources.fd(selected).unwrap(), owner.fd(ROOT).unwrap(),
                    c"Applications", apps, &work).is_err());
                let alias = copy::named(owner.fd(ROOT).unwrap(), c"Applications", &work).unwrap();
                assert!(sources.open_applications(owner.fd(ROOT).unwrap(), alias, &work).is_err());
                assert_eq!(fs::read_link(path.join("Applications")).unwrap(),
                    std::path::Path::new("Applications-original"));
                owner.clock.work = Instant::now();
                assert_eq!(owner.mkdir(ROOT, "late", STAGED, 0o755), Err(Failure::Clock));
                assert!(!path.join("late").exists());
            }));
            // Known original closes precede task-only cleanup even on assertion
            // failure. A failed/unknown close preserves this exclusive fixture.
            let source_closed = sources.close_all() && sources.live() == 0;
            let system_closed = system_root.map_or(true, |fd| {
                Instant::now() < now + Duration::from_secs(40) && unsafe { libc::close(fd) } == 0
            });
            let settled = owner.settle(None).is_ok() && source_closed && system_closed && !owner.unknown()
                && owner.slots.iter().all(|s| matches!(s, Slot::Vacant | Slot::Closed));
            drop(mask);
            let current = fs::symlink_metadata(&path).unwrap();
            assert!(settled && current.is_dir() && current.dev() == original.dev()
                && current.ino() == original.ino() && current.uid() == 0,
                "namespace fixture retained: original settlement/root changed");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir_all(&path).unwrap();
            if let Err(error) = observed { std::panic::resume_unwind(error); }
        }
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use native::{carrier_once, copier_entry, setup_once};

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Record {
        Record::reserved(
            "0".repeat(32),
            Node {
                device: 1,
                inode: 2,
            },
            Node {
                device: 1,
                inode: 3,
            },
            Node {
                device: 1,
                inode: 4,
            },
            "a".repeat(64),
        )
        .unwrap()
    }
    #[test]
    fn xcode_refusal_trace_preserves_primary_and_emits_only_closed_data() {
        let mut trace = Trace::new(Stage::Copy);
        trace.record(&Ok::<(), Failure>(()));
        trace.fallback(false);
        assert_eq!(trace.first, None);
        trace.record(&Err::<(), _>(Failure::Write));
        trace.at(Stage::FilesSettle);
        trace.note(Failure::Close);
        trace.fallback(true);
        assert_eq!(
            trace.first,
            Some(Diagnostic {
                stage: Stage::Copy,
                failure: Failure::Write
            })
        );
        let mut cleanup = Trace::new(Stage::SourceSettle);
        cleanup.record(&Err::<(), _>(Failure::Close));
        assert_eq!(cleanup.first.unwrap().stage, Stage::SourceSettle);
        let mut fallback = Trace::new(Stage::Input);
        fallback.fallback(true);
        assert_eq!(
            fallback.first,
            Some(Diagnostic {
                stage: Stage::Finality,
                failure: Failure::Unknown
            })
        );
        for stage in [
            Stage::Input,
            Stage::Source,
            Stage::SelfCheck,
            Stage::Carrier,
            Stage::Selection,
            Stage::SourceApple,
            Stage::StagedApple,
            Stage::FinalApple,
            Stage::Facts,
            Stage::Census,
            Stage::Copy,
            Stage::Record,
            Stage::RetireTree,
            Stage::Current,
            Stage::SourcePost,
            Stage::FilesSettle,
            Stage::SourceSettle,
            Stage::LoansSettle,
            Stage::Reply,
            Stage::EndpointSettle,
            Stage::Namespace,
            Stage::Reservation,
            Stage::Child,
            Stage::Publication,
            Stage::NamespaceSettle,
            Stage::Finality,
        ] {
            for failure in [
                Failure::Clock,
                Failure::Access,
                Failure::Bounds,
                Failure::State,
                Failure::Binding,
                Failure::Present,
                Failure::Read,
                Failure::Write,
                Failure::Sync,
                Failure::Close,
                Failure::Child,
                Failure::Unknown,
            ] {
                let diagnostic = Diagnostic { stage, failure };
                for scope in [DiagnosticScope::Public, DiagnosticScope::Child] {
                    let line = diagnostic.line(scope);
                    assert!(line.len() < 192 && line.ends_with('\n'));
                    assert!(line[..line.len() - 1]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_=-;".contains(&b)));
                    assert_eq!(line.matches('\n').count(), 1);
                }
            }
        }
        assert_eq!(
            trace.first.unwrap().line(DiagnosticScope::Child),
            "MRK_XCODE_SETUP_REFUSED=scope=child;stage=copy;reason=write\n"
        );
        assert_eq!(
            trace.first.unwrap().line(DiagnosticScope::Public),
            "MRK_XCODE_SETUP_REFUSED=scope=public;stage=copy;reason=write\n"
        );
    }
    #[test]
    fn xcode_child_tail_is_one_use_and_lost_wait_never_reauthorizes_signals() {
        let now = Instant::now();
        let hard = now + Duration::from_secs(10);
        let mut tail = ChildTail::new();
        assert!(
            !tail.signal(now, hard, false),
            "signal before cleanup entry"
        );
        assert!(tail.begin());
        assert!(tail.signal(now, hard, false));
        assert!(!tail.signal(now, hard, false), "TERM once");
        assert!(tail.signal(now, hard, true));
        assert!(!tail.signal(now, hard, true), "KILL once");
        tail.lose_wait();
        assert_eq!(tail.finish(Err(Failure::Unknown)), Err(Failure::Unknown));
        assert!(!tail.begin());
        assert_eq!(tail.cached(), Err(Failure::Unknown));
        assert!(!tail.signal(now, hard, false));
        assert!(!tail.signal(now, hard, true));
        let mut lost = ChildTail::new();
        lost.lose_wait();
        assert!(lost.begin());
        assert!(!lost.signal(now, hard, false));
        assert!(!lost.signal(now, hard, true));
        let mut expired = ChildTail::new();
        assert!(expired.begin());
        assert!(!expired.signal(hard, hard, false));
        assert!(!expired.signal(hard, hard, true));
        let mut closed = ChildTail::new();
        assert!(closed.begin());
        assert_eq!(closed.finish(Ok(())), Ok(()));
        assert!(!closed.begin());
        assert_eq!(closed.cached(), Ok(()));
        assert!(!closed.signal(now, hard, false));
    }
    #[test]
    fn xcode_current_crash_cuts_are_closed_and_never_infer_old_finality() {
        for (bits, expected) in [
            ((false, false, false), Some(Current::Fresh)),
            ((false, true, true), Some(Current::Pending)),
            ((false, false, true), Some(Current::Attempt)),
            ((true, false, false), Some(Current::Final)),
            ((true, false, true), Some(Current::FinalAttempt)),
            ((true, true, true), Some(Current::FinalPending)),
            ((false, true, false), None),
            ((true, true, false), None),
        ] {
            assert_eq!(Current::observed(bits.0, bits.1, bits.2).ok(), expected);
        }
        assert!(!Current::Attempt.has_final());
        assert!(!Current::Attempt.has_pending());
        assert!(Current::Attempt.has_attempt());
        assert!(Current::FinalPending.has_final());
        assert!(Current::FinalPending.has_pending());
        assert!(Current::FinalPending.has_attempt());
    }
    #[test]
    fn xcode_current_retirement_binds_helper_namespace_final_and_optional_wrapper() {
        let mut r = record();
        let ns = r.reserved.namespace;
        let stage = r.reserved.staged;
        let pending = r.reserved.pending;
        let hash = "a".repeat(64);
        assert!(
            r.binds_current(ns, &hash, None, None),
            "attempt-only current cleanup uses no invented pending original"
        );
        assert!(
            !r.binds_current(ns, &hash, Some(stage), None),
            "Reserved never authorizes final cleanup"
        );
        r.add_copied(stage, "b".repeat(64)).unwrap();
        assert!(r.binds_current(ns, &hash, Some(stage), Some(pending)));
        assert!(
            r.binds_current(ns, &hash, Some(stage), None),
            "post-rmdir crash cut"
        );
        let foreign = Node {
            device: ns.device,
            inode: 99,
        };
        assert!(!r.binds_current(foreign, &hash, Some(stage), None));
        assert!(!r.binds_current(ns, &"c".repeat(64), Some(stage), None));
        assert!(!r.binds_current(ns, &hash, Some(foreign), None));
        assert!(!r.binds_current(ns, &hash, Some(stage), Some(foreign)));
    }
    #[test]
    fn xcode_attempt_is_exact_reserved_then_one_copied_not_finality() {
        let mut r = record();
        assert_eq!(Record::decode(&r.encode().unwrap()).unwrap(), r);
        r.add_copied(
            Node {
                device: 1,
                inode: 4,
            },
            "b".repeat(64),
        )
        .unwrap();
        let bytes = r.encode().unwrap();
        assert_eq!(Record::decode(&bytes).unwrap(), r);
        assert!(r
            .add_copied(
                Node {
                    device: 1,
                    inode: 5
                },
                "c".repeat(64)
            )
            .is_err());
        for cut in [0, 1, bytes.len() - 1] {
            assert!(Record::decode(&bytes[..cut]).is_err());
        }
        let mut extra = bytes.clone();
        extra.extend_from_slice(b"{}\n");
        assert!(Record::decode(&extra).is_err());
        let mut padded = bytes.clone();
        padded.insert(1, b' ');
        assert!(Record::decode(&padded).is_err());
        let mut wrong = r.clone();
        wrong.copied.as_mut().unwrap().id = "1".repeat(32);
        assert!(wrong.encode().is_err());
    }
    #[test]
    fn xcode_reserved_root_is_durable_exact_identity_not_a_name_or_old_format() {
        let r = record();
        assert!(r.binds_originals(r.reserved.namespace, r.reserved.pending, &"a".repeat(64)));
        assert!(!r.binds_originals(
            r.reserved.namespace,
            Node {
                device: 1,
                inode: 99
            },
            &"a".repeat(64)
        ));
        assert!(!r.binds_originals(r.reserved.namespace, r.reserved.pending, &"b".repeat(64)));
        let mut mismatch = r.clone();
        assert!(mismatch
            .add_copied(
                Node {
                    device: 1,
                    inode: 99
                },
                "b".repeat(64)
            )
            .is_err());
        assert_eq!(
            mismatch, r,
            "failed append cannot change the reserved identity"
        );
        let mut old: serde_json::Value = serde_json::from_slice(&r.encode().unwrap()).unwrap();
        old.as_object_mut().unwrap().remove("staged");
        let mut bytes = serde_json::to_vec(&old).unwrap();
        bytes.push(b'\n');
        assert!(
            Record::decode(&bytes).is_err(),
            "unrecorded stage never recovered by basename"
        );
        let mut foreign = r.clone();
        foreign.reserved.staged.device = 2;
        assert!(foreign.encode().is_err());
        let mut reused = r.clone();
        reused.reserved.staged = reused.reserved.pending;
        assert!(reused.encode().is_err());
    }
    #[test]
    fn xcode_parent_requires_actual_join_and_never_unknown_cleanup_credit() {
        let mut life = Lifecycle::new();
        life.reserve().unwrap();
        assert!(life.may_remove_empty_reservation());
        life.spawned().unwrap();
        life.output_complete = true;
        life.eof = true;
        life.exit_zero = true;
        assert!(life.joined().is_err());
        assert!(!life.may_remove_empty_reservation());
        life.controls_closed = true;
        life.joined().unwrap();
        life.copied().unwrap();
        life.published().unwrap();
        life.retired().unwrap();
        let mut unknown = Lifecycle::new();
        unknown.reserve().unwrap();
        unknown.unknown();
        assert!(!unknown.may_remove_empty_reservation());
        assert!(unknown.spawned().is_err());
    }
    #[test]
    fn xcode_parent_failure_cutoff_never_renews_original_work() {
        let now = Instant::now();
        let mut c = Clock::new(
            now + Duration::from_secs(10),
            now + Duration::from_secs(130),
            now + Duration::from_secs(140),
        )
        .unwrap();
        c.fail_at(now - Duration::from_secs(1));
        assert_eq!(c.finish, now + Duration::from_secs(119));
        assert!(c.point(false).is_err());
        assert!(c.point(true).is_ok());
        c.fail_at(now + Duration::from_secs(20));
        assert_eq!(c.finish, now + Duration::from_secs(119));
        assert_eq!(c.work, now + Duration::from_secs(10));
        let mut combined = Clock::new(
            now + Duration::from_secs(300),
            now + Duration::from_secs(420),
            now + Duration::from_secs(430),
        )
        .unwrap();
        combined.absorb(Some(now - Duration::from_secs(100)), true);
        assert_eq!(combined.finish, now + Duration::from_secs(20));
        assert_eq!(combined.hard, now + Duration::from_secs(30));
        // A subordinate that spent time closing may return much later; both
        // its original failure and the next owner's cutoff stay the earliest.
        combined.absorb(Some(now - Duration::from_secs(90)), true);
        combined.absorb(None, true);
        assert_eq!(combined.first, Some(now - Duration::from_secs(100)));
        assert_eq!(combined.finish, now + Duration::from_secs(20));
        assert_eq!(combined.hard, now + Duration::from_secs(30));
    }
}
