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
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    reserved: Reserved,
    copied: Option<Copied>,
}
impl Record {
    fn reserved(id: String, namespace: Node, pending: Node, source_sha256: String) -> Result<Self> {
        let out = Self {
            reserved: Reserved {
                id,
                kind: "reserved".into(),
                namespace,
                pending,
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
            || r.namespace.device != r.pending.device
            || !hex(&r.source_sha256, 64)
        {
            return Err(Failure::Binding);
        }
        if let Some(c) = &self.copied {
            if c.id != r.id
                || c.kind != "copied"
                || c.version != 1
                || !c.staged.valid()
                || c.staged.device != r.namespace.device
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
    use crate::{macos_xcode_copy as copy, macos_xcode_setup as profile};
    use mrk_macos_installed_native as abi;
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
            self.mode & libc::S_IFMT == libc::S_IFDIR
                && self.uid == 0
                && self.flags == 0
                && self.mode & 0o7022 == 0
                && mode.is_none_or(|mode| self.mode & 0o7777 == mode && self.gid == 0)
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
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Start {
        fds: [i32; 5],
        hard_ns: u64,
        finish_ns: u64,
        nodes: [Node; 5],
        nonce: String,
        parent: i32,
        version: u32,
        work_ns: u64,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report {
        nonce: String,
        staged: Node,
        tree_sha256: String,
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
        report: Option<Report>,
        unknown: bool,
    }
    impl Copier {
        fn spawn(executable: &str, loans: [i32; 5], clock: Clock, nonce: String) -> Result<Self> {
            if !hex(&nonce, 32) || loans.iter().any(|fd| *fd < 3) {
                return Err(Failure::Binding);
            }
            for (n, fd) in loans.iter().enumerate() {
                if loans[..n].contains(fd) {
                    return Err(Failure::Binding);
                }
            }
            let nodes =
                loans.map(|fd| fstat(unsafe { BorrowedFd::borrow_raw(fd) }).map(|s| s.node));
            let nodes = [nodes[0]?, nodes[1]?, nodes[2]?, nodes[3]?, nodes[4]?];
            let (work_ns, finish_ns, hard_ns) = wire_endpoints(&clock)?;
            let request = frame(&Start {
                fds: loans,
                hard_ns,
                finish_ns,
                nodes,
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
                        for fd in loans {
                            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
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
                    report: None,
                    unknown: !closed,
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
            let mut status = 0;
            let n = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if n == 0 {
                return Ok(());
            }
            if n != self.pid {
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
                || !report.staged.valid()
                || !hex(&report.tree_sha256, 64)
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
            // Never wait() without original hard bound. Once forwardwork
            // fails, stop child before any reservation cleanup/publication.
            let mut result = None;
            if !self.reaped {
                if unsafe { libc::kill(self.pid, libc::SIGTERM) } != 0 {
                    result = Some(Failure::Unknown);
                }
                let kill_at = Instant::now()
                    .checked_add(Duration::from_secs(1))
                    .map_or(self.clock.finish, |v| v.min(self.clock.finish));
                let mut killed = false;
                while !self.reaped && Instant::now() < self.clock.hard {
                    if !killed && Instant::now() >= kill_at {
                        killed = true;
                        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
                            result.get_or_insert(Failure::Unknown);
                        }
                    }
                    if let Err(e) = self.child_status() {
                        result.get_or_insert(e);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                if !self.reaped {
                    self.unknown = true;
                    result.get_or_insert(Failure::Unknown);
                }
            }
            if let Err(e) = self.close_endpoint() {
                result.get_or_insert(e);
            }
            if self.unknown {
                result.get_or_insert(Failure::Unknown);
            }
            result.map_or(Ok(()), Err)
        }
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
            self.absent(parent, name)?;
            if unsafe { libc::mkdirat(self.fd(parent)?.as_raw_fd(), c(name)?.as_ptr(), mode) } != 0
            {
                return Err(Failure::Write);
            }
            // Effect happened: a later failure never permits an eager unlink
            // using only this name. Original acquisition is required first.
            self.open(index, parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            if !self.original[index].is_some_and(|s| s.directory(Some(mode))) {
                return Err(Failure::Access);
            }
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
        fn admit_fresh(&mut self) -> Result<()> {
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
            for name in [profile::PENDING, profile::ATTEMPT, profile::APP] {
                self.absent(NAMESPACE, name)?;
            }
            if named(self.fd(NAMESPACE)?, &c(profile::LOCK)?)?.is_none() {
                self.roster(NAMESPACE, &[], false)?;
                self.create_control(LOCK, profile::LOCK)?;
                self.new_lock = true;
            } else {
                self.roster(NAMESPACE, &[profile::LOCK], false)?;
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
            self.roster(NAMESPACE, &[profile::LOCK], false)?;
            for name in [profile::PENDING, profile::ATTEMPT, profile::APP] {
                self.absent(NAMESPACE, name)?;
            }
            Ok(())
        }
        pub(crate) fn reserve(&mut self, id: String, source_sha256: String) -> Result<()> {
            let result = (|| -> Result<()> {
                if self.life.phase != Phase::New || !hex(&id, 32) || !hex(&source_sha256, 64) {
                    return Err(Failure::State);
                }
                self.admit_fresh()?;
                self.mkdir(NAMESPACE, profile::PENDING, PENDING, 0o700)?;
                self.own_pending = true;
                self.roster(PENDING, &[], false)?;
                self.create_control(ATTEMPT, profile::ATTEMPT)?;
                self.own_attempt = true;
                let record = Record::reserved(
                    id,
                    self.original[NAMESPACE].ok_or(Failure::Binding)?.node,
                    self.original[PENDING].ok_or(Failure::Binding)?.node,
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
                let child = Copier::spawn(executable, loans, self.clock, nonce)?;
                self.child = Some(child);
                self.life.spawned()?;
                let child = self.child.as_mut().ok_or(Failure::State)?;
                let worked = child.pump();
                if worked.is_err() {
                    child.clock.fail();
                }
                let settled = child.settle();
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
                self.open(
                    STAGED,
                    PENDING,
                    profile::APP,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                let staged = self.original[STAGED].ok_or(Failure::Binding)?;
                let report = self
                    .child
                    .as_ref()
                    .and_then(|c| c.report.as_ref())
                    .ok_or(Failure::State)?;
                if !staged.directory(Some(0o555)) || staged.node != report.staged {
                    return Err(Failure::Binding);
                }
                let mut record = self.record.clone().ok_or(Failure::State)?;
                record.add_copied(staged.node, report.tree_sha256.clone())?;
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
                    if child.settle().is_err() || !child.reaped || child.unknown {
                        self.unknown = true;
                        self.life.unknown();
                    }
                }
            }
            result
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
                if !self.life.may_remove_empty_reservation()
                    || !self.own_pending
                    || !self.own_attempt
                {
                    return Err(Failure::State);
                }
                self.roots(true)?;
                self.join(PENDING, NAMESPACE, profile::PENDING, true)?;
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
                if let Err(e) = child.settle() {
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
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use native::Namespace;

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
            "a".repeat(64),
        )
        .unwrap()
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
    }
}
