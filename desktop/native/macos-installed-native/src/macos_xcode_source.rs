//! Fixed extracted setup SOURCE originals; never signer or root authority.
//! Parent authenticates the signed package/executing identity separately and
//! must join children before this owner's roster POST or original settlement.
use std::time::{Duration, Instant};
const PROGRAM: &str = "mrk-macos-xcode-setup";
const SLOTS: usize = 16;
const SELF_LIMIT: usize = 64 * 1024 * 1024;
const BOM_LIMIT: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Shape,
    Clock,
    Access,
    Changed,
    Io,
    Close,
    Used,
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;
fn executable_parts(path: &str) -> Result<Vec<&str>> {
    if !path.starts_with('/') || path.len() > 4096 {
        return Err(Failure::Shape);
    }
    let parts: Vec<_> = path[1..].split('/').collect();
    if !(3..=10).contains(&parts.len())
        || parts.last() != Some(&PROGRAM)
        || parts[parts.len() - 2] != "setup"
        || parts.iter().any(|s| {
            s.is_empty()
                || *s == "."
                || *s == ".."
                || s.len() > 255
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-+ ".contains(&b))
        })
    {
        return Err(Failure::Shape);
    }
    // Root + every directory/file in the path + pre/post/Bom.
    if parts.len() + 4 > SLOTS {
        return Err(Failure::Shape);
    }
    Ok(parts)
}
fn ancestor_allowed(mode: u16, uid: u32, previous_sticky: bool) -> bool {
    uid == 0
        && mode & 0o170000 == 0o040000
        && mode & 0o6000 == 0
        && if previous_sticky {
            mode & 0o1022 == 0
        } else {
            mode & 0o022 == 0 || mode & 0o1000 != 0
        }
}
#[derive(Clone, Copy)]
struct Clock {
    work: Instant,
    finish: Instant,
    first: Option<Instant>,
    last: Instant,
    regressed: bool,
}
impl Clock {
    fn new(work: Instant, finish: Instant) -> Result<Self> {
        let now = Instant::now();
        if now >= work || work >= finish {
            return Err(Failure::Clock);
        }
        Ok(Self {
            work,
            finish,
            first: None,
            last: now,
            regressed: false,
        })
    }
    fn point(&mut self, cleanup: bool) -> Result<()> {
        let now = Instant::now();
        let limit = if cleanup { self.finish } else { self.work };
        self.regressed |= now < self.last;
        let ok = !self.regressed && now < limit;
        self.last = self.last.max(now);
        if ok {
            Ok(())
        } else {
            Err(Failure::Clock)
        }
    }
    fn fail_at(&mut self, at: Instant) {
        let at = self.first.map_or(at, |old| old.min(at));
        self.first = Some(at);
        if let Some(cut) = at.checked_add(Duration::from_secs(120)) {
            self.finish = self.finish.min(cut);
        }
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
    use nix::{libc, mount::MntFlags, sys::statfs};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::{CStr, CString},
        os::fd::{AsRawFd, BorrowedFd},
    };
    const PRE: &[u8] = include_bytes!("../../../macos-xcode-setup-inputs/preinstall");
    const POST: &[u8] = include_bytes!("../../../macos-xcode-setup-inputs/setup/postinstall");
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Identity {
        dev: libc::dev_t,
        ino: libc::ino_t,
        mode: libc::mode_t,
        uid: u32,
        gid: u32,
        links: libc::nlink_t,
        size: libc::off_t,
        flags: u32,
        gen: u32,
        mt: libc::time_t,
        mn: libc::c_long,
        ct: libc::time_t,
        cn: libc::c_long,
    }
    impl Identity {
        fn from(s: libc::stat) -> Self {
            Self {
                dev: s.st_dev,
                ino: s.st_ino,
                mode: s.st_mode,
                uid: s.st_uid,
                gid: s.st_gid,
                links: s.st_nlink,
                size: s.st_size,
                flags: s.st_flags,
                gen: s.st_gen,
                mt: s.st_mtime,
                mn: s.st_mtime_nsec,
                ct: s.st_ctime,
                cn: s.st_ctime_nsec,
            }
        }
        fn same_directory(self, other: Self) -> bool {
            self.dev == other.dev
                && self.ino == other.ino
                && self.mode == other.mode
                && self.uid == other.uid
                && self.gid == other.gid
                && self.flags == other.flags
                && self.gen == other.gen
        }
    }
    fn stat(fd: BorrowedFd<'_>) -> Result<Identity> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), s.as_mut_ptr()) } != 0 {
            return Err(Failure::Io);
        }
        Ok(Identity::from(unsafe { s.assume_init() }))
    }
    fn named(parent: libc::c_int, name: &CStr) -> Result<Identity> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                s.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(Failure::Io);
        }
        Ok(Identity::from(unsafe { s.assume_init() }))
    }
    #[derive(Clone, Copy)]
    enum State {
        Reserved,
        Held(libc::c_int),
        Closed,
        Unknown,
    }
    struct Original {
        state: State,
        parent: libc::c_int,
        name: CString,
        id: Option<Identity>,
        dir: bool,
        exact: Option<u16>,
        ancestor: bool,
        previous_sticky: bool,
        digest: Option<[u8; 32]>,
    }
    pub(crate) struct SetupSource {
        clock: Clock,
        originals: [Option<Original>; SLOTS],
        path: Option<String>,
        script: Option<usize>,
        setup: Option<usize>,
        image: Option<usize>,
        used: bool,
        admitted: bool,
        settled: bool,
        settlement_entered: bool,
        failed: bool,
        unknown: bool,
    }
    impl SetupSource {
        pub(crate) fn new(work: Instant, finish: Instant) -> Result<Self> {
            Ok(Self {
                clock: Clock::new(work, finish)?,
                originals: std::array::from_fn(|_| None),
                path: None,
                script: None,
                setup: None,
                image: None,
                used: false,
                admitted: false,
                settled: false,
                settlement_entered: false,
                failed: false,
                unknown: false,
            })
        }
        fn point(&mut self, cleanup: bool) -> Result<()> {
            let result = self.clock.point(cleanup);
            if self.clock.regressed {
                self.unknown = true;
            }
            if result.is_err() {
                self.failed();
            }
            result
        }
        fn failed(&mut self) {
            self.failed = true;
            self.clock.fail_at(Instant::now());
        }
        fn fd(&self, n: usize) -> Result<BorrowedFd<'_>> {
            match self
                .originals
                .get(n)
                .and_then(Option::as_ref)
                .map(|v| v.state)
            {
                Some(State::Held(fd)) => Ok(unsafe { BorrowedFd::borrow_raw(fd) }),
                _ => Err(Failure::Changed),
            }
        }
        fn id(&self, n: usize) -> Result<Identity> {
            self.originals[n]
                .as_ref()
                .and_then(|v| v.id)
                .ok_or(Failure::Changed)
        }
        fn check(&mut self, n: usize, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let o = self.originals[n].as_ref().ok_or(Failure::Changed)?;
            let before = o.id.ok_or(Failure::Changed)?;
            let (parent, name, ancestor, dir, exact, previous_sticky) = (
                o.parent,
                o.name.clone(),
                o.ancestor,
                o.dir,
                o.exact,
                o.previous_sticky,
            );
            let actual = stat(self.fd(n)?)?;
            self.point(cleanup)?;
            let name = named(parent, &name)?;
            self.point(cleanup)?;
            let same = if ancestor {
                before.same_directory(actual) && before.same_directory(name)
            } else {
                before == actual && before == name
            };
            if !same || actual.ino == 0 || actual.size < 0 || actual.links == 0 {
                return Err(Failure::Changed);
            }
            if ancestor {
                if !ancestor_allowed(actual.mode, actual.uid, previous_sticky) {
                    return Err(Failure::Access);
                }
            } else {
                let kind = if dir { libc::S_IFDIR } else { libc::S_IFREG };
                if actual.uid != 0
                    || actual.gid != 0
                    || actual.mode != (kind | exact.ok_or(Failure::Shape)?)
                {
                    return Err(Failure::Access);
                }
            }
            if !dir && (actual.links != 1 || actual.flags != 0) {
                return Err(Failure::Access);
            }
            let acl = abi::empty_acl_observed(self.fd(n)?);
            if let Err(ref failure) = acl {
                if failure.free_result != 0 || failure.refusal_code.is_none() {
                    self.unknown = true;
                }
            }
            self.point(cleanup)?;
            acl.map_err(|_| Failure::Access)?;
            if !ancestor {
                let attributes = abi::no_xattrs(self.fd(n)?);
                self.point(cleanup)?;
                attributes.map_err(|_| Failure::Access)?;
            }
            let fs = statfs::fstatfs(self.fd(n)?);
            self.point(cleanup)?;
            let fs = fs.map_err(|_| Failure::Access)?;
            if fs.filesystem_type_name() != "apfs"
                || !fs.flags().contains(MntFlags::MNT_LOCAL)
                || fs.flags().intersects(
                    MntFlags::MNT_UNION
                        | MntFlags::MNT_AUTOMOUNTED
                        | MntFlags::MNT_IGNORE_OWNERSHIP,
                )
            {
                return Err(Failure::Access);
            }
            Ok(())
        }
        fn open(
            &mut self,
            parent: libc::c_int,
            name: &str,
            dir: bool,
            exact: Option<u16>,
            ancestor: bool,
            previous_sticky: bool,
        ) -> Result<usize> {
            self.point(false)?;
            let name = CString::new(name).map_err(|_| Failure::Shape)?;
            let n = self
                .originals
                .iter()
                .position(Option::is_none)
                .ok_or(Failure::Shape)?;
            let before = named(parent, &name)?;
            self.point(false)?;
            if before.mode & libc::S_IFMT != if dir { libc::S_IFDIR } else { libc::S_IFREG } {
                return Err(Failure::Shape);
            }
            self.originals[n] = Some(Original {
                state: State::Reserved,
                parent,
                name,
                id: None,
                dir,
                exact,
                ancestor,
                previous_sticky,
                digest: None,
            });
            let flags = libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if dir { libc::O_DIRECTORY } else { 0 };
            self.point(false)?;
            let fd = unsafe {
                libc::openat(
                    parent,
                    self.originals[n].as_ref().unwrap().name.as_ptr(),
                    flags,
                )
            };
            self.originals[n].as_mut().unwrap().state = if fd < 0 {
                State::Closed
            } else {
                State::Held(fd)
            };
            self.point(false)?;
            if fd < 0 {
                return Err(Failure::Io);
            }
            let actual = stat(self.fd(n)?)?;
            self.point(false)?;
            self.originals[n].as_mut().unwrap().id = Some(actual);
            if before != actual {
                return Err(Failure::Changed);
            }
            self.check(n, false)?;
            Ok(n)
        }
        fn read(
            &mut self,
            n: usize,
            limit: usize,
            expected: Option<&[u8]>,
            cleanup: bool,
        ) -> Result<[u8; 32]> {
            self.check(n, cleanup)?;
            let id = self.id(n)?;
            if id.size <= 0
                || id.size as u64 > limit as u64
                || expected.is_some_and(|v| v.len() != id.size as usize)
            {
                return Err(Failure::Shape);
            }
            let mut hash = Sha256::new();
            let mut offset = 0usize;
            let mut buffer = [0u8; 65536];
            loop {
                self.point(cleanup)?;
                let used = unsafe {
                    libc::pread(
                        self.fd(n)?.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        offset as libc::off_t,
                    )
                };
                let error = std::io::Error::last_os_error();
                self.point(cleanup)?;
                if used < 0 {
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(Failure::Io);
                }
                if used == 0 {
                    break;
                }
                let end = offset
                    .checked_add(used as usize)
                    .filter(|v| *v <= id.size as usize)
                    .ok_or(Failure::Changed)?;
                if let Some(bytes) = expected {
                    if bytes[offset..end] != buffer[..used as usize] {
                        return Err(Failure::Changed);
                    }
                }
                hash.update(&buffer[..used as usize]);
                offset = end;
            }
            if offset != id.size as usize {
                return Err(Failure::Changed);
            }
            self.check(n, cleanup)?;
            Ok(hash.finalize().into())
        }
        fn roster(&mut self, parent: usize, children: &[usize], cleanup: bool) -> Result<()> {
            self.check(parent, cleanup)?;
            self.point(cleanup)?;
            if unsafe { libc::lseek(self.fd(parent)?.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
                return Err(Failure::Io);
            }
            let mut buffer = [0u8; 65536];
            let mut mask = 0u8;
            let mut records = 0;
            loop {
                self.point(cleanup)?;
                let used =
                    abi::directory_block(self.fd(parent)?, &mut buffer).map_err(|_| Failure::Io)?;
                self.point(cleanup)?;
                if used == 0 {
                    break;
                }
                let mut offset = 0;
                while offset < used {
                    if used - offset < 11 {
                        return Err(Failure::Shape);
                    }
                    records += 1;
                    if records > 8 {
                        return Err(Failure::Shape);
                    }
                    let ino = u64::from_ne_bytes(
                        buffer[offset..offset + 8]
                            .try_into()
                            .map_err(|_| Failure::Shape)?,
                    );
                    let kind = buffer[offset + 8];
                    let len =
                        u16::from_ne_bytes([buffer[offset + 9], buffer[offset + 10]]) as usize;
                    let end = offset
                        .checked_add(11 + len)
                        .filter(|v| *v <= used)
                        .ok_or(Failure::Shape)?;
                    let name = &buffer[offset + 11..end];
                    offset = end;
                    if name == b"." || name == b".." {
                        continue;
                    }
                    let found = children
                        .iter()
                        .position(|n| {
                            self.originals[*n]
                                .as_ref()
                                .is_some_and(|v| v.name.to_bytes() == name)
                        })
                        .ok_or(Failure::Changed)?;
                    let child = self.originals[children[found]]
                        .as_ref()
                        .ok_or(Failure::Changed)?;
                    if mask & (1 << found) != 0
                        || ino != self.id(children[found])?.ino
                        || kind
                            != if child.dir {
                                libc::DT_DIR
                            } else {
                                libc::DT_REG
                            }
                    {
                        return Err(Failure::Changed);
                    }
                    mask |= 1 << found;
                }
            }
            if mask != (1 << children.len()) - 1 {
                return Err(Failure::Changed);
            }
            self.check(parent, cleanup)
        }
        pub(crate) fn admit(&mut self) -> Result<()> {
            if self.used || self.settlement_entered {
                self.failed();
                return Err(Failure::Used);
            }
            self.used = true;
            let result = self.admit_inner();
            if result.is_err() {
                self.failed();
            }
            result
        }
        fn admit_inner(&mut self) -> Result<()> {
            self.point(false)?;
            if unsafe { libc::getuid() } != 0
                || unsafe { libc::geteuid() } != 0
                || unsafe { libc::getgid() } != 0
                || unsafe { libc::getegid() } != 0
            {
                return Err(Failure::Access);
            }
            abi::platform().map_err(|_| Failure::Access)?;
            self.point(false)?;
            let actual = std::env::current_exe().map_err(|_| Failure::Io)?;
            self.point(false)?;
            let path = actual.to_str().ok_or(Failure::Shape)?.to_owned();
            let parts = executable_parts(&path)?;
            let mut parent = self.open(libc::AT_FDCWD, "/", true, None, true, false)?;
            for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
                let is_setup = i == parts.len() - 2;
                let is_script = i == parts.len() - 3;
                let sticky = self.id(parent)?.mode & 0o1022 != 0;
                parent = self.open(
                    self.fd(parent)?.as_raw_fd(),
                    part,
                    true,
                    if is_setup {
                        Some(0o555)
                    } else if is_script {
                        Some(0o755)
                    } else {
                        None
                    },
                    !is_setup && !is_script,
                    sticky,
                )?;
                if is_script {
                    self.script = Some(parent);
                }
                if is_setup {
                    self.setup = Some(parent);
                }
            }
            let image = self.open(
                self.fd(parent)?.as_raw_fd(),
                PROGRAM,
                false,
                Some(0o555),
                false,
                false,
            )?;
            self.image = Some(image);
            self.path = Some(path);
            let script = self.script.ok_or(Failure::Shape)?;
            let setup = self.setup.ok_or(Failure::Shape)?;
            let pre = self.open(
                self.fd(script)?.as_raw_fd(),
                "preinstall",
                false,
                Some(0o555),
                false,
                false,
            )?;
            let post = self.open(
                self.fd(setup)?.as_raw_fd(),
                "postinstall",
                false,
                Some(0o555),
                false,
                false,
            )?;
            let bom = self.open(
                self.fd(setup)?.as_raw_fd(),
                "carrier.bom",
                false,
                Some(0o444),
                false,
                false,
            )?;
            for (n, limit, bytes) in [
                (image, SELF_LIMIT, None),
                (pre, PRE.len(), Some(PRE)),
                (post, POST.len(), Some(POST)),
                (bom, BOM_LIMIT, None),
            ] {
                let digest = self.read(n, limit, bytes, false)?;
                self.originals[n].as_mut().unwrap().digest = Some(digest);
            }
            self.roster(script, &[pre, setup], false)?;
            self.roster(setup, &[post, image, bom], false)?;
            self.post_inner(false)?;
            self.admitted = true;
            Ok(())
        }
        fn post_inner(&mut self, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            if std::env::current_exe().map_err(|_| Failure::Io)?.to_str() != self.path.as_deref() {
                return Err(Failure::Changed);
            }
            self.point(cleanup)?;
            for n in 0..SLOTS {
                let Some(o) = self.originals[n].as_ref() else {
                    continue;
                };
                if !matches!(o.state, State::Held(_)) {
                    continue;
                }
                let digest = o.digest;
                let name = o.name.clone();
                self.check(n, cleanup)?;
                if let Some(expected) = digest {
                    let (limit, bytes) = match name.to_bytes() {
                        b"preinstall" => (PRE.len(), Some(PRE)),
                        b"postinstall" => (POST.len(), Some(POST)),
                        b"carrier.bom" => (BOM_LIMIT, None),
                        _ => (SELF_LIMIT, None),
                    };
                    if self.read(n, limit, bytes, cleanup)? != expected {
                        return Err(Failure::Changed);
                    }
                }
            }
            if let (Some(script), Some(setup), Some(image)) = (self.script, self.setup, self.image)
            {
                let child = |parent: usize, name: &[u8]| {
                    let raw = self.fd(parent)?.as_raw_fd();
                    self.originals
                        .iter()
                        .position(|v| {
                            v.as_ref().is_some_and(|o| {
                                !o.dir && o.parent == raw && o.name.to_bytes() == name
                            })
                        })
                        .ok_or(Failure::Changed)
                };
                let (pre, post, bom) = (
                    child(script, b"preinstall")?,
                    child(setup, b"postinstall")?,
                    child(setup, b"carrier.bom")?,
                );
                self.roster(script, &[pre, setup], cleanup)?;
                self.roster(setup, &[post, image, bom], cleanup)?;
            }
            self.point(cleanup)
        }
        pub(crate) fn post(&mut self) -> Result<()> {
            if !self.admitted || self.settlement_entered || self.failed {
                return Err(Failure::Used);
            }
            let result = self.post_inner(false);
            if result.is_err() {
                self.failed();
            }
            result
        }
        fn loan(&self, n: Option<usize>) -> Result<BorrowedFd<'_>> {
            if !self.admitted
                || self.settlement_entered
                || self.failed
                || Instant::now() >= self.clock.work
            {
                return Err(Failure::Used);
            }
            self.fd(n.ok_or(Failure::Changed)?)
        }
        pub(crate) fn setup(&self) -> Result<BorrowedFd<'_>> {
            self.loan(self.setup)
        }
        pub(crate) fn image(&self) -> Result<BorrowedFd<'_>> {
            self.loan(self.image)
        }
        /// DATA from this admitted original image, not signer/package authority.
        /// The caller still owes genuine SELF verification and final source POST.
        pub(crate) fn image_sha256(&mut self) -> Result<[u8; 32]> {
            if self.unknown {
                return Err(Failure::Used);
            }
            self.loan(self.image)?;
            self.point(false)?;
            self.originals[self.image.ok_or(Failure::Changed)?]
                .as_ref()
                .and_then(|o| o.digest)
                .ok_or(Failure::Changed)
        }
        pub(crate) fn executable(&self) -> Result<&str> {
            self.loan(self.image)?;
            self.path.as_deref().ok_or(Failure::Changed)
        }
        pub(crate) fn held_count(&self) -> usize {
            self.originals
                .iter()
                .flatten()
                .filter(|o| matches!(o.state, State::Held(_) | State::Reserved | State::Unknown))
                .count()
        }
        pub(crate) fn first_failure(&self) -> Option<Instant> {
            self.clock.first
        }
        /// Original Parent calls only after all borrowed consumers have joined.
        /// Close accounting remains independent of an earlier admission refusal.
        pub(crate) fn settle(&mut self, parent_first: Option<Instant>) -> Result<()> {
            if self.settlement_entered {
                return Err(Failure::Used);
            }
            self.settlement_entered = true;
            if let Some(at) = parent_first {
                self.failed = true;
                if at > Instant::now() {
                    self.unknown = true;
                    self.clock.fail_at(Instant::now());
                } else {
                    self.clock.fail_at(at);
                }
            }
            if self.admitted {
                if self.post_inner(true).is_err() {
                    self.failed();
                }
            }
            let mut close_failed = false;
            for n in (0..SLOTS).rev() {
                let Some(o) = self.originals[n].as_ref() else {
                    continue;
                };
                let state = o.state;
                match state {
                    State::Held(fd) => {
                        if self.point(true).is_err() {
                            self.failed();
                            close_failed = true;
                            continue;
                        }
                        self.originals[n].as_mut().unwrap().state = State::Unknown;
                        let returned = unsafe { libc::close(fd) };
                        if returned == 0 {
                            self.originals[n].as_mut().unwrap().state = State::Closed;
                        } else {
                            self.unknown = true;
                            self.failed();
                            close_failed = true;
                        }
                        if self.point(true).is_err() {
                            self.failed();
                            close_failed = true;
                        }
                    }
                    State::Reserved => self.originals[n].as_mut().unwrap().state = State::Closed,
                    State::Unknown => {
                        self.unknown = true;
                        close_failed = true;
                    }
                    State::Closed => (),
                }
            }
            if self.point(true).is_err() {
                close_failed = true;
            }
            self.settled = self.held_count() == 0 && !self.unknown && !close_failed;
            if close_failed || !self.settled {
                Err(Failure::Close)
            } else {
                Ok(())
            }
        }
        /// Timely cleanup finality; held_count separately reports known FD closes.
        pub(crate) fn settled(&self) -> bool {
            self.settled
        }
        pub(crate) fn accepted(&self) -> bool {
            self.admitted
                && self.settled
                && !self.failed
                && !self.unknown
                && Instant::now() < self.clock.work
        }
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use native::SetupSource;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_source_grammar_and_actual_slot_budget() {
        assert!(executable_parts("/Library/InstallerSandboxes/.PKInstallSandboxManager/a/Scripts/pkg/setup/mrk-macos-xcode-setup").is_ok());
        assert!(executable_parts(
            "/private/tmp/PKInstallSandbox.a/Scripts/package/setup/mrk-macos-xcode-setup"
        )
        .is_ok());
        for path in [
            "/setup/mrk-macos-xcode-setup",
            "/tmp/x/setup/other",
            "/tmp/x/../setup/mrk-macos-xcode-setup",
            "/tmp//x/setup/mrk-macos-xcode-setup",
            "relative/setup/mrk-macos-xcode-setup",
            "/tmp/x\n/setup/mrk-macos-xcode-setup",
            "/a/b/c/d/e/f/g/h/i/setup/mrk-macos-xcode-setup",
        ] {
            assert!(executable_parts(path).is_err(), "{path}");
        }
    }
    #[test]
    fn temporary_ancestor_requires_root_sticky_and_protected_next() {
        assert!(ancestor_allowed(0o041777, 0, false));
        assert!(ancestor_allowed(0o040700, 0, true));
        assert!(ancestor_allowed(0o040755, 0, false));
        for (mode, uid, sticky) in [
            (0o040777, 0, false),
            (0o041777, 501, false),
            (0o041777, 0, true),
            (0o040775, 0, true),
            (0o042755, 0, false),
            (0o120755, 0, false),
        ] {
            assert!(!ancestor_allowed(mode, uid, sticky));
        }
    }
    #[test]
    fn cleanup_keeps_earliest_failure_and_original_cutoff() {
        let now = Instant::now();
        let mut clock = Clock::new(
            now + Duration::from_secs(3600),
            now + Duration::from_secs(3720),
        )
        .unwrap();
        clock.fail_at(now + Duration::from_secs(10));
        clock.fail_at(now + Duration::from_secs(20));
        assert_eq!(clock.first, Some(now + Duration::from_secs(10)));
        assert_eq!(clock.finish, now + Duration::from_secs(130));
        clock.fail_at(now + Duration::from_secs(5));
        assert_eq!(clock.finish, now + Duration::from_secs(125));
        assert!(clock.point(true).is_ok());
        assert!(Clock::new(now, now + Duration::from_secs(1)).is_err());
        clock.last = now + Duration::from_secs(5);
        assert!(clock.point(true).is_err());
        assert!(clock.regressed);
        clock.last = now;
        assert!(clock.point(true).is_err()); // cannot clear regression
    }
}
