//! Fixed read-only Xcode version/SDK observations, never execution authority.
//! Caller owns bundle/ancestor/Apple signature/census and the child's original H.
//! All returned DATA is provisional until POST and positive original settlement.
use plist::stream::{BinaryReader, Event, XmlReader};
use std::{
    collections::BTreeSet,
    io::Cursor,
    time::{Duration, Instant},
};

pub(crate) const OWNED_FDS: usize = 8;
// Two64KiB body copies, plist offset/scalar storage, XML buffers and8FD records.
// Native allocator/kernel consumption is not claimed by this owned-space quote.
pub(crate) const OWNED_BYTES: usize = 2 * 1024 * 1024;
const BODY_LIMIT: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Shape,
    Clock,
    Changed,
    Io,
    Close,
    Used,
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observed {
    pub(crate) version: String,
    pub(crate) build: String,
    pub(crate) sdk_leaf: String,
}

fn version_data(version: &str, build: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !build.is_empty()
        && build.len() <= 64
        && version
            .split('.')
            .enumerate()
            .all(|(n, p)| n < 3 && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && build.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn sdk_data(leaf: &str) -> bool {
    leaf == "iPhoneOS.sdk" || crate::ios_sdk_selection::sdk_sibling_target(leaf).is_some()
}

// plist's XML event reader deliberately ignores the plist envelope. Validate
// that envelope with its existing tokenizer, not a new XML/plist decoder.
fn xml_envelope(body: &[u8], point: &mut impl FnMut() -> Result<()>) -> Result<()> {
    use quick_xml::{events::Event as X, Reader};
    let mut reader = Reader::from_reader(body);
    let mut depth = 0usize;
    let mut started = false;
    let mut ended = false;
    let mut events = 0;
    loop {
        point()?;
        let event = reader.read_event().map_err(|_| Failure::Shape)?;
        point()?;
        events += 1;
        if events > 512 {
            return Err(Failure::Shape);
        }
        match event {
            X::Start(ref e) => {
                if ended || depth == 0 && (started || e.name().as_ref() != "plist") {
                    return Err(Failure::Shape);
                }
                started = true;
                depth += 1;
                if depth > 3 {
                    return Err(Failure::Shape);
                }
            }
            X::Empty(_) if depth == 0 || ended => return Err(Failure::Shape),
            X::End(_) => {
                depth = depth.checked_sub(1).ok_or(Failure::Shape)?;
                if depth == 0 {
                    ended = true;
                }
            }
            X::Text(ref t)
                if depth == 0 && !t.as_ref().bytes().all(|b| b.is_ascii_whitespace()) =>
            {
                return Err(Failure::Shape)
            }
            X::Decl(_) | X::DocType(_) if started => return Err(Failure::Shape),
            X::CData(_) | X::GeneralRef(_) if depth == 0 => return Err(Failure::Shape),
            X::Eof => break,
            _ => (),
        }
    }
    if started && ended && depth == 0 {
        Ok(())
    } else {
        Err(Failure::Shape)
    }
}
fn version_plist(body: &[u8], mut point: impl FnMut() -> Result<()>) -> Result<(String, String)> {
    point()?;
    if body.is_empty() || body.len() > BODY_LIMIT {
        return Err(Failure::Shape);
    }
    let binary = body.starts_with(b"bplist00");
    if !binary {
        xml_envelope(body, &mut point)?;
    }
    let mut reader: Box<
        dyn Iterator<Item = std::result::Result<Event<'static>, plist::Error>> + '_,
    > = if binary {
        Box::new(BinaryReader::new(Cursor::new(body)))
    } else {
        Box::new(XmlReader::new(body))
    };
    let mut started = false;
    let mut ended = false;
    let mut keys = BTreeSet::new();
    let mut pending: Option<String> = None;
    let mut version = None;
    let mut build = None;
    let mut events = 0usize;
    loop {
        point()?;
        let item = reader.next();
        point()?;
        let Some(item) = item else {
            break;
        };
        let item = item.map_err(|_| Failure::Shape)?;
        events += 1;
        if events > 256 || ended {
            return Err(Failure::Shape);
        }
        if !started {
            if !matches!(
                item,
                Event::StartDictionary(None) | Event::StartDictionary(Some(0..=64))
            ) {
                return Err(Failure::Shape);
            }
            started = true;
            continue;
        }
        if let Some(key) = pending.take() {
            match &item {
                Event::String(s) if s.len() <= 4096 => (),
                Event::Data(b) if b.len() <= 4096 => (),
                Event::Boolean(_) | Event::Integer(_) | Event::Real(_) | Event::Date(_) => (),
                _ => return Err(Failure::Shape),
            }
            if key == "CFBundleShortVersionString" || key == "ProductBuildVersion" {
                let Event::String(s) = item else {
                    return Err(Failure::Shape);
                };
                if s.len() > 64 {
                    return Err(Failure::Shape);
                }
                if key == "CFBundleShortVersionString" {
                    version = Some(s.into_owned());
                } else {
                    build = Some(s.into_owned());
                }
            }
        } else {
            match item {
                Event::String(key) if !key.is_empty() && key.len() <= 128 && keys.len() < 64 => {
                    if !keys.insert(key.to_string()) {
                        return Err(Failure::Shape);
                    }
                    pending = Some(key.into_owned());
                }
                Event::EndCollection => ended = true,
                _ => return Err(Failure::Shape),
            }
        }
    }
    point()?;
    let (Some(version), Some(build)) = (version, build) else {
        return Err(Failure::Shape);
    };
    if !ended || pending.is_some() || !version_data(&version, &build) {
        return Err(Failure::Shape);
    }
    Ok((version, build))
}

#[derive(Clone, Copy)]
struct Clock {
    work: Instant,
    finish: Instant,
    last: Instant,
    first: Option<Instant>,
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
            last: now,
            first: None,
            regressed: false,
        })
    }
    fn point_at(&mut self, now: Instant, cleanup: bool) -> Result<()> {
        self.regressed |= now < self.last;
        self.last = self.last.max(now);
        if self.regressed || now >= if cleanup { self.finish } else { self.work } {
            Err(Failure::Clock)
        } else {
            Ok(())
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
    use nix::libc;
    use std::{
        ffi::{CStr, CString},
        os::fd::{AsRawFd, BorrowedFd},
    };
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
        fn of(s: libc::stat) -> Self {
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
    }
    fn held(fd: libc::c_int) -> Result<Identity> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, s.as_mut_ptr()) } != 0 {
            return Err(Failure::Io);
        }
        Ok(Identity::of(unsafe { s.assume_init() }))
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
        Ok(Identity::of(unsafe { s.assume_init() }))
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
    }
    struct Alias {
        parent: libc::c_int,
        id: Identity,
        bytes: Vec<u8>,
    }
    pub(crate) struct Facts<'a> {
        app: Option<BorrowedFd<'a>>,
        app_id: Option<Identity>,
        clock: Clock,
        slots: [Option<Original>; OWNED_FDS],
        alias: Option<Alias>,
        body: Option<Vec<u8>>,
        observed: Option<Observed>,
        used: bool,
        posted: bool,
        failed: bool,
        settlement_entered: bool,
        settled: bool,
        unknown: bool,
    }
    impl<'a> Facts<'a> {
        pub(crate) fn new(work: Instant, finish: Instant) -> Result<Self> {
            Ok(Self {
                app: None,
                app_id: None,
                clock: Clock::new(work, finish)?,
                slots: std::array::from_fn(|_| None),
                alias: None,
                body: None,
                observed: None,
                used: false,
                posted: false,
                failed: false,
                settlement_entered: false,
                settled: false,
                unknown: false,
            })
        }
        fn fail(&mut self) {
            self.failed = true;
            self.clock.fail_at(Instant::now());
        }
        fn point(&mut self, cleanup: bool) -> Result<()> {
            let result = self.clock.point_at(Instant::now(), cleanup);
            if self.clock.regressed {
                self.unknown = true;
            }
            if result.is_err() {
                self.fail();
            }
            result
        }
        fn fd(&self, n: usize) -> Result<libc::c_int> {
            match self.slots.get(n).and_then(Option::as_ref).map(|s| s.state) {
                Some(State::Held(fd)) => Ok(fd),
                _ => Err(Failure::Changed),
            }
        }
        fn app_post(&mut self, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let id = held(self.app.ok_or(Failure::Used)?.as_raw_fd())?;
            self.point(cleanup)?;
            if Some(id) != self.app_id {
                return Err(Failure::Changed);
            }
            Ok(())
        }
        fn check(&mut self, n: usize, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let o = self.slots[n].as_ref().ok_or(Failure::Used)?;
            let (parent, name, id, dir) = (o.parent, o.name.clone(), o.id, o.dir);
            let actual = held(self.fd(n)?)?;
            self.point(cleanup)?;
            let current = named(parent, &name)?;
            self.point(cleanup)?;
            if id != Some(actual)
                || actual != current
                || actual.dev != self.app_id.ok_or(Failure::Used)?.dev
                || actual.ino == 0
                || actual.links == 0
                || actual.size < 0
                || actual.mode & libc::S_IFMT != if dir { libc::S_IFDIR } else { libc::S_IFREG }
            {
                return Err(Failure::Changed);
            }
            Ok(())
        }
        fn open(&mut self, parent: libc::c_int, name: &str, dir: bool) -> Result<usize> {
            self.point(false)?;
            let name = CString::new(name).map_err(|_| Failure::Shape)?;
            let n = self
                .slots
                .iter()
                .position(Option::is_none)
                .ok_or(Failure::Shape)?;
            let before = named(parent, &name)?;
            self.point(false)?;
            if before.mode & libc::S_IFMT != if dir { libc::S_IFDIR } else { libc::S_IFREG } {
                return Err(Failure::Shape);
            }
            self.slots[n] = Some(Original {
                state: State::Reserved,
                parent,
                name,
                id: None,
                dir,
            });
            self.point(false)?;
            let fd = unsafe {
                libc::openat(
                    parent,
                    self.slots[n].as_ref().unwrap().name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | if dir { libc::O_DIRECTORY } else { 0 },
                )
            };
            self.slots[n].as_mut().unwrap().state = if fd < 0 {
                State::Closed
            } else {
                State::Held(fd)
            };
            self.point(false)?;
            if fd < 0 {
                return Err(Failure::Io);
            }
            let id = held(fd)?;
            self.slots[n].as_mut().unwrap().id = Some(id);
            self.point(false)?;
            if id != before {
                return Err(Failure::Changed);
            }
            self.check(n, false)?;
            Ok(n)
        }
        fn read_body(&mut self, n: usize, cleanup: bool) -> Result<Vec<u8>> {
            self.check(n, cleanup)?;
            let size = self.slots[n]
                .as_ref()
                .and_then(|o| o.id)
                .ok_or(Failure::Changed)?
                .size;
            if size <= 0 || size as u64 > BODY_LIMIT as u64 {
                return Err(Failure::Shape);
            }
            let mut body = vec![0u8; size as usize];
            let mut offset = 0;
            while offset < body.len() {
                self.point(cleanup)?;
                let count = unsafe {
                    libc::pread(
                        self.fd(n)?,
                        body[offset..].as_mut_ptr().cast(),
                        body.len() - offset,
                        offset as libc::off_t,
                    )
                };
                let err = std::io::Error::last_os_error();
                self.point(cleanup)?;
                if count < 0 {
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(Failure::Io);
                }
                if count == 0 {
                    return Err(Failure::Changed);
                }
                offset = offset
                    .checked_add(count as usize)
                    .filter(|v| *v <= body.len())
                    .ok_or(Failure::Changed)?;
            }
            let mut tail = 0u8;
            self.point(cleanup)?;
            let nread = unsafe { libc::pread(self.fd(n)?, (&mut tail as *mut u8).cast(), 1, size) };
            self.point(cleanup)?;
            if nread != 0 {
                return Err(Failure::Changed);
            }
            self.check(n, cleanup)?;
            Ok(body)
        }
        fn alias_bytes(&mut self, parent: libc::c_int, cleanup: bool) -> Result<Vec<u8>> {
            self.point(cleanup)?;
            let mut bytes = [0u8; 1025];
            let n = unsafe {
                libc::readlinkat(
                    parent,
                    c"iPhoneOS.sdk".as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            self.point(cleanup)?;
            if n <= 0 || n > 1024 {
                return Err(Failure::Shape);
            }
            Ok(bytes[..n as usize].to_vec())
        }
        fn alias_post(&mut self, cleanup: bool) -> Result<()> {
            let Some(a) = &self.alias else {
                return Ok(());
            };
            let (parent, id, expected) = (a.parent, a.id, a.bytes.clone());
            self.point(cleanup)?;
            let before = named(parent, c"iPhoneOS.sdk")?;
            self.point(cleanup)?;
            if before != id || self.alias_bytes(parent, cleanup)? != expected {
                return Err(Failure::Changed);
            }
            let after = named(parent, c"iPhoneOS.sdk")?;
            self.point(cleanup)?;
            if after != id {
                return Err(Failure::Changed);
            }
            Ok(())
        }
        pub(crate) fn inspect(&mut self, app: BorrowedFd<'a>) -> Result<Observed> {
            let result = self.inspect_inner(app);
            if result.is_err() {
                self.fail();
            }
            result
        }
        fn inspect_inner(&mut self, app: BorrowedFd<'a>) -> Result<Observed> {
            if self.used || self.failed || self.settlement_entered {
                return Err(Failure::Used);
            }
            self.used = true;
            self.point(false)?;
            self.app = Some(app);
            let id = held(app.as_raw_fd())?;
            self.app_id = Some(id);
            self.point(false)?;
            if id.mode & libc::S_IFMT != libc::S_IFDIR || id.ino == 0 || id.links == 0 {
                return Err(Failure::Shape);
            }
            let contents = self.open(app.as_raw_fd(), "Contents", true)?;
            let version = self.open(self.fd(contents)?, "version.plist", false)?;
            let body = self.read_body(version, false)?;
            let (version, build) = version_plist(&body, || self.point(false))?;
            self.body = Some(body);
            let mut parent = self.open(self.fd(contents)?, "Developer", true)?;
            for name in &crate::ios_sdk_selection::SDK_COMPONENTS[..4] {
                parent = self.open(self.fd(parent)?, name, true)?;
            }
            let sdk_parent = self.fd(parent)?;
            self.point(false)?;
            let alias = named(sdk_parent, c"iPhoneOS.sdk")?;
            self.point(false)?;
            let leaf = if alias.mode & libc::S_IFMT == libc::S_IFLNK {
                if alias.links != 1 || !(1..=1024).contains(&alias.size) {
                    return Err(Failure::Shape);
                }
                let bytes = self.alias_bytes(sdk_parent, false)?;
                let name = std::str::from_utf8(&bytes).map_err(|_| Failure::Shape)?;
                if crate::ios_sdk_selection::sdk_sibling_target(name).is_none() {
                    return Err(Failure::Shape);
                }
                let name = name.to_owned();
                self.alias = Some(Alias {
                    parent: sdk_parent,
                    id: alias,
                    bytes,
                });
                self.alias_post(false)?;
                name
            } else {
                "iPhoneOS.sdk".to_owned()
            };
            self.open(sdk_parent, &leaf, true)?;
            let observed = Observed {
                version,
                build,
                sdk_leaf: leaf,
            };
            self.observed = Some(observed.clone());
            self.post_inner(false)?;
            Ok(observed)
        }
        fn post_inner(&mut self, cleanup: bool) -> Result<()> {
            self.app_post(cleanup)?;
            for n in 0..OWNED_FDS {
                if self.slots[n]
                    .as_ref()
                    .is_some_and(|o| matches!(o.state, State::Held(_)))
                {
                    self.check(n, cleanup)?;
                }
            }
            self.alias_post(cleanup)?;
            if let Some(original) = self.body.take() {
                let compared = self.read_body(1, cleanup).map(|body| body == original);
                self.body = Some(original);
                if !compared? {
                    return Err(Failure::Changed);
                }
            }
            self.app_post(cleanup)?;
            self.point(cleanup)
        }
        pub(crate) fn post(&mut self) -> Result<()> {
            let result = if !self.used
                || self.observed.is_none()
                || self.failed
                || self.settlement_entered
            {
                Err(Failure::Used)
            } else {
                self.post_inner(false)
            };
            if result.is_err() {
                self.fail();
            } else {
                self.posted = true;
            }
            result
        }
        pub(crate) fn settle(&mut self, parent_first_failure: Option<Instant>) -> Result<()> {
            if self.settlement_entered {
                self.fail();
                return Err(Failure::Used);
            }
            self.settlement_entered = true;
            if let Some(at) = parent_first_failure {
                let now = Instant::now();
                if at > now {
                    self.unknown = true;
                }
                self.failed = true;
                self.clock.fail_at(at.min(now));
            }
            let mut error = None;
            if self.app_id.is_some() {
                if let Err(e) = self.post_inner(true) {
                    error = Some(e);
                    self.fail();
                }
            }
            for n in (0..OWNED_FDS).rev() {
                let may_close = match self.point(true) {
                    Ok(()) => true,
                    Err(e) => {
                        error.get_or_insert(e);
                        // Lateness does not undo a positively closed original.
                        // Remaining live/unknown cells cannot be consumed now.
                        self.unknown |= self.held_count() != 0;
                        false
                    }
                };
                let mut close_failed = false;
                if let Some(o) = self.slots[n].as_mut() {
                    match o.state {
                        State::Held(fd) if may_close => {
                            o.state = State::Unknown;
                            let r = unsafe { libc::close(fd) };
                            if r == 0 {
                                o.state = State::Closed;
                            } else {
                                self.unknown = true;
                                close_failed = true;
                                error.get_or_insert(Failure::Close);
                            }
                        }
                        State::Reserved => o.state = State::Closed,
                        _ => (),
                    }
                }
                if close_failed {
                    self.fail();
                }
                if let Err(e) = self.point(true) {
                    error.get_or_insert(e);
                }
            }
            if let Err(e) = self.point(true) {
                error.get_or_insert(e);
            }
            self.settled = self.held_count() == 0 && !self.unknown && error.is_none();
            if let Some(e) = error {
                self.fail();
                Err(e)
            } else {
                Ok(())
            }
        }
        pub(crate) fn accepted(&self) -> bool {
            let now = Instant::now();
            self.observed.is_some()
                && self.posted
                && self.settled
                && !self.failed
                && !self.unknown
                && !self.clock.regressed
                && now >= self.clock.last
                && now < self.clock.work
        }
        pub(crate) fn settled(&self) -> bool {
            self.settled
        }
        pub(crate) fn unknown(&self) -> bool {
            self.unknown
        }
        pub(crate) fn first_failure(&self) -> Option<Instant> {
            self.clock.first
        }
        pub(crate) fn held_count(&self) -> usize {
            self.slots
                .iter()
                .flatten()
                .filter(|o| matches!(o.state, State::Held(_) | State::Unknown))
                .count()
        }
    }
    // No Drop closes: caller must settle independently while original F allows.
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use native::Facts;

#[cfg(test)]
mod tests {
    use super::*;
    fn xml(version: &str, build: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleShortVersionString</key><string>{version}</string><key>ProductBuildVersion</key><string>{build}</string></dict></plist>").into_bytes()
    }
    #[test]
    fn current_desktop_version_and_exact_sdk_shapes_not_cli_pin() {
        for (v, b) in [
            ("26.0", "17A123"),
            ("99.12.345", "BuildX"),
            ("0", "A"),
            ("01.00", "1"),
        ] {
            assert!(version_data(v, b));
        }
        for (v, b) in [
            ("26.0.0.1", "A"),
            ("26-beta", "A"),
            ("26..0", "A"),
            ("26", "A-B"),
            ("", "A"),
            ("26", ""),
        ] {
            assert!(!version_data(v, b));
        }
        assert!(sdk_data("iPhoneOS.sdk"));
        assert!(sdk_data("iPhoneOS26.0.sdk"));
        for leaf in [
            "../iPhoneOS26.sdk",
            "iPhoneSimulator26.sdk",
            "iPhoneOS026.sdk",
            "/x/iPhoneOS26.sdk",
        ] {
            assert!(!sdk_data(leaf));
        }
    }
    #[test]
    fn xml_and_binary_same_facts_and_complete_document() {
        let body = xml("26.0", "17A123");
        let expected = ("26.0".to_owned(), "17A123".to_owned());
        assert_eq!(version_plist(&body, || Ok(())), Ok(expected.clone()));
        let value = plist::Value::from_reader_xml(body.as_slice()).unwrap();
        let mut binary = Vec::new();
        value.to_writer_binary(&mut binary).unwrap();
        assert_eq!(version_plist(&binary, || Ok(())), Ok(expected));
        for tail in [b"junk".as_slice(), b"<dict/>".as_slice()] {
            let mut bad = body.clone();
            bad.extend_from_slice(tail);
            assert!(version_plist(&bad, || Ok(())).is_err());
        }
        assert!(version_plist(&body[..body.len() - 8], || Ok(())).is_err());
        let mut bad = binary;
        bad.extend_from_slice(b"junk");
        assert!(version_plist(&bad, || Ok(())).is_err());
    }
    #[test]
    fn malformed_duplicate_nested_missing_or_oversized_facts_refuse() {
        let original = String::from_utf8(xml("26", "17A")).unwrap();
        for body in [
            original.replace(
                "</dict>",
                "<key>CFBundleShortVersionString</key><string>27</string></dict>",
            ),
            original.replace("ProductBuildVersion", "WrongKey"),
            original.replace("<string>17A</string>", "<integer>17</integer>"),
            original.replace("<string>17A</string>", "<dict/>"),
            original.replace("17A", &"A".repeat(65)),
            original.replace("</dict>", "<key>Other</key><dict/></dict>"),
        ] {
            assert!(version_plist(body.as_bytes(), || Ok(())).is_err());
        }
        assert!(version_plist(&vec![b' '; BODY_LIMIT + 1], || Ok(())).is_err());
        assert_eq!(
            version_plist(&xml("26", "A"), || Err(Failure::Clock)),
            Err(Failure::Clock)
        );
    }
    #[test]
    fn original_clock_no_late_success_and_failure_cut_does_not_renew() {
        let start = Instant::now();
        let mut c = Clock::new(
            start + Duration::from_secs(300),
            start + Duration::from_secs(420),
        )
        .unwrap();
        let first = start + Duration::from_secs(1);
        c.fail_at(first);
        assert_eq!(c.finish, start + Duration::from_secs(121));
        c.fail_at(first + Duration::from_secs(20));
        assert_eq!(c.finish, start + Duration::from_secs(121));
        assert!(c.point_at(c.finish, true).is_err());
        assert!(c.point_at(start, true).is_err());
        assert!(c.regressed);
        let mut c = Clock::new(
            start + Duration::from_secs(300),
            start + Duration::from_secs(420),
        )
        .unwrap();
        assert!(c.point_at(c.work, false).is_err());
        assert!(c.point_at(c.work, true).is_ok());
    }
}
