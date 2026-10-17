//! Read-only same-package carrier admission. Not a PackageKit or root grant.
//!
//! Entry authenticates its signed Scripts and borrows the original setup dir.
//! This module never creates, removes, repairs, launches, or publishes anything.
//! Binary PackageKit receipt shape observed on macOS26 ARM; native entry remains
//! unqualified until actual caller/package integration.
use plist::stream::{BinaryReader, Event};
use std::{collections::BTreeSet, io::Cursor};

pub(crate) const PACKAGE_ID: &str = "dev.mobile-release-kit.desktop.xcode-setup";
pub(crate) const BODY_LIMIT: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Clock,
    Used,
    Shape,
    Receipt,
    Changed,
    Access,
    Io,
    Close,
}
pub(crate) type Result<T> = std::result::Result<T, Failure>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Absent,
    Exact,
}

fn presence(carrier: bool, receipt: bool, bom: bool) -> Result<Admission> {
    match (carrier, receipt, bom) {
        (false, false, false) => Ok(Admission::Absent),
        (true, true, true) => Ok(Admission::Exact),
        _ => Err(Failure::Receipt),
    }
}

/// The bounded streaming dependency owns binary parsing; no recursive Value
/// expansion, custom plist decoder or arbitrary receipt-selected paths. Native
/// callers have already authenticated the root-protected original bytes. Each
/// event and allocation remains bounded by this 64KiB input and finite depth.
fn receipt_identity(
    body: &[u8],
    version: &str,
    mut point: impl FnMut() -> Result<()>,
) -> Result<()> {
    point()?;
    if body.len() < 40
        || body.len() > BODY_LIMIT
        || !body.starts_with(b"bplist00")
        || version.is_empty()
        || version.len() > 64
    {
        return Err(Failure::Receipt);
    }
    let mut reader = BinaryReader::new(Cursor::new(body));
    let mut depth = 0usize;
    let mut started = false;
    let mut finished = false;
    let mut pending: Option<String> = None;
    let mut keys = BTreeSet::new();
    let mut required = 0u8;
    let mut events = 0usize;
    loop {
        point()?;
        let Some(event) = reader.next() else {
            break;
        };
        point()?;
        events += 1;
        if events > 256 || finished {
            return Err(Failure::Receipt);
        }
        let event = event.map_err(|_| Failure::Receipt)?;
        if !started {
            if !matches!(event, Event::StartDictionary(Some(n)) if n <= 32) {
                return Err(Failure::Receipt);
            }
            started = true;
            depth = 1;
            continue;
        }
        match &event {
            Event::String(s) if s.len() > 4096 => return Err(Failure::Receipt),
            Event::Data(b) if b.len() > 4096 => return Err(Failure::Receipt),
            Event::StartDictionary(Some(n)) | Event::StartArray(Some(n)) if *n > 64 => {
                return Err(Failure::Receipt)
            }
            Event::Uid(_) | Event::StartDictionary(None) | Event::StartArray(None) => {
                return Err(Failure::Receipt)
            }
            _ => (),
        }
        if depth == 1 {
            if let Some(key) = pending.take() {
                let wanted = match key.as_str() {
                    "PackageIdentifier" => Some((PACKAGE_ID, 1)),
                    "PackageVersion" => Some((version, 2)),
                    // PackageKit records volume-relative prefix although pkgbuild takes /Library.
                    "InstallPrefixPath" => Some(("Library", 4)),
                    _ => None,
                };
                if let Some((value, bit)) = wanted {
                    if !matches!(&event, Event::String(s) if s.as_ref() == value) {
                        return Err(Failure::Receipt);
                    }
                    required |= bit;
                }
                if matches!(event, Event::EndCollection) {
                    return Err(Failure::Receipt);
                }
            } else if matches!(event, Event::EndCollection) {
                finished = true;
            } else if let Event::String(key) = &event {
                if key.is_empty()
                    || key.len() > 128
                    || keys.len() >= 32
                    || !keys.insert(key.to_string())
                {
                    return Err(Failure::Receipt);
                }
                pending = Some(key.to_string());
                continue;
            } else {
                return Err(Failure::Receipt);
            }
        }
        match event {
            Event::StartDictionary(_) | Event::StartArray(_) => {
                depth += 1;
                if depth > 4 {
                    return Err(Failure::Receipt);
                }
            }
            Event::EndCollection => {
                depth = depth.checked_sub(1).ok_or(Failure::Receipt)?;
            }
            _ => (),
        }
    }
    point()?;
    if !finished || depth != 0 || pending.is_some() || required != 7 {
        return Err(Failure::Receipt);
    }
    Ok(())
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
    use std::{
        ffi::CStr,
        os::fd::{AsRawFd, BorrowedFd},
        time::{Duration, Instant},
    };

    const SLOTS: usize = 16;
    const CARRIER: &CStr = c"MobileReleaseKitXcodeSetup.bundle";
    const RECEIPT: &CStr = c"dev.mobile-release-kit.desktop.xcode-setup.plist";
    const BOM: &CStr = c"dev.mobile-release-kit.desktop.xcode-setup.bom";
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Identity {
        dev: libc::dev_t,
        ino: libc::ino_t,
        mode: libc::mode_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
        links: libc::nlink_t,
        size: libc::off_t,
        flags: u32,
        mtime: libc::time_t,
        mtime_ns: libc::c_long,
        ctime: libc::time_t,
        ctime_ns: libc::c_long,
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
                mtime: s.st_mtime,
                mtime_ns: s.st_mtime_nsec,
                ctime: s.st_ctime,
                ctime_ns: s.st_ctime_nsec,
            }
        }
        fn protection(&self, dir: bool, mode: Option<u16>) -> Result<()> {
            if self.uid != 0
                || self.mode & 0o7022 != 0
                || self.ino == 0
                || self.size < 0
                || self.mode & libc::S_IFMT != if dir { libc::S_IFDIR } else { libc::S_IFREG }
                || !dir
                    && (self.links != 1 || self.flags != 0 || self.size as u64 > BODY_LIMIT as u64)
                || mode.is_some_and(|m| self.mode & 0o7777 != m || self.gid != 0)
                || !(0..1_000_000_000).contains(&self.mtime_ns)
                || !(0..1_000_000_000).contains(&self.ctime_ns)
            {
                return Err(Failure::Access);
            }
            Ok(())
        }
    }
    fn stat(fd: BorrowedFd<'_>) -> Result<Identity> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), s.as_mut_ptr()) } != 0 {
            return Err(Failure::Io);
        }
        Ok(Identity::from(unsafe { s.assume_init() }))
    }
    fn named(parent: libc::c_int, name: &CStr) -> Result<Option<Identity>> {
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                s.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Ok(Some(Identity::from(unsafe { s.assume_init() })));
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(Failure::Io)
        }
    }
    #[derive(Clone, Copy)]
    enum Owner {
        New,
        Acquiring,
        Held(libc::c_int),
        Closed,
        Unknown,
    }
    struct Original {
        owner: Owner,
        parent: libc::c_int,
        name: &'static CStr,
        id: Identity,
        body: Option<Vec<u8>>,
        dir: bool,
        exact_mode: Option<u16>,
    }
    #[derive(Clone, Copy)]
    struct Absence {
        parent: libc::c_int,
        name: &'static CStr,
    }

    /// Sole-use preinstall scope. `setup` stays borrowed through settlement and
    /// its owner remains responsible for its own signed-source POST and close.
    pub(crate) struct CarrierPreflight<'a> {
        work: Instant,
        finish: Instant,
        setup: BorrowedFd<'a>,
        setup_id: Identity,
        originals: [Option<Original>; SLOTS],
        absences: [Option<Absence>; 3],
        used: bool,
        result: Option<Admission>,
        failed: bool,
        unknown: bool,
        settled: bool,
        first_failure: Option<Instant>,
        rosters: [Option<(usize, usize)>; 2],
    }
    impl<'a> CarrierPreflight<'a> {
        pub(crate) fn new(work: Instant, finish: Instant, setup: BorrowedFd<'a>) -> Result<Self> {
            if Instant::now() >= work || work >= finish {
                return Err(Failure::Clock);
            }
            let setup_id = stat(setup)?;
            setup_id.protection(true, None)?;
            abi::empty_acl(setup).map_err(|_| Failure::Access)?;
            if Instant::now() >= work {
                return Err(Failure::Clock);
            }
            Ok(Self {
                work,
                finish,
                setup,
                setup_id,
                originals: std::array::from_fn(|_| None),
                absences: [None; 3],
                used: false,
                result: None,
                failed: false,
                unknown: false,
                settled: false,
                first_failure: None,
                rosters: [None; 2],
            })
        }
        fn point(&self, cleanup: bool) -> Result<()> {
            if Instant::now() >= if cleanup { self.finish } else { self.work } {
                Err(Failure::Clock)
            } else {
                Ok(())
            }
        }
        fn fd(&self, slot: usize) -> Result<BorrowedFd<'_>> {
            match self
                .originals
                .get(slot)
                .and_then(Option::as_ref)
                .map(|o| o.owner)
            {
                Some(Owner::Held(fd)) => Ok(unsafe { BorrowedFd::borrow_raw(fd) }),
                _ => Err(Failure::Changed),
            }
        }
        fn post(&self, slot: usize, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            let original = self.originals[slot].as_ref().ok_or(Failure::Changed)?;
            let fd = self.fd(slot)?;
            if stat(fd)? != original.id
                || named(original.parent, original.name)? != Some(original.id)
            {
                return Err(Failure::Changed);
            }
            original.id.protection(original.dir, original.exact_mode)?;
            abi::empty_acl(fd).map_err(|_| Failure::Access)?;
            if !original.dir {
                abi::no_xattrs(fd).map_err(|_| Failure::Access)?;
            }
            self.point(cleanup)
        }
        fn open(
            &mut self,
            parent: libc::c_int,
            name: &'static CStr,
            dir: bool,
            mode: Option<u16>,
            optional: bool,
        ) -> Result<Option<usize>> {
            self.point(false)?;
            let Some(id) = named(parent, name)? else {
                if !optional {
                    return Err(Failure::Changed);
                }
                let place = self
                    .absences
                    .iter_mut()
                    .find(|x| x.is_none())
                    .ok_or(Failure::Shape)?;
                *place = Some(Absence { parent, name });
                self.point(false)?;
                return Ok(None);
            };
            id.protection(dir, mode)?;
            let slot = self
                .originals
                .iter()
                .position(Option::is_none)
                .ok_or(Failure::Shape)?;
            self.originals[slot] = Some(Original {
                owner: Owner::New,
                parent,
                name,
                id,
                body: None,
                dir,
                exact_mode: mode,
            });
            self.originals[slot].as_mut().unwrap().owner = Owner::Acquiring;
            let fd = unsafe {
                libc::openat(
                    parent,
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | if dir { libc::O_DIRECTORY } else { 0 },
                )
            };
            self.originals[slot].as_mut().unwrap().owner = if fd < 0 {
                Owner::Closed
            } else {
                Owner::Held(fd)
            };
            if fd < 0 {
                return Err(Failure::Io);
            }
            self.post(slot, false)?;
            let fs = statfs::fstatfs(self.fd(slot)?).map_err(|_| Failure::Access)?;
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
            self.post(slot, false)?;
            Ok(Some(slot))
        }
        fn required(
            &mut self,
            parent: libc::c_int,
            name: &'static CStr,
            dir: bool,
            mode: Option<u16>,
        ) -> Result<usize> {
            self.open(parent, name, dir, mode, false)?
                .ok_or(Failure::Changed)
        }
        fn read(&self, slot: usize, cleanup: bool) -> Result<Vec<u8>> {
            self.post(slot, cleanup)?;
            let original = self.originals[slot].as_ref().ok_or(Failure::Changed)?;
            if original.dir || original.id.size <= 0 || original.id.size as u64 > BODY_LIMIT as u64
            {
                return Err(Failure::Shape);
            }
            let mut body = vec![0u8; original.id.size as usize];
            let mut offset = 0;
            while offset < body.len() {
                self.point(cleanup)?;
                let count = unsafe {
                    libc::pread(
                        self.fd(slot)?.as_raw_fd(),
                        body[offset..].as_mut_ptr().cast(),
                        body.len() - offset,
                        offset as libc::off_t,
                    )
                };
                if count <= 0 {
                    return Err(Failure::Io);
                }
                offset += count as usize;
            }
            let mut tail = 0u8;
            if unsafe {
                libc::pread(
                    self.fd(slot)?.as_raw_fd(),
                    (&mut tail as *mut u8).cast(),
                    1,
                    offset as libc::off_t,
                )
            } != 0
            {
                return Err(Failure::Changed);
            }
            self.post(slot, cleanup)?;
            Ok(body)
        }
        fn keep_body(&mut self, slot: usize) -> Result<()> {
            let body = self.read(slot, false)?;
            self.originals[slot].as_mut().unwrap().body = Some(body);
            Ok(())
        }
        fn body(&self, slot: usize) -> Result<&[u8]> {
            self.originals[slot]
                .as_ref()
                .and_then(|o| o.body.as_deref())
                .ok_or(Failure::Shape)
        }
        fn roster(&self, parent: usize, child: usize, cleanup: bool) -> Result<()> {
            self.post(parent, cleanup)?;
            self.post(child, cleanup)?;
            let fd = self.fd(parent)?;
            self.point(cleanup)?;
            if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
                return Err(Failure::Io);
            }
            let entry = self.originals[child].as_ref().ok_or(Failure::Changed)?;
            let mut found = false;
            let mut block = [0u8; 65536];
            loop {
                self.point(cleanup)?;
                let used = abi::directory_block(fd, &mut block).map_err(|_| Failure::Io)?;
                self.point(cleanup)?;
                if used == 0 {
                    break;
                }
                let mut offset = 0usize;
                while offset < used {
                    if used - offset < 11 {
                        return Err(Failure::Shape);
                    }
                    let ino = u64::from_ne_bytes(
                        block[offset..offset + 8]
                            .try_into()
                            .map_err(|_| Failure::Shape)?,
                    );
                    let kind = block[offset + 8];
                    let length =
                        usize::from(u16::from_ne_bytes([block[offset + 9], block[offset + 10]]));
                    let end = offset
                        .checked_add(11 + length)
                        .filter(|n| *n <= used)
                        .ok_or(Failure::Shape)?;
                    let name = &block[offset + 11..end];
                    offset = end;
                    if name == b"." || name == b".." {
                        continue;
                    }
                    if found
                        || name != entry.name.to_bytes()
                        || ino != entry.id.ino
                        || kind
                            != if entry.dir {
                                libc::DT_DIR
                            } else {
                                libc::DT_REG
                            }
                    {
                        return Err(Failure::Changed);
                    }
                    found = true;
                }
            }
            if !found {
                return Err(Failure::Changed);
            }
            self.post(parent, cleanup)?;
            self.post(child, cleanup)
        }
        pub(crate) fn check(
            &mut self,
            expected_version: &str,
            expected_info: &[u8],
        ) -> Result<Admission> {
            if self.used || self.settled {
                self.fail();
                return Err(Failure::Used);
            }
            self.used = true;
            let outcome = self.check_inner(expected_version, expected_info);
            match outcome {
                Ok(value) => self.result = Some(value),
                Err(_) => self.fail(),
            }
            outcome
        }
        fn check_inner(&mut self, version: &str, info: &[u8]) -> Result<Admission> {
            self.point(false)?;
            if unsafe { libc::getuid() } != 0
                || unsafe { libc::geteuid() } != 0
                || info.is_empty()
                || info.len() > BODY_LIMIT
            {
                return Err(Failure::Access);
            }
            let own_bom =
                self.required(self.setup.as_raw_fd(), c"carrier.bom", false, Some(0o444))?;
            self.keep_body(own_bom)?;
            let root = self.required(libc::AT_FDCWD, c"/", true, None)?;
            let library = self.required(self.fd(root)?.as_raw_fd(), c"Library", true, None)?;
            let private = self.required(self.fd(root)?.as_raw_fd(), c"private", true, None)?;
            let var = self.required(self.fd(private)?.as_raw_fd(), c"var", true, None)?;
            let db = self.required(self.fd(var)?.as_raw_fd(), c"db", true, None)?;
            let receipts = self.required(self.fd(db)?.as_raw_fd(), c"receipts", true, None)?;
            let carrier = self.open(
                self.fd(library)?.as_raw_fd(),
                CARRIER,
                true,
                Some(0o555),
                true,
            )?;
            let receipt = self.open(self.fd(receipts)?.as_raw_fd(), RECEIPT, false, None, true)?;
            let bom = self.open(self.fd(receipts)?.as_raw_fd(), BOM, false, None, true)?;
            let admission = presence(carrier.is_some(), receipt.is_some(), bom.is_some())?;
            if admission == Admission::Exact {
                let carrier = carrier.ok_or(Failure::Receipt)?;
                let contents = self.required(
                    self.fd(carrier)?.as_raw_fd(),
                    c"Contents",
                    true,
                    Some(0o555),
                )?;
                let information = self.required(
                    self.fd(contents)?.as_raw_fd(),
                    c"Info.plist",
                    false,
                    Some(0o444),
                )?;
                let receipt = receipt.ok_or(Failure::Receipt)?;
                let bom = bom.ok_or(Failure::Receipt)?;
                for slot in [information, receipt, bom] {
                    self.keep_body(slot)?;
                }
                if self.body(information)? != info || self.body(bom)? != self.body(own_bom)? {
                    return Err(Failure::Receipt);
                }
                receipt_identity(self.body(receipt)?, version, || self.point(false))?;
                self.roster(carrier, contents, false)?;
                self.roster(contents, information, false)?;
                self.rosters = [Some((carrier, contents)), Some((contents, information))];
            }
            self.posts(false)?;
            Ok(admission)
        }
        fn posts(&self, cleanup: bool) -> Result<()> {
            self.point(cleanup)?;
            if stat(self.setup)? != self.setup_id {
                return Err(Failure::Changed);
            }
            abi::empty_acl(self.setup).map_err(|_| Failure::Access)?;
            for (slot, original) in self.originals.iter().enumerate() {
                if let Some(original) = original {
                    if matches!(original.owner, Owner::Closed) {
                        continue;
                    }
                    self.post(slot, cleanup)?;
                    if let Some(body) = &original.body {
                        if self.read(slot, cleanup)? != *body {
                            return Err(Failure::Changed);
                        }
                    }
                }
            }
            for (parent, child) in self.rosters.iter().flatten() {
                self.roster(*parent, *child, cleanup)?;
            }
            for absence in self.absences.iter().flatten() {
                self.point(cleanup)?;
                if named(absence.parent, absence.name)?.is_some() {
                    return Err(Failure::Changed);
                }
            }
            self.point(cleanup)
        }
        fn fail(&mut self) {
            self.failed = true;
            if self.first_failure.is_none() {
                let now = Instant::now();
                self.first_failure = Some(now);
                if let Some(end) = now.checked_add(Duration::from_secs(120)) {
                    self.finish = self.finish.min(end);
                }
            }
        }
        pub(crate) fn first_failure(&self) -> Option<Instant> {
            self.first_failure
        }
        /// Always call, including after refused check. Every held original is
        /// consumed once independently. A failed POST cannot skip other closes.
        pub(crate) fn settle(&mut self) -> Result<()> {
            if self.settled {
                self.fail();
                return Err(Failure::Used);
            }
            let mut error = self.posts(true).err();
            if error.is_some() {
                self.fail();
            }
            for slot in (0..SLOTS).rev() {
                let mut close_failed = false;
                if let Some(original) = self.originals[slot].as_mut() {
                    match original.owner {
                        Owner::Held(fd) => {
                            // Never start another native call beyond the original
                            // cleanup cutoff. Keep this known-held slot charged;
                            // the supervising Parent owns eventual process exit.
                            if Instant::now() >= self.finish {
                                close_failed = true;
                            } else {
                                original.owner = Owner::Unknown;
                                let closed = unsafe { libc::close(fd) } == 0;
                                if closed {
                                    original.owner = Owner::Closed;
                                }
                                // A late positive close is known, but cannot buy
                                // timely finality or permit another close call.
                                close_failed = !closed || Instant::now() >= self.finish;
                            }
                        }
                        Owner::Closed => (),
                        _ => close_failed = true,
                    }
                }
                if close_failed {
                    self.unknown = true;
                    self.fail();
                    error.get_or_insert(Failure::Close);
                }
            }
            self.settled = true;
            if Instant::now() >= self.work {
                self.fail();
                error.get_or_insert(Failure::Clock);
            }
            // Return cleanup's outcome, not the earlier operation's failure.
            // The entry must separately require accepted(), never settle alone.
            match error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        pub(crate) fn settled(&self) -> bool {
            self.settled
                && !self.unknown
                && self
                    .originals
                    .iter()
                    .flatten()
                    .all(|o| matches!(o.owner, Owner::Closed))
        }
        pub(crate) fn accepted(&self) -> bool {
            self.settled() && !self.failed && self.result.is_some() && Instant::now() < self.work
        }
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(crate) use native::CarrierPreflight;

#[cfg(test)]
mod tests {
    use super::*;
    use plist::stream::BinaryWriter;
    fn encoded(events: Vec<Event<'static>>) -> Vec<u8> {
        use plist::stream::Writer;
        let mut body = Vec::new();
        {
            let mut writer = BinaryWriter::new(&mut body);
            for event in events {
                writer.write(event).unwrap();
            }
        }
        body
    }
    fn receipt(extra: Vec<Event<'static>>) -> Vec<u8> {
        let mut events = vec![
            Event::StartDictionary(Some(3 + (extra.len() / 2) as u64)),
            Event::String("PackageIdentifier".into()),
            Event::String(PACKAGE_ID.into()),
            Event::String("PackageVersion".into()),
            Event::String("1.0.0".into()),
            Event::String("InstallPrefixPath".into()),
            Event::String("Library".into()),
        ];
        events.extend(extra);
        events.push(Event::EndCollection);
        encoded(events)
    }
    #[test]
    fn absence_requires_all_three_actual_names_absent() {
        for carrier in [false, true] {
            for receipt in [false, true] {
                for bom in [false, true] {
                    assert_eq!(
                        presence(carrier, receipt, bom),
                        if carrier == receipt && receipt == bom {
                            Ok(if carrier {
                                Admission::Exact
                            } else {
                                Admission::Absent
                            })
                        } else {
                            Err(Failure::Receipt)
                        }
                    );
                }
            }
        }
    }
    #[test]
    fn receipt_requires_matching_typed_identity_and_rejects_duplicates() {
        let body = receipt(vec![]);
        assert_eq!(receipt_identity(&body, "1.0.0", || Ok(())), Ok(()));
        assert_eq!(
            receipt_identity(&body, "2.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
        for key in ["PackageIdentifier", "PackageVersion", "InstallPrefixPath"] {
            let duplicate = receipt(vec![
                Event::String(key.into()),
                Event::String("wrong".into()),
            ]);
            assert_eq!(
                receipt_identity(&duplicate, "1.0.0", || Ok(())),
                Err(Failure::Receipt)
            );
        }
        let duplicate = receipt(vec![
            Event::String("Other".into()),
            Event::Integer(1.into()),
            Event::String("Other".into()),
            Event::Integer(1.into()),
        ]);
        assert_eq!(
            receipt_identity(&duplicate, "1.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
        for bad in [
            Event::Integer(1.into()),
            Event::String("/elsewhere".into()),
            Event::String("/Library".into()),
            Event::Boolean(true),
        ] {
            let body = encoded(vec![
                Event::StartDictionary(Some(3)),
                Event::String("PackageIdentifier".into()),
                Event::String(PACKAGE_ID.into()),
                Event::String("PackageVersion".into()),
                Event::String("1.0.0".into()),
                Event::String("InstallPrefixPath".into()),
                bad,
                Event::EndCollection,
            ]);
            assert_eq!(
                receipt_identity(&body, "1.0.0", || Ok(())),
                Err(Failure::Receipt)
            );
        }
    }
    #[test]
    fn bounded_auxiliary_fields_do_not_grant_identity_or_renew_clock() {
        let body = receipt(vec![
            Event::String("InstallDate".into()),
            Event::Date(std::time::SystemTime::UNIX_EPOCH.into()),
            Event::String("PackageFileName".into()),
            Event::String("PrepareXcode.pkg".into()),
            Event::String("InstallProcessName".into()),
            Event::String("installer".into()),
        ]);
        assert_eq!(receipt_identity(&body, "1.0.0", || Ok(())), Ok(()));
        let mut calls = 0;
        assert_eq!(
            receipt_identity(&body, "1.0.0", || {
                calls += 1;
                if calls >= 5 {
                    Err(Failure::Clock)
                } else {
                    Ok(())
                }
            }),
            Err(Failure::Clock)
        );
        for body in [
            vec![],
            b"<?xml version=\"1.0\"?><plist><dict/></plist>".to_vec(),
            vec![0; BODY_LIMIT + 1],
            body[..body.len() - 1].to_vec(),
        ] {
            assert_eq!(
                receipt_identity(&body, "1.0.0", || Ok(())),
                Err(Failure::Receipt)
            );
        }
        let large = receipt(vec![
            Event::String("Other".into()),
            Event::Data(vec![0; 4097].into()),
        ]);
        assert_eq!(
            receipt_identity(&large, "1.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
    }
    #[test]
    fn required_fields_cannot_hide_in_nested_metadata_and_event_work_is_bounded() {
        let missing = encoded(vec![
            Event::StartDictionary(None),
            Event::String("Other".into()),
            Event::StartDictionary(None),
            Event::String("PackageIdentifier".into()),
            Event::String(PACKAGE_ID.into()),
            Event::EndCollection,
            Event::EndCollection,
        ]);
        assert_eq!(
            receipt_identity(&missing, "1.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
        let mut nested = vec![Event::String("Other".into())];
        for _ in 0..4 {
            nested.push(Event::StartArray(None));
        }
        nested.push(Event::Integer(1.into()));
        for _ in 0..4 {
            nested.push(Event::EndCollection);
        }
        assert_eq!(
            receipt_identity(&receipt(nested), "1.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
        let mut many = Vec::new();
        for n in 0..5 {
            many.push(Event::String(format!("Other{n}").into()));
            many.push(Event::StartArray(None));
            for _ in 0..64 {
                many.push(Event::Integer(1.into()));
            }
            many.push(Event::EndCollection);
        }
        assert_eq!(
            receipt_identity(&receipt(many), "1.0.0", || Ok(())),
            Err(Failure::Receipt)
        );
    }
}
