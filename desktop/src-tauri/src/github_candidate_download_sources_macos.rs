//! Fixed output facet of the SAME History SourceBook. Four original slots,
//! two exclusive files, one RENAME_EXCL; no new book, cleanup task or retry.
use super::*;
use std::sync::Arc;
use wire::download::{self as data, Candidate, Pins, Trace};

pub(super) const ORIGINALS: usize = 4;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Made {
    New,
    Entered,
    Existing,
    Created,
    Refused,
}
pub(super) struct State {
    trace: Arc<Trace>,
    final_name: String,
    pending_name: String,
    primary_name: &'static str,
    release: Option<usize>,
    parent: Option<usize>,
    staging: Option<usize>,
    files: [Option<usize>; 2],
    made: [Made; 2],
    sync: [CallState; 6],
    pins: Option<Pins>,
    candidate: Option<Candidate>,
    result: Option<wire::ResultData>,
    armed: bool,
    consumed: bool,
    verified: [Option<wire::FileIdentity>; 2],
}
fn output_file(value: &FileStat, maximum: u64) -> Result<wire::FileIdentity, Reason> {
    let id = file_identity(value)?;
    let result = wire::FileIdentity {
        device: id.common.dev.to_string(),
        inode: id.common.ino.to_string(),
        mode: id.common.mode,
        uid: id.common.uid,
        gid: id.common.gid,
        nlink: id.nlink.to_string(),
        bytes: id.size.to_string(),
        mtime_seconds: id.mtime.0.to_string(),
        ctime_seconds: id.ctime.0.to_string(),
        mtime_nanos: u32::try_from(id.mtime.1).map_err(|_| Reason::SourceRefused)?,
        ctime_nanos: u32::try_from(id.ctime.1).map_err(|_| Reason::SourceRefused)?,
        flags: value.st_flags,
    };
    if result.mode != 0o100600
        || result.flags != 0
        || result.uid != unistd::geteuid().as_raw()
        || !result.valid(maximum, false)
    {
        return Err(Reason::SourceRefused);
    }
    Ok(result)
}
fn same_file(original: &wire::FileIdentity, actual: &wire::FileIdentity) -> bool {
    original.device == actual.device
        && original.inode == actual.inode
        && original.mode == actual.mode
        && original.uid == actual.uid
        && original.gid == actual.gid
        && original.nlink == actual.nlink
        && original.flags == actual.flags
}
fn absent(
    book: &SourceBook,
    parent: usize,
    name: &str,
    stop: &mut dyn FnMut() -> bool,
) -> Result<(), Reason> {
    checkpoint(stop)?;
    let observed = stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW);
    checkpoint(stop)?;
    match observed {
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        _ => Err(Reason::SourceRefused),
    }
}
impl State {
    pub(super) fn new(selection: &wire::Selection, trace: Arc<Trace>) -> Result<Self, Reason> {
        let (final_name, pending_name, primary_name) =
            data::names(selection).ok_or(Reason::InvalidRequest)?;
        if !trace.snapshot().valid(selection) {
            return Err(Reason::InvalidRequest);
        }
        Ok(Self {
            trace,
            final_name,
            pending_name,
            primary_name,
            release: None,
            parent: None,
            staging: None,
            files: [None; 2],
            made: [Made::New; 2],
            sync: [CallState::NotStarted; 6],
            pins: None,
            candidate: None,
            result: None,
            armed: false,
            consumed: false,
            verified: [None, None],
        })
    }
    pub(super) fn pending(&self) -> bool {
        self.made.contains(&Made::Entered) || self.sync.iter().any(|v| !v.settled())
    }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        let mut size = std::mem::size_of::<Self>()
            .checked_add(self.final_name.capacity())?
            .checked_add(self.pending_name.capacity())?
            .checked_add(self.trace.retained_bytes()?)?
            .checked_add(self.pins.as_ref().map_or(Some(0), Pins::retained_bytes)?)?
            .checked_add(
                self.candidate
                    .as_ref()
                    .map_or(Some(0), Candidate::retained_bytes)?,
            )?
            .checked_add(
                self.result
                    .as_ref()
                    .map_or(Some(0), wire::ResultData::retained_heap_bytes)?,
            )?;
        for item in self.verified.iter().flatten() {
            size = size.checked_add(item.retained_heap_bytes()?)?;
        }
        Some(size)
    }
    pub(super) fn pins(&self) -> Result<Pins, Reason> {
        self.pins.clone().ok_or(Reason::SourceRefused)
    }
    fn sync_once(
        &mut self,
        book: &SourceBook,
        index: usize,
        call: usize,
        file: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.sync[call] != CallState::NotStarted {
            return Err(Reason::CleanupUnknown);
        }
        checkpoint(stop)?;
        let fd = book.fd(index)?;
        self.sync[call] = CallState::Entered;
        let returned = mrk_macos_installed_native::sync(fd.as_fd(), file);
        self.sync[call] = CallState::Settled; // A returned error is not an unjoined call.
        returned.map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)
    }
    fn directory(
        &mut self,
        book: &mut SourceBook,
        parent: usize,
        name: &str,
        creation: usize,
        allow_existing: bool,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<usize, Reason> {
        let index = book.reserve(Some(parent), name.as_bytes())?;
        checkpoint(stop)?;
        let found = stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW);
        checkpoint(stop)?;
        let expected = match found {
            Ok(value) if allow_existing => {
                self.made[creation] = Made::Existing;
                directory_identity(&value)?
            }
            Err(nix::errno::Errno::ENOENT) => {
                // The reserved name/creation original precede the sole mkdir.
                checkpoint(stop)?;
                self.made[creation] = Made::Entered;
                let returned =
                    stat::mkdirat(book.fd(parent)?, name, Mode::from_bits_truncate(0o700));
                self.made[creation] = if returned.is_ok() {
                    Made::Created
                } else {
                    Made::Refused
                };
                // In particular EEXIST after the absent lookup is not adopted.
                returned.map_err(|_| Reason::SourceRefused)?;
                checkpoint(stop)?;
                let named = stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| Reason::SourceRefused)?;
                checkpoint(stop)?;
                directory_identity(&named)?
            }
            _ => {
                self.made[creation] = Made::Refused;
                return Err(Reason::SourceRefused);
            }
        };
        if expected.mode != 0o40700 || expected.uid != unistd::geteuid().as_raw() {
            return Err(Reason::SourceRefused);
        }
        book.slots[index].state = OriginalState::Acquiring;
        let opened = fcntl::openat(book.fd(parent)?, name, directory_flags(), Mode::empty());
        book.adopt(index, opened)?;
        checkpoint(stop)?;
        filesystem(book.fd(index)?, stop)?;
        let held = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(book.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if directory_identity(&held)? != expected || directory_identity(&named)? != expected {
            return Err(Reason::SourceChanged);
        }
        book.slots[index].identity = Some(Identity::Directory(expected));
        book.private_acl(index, 0, stop)?;
        Ok(index)
    }
    pub(super) fn inspect(
        &mut self,
        book: &mut SourceBook,
        release: usize,
        work: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if self.release.is_some() || self.made != [Made::New; 2] {
            return Err(Reason::CleanupUnknown);
        }
        self.release = Some(release);
        let parent = self.directory(book, release, "downloads", 0, true, stop)?;
        self.parent = Some(parent);
        if self.made[0] == Made::Created {
            self.sync_once(book, parent, 0, false, stop)?;
            self.sync_once(book, release, 1, false, stop)?;
        }
        absent(book, parent, &self.final_name, stop)?;
        absent(book, parent, &self.pending_name, stop)?;
        checkpoint(stop)?;
        let destination = statfs::fstatfs(book.fd(parent)?).map_err(|_| Reason::Capacity)?;
        checkpoint(stop)?;
        let scratch = statfs::fstatfs(book.fd(work)?).map_err(|_| Reason::Capacity)?;
        checkpoint(stop)?;
        let available = |v: &statfs::Statfs| {
            u64::try_from(v.block_size())
                .ok()
                .and_then(|n| n.checked_mul(v.blocks_available()))
        };
        let same = book.directory(parent)?.dev == book.directory(work)?.dev;
        if available(&destination)
            .is_none_or(|v| v < data::DESTINATION_RESERVE + if same { DISK_FLOOR } else { 0 })
            || available(&scratch).is_none_or(|v| v < DISK_FLOOR)
        {
            return Err(Reason::Capacity);
        }
        let pending = self.pending_name.clone();
        let stage = self.directory(book, parent, &pending, 1, false, stop)?;
        self.staging = Some(stage);
        for (i, name) in [self.primary_name, data::RECEIPT].into_iter().enumerate() {
            let index = book.reserve(Some(stage), name.as_bytes())?;
            self.files[i] = Some(index);
            checkpoint(stop)?;
            book.slots[index].state = OriginalState::Acquiring;
            let opened = fcntl::openat(
                book.fd(stage)?,
                name,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NONBLOCK,
                Mode::from_bits_truncate(0o600),
            );
            book.adopt(index, opened)?;
            checkpoint(stop)?;
            filesystem(book.fd(index)?, stop)?;
            let held = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            let named = stat::fstatat(book.fd(stage)?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if output_file(&held, 0)? != output_file(&named, 0)? {
                return Err(Reason::SourceChanged);
            }
            book.slots[index].identity = Some(Identity::File(file_identity(&held)?));
            book.private_acl(index, 0, stop)?;
        }
        let file = |i: usize| -> Result<wire::FileIdentity, Reason> {
            let stat = stat::fstat(book.fd(self.files[i].ok_or(Reason::SourceRefused)?)?)
                .map_err(|_| Reason::SourceRefused)?;
            output_file(&stat, 0)
        };
        self.pins = Some(Pins {
            consent_version: data::CONSENT.into(),
            parent_identity: directory_data(book.directory(parent)?),
            staging_identity: directory_data(book.directory(stage)?),
            primary_identity: file(0)?,
            receipt_identity: file(1)?,
        });
        checkpoint(stop)?;
        if !self.pins.as_ref().is_some_and(Pins::valid) {
            return Err(Reason::SourceRefused);
        }
        self.roster(book, stop)?;
        self.check(book, stop)
    }
    pub(super) fn owns_file(&self, index: usize) -> bool {
        self.files.contains(&Some(index))
    }
    pub(super) fn check_file(
        &self,
        book: &SourceBook,
        index: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let at = self
            .files
            .iter()
            .position(|v| *v == Some(index))
            .ok_or(Reason::SourceRefused)?;
        let pins = self.pins.as_ref().ok_or(Reason::SourceRefused)?;
        let expected = if at == 0 {
            &pins.primary_identity
        } else {
            &pins.receipt_identity
        };
        let maximum = if at == 0 {
            data::PRIMARY_LIMIT
        } else {
            data::RECEIPT_LIMIT as u64
        };
        let slot = &book.slots[index];
        checkpoint(stop)?;
        filesystem(book.fd(index)?, stop)?;
        let held = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let named = stat::fstatat(
            book.fd(slot.parent.ok_or(Reason::SourceChanged)?)?,
            OsStr::from_bytes(&slot.name),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let held = output_file(&held, maximum)?;
        let named = output_file(&named, maximum)?;
        if !same_file(expected, &held)
            || held != named
            || self.verified[at].as_ref().is_some_and(|v| v != &held)
        {
            return Err(Reason::SourceChanged);
        }
        Ok(())
    }
    pub(super) fn check(
        &self,
        book: &SourceBook,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        for index in [self.release, self.parent, self.staging]
            .into_iter()
            .flatten()
        {
            let slot = &book.slots[index];
            let expected = book.directory(index)?;
            checkpoint(stop)?;
            filesystem(book.fd(index)?, stop)?;
            let held = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            let named = stat::fstatat(
                book.fd(slot.parent.ok_or(Reason::SourceChanged)?)?,
                OsStr::from_bytes(&slot.name),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if directory_identity(&held)? != expected || directory_identity(&named)? != expected {
                return Err(Reason::SourceChanged);
            }
        }
        for index in self.files.into_iter().flatten() {
            self.check_file(book, index, stop)?;
        }
        Ok(())
    }
    fn roster(&self, book: &SourceBook, stop: &mut dyn FnMut() -> bool) -> Result<(), Reason> {
        let fd = book.fd(self.staging.ok_or(Reason::SourceRefused)?)?;
        checkpoint(stop)?;
        unistd::lseek(fd, 0, unistd::Whence::SeekSet).map_err(|_| Reason::SourceRefused)?;
        checkpoint(stop)?;
        let mut buffer = [0u8; 4096];
        let mut seen = [false; 2];
        let mut dots = 0usize;
        loop {
            checkpoint(stop)?;
            let used = mrk_macos_installed_native::directory_block(fd.as_fd(), &mut buffer)
                .map_err(|_| Reason::SourceRefused)?;
            checkpoint(stop)?;
            if used == 0 {
                return if seen == [true; 2] {
                    Ok(())
                } else {
                    Err(Reason::SourceChanged)
                };
            }
            if used > buffer.len() {
                return Err(Reason::SourceChanged);
            }
            let mut offset = 0usize;
            while offset < used {
                if used - offset < 11 {
                    return Err(Reason::SourceChanged);
                }
                let length = usize::from(u16::from_ne_bytes([
                    buffer[offset + 9],
                    buffer[offset + 10],
                ]));
                let next = offset
                    .checked_add(11 + length)
                    .filter(|n| *n <= used)
                    .ok_or(Reason::SourceChanged)?;
                let name = &buffer[offset + 11..next];
                let kind = buffer[offset + 8];
                if matches!(name, b"." | b"..") {
                    if kind != nix::libc::DT_DIR || dots >= 2 {
                        return Err(Reason::SourceChanged);
                    }
                    dots += 1;
                } else {
                    let i = if name == self.primary_name.as_bytes() {
                        0
                    } else if name == data::RECEIPT.as_bytes() {
                        1
                    } else {
                        return Err(Reason::SourceChanged);
                    };
                    if seen[i] || kind != nix::libc::DT_REG {
                        return Err(Reason::SourceChanged);
                    }
                    seen[i] = true;
                }
                offset = next;
            }
        }
    }
    // The driver alone arms this after its original terminal/wait/IO returns.
    // No call here reads a public status or reopens a source.
    pub(super) fn arm(
        &mut self,
        candidate: &Candidate,
        result: &wire::ResultData,
    ) -> Result<(), Reason> {
        if self.armed
            || self.consumed
            || self.pins.is_none()
            || !candidate.valid()
            || !data::result_eligible(result)
            || result
                .retained_heap_bytes()
                .and_then(|n| n.checked_add(std::mem::size_of::<wire::ResultData>()))
                .is_none_or(|n| n > wire::RETAINED_REPLY_LIMIT)
        {
            return Err(Reason::SourceRefused);
        }
        self.candidate = Some(candidate.clone());
        self.result = Some(result.clone());
        // Actual retained clone/backing, not serialized length or spare quota.
        if self
            .retained_bytes()
            .is_none_or(|n| n > wire::RETAINED_REPLY_LIMIT + 32 * 1024)
        {
            return Err(Reason::Capacity);
        }
        self.armed = true;
        Ok(())
    }
    pub(super) fn armed(&self) -> bool {
        self.armed
    }
    fn verify_file(
        &mut self,
        book: &SourceBook,
        at: usize,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        let index = self.files[at].ok_or(Reason::SourceRefused)?;
        self.check_file(book, index, stop)?;
        let (expected_size, expected_hash) = {
            let c = self.candidate.as_ref().ok_or(Reason::SourceRefused)?;
            if at == 0 {
                (c.primary_bytes, c.primary_sha256.clone())
            } else {
                (u64::from(c.receipt_bytes), c.receipt_sha256.clone())
            }
        };
        checkpoint(stop)?;
        let before = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let before = output_file(&before, expected_size)?;
        if before.bytes != expected_size.to_string() {
            return Err(Reason::SourceChanged);
        }
        unistd::lseek(book.fd(index)?, 0, unistd::Whence::SeekSet)
            .map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        let mut buffer = [0u8; 65536];
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut receipt = Vec::new();
        if at == 1 {
            receipt
                .try_reserve_exact(data::RECEIPT_LIMIT)
                .map_err(|_| Reason::Capacity)?;
            if receipt.capacity() > data::RECEIPT_LIMIT {
                return Err(Reason::Capacity);
            }
        }
        loop {
            checkpoint(stop)?;
            let used =
                unistd::read(book.fd(index)?, &mut buffer).map_err(|_| Reason::SourceChanged)?;
            checkpoint(stop)?;
            if used == 0 {
                break;
            }
            count = count
                .checked_add(used as u64)
                .filter(|n| *n <= expected_size)
                .ok_or(Reason::SourceChanged)?;
            hash.update(&buffer[..used]);
            if at == 1 {
                receipt.extend_from_slice(&buffer[..used]);
            }
        }
        if count != expected_size || format!("{:x}", hash.finalize()) != expected_hash {
            return Err(Reason::SourceChanged);
        }
        if at == 1
            && !data::receipt_matches(
                &receipt,
                self.candidate.as_ref().ok_or(Reason::SourceRefused)?,
                self.result.as_ref().ok_or(Reason::SourceRefused)?,
            )
        {
            return Err(Reason::SourceChanged);
        }
        let after = stat::fstat(book.fd(index)?).map_err(|_| Reason::SourceChanged)?;
        checkpoint(stop)?;
        if output_file(&after, expected_size)? != before {
            return Err(Reason::SourceChanged);
        }
        self.verified[at] = Some(before);
        self.check_file(book, index, stop)
    }
    pub(super) fn publish_once(
        &mut self,
        book: &mut SourceBook,
        config: &Option<(usize, wire::FileIdentity, String)>,
        removed_work: Option<usize>,
        work: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if !self.armed || self.consumed {
            return Err(Reason::SourceRefused);
        }
        self.consumed = true;
        checkpoint(work)?;
        self.check(book, work)?;
        self.roster(book, work)?;
        for i in 0..2 {
            self.verify_file(book, i, work)?;
            self.sync_once(
                book,
                self.files[i].ok_or(Reason::SourceRefused)?,
                2 + i,
                true,
                work,
            )?;
        }
        let stage = self.staging.ok_or(Reason::SourceRefused)?;
        let parent = self.parent.ok_or(Reason::SourceRefused)?;
        self.sync_once(book, stage, 4, false, work)?;
        self.check(book, work)?;
        self.roster(book, work)?;
        absent(book, parent, &self.final_name, work)?;
        // Allocate the exact new edge BEFORE entry. Never adopt an observed
        // destination or rebuild this record after a returned/unknown rename.
        let new_name = copy_bytes(self.final_name.as_bytes())?;
        HistorySources::post_book(book, config, removed_work, Some(self), work)?;
        checkpoint(work)?;
        let parent_fd = book.fd(parent)?;
        if !self.trace.enter() {
            return Err(Reason::CleanupUnknown);
        }
        let returned = mrk_macos_installed_native::publish_directory(
            parent_fd.as_fd(),
            &self.pending_name,
            parent_fd.as_fd(),
            &self.final_name,
        );
        let collision = returned
            .as_ref()
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(nix::libc::EEXIST));
        self.trace.returned(returned.is_ok(), collision);
        if returned.is_err() {
            return Err(if collision {
                Reason::SourceRefused
            } else {
                Reason::CleanupUnknown
            });
        }
        book.slots[stage].name = new_name;
        if !self.trace.sync_entered() {
            return Err(Reason::CleanupUnknown);
        }
        let durable = self
            .sync_once(book, parent, 5, false, work)
            .and_then(|_| HistorySources::post_book(book, config, removed_work, Some(self), work))
            .and_then(|_| self.roster(book, work))
            .and_then(|_| absent(book, parent, &self.pending_name, work));
        self.trace.sync_returned(durable.is_ok());
        durable
    }
    pub(super) fn terminal(
        &mut self,
        book: &mut SourceBook,
        stop: &mut dyn FnMut() -> bool,
        failed: &mut dyn FnMut(Reason),
    ) {
        // No deletion/rollback or name adoption. A known pre-effect failure may
        // leave its exact pending directory for manual inspection; collisions
        // are refused by the next independent operation, never read as success.
        if self.pins.is_some() {
            if let Err(reason) = self.check(book, stop).and_then(|_| self.roster(book, stop)) {
                failed(reason);
            }
        }
        for index in [self.parent, self.staging, self.files[0], self.files[1]]
            .into_iter()
            .flatten()
        {
            if book.slots[index].state == OriginalState::Owned
                && book.slots[index].acl[0] == CallState::Settled
            {
                if let Err(reason) = book.private_acl(index, 1, stop) {
                    failed(reason);
                }
            }
        }
    }
    pub(super) fn closed(&self, known: bool) {
        self.trace.closed(known);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_source_reserve_keeps_four_actual_slots_and_complete_state() {
        let selection = wire::Selection {
            run_id: "1".into(),
            attempt: 100,
            stage: wire::Stage::Candidate,
            platform: wire::Platform::Ios,
        };
        let state = State::new(&selection, Trace::new(&selection).unwrap()).unwrap();
        assert_eq!(ORIGINALS, 4);
        assert!(!state.pending() && !state.armed());
        assert!(
            state.retained_bytes().unwrap()
                + wire::RETAINED_REPLY_LIMIT
                + 2 * 65536
                + data::RECEIPT_PARSE_RESERVE
                + 4 * data::RECEIPT_LIMIT
                <= data::CONTROL_RESERVE
        );
        // No SourceBook/FD/native operation is entered by this DATA assertion.
    }
    #[test]
    fn download_output_comparison_never_adopts_replaced_inode_mode_owner_or_link() {
        let original = wire::FileIdentity {
            device: "1".into(),
            inode: "2".into(),
            mode: 0o100600,
            uid: 501,
            gid: 20,
            nlink: "1".into(),
            bytes: "0".into(),
            mtime_seconds: "0".into(),
            ctime_seconds: "0".into(),
            mtime_nanos: 0,
            ctime_nanos: 0,
            flags: 0,
        };
        for n in 0..7 {
            let mut changed = original.clone();
            match n {
                0 => changed.device = "2".into(),
                1 => changed.inode = "3".into(),
                2 => changed.mode = 0o100644,
                3 => changed.uid = 502,
                4 => changed.gid = 21,
                5 => changed.nlink = "2".into(),
                _ => changed.flags = 1,
            }
            assert!(!same_file(&original, &changed));
        }
        let mut written = original.clone();
        written.bytes = "3".into();
        written.mtime_seconds = "1".into();
        written.ctime_seconds = "1".into();
        assert!(same_file(&original, &written)); // actual hash/size and full POST are still separately required
        let selection = wire::Selection {
            run_id: "1".into(),
            attempt: 1,
            stage: wire::Stage::Candidate,
            platform: wire::Platform::Android,
        };
        let mut state = State::new(&selection, Trace::new(&selection).unwrap()).unwrap();
        assert!(state
            .arm(
                &wire::download::tests::reply().download.unwrap(),
                wire::download::tests::reply().result.as_ref().unwrap()
            )
            .is_err());
        assert!(!state.armed()); // no original pins: never arm from valid public/terminal DATA alone
    }
}
