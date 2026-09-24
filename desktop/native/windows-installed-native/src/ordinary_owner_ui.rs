//! Fixed normal-UI extension of the existing original Account/Launch owner.
//! No general launcher, inherited user environment, shipping switch or fallback.
use super::*;
use std::{ffi::c_void, marker::PhantomData, path::PathBuf};
use windows_sys::Win32::System::{Com as CO, Ole as OLE, Registry as R};
use windows_sys::Win32::UI::WindowsAndMessaging as W;
use windows::{core::Interface, Win32::{Foundation::HWND, UI::Accessibility as A}};

const PROFILE_LIST: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

struct Clock { start: Instant, end: Instant, entry_tick: u64, endpoint_tick: u64, latched: bool, aggregate: Option<AggregateClock> }
impl Clock {
    fn new(entry_tick: u64) -> Result<Self> {
        let start = Instant::now();
        let endpoint_tick = entry_tick.checked_add(90_000).ok_or(Error::Bounds)?;
        let remaining = endpoint_tick.checked_sub(unsafe { SI::GetTickCount64() }).ok_or(Error::Unsafe)?;
        need(remaining > 0 && remaining <= 90_000)?;
        let end = start.checked_add(Duration::from_millis(remaining)).ok_or(Error::Bounds)?;
        // Existing Launch/Account helpers use start+90s. Backdate that same
        // endpoint instead of quietly creating a second ninety-second budget.
        let start = end.checked_sub(Duration::from_secs(90)).ok_or(Error::Bounds)?;
        Ok(Self { start, end, entry_tick, endpoint_tick, latched: false, aggregate: None })
    }
    fn effect(&mut self) -> Result<()> {
        let tick = unsafe { SI::GetTickCount64() };
        self.latched |= tick < self.entry_tick || tick >= self.endpoint_tick;
        owner_effect(self.start, &mut self.latched, &mut self.aggregate)
    }
    fn remaining_ms(&mut self) -> Result<u32> {
        self.effect()?;
        let remaining = self.endpoint_tick.checked_sub(unsafe { SI::GetTickCount64() }).ok_or(Error::Unsafe)?;
        need(remaining > 0 && remaining <= 90_000)?; Ok(remaining as u32)
    }
}

impl Launch {
    fn ui(request: &UiRequest, identity: &str, raw_request: &str, output: &Path,
        account: &Account, parent: &[u8], endpoint: u64) -> Result<Pin<Box<Self>>> {
        let binding = Binding { source: request.source.clone(), tree: request.tree.clone(), run: request.run.clone(),
            artifact: request.app.path.clone(), bytes: request.app.bytes, sha: request.app.sha.clone(),
            command_sha: request.app.command_sha.clone(), identity: identity.to_owned() };
        // Reuse the existing checked, explicit Windows system environment and
        // initialized original PI/STARTUPINFO. No ambient user values are added.
        let mut value = Self::new(OwnerVariant::Ordinary, &binding, None, output, account, parent)?;
        let current = unsafe { value.as_mut().get_unchecked_mut() };
        let text = String::from_utf16(&current.environment[..current.environment.len() - 1]).map_err(|_| Error::Unsafe)?;
        let mut pairs: Vec<(String, String)> = text.split('\0').filter(|entry| !entry.is_empty()).map(|entry| {
            entry.split_once('=').map(|(name, value)| (name.to_owned(), value.to_owned())).ok_or(Error::Unsafe)
        }).collect::<Result<_>>()?;
        pairs.retain(|(name, _)| !name.starts_with("MRK_WINDOWS_NATIVE_") && name != "MRK_WINDOWS_ORDINARY_OUTPUT");
        pairs.extend([
            ("MRK_WINDOWS_NORMAL_UI_REQUEST".to_owned(), raw_request.to_owned()),
            ("MRK_WINDOWS_NORMAL_UI_OUTPUT".to_owned(), output.to_str().ok_or(Error::Unsafe)?.to_owned()),
            ("MRK_WINDOWS_NORMAL_UI_ARTIFACT_IDENTITY".to_owned(), identity.to_owned()),
            ("MRK_WINDOWS_NORMAL_UI_END_TICK_MS".to_owned(), endpoint.to_string()),
            ("MRK_DESKTOP_DISPATCH_SCOPE".to_owned(), "windows-normal-project-ui".to_owned()),
            ("GITHUB_REF".to_owned(), "refs/heads/verify/desktop-windows-normal-project-ui".to_owned()),
            ("GITHUB_EVENT_NAME".to_owned(), "workflow_dispatch".to_owned()),
        ]);
        pairs.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        need(pairs.windows(2).all(|pair| !pair[0].0.eq_ignore_ascii_case(&pair[1].0)))?;
        current.environment = pairs.iter().flat_map(|(name, value)| wide(&format!("{name}={value}")))
            .chain(std::iter::once(0)).collect();
        current.command = wide(&request.role.command(&request.app.path, false));
        current.logon_flags = T::LOGON_WITH_PROFILE;
        need(current.environment.len() <= 8192 && current.command.len() <= 1024)?;
        Ok(value)
    }
}

// Every registry output/name/query/close destination lives in one retained
// original, including no-handle results. Borrowed HKLM/HKU are never closed.
struct Key {
    root: R::HKEY, name: Vec<u16>, handle: R::HKEY, state: SlotState,
    status: u32, value_name: Vec<u16>, value_kind: u32, value_size: u32,
    value: Box<[u8; 4096]>, active: bool,
}
impl Key {
    fn new(root: R::HKEY, name: &str) -> Self {
        Self { root, name: wide(name), handle: null_mut(), state: SlotState::Reserved,
            status: u32::MAX, value_name: wide("ProfileImagePath"), value_kind: 0, value_size: 4096,
            value: Box::new([0; 4096]), active: false }
    }
    fn open(&mut self, clock: &mut Clock) -> Result<bool> {
        need(self.state == SlotState::Reserved)?; clock.effect()?;
        self.state = SlotState::Acquiring; self.active = true;
        self.status = unsafe { R::RegOpenKeyExW(self.root, self.name.as_ptr(), 0,
            R::KEY_READ | R::KEY_WOW64_64KEY, &mut self.handle) };
        if self.status == F::ERROR_SUCCESS && !self.handle.is_null() {
            self.active = false; self.state = SlotState::Owned; clock.effect()?; return Ok(true);
        }
        if self.handle.is_null() && self.status != F::ERROR_SUCCESS && self.status != F::ERROR_IO_PENDING {
            self.active = false; self.state = SlotState::NoHandle; clock.effect()?;
            return if self.status == F::ERROR_FILE_NOT_FOUND { Ok(false) } else { Err(Error::Unavailable) };
        }
        self.state = SlotState::Unknown; Err(Error::Unknown)
    }
    fn profile_path(&mut self, expected: &Path, clock: &mut Clock) -> Result<()> {
        need(self.state == SlotState::Owned && !self.active)?; clock.effect()?;
        self.value_kind = 0; self.value_size = self.value.len() as u32; self.value.fill(0);
        self.active = true;
        self.status = unsafe { R::RegQueryValueExW(self.handle, self.value_name.as_ptr(), null(),
            &mut self.value_kind, self.value.as_mut_ptr(), &mut self.value_size) };
        self.active = self.status == F::ERROR_IO_PENDING;
        if self.active { self.state = SlotState::Unknown; return Err(Error::Unknown); }
        clock.effect()?;
        need(self.status == F::ERROR_SUCCESS && matches!(self.value_kind, R::REG_SZ | R::REG_EXPAND_SZ)
            && self.value_size >= 4 && self.value_size as usize <= self.value.len() && self.value_size % 2 == 0)?;
        let units: Vec<u16> = self.value[..self.value_size as usize].chunks_exact(2).map(|v| u16::from_le_bytes([v[0], v[1]])).collect();
        need(units.last() == Some(&0) && !units[..units.len() - 1].contains(&0))?;
        let text = String::from_utf16(&units[..units.len() - 1]).map_err(|_| Error::Unsafe)?;
        // REG_EXPAND_SZ is accepted only if already the exact absolute path;
        // no process/user environment expansion or redirected-profile fallback.
        need(fixed_path(&text)? == expected)
    }
    fn close(&mut self) -> Result<()> {
        match self.state {
            SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
            SlotState::Owned if !self.active => (), _ => return Err(Error::Unknown),
        }
        self.state = SlotState::Closing;
        self.status = unsafe { R::RegCloseKey(self.handle) };
        self.state = if self.status == F::ERROR_SUCCESS { SlotState::Closed } else { SlotState::Unknown };
        need(self.state == SlotState::Closed).map_err(|_| Error::Unknown)
    }
}

// These are two different lifecycle observations, not retries of the one genuine
// profile binding. NativeBook retains its once-only canonical-path reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbsenceEpoch { BeforeLogon, AfterDeletion }
impl AbsenceEpoch {
    fn index(self) -> usize { match self { Self::BeforeLogon => 0, Self::AfterDeletion => 1 } }
}

// Each fixed epoch owns its original relative output and every native borrower.
// A coherent success is collision, never adoption/deletion; ambiguity retains
// this pinned frame and the same original namespace parent through settlement.
struct Absence {
    epoch: AbsenceEpoch, parent: usize, parent_handle: F::HANDLE, name: Vec<u16>,
    output: UnsafeCell<F::HANDLE>, state: SlotState,
    attributes: OBJECT_ATTRIBUTES, unicode: F::UNICODE_STRING,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>, returned: i32, entered: bool, completed: bool,
    claimed: bool, absent: bool, close_handle: F::HANDLE, close_entered: bool,
    close_return: i32, close_error: u32,
    _pin: PhantomPinned,
}
impl Absence {
    fn new(epoch: AbsenceEpoch, parent: usize, parent_handle: F::HANDLE, name: &str) -> Result<Pin<Box<Self>>> {
        need(valid_handle(parent_handle) && decode::component(name))?;
        let name = wide(name);
        let length = u16::try_from((name.len() - 1).checked_mul(2).ok_or(Error::Bounds)?).map_err(|_| Error::Bounds)?;
        let maximum = u16::try_from(name.len().checked_mul(2).ok_or(Error::Bounds)?).map_err(|_| Error::Bounds)?;
        let mut frame = Box::pin(Self { epoch, parent, parent_handle, name,
            output: UnsafeCell::new(null_mut()), state: SlotState::Reserved,
            attributes: OBJECT_ATTRIBUTES::default(), unicode: F::UNICODE_STRING::default(),
            iosb: UnsafeCell::new(IO::IO_STATUS_BLOCK {
                Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING }, Information: usize::MAX }),
            returned: F::STATUS_PENDING, entered: false, completed: false, claimed: false, absent: false,
            close_handle: null_mut(), close_entered: false, close_return: 0, close_error: 0, _pin: PhantomPinned });
        // SAFETY: pinning precedes these self-references, publication and entry.
        // Neither the name allocation nor this frame moves before settlement.
        let f = unsafe { frame.as_mut().get_unchecked_mut() };
        f.unicode = F::UNICODE_STRING { Length: length, MaximumLength: maximum, Buffer: f.name.as_mut_ptr() };
        f.attributes = OBJECT_ATTRIBUTES { Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent_handle, ObjectName: &mut f.unicode,
            Attributes: F::OBJ_CASE_INSENSITIVE | F::OBJ_DONT_REPARSE,
            SecurityDescriptor: null_mut(), SecurityQualityOfService: null_mut() };
        Ok(frame)
    }
    fn unstarted(&self) -> bool {
        !self.claimed && !self.entered && !self.completed && !self.close_entered && self.state == SlotState::Reserved
    }
    fn claim(&mut self) -> Result<()> {
        if !self.unstarted() { return Err(Error::State); }
        self.claimed = true; Ok(())
    }
    fn begin(&mut self) -> Result<()> {
        if !self.claimed || self.entered || self.completed || self.state != SlotState::Reserved { return Err(Error::State); }
        self.entered = true; self.state = SlotState::Acquiring; Ok(())
    }
    fn unknown(&mut self) -> Result<()> { self.state = SlotState::Unknown; Err(Error::Unknown) }
    // Pure return/ownership decisions used by the real original call and the
    // inert contracts. No native acquisition, clock or close is reachable here.
    fn observe_return(&mut self, book: &NativeBook, other: &Absence) -> Result<()> {
        if !self.entered || self.completed || self.state != SlotState::Acquiring { return Err(Error::State); }
        if self.returned == F::STATUS_PENDING || self.returned != F::STATUS_SUCCESS && (self.returned as u32 >> 30) != 3 {
            return self.unknown(); // Do not read possibly outstanding output/IOSB.
        }
        self.completed = true;
        // SAFETY: only a definite completed NT return reaches these original
        // output reads. The other/book owners are serialized and already Owned.
        let handle = unsafe { *self.output.get() };
        if self.returned == F::STATUS_SUCCESS {
            if !valid_handle(handle) || unsafe { (*self.iosb.get()).Anonymous.Status } != F::STATUS_SUCCESS
                || unsafe { (*self.iosb.get()).Information } != WP::FILE_OPENED as usize
                || book.slots.iter().any(|slot| slot.state == SlotState::Owned && unsafe { *slot.output.get() == handle })
                || other.state == SlotState::Owned && unsafe { *other.output.get() == handle } {
                return self.unknown();
            }
            self.state = SlotState::Owned;
            return Err(Error::Unsafe); // A collision has one close, never deletion.
        }
        if !handle.is_null() { return self.unknown(); }
        self.state = SlotState::NoHandle;
        // Error IOSB fields are unspecified; do not reinterpret their sentinels.
        self.absent = self.returned as u32 == 0xc0000034;
        need(self.absent)
    }
    fn exact_absence(&self) -> bool {
        self.claimed && self.entered && self.completed && self.absent && !self.close_entered
            && self.state == SlotState::NoHandle && self.returned as u32 == 0xc0000034
    }
    fn unresolved(&self) -> bool {
        self.entered && !self.completed || matches!(self.state, SlotState::Acquiring | SlotState::Closing | SlotState::Unknown)
            || self.close_entered && self.state != SlotState::Closed
    }
    fn begin_close(&mut self) -> Result<Option<F::HANDLE>> {
        if self.unresolved() { self.unknown()?; }
        if !self.entered && !self.completed && !self.close_entered && self.state == SlotState::Reserved {
            self.state = SlotState::NoHandle; // Genuinely unentered, not an absence receipt.
        }
        if matches!(self.state, SlotState::NoHandle | SlotState::Closed) { return Ok(None); }
        if self.state != SlotState::Owned || !self.completed || self.close_entered { self.unknown()?; }
        // SAFETY: Owned was established by the definite coherent create return.
        let handle = unsafe { *self.output.get() };
        if !valid_handle(handle) { self.unknown()?; }
        self.close_handle = handle; self.close_entered = true; self.state = SlotState::Closing;
        unsafe { *self.output.get() = null_mut(); }
        Ok(Some(handle))
    }
    fn observe_close(&mut self) -> Result<()> {
        if !self.close_entered || self.state != SlotState::Closing { return Err(Error::State); }
        if self.close_return == 0 { return self.unknown(); }
        self.state = SlotState::Closed; Ok(())
    }
    fn close_once(&mut self) -> Result<()> {
        if self.begin_close()?.is_none() { return Ok(()); }
        // All return/error/input destinations were preregistered in this frame.
        self.close_return = unsafe { F::CloseHandle(self.close_handle) };
        self.close_error = if self.close_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        self.observe_close()
    }
    fn settled(&self) -> bool {
        !self.unresolved() && match self.state {
            SlotState::NoHandle => !self.close_entered && (!self.entered || self.completed),
            SlotState::Closed => self.entered && self.completed && self.close_entered && self.close_return != 0,
            _ => false,
        }
    }
}
struct ProfilePath { original: Original, metadata: Metadata }
struct Profile {
    native: NativeBook, paths: Vec<ProfilePath>, absence: [Option<Held<Absence>>; 2], keys: Vec<Box<Key>>,
    directory: Box<[u16; 1024]>, units: u32, getter_entered: bool, getter_return: i32, getter_error: u32,
    sid: Vec<u16>, name: String, drive: String, device: String, expected: PathBuf,
    profile: Option<ProfilePath>, mapping: Option<usize>, root_key: Option<usize>,
    prestate: bool, exact: bool, hives_unloaded: bool, delete_entered: bool, delete_return: i32, delete_error: u32,
    poststate: bool, unknown: bool, settled: bool,
}
impl Profile {
    fn new(account: &Account) -> Result<Self> {
        need(local_account_sid(&account.sid))?;
        let sid = format!("S-1-5-21-{}-{}-{}-{}", decode::u32_at(&account.sid, 12)?,
            decode::u32_at(&account.sid, 16)?, decode::u32_at(&account.sid, 20)?, decode::u32_at(&account.sid, 24)?);
        let name = String::from_utf16(&account.name[..account.name.len() - 1]).map_err(|_| Error::Unsafe)?;
        need(name.len() == 19 && name.starts_with("mrk") && is_hex(&name[3..], 16))?;
        Ok(Self { native: NativeBook::new(), paths: Vec::with_capacity(16), absence: [None, None],
            keys: Vec::with_capacity(64), directory: Box::new([0; 1024]), units: 1024,
            getter_entered: false, getter_return: 0, getter_error: 0, sid: wide(&sid), name,
            drive: String::new(), device: String::new(), expected: PathBuf::new(), profile: None,
            mapping: None, root_key: None, prestate: false, exact: false, hives_unloaded: false,
            delete_entered: false, delete_return: 0, delete_error: 0, poststate: false, unknown: false, settled: false })
    }
    fn key(&mut self, root: R::HKEY, name: &str, clock: &mut Clock) -> Result<(usize, bool)> {
        need(self.keys.len() < 64)?;
        let index = self.keys.len(); self.keys.push(Box::new(Key::new(root, name)));
        let opened = self.keys[index].open(clock)?; Ok((index, opened))
    }
    fn sid_name(&self) -> Result<String> { String::from_utf16(&self.sid[..self.sid.len() - 1]).map_err(|_| Error::Unsafe) }
    fn hives_absent(&mut self, clock: &mut Clock) -> Result<bool> {
        let sid = self.sid_name()?;
        let mut absent = true;
        for name in [sid.clone(), format!("{sid}_Classes")] {
            let (index, present) = self.key(R::HKEY_USERS, &name, clock)?;
            self.keys[index].close()?; absent &= !present;
        }
        Ok(absent)
    }
    fn absence(&self, epoch: AbsenceEpoch) -> Result<&Absence> {
        self.absence[epoch.index()].as_ref().map(|frame| frame.as_ref().get_ref()).ok_or(Error::State)
    }
    fn absence_mut(&mut self, epoch: AbsenceEpoch) -> Result<&mut Absence> {
        let frame = self.absence[epoch.index()].as_mut().ok_or(Error::State)?;
        Ok(unsafe { frame.as_mut().get_unchecked_mut() })
    }
    fn register_absence(&mut self) -> Result<()> {
        self.native.clear()?;
        need(!self.unknown && !self.settled && self.absence.iter().all(Option::is_none)
            && !self.paths.is_empty() && self.paths.len() <= 14 && self.native.slots.len() == self.paths.len())?;
        // Two fixed output originals plus the one future binding count against
        // the SAME existing limits. At most14 parents+2 epochs+1 binding =17.
        let records = self.native.slots.len().checked_add(3).ok_or(Error::Bounds)?;
        if records > MAX_RECORDS || records > MAX_LIVE { return Err(Error::Bounds); }
        let parent = self.paths.last().ok_or(Error::State)?.original.index;
        let handle = self.native.handle(parent)?;
        let before = Absence::new(AbsenceEpoch::BeforeLogon, parent, handle, &self.name)?;
        let after = Absence::new(AbsenceEpoch::AfterDeletion, parent, handle, &self.name)?;
        self.absence = [Some(ManuallyDrop::new(before)), Some(ManuallyDrop::new(after))];
        Ok(()) // Both fixed frames are owned BEFORE either original call.
    }
    fn absence_permitted(&self, epoch: AbsenceEpoch) -> Result<()> {
        if self.unknown { return Err(Error::Unknown); }
        self.native.clear()?; need(!self.settled && !self.poststate)?;
        let parent = self.paths.last().ok_or(Error::State)?.original.index;
        let handle = self.native.handle(parent)?; let name = wide(&self.name);
        for expected in [AbsenceEpoch::BeforeLogon, AbsenceEpoch::AfterDeletion] {
            let frame = self.absence(expected)?;
            need(frame.epoch == expected && frame.parent == parent && frame.parent_handle == handle && frame.name == name)?;
        }
        need(self.absence(epoch)?.unstarted())?;
        match epoch {
            AbsenceEpoch::BeforeLogon => need(!self.prestate && !self.exact && self.profile.is_none()
                && !self.delete_entered && self.absence(AbsenceEpoch::AfterDeletion)?.unstarted()),
            AbsenceEpoch::AfterDeletion => need(self.prestate && self.exact && self.hives_unloaded
                && self.absence(AbsenceEpoch::BeforeLogon)?.exact_absence()
                && self.profile.as_ref().is_some_and(|path| self.native.state(&path.original) == Ok(SlotState::Closed))
                && self.mapping.and_then(|index| self.keys.get(index)).is_some_and(|key| key.state == SlotState::Closed && !key.active)
                && self.delete_entered && self.delete_return != 0),
        }
    }
    fn binding_permitted(&self) -> Result<()> {
        if self.unknown { return Err(Error::Unknown); }
        self.native.clear()?;
        need(self.prestate && !self.exact && self.profile.is_none() && !self.delete_entered && !self.settled
            && self.absence(AbsenceEpoch::BeforeLogon)?.exact_absence() && self.absence(AbsenceEpoch::AfterDeletion)?.unstarted())
    }
    fn absence_dependents_settled(&self) -> bool {
        self.absence.iter().flatten().all(|frame| frame.settled())
    }
    fn profile_absent(&mut self, epoch: AbsenceEpoch, clock: &mut Clock) -> Result<()> {
        let permission = self.absence_permitted(epoch);
        if matches!(permission, Err(Error::Unknown)) { self.unknown = true; return permission; }
        self.absence_mut(epoch)?.claim()?; // Even a pre-entry refusal spends this fixed epoch.
        permission?; clock.effect()?;
        let native = &self.native;
        let [before, after] = &mut self.absence;
        let (frame, other) = match epoch { AbsenceEpoch::BeforeLogon => (before, after), AbsenceEpoch::AfterDeletion => (after, before) };
        let f = unsafe { frame.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
        let other = other.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        f.begin()?;
        f.returned = unsafe { N::NtCreateFile(f.output.get(), FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE,
            &f.attributes, f.iosb.get(), null(), 0, FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE, N::FILE_OPEN,
            N::FILE_DIRECTORY_FILE | N::FILE_OPEN_REPARSE_POINT | N::FILE_SYNCHRONOUS_IO_NONALERT, null(), 0) };
        let result = f.observe_return(native, other);
        self.unknown |= f.state == SlotState::Unknown;
        result?; clock.effect()
    }
    fn prepare(&mut self, clock: &mut Clock) -> Result<()> {
        need(!self.getter_entered)?; clock.effect()?;
        self.getter_entered = true;
        self.getter_return = unsafe { SH::GetProfilesDirectoryW(self.directory.as_mut_ptr(), &mut self.units) };
        self.getter_error = if self.getter_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        if self.getter_return == 0 && (self.getter_error == 0 || self.getter_error == F::ERROR_IO_PENDING) {
            self.unknown = true; return Err(Error::Unknown);
        }
        clock.effect()?; need(self.getter_return != 0 && self.units > 1 && self.units as usize <= self.directory.len())?;
        let count = self.directory.iter().position(|unit| *unit == 0).ok_or(Error::Unsafe)?;
        let path = String::from_utf16(&self.directory[..count]).map_err(|_| Error::Unsafe)?;
        let root = fixed_path(&path)?;
        let (drive, parts) = decode::dos_location(&path)?;
        need(!parts.is_empty() && parts.len() < 14)?;
        self.drive = drive; self.device = self.native.mapping(&self.drive)?; clock.effect()?;
        let name = format!("{}\\", self.device);
        let original = self.native.reserve(Kind::Directory, None, &name, name.clone())?;
        // NativeBook keeps the original output even if an error prevents the
        // higher-level metadata record from being added to paths.
        self.native.call(Call::Open(original.index), null_mut(), Vec::new())?;
        clock.effect()?; self.native.noninherited(original.index)?; clock.effect()?;
        let metadata = self.native.metadata(&original)?; clock.effect()?; self.native.local_ntfs(&original)?;
        clock.effect()?; self.native.security(&original, AuthorityScope::AncestorOutsideVersion)?; clock.effect()?;
        self.paths.push(ProfilePath { original, metadata });
        for name in parts {
            clock.effect()?;
            let original = self.native.open_child(&self.paths.last().ok_or(Error::State)?.original, &name, FileKind::Directory)?;
            clock.effect()?; let metadata = self.native.metadata(&original)?; clock.effect()?;
            self.native.security(&original, AuthorityScope::AncestorOutsideVersion)?; clock.effect()?;
            self.paths.push(ProfilePath { original, metadata });
        }
        self.expected = root.join(&self.name);
        self.register_absence()?;
        self.profile_absent(AbsenceEpoch::BeforeLogon, clock)?;
        let (index, present) = self.key(R::HKEY_LOCAL_MACHINE, PROFILE_LIST, clock)?;
        need(present)?; self.root_key = Some(index);
        let handle = self.keys[index].handle;
        let (sid_key, present) = self.key(handle, &self.sid_name()?, clock)?;
        self.keys[sid_key].close()?; need(!present && self.hives_absent(clock)?)?;
        self.prestate = true; clock.effect()
    }
    fn bind_after_logon(&mut self, clock: &mut Clock) -> Result<()> {
        self.binding_permitted()?; clock.effect()?;
        let root = &self.paths.last().ok_or(Error::State)?.original;
        let original = self.native.open_child(root, &self.name, FileKind::Directory)?;
        clock.effect()?; let metadata = self.native.metadata(&original)?; clock.effect()?;
        self.native.local_ntfs(&original)?; clock.effect()?;
        self.profile = Some(ProfilePath { original, metadata });
        let handle = self.keys[self.root_key.ok_or(Error::State)?].handle;
        let (index, present) = self.key(handle, &self.sid_name()?, clock)?;
        need(present)?; self.mapping = Some(index);
        self.keys[index].profile_path(&self.expected, clock)?;
        self.recheck(clock)?; self.exact = true; Ok(())
    }
    fn recheck(&mut self, clock: &mut Clock) -> Result<()> {
        clock.effect()?;
        need(self.native.mapping(&self.drive)? == self.device)?;
        for path in &self.paths {
            clock.effect()?;
            let after = self.native.metadata(&path.original)?;
            clock.effect()?;
            need(after.identity == path.metadata.identity && after.kind == FileKind::Directory)?;
            self.native.security(&path.original, AuthorityScope::AncestorOutsideVersion)?; clock.effect()?;
        }
        if let Some(path) = &self.profile {
            let after = self.native.metadata(&path.original)?;
            clock.effect()?;
            need(after.identity == path.metadata.identity && after.kind == FileKind::Directory)?;
        }
        if let Some(index) = self.mapping { self.keys[index].profile_path(&self.expected, clock)?; }
        clock.effect()
    }
    fn retire(&mut self, clock: &mut Clock) -> Result<()> {
        need(self.prestate && self.exact && !self.unknown && !self.delete_entered && !self.settled)?;
        // B's genuine application exit already joined its browser/user-data
        // lifetime. LOGON_WITH_PROFILE owns automatic hive unload, not this test.
        for _ in 0..20 {
            if self.hives_absent(clock)? { self.hives_unloaded = true; break; }
            clock.effect()?; std::thread::sleep(Duration::from_millis(250));
        }
        need(self.hives_unloaded)?; self.recheck(clock)?;
        self.keys[self.mapping.ok_or(Error::State)?].close()?;
        self.native.close_once(&self.profile.as_ref().ok_or(Error::State)?.original)?;
        // Release the profile child only, not the original namespace parent.
        // DeleteProfileW takes exact owned SID; no alternate path is supplied.
        clock.effect()?; self.delete_entered = true;
        self.delete_return = unsafe { SH::DeleteProfileW(self.sid.as_ptr(), null(), null()) };
        self.delete_error = if self.delete_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        if self.delete_return == 0 { self.unknown = true; return Err(Error::Unknown); }
        clock.effect()?;
        self.profile_absent(AbsenceEpoch::AfterDeletion, clock)?;
        let handle = self.keys[self.root_key.ok_or(Error::State)?].handle;
        let (index, present) = self.key(handle, &self.sid_name()?, clock)?;
        self.keys[index].close()?; need(!present && self.hives_absent(clock)?)?;
        // Recheck surviving namespace originals without reusing the now-closed
        // profile/mapping handles or adopting a replacement profile path.
        need(self.native.mapping(&self.drive)? == self.device)?;
        for path in &self.paths { clock.effect()?; need(self.native.metadata(&path.original)?.identity == path.metadata.identity)?; }
        self.poststate = true; self.settle()?; clock.effect()
    }
    fn settle(&mut self) -> Result<()> {
        if self.settled { return Ok(()); }
        if self.unknown || self.native.is_unknown() || self.absence.iter().flatten().any(|frame| frame.unresolved()) {
            self.unknown = true; return Err(Error::Unknown);
        }
        // These fixed frames are dependents of the original namespace parent,
        // outside the binding path book. Their one closes MUST precede it.
        for frame in self.absence.iter_mut().flatten() {
            let frame = unsafe { frame.as_mut().get_unchecked_mut() };
            if frame.close_once().is_err() { self.unknown = true; return Err(Error::Unknown); }
        }
        if !self.absence_dependents_settled() { self.unknown = true; return Err(Error::Unknown); }
        for key in self.keys.iter_mut().rev() {
            if key.close().is_err() { self.unknown = true; return Err(Error::Unknown); }
        }
        self.settled = self.native.settle_once() == CloseOutcome::Settled && self.native.settled();
        if !self.settled { self.unknown = true; return Err(Error::Unknown); }
        // Original native frames have returned and every dependent original is
        // closed before any frame storage is deallocated.
        for frame in &mut self.absence { if let Some(frame) = frame.take() { drop(ManuallyDrop::into_inner(frame)); } }
        Ok(())
    }
}

struct DirectoryCreate { name: Vec<u16>, entered: bool, returned: i32, error: u32 }
struct FixtureFile { index: usize, stamp: Stamp, bytes: &'static [u8] }
struct Fixture {
    project: usize, app: usize, release: usize, original_files: Vec<FixtureFile>,
    directory_stamps: [Stamp; 3], initial_config: bool, verified: bool,
}

fn input(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32,
    clock: &mut Clock, trace: &mut InputTrace) -> Result<usize> {
    need(files.len() < 48)?; clock.effect()?;
    let index = files.len(); files.push(OriginalFile::fixture_new(path, directory, clock.end)?);
    files[index].open_traced(access, false, null(), trace)?;
    files[index].named_traced(path, trace)?; files[index].stamp_traced(trace)?;
    clock.effect()?; Ok(index)
}
fn new_directory(creates: &mut Vec<Box<DirectoryCreate>>, files: &mut Vec<OriginalFile>, path: &Path,
    clock: &mut Clock, trace: &mut InputTrace) -> Result<usize> {
    need(creates.len() < 4)?; clock.effect()?;
    creates.push(Box::new(DirectoryCreate { name: wide(path.to_str().ok_or(Error::Unsafe)?),
        entered: false, returned: 0, error: 0 }));
    let call = creates.last_mut().ok_or(Error::State)?;
    call.entered = true;
    call.returned = unsafe { FS::CreateDirectoryW(call.name.as_ptr(), null()) };
    call.error = if call.returned != 0 { 0 } else { unsafe { F::GetLastError() } };
    if call.returned == 0 && (call.error == 0 || call.error == F::ERROR_IO_PENDING) { return Err(Error::Unknown); }
    // Neither an existing path nor a failed creation is adopted or deleted.
    need(call.returned != 0)?; clock.effect()?;
    input(files, path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC, clock, trace)
}
fn read_hash(files: &mut [OriginalFile], index: usize, bytes: usize, sha: &str, app: bool,
    clock: &mut Clock, trace: &mut InputTrace) -> Result<Stamp> {
    clock.effect()?; let before = files[index].stamp_traced(trace)?;
    let raw = if app { files[index].read_app_traced(trace)? } else { files[index].read_traced(128 << 20, trace)? };
    clock.effect()?; need(raw.len() == bytes)?;
    let actual = if app { digest_app_traced(&raw, trace)? } else { digest_traced(&raw, trace)? };
    clock.effect()?; need(actual == sha && files[index].stamp_traced(trace)? == before)?; Ok(before)
}
fn acl(files: &mut [OriginalFile], index: usize, label: &str, mask: u32, parent: &[u8], account: &[u8],
    clock: &mut Clock, trace: &mut InputTrace, transitions: &mut Vec<String>) -> Result<()> {
    clock.effect()?;
    transitions.push(grant(&mut files[index], label, parent, account, mask,
        clock.start, &mut clock.latched, &mut clock.aggregate, trace)?);
    clock.effect()
}
fn create_fixture_file(files: &mut Vec<OriginalFile>, path: &Path, bytes: &'static [u8], parent: &[u8], account: &[u8],
    clock: &mut Clock, trace: &mut InputTrace, transitions: &mut Vec<String>) -> Result<FixtureFile> {
    need(files.len() < 48)?; clock.effect()?;
    let writer = files.len(); files.push(OriginalFile::fixture_new(path, false, clock.end)?);
    files[writer].open(FS::FILE_GENERIC_WRITE, true, null())?;
    files[writer].named(path)?; files[writer].write_fixture_payload(bytes)?;
    let created = files[writer].stamp()?;
    // Do not retain a write-data handle while the ordinary core opens the same
    // immutable file share-read-only. Close it once and authenticate the new
    // read original against the actual CREATE_NEW identity under pinned parents.
    files[writer].close()?; clock.effect()?;
    let index = input(files, path, false, FS::FILE_GENERIC_READ | FS::WRITE_DAC, clock, trace)?;
    let reopened = files[index].stamp()?;
    // Windows can publish the final write/change times only when the last
    // write-data handle closes. Identity and bytes are not allowed to change.
    need(reopened.volume == created.volume && reopened.id == created.id && reopened.creation == created.creation
        && reopened.size == bytes.len() as i64 && reopened.size == created.size && reopened.links == 1
        && reopened.attributes == created.attributes && reopened.write >= created.write && reopened.change >= created.change
        && files[index].read(LIMIT)? == bytes)?;
    acl(files, index, "synthetic-input", FS::FILE_GENERIC_READ, parent, account, clock, trace, transitions)?;
    Ok(FixtureFile { index, stamp: files[index].stamp()?, bytes })
}
impl Fixture {
    fn create(role: UiRole, output: &Path, creates: &mut Vec<Box<DirectoryCreate>>, files: &mut Vec<OriginalFile>,
        parent: &[u8], account: &[u8], clock: &mut Clock, trace: &mut InputTrace, transitions: &mut Vec<String>) -> Result<Self> {
        need(matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss))?;
        let path = output.join("project");
        let project = new_directory(creates, files, &path, clock, trace)?;
        let app = new_directory(creates, files, &path.join("app"), clock, trace)?;
        let release = new_directory(creates, files, &path.join("release"), clock, trace)?;
        for (index, label) in [(project, "synthetic-project"), (app, "synthetic-app"), (release, "synthetic-release")] {
            let mask = FS::FILE_GENERIC_READ | FS::FILE_TRAVERSE
                | if index == release && role == UiRole::ProjectDraft { FS::FILE_ADD_FILE } else { 0 };
            acl(files, index, label, mask, parent, account, clock, trace, transitions)?;
        }
        let mut original_files = Vec::with_capacity(4);
        for (name, bytes) in [("app/build.gradle.kts", UI_FIXTURE_SOURCE), ("version.properties", UI_FIXTURE_VERSION),
            ("keep.txt", UI_FIXTURE_KEEP)] {
            original_files.push(create_fixture_file(files, &path.join(name), bytes, parent, account, clock, trace, transitions)?);
        }
        let initial_config = role != UiRole::ProjectDraft;
        if initial_config {
            original_files.push(create_fixture_file(files, &path.join("release/mobile-release.json"), UI_FIXTURE_CONFIG,
                parent, account, clock, trace, transitions)?);
        }
        Ok(Self { project, app, release, original_files,
            directory_stamps: [files[project].stamp()?, files[app].stamp()?, files[release].stamp()?],
            initial_config, verified: false })
    }
}

// Independent post-exit full output inventory. It reads from original pinned
// directory cursors and joins each entry to the already-retained input full ID.
// No recursive deletion or replacement/reacquisition as a finality shortcut.
fn output_poststate(native: &mut NativeBook, files: &mut Vec<OriginalFile>, fixture: &mut Option<Fixture>,
    role: UiRole, output: &Path, output_index: usize, result_index: Option<usize>, clock: &mut Clock,
    trace: &mut InputTrace) -> Result<()> {
    let (drive, parts) = decode::dos_location(output.to_str().ok_or(Error::Unsafe)?)?;
    need(parts.len() < 16)?; clock.effect()?;
    let device = native.mapping(&drive)?; let name = format!("{device}\\");
    let root = native.reserve(Kind::Directory, None, &name, name.clone())?;
    native.call(Call::Open(root.index), null_mut(), Vec::new())?;
    native.noninherited(root.index)?; native.local_ntfs(&root)?;
    let root_metadata = native.metadata(&root)?;
    let mut entries = vec![(root, root_metadata)];
    for name in parts {
        clock.effect()?;
        let original = native.open_child(&entries.last().ok_or(Error::State)?.0, &name, FileKind::Directory)?;
        let metadata = native.metadata(&original)?; entries.push((original, metadata));
    }
    let at = entries.len() - 1;
    let output_stamp = files[output_index].stamp()?;
    need(entries[at].1.identity.volume_serial == output_stamp.volume && entries[at].1.identity.file_id == output_stamp.id)?;
    let mut directories = vec![(at, at - 1)];
    let mut children: Vec<(usize, String, Stamp, FileKind)> = Vec::with_capacity(9);
    if let Some(result) = result_index {
        children.push((at, role.name("result.private.json"), files[result].stamp()?, FileKind::File));
    }
    if let Some(fixture) = fixture.as_mut() {
        let project_path = output.join("project");
        for (index, before) in [fixture.project, fixture.app, fixture.release].into_iter().zip(&fixture.directory_stamps) {
            let after = files[index].stamp()?;
            need(after.volume == before.volume && after.id == before.id && after.creation == before.creation
                && after.attributes == before.attributes && after.links == before.links)?;
        }
        let project = native.open_child(&entries[at].0, "project", FileKind::Directory)?;
        let metadata = native.metadata(&project)?; let project_at = entries.len(); entries.push((project, metadata));
        need(entries[project_at].1.identity.file_id == files[fixture.project].stamp()?.id)?;
        directories.push((project_at, at));
        children.push((at, "project".to_owned(), files[fixture.project].stamp()?, FileKind::Directory));
        let mut branch = Vec::with_capacity(2);
        for (name, index) in [("app", fixture.app), ("release", fixture.release)] {
            let original = native.open_child(&entries[project_at].0, name, FileKind::Directory)?;
            let metadata = native.metadata(&original)?; let n = entries.len(); entries.push((original, metadata));
            need(entries[n].1.identity.file_id == files[index].stamp()?.id)?;
            directories.push((n, project_at)); branch.push(n);
            children.push((project_at, name.to_owned(), files[index].stamp()?, FileKind::Directory));
        }
        for file in &fixture.original_files { need(files[file.index].stamp()? == file.stamp)?; }
        for (position, parent, name) in [(0, branch[0], "build.gradle.kts"), (1, project_at, "version.properties"),
            (2, project_at, "keep.txt")] {
            let file = &fixture.original_files[position];
            children.push((parent, name.to_owned(), file.stamp.clone(), FileKind::File));
            // The retained share-read-only original protects immutable bytes;
            // this fresh cursor adds full EOF readback, not replacement identity.
            let original = native.open_child(&entries[parent].0, name, FileKind::File)?;
            let metadata = native.metadata(&original)?;
            clock.effect()?; native.no_alternate_streams(&original)?; clock.effect()?;
            need(metadata.identity.volume_serial == file.stamp.volume && metadata.identity.file_id == file.stamp.id
                && native.read_next(&original, LIMIT)? == file.bytes && native.read_next(&original, 1)?.is_empty())?;
            entries.push((original, metadata));
        }
        let config = if fixture.initial_config {
            let original = &fixture.original_files[3]; need(files[original.index].stamp()? == original.stamp)?; original.index
        } else {
            need(role == UiRole::ProjectDraft)?;
            let index = input(files, &project_path.join("release/mobile-release.json"), false, FS::FILE_GENERIC_READ, clock, trace)?;
            need(files[index].read(LIMIT)? == UI_FIXTURE_CONFIG_AFTER)?; index
        };
        let stamp = files[config].stamp()?;
        children.push((branch[1], "mobile-release.json".to_owned(), stamp.clone(), FileKind::File));
        let original = native.open_child(&entries[branch[1]].0, "mobile-release.json", FileKind::File)?;
        let metadata = native.metadata(&original)?;
        clock.effect()?; native.no_alternate_streams(&original)?; clock.effect()?;
        need(metadata.identity.volume_serial == stamp.volume && metadata.identity.file_id == stamp.id
            && native.read_next(&original, LIMIT)? == if fixture.initial_config { UI_FIXTURE_CONFIG } else { UI_FIXTURE_CONFIG_AFTER }
            && native.read_next(&original, 1)?.is_empty())?;
        entries.push((original, metadata));
    } else { need(matches!(role, UiRole::Prerequisite | UiRole::NormalSmoke))?; }
    for (index, parent) in directories {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            clock.effect()?; let Some(batch) = native.next_entries(&entries[index].0)? else { break; };
            for entry in batch {
                need(seen.insert(entry.name.clone()) && seen.len() <= 6)?;
                if entry.name == "." { need(entry.file_id == entries[index].1.identity.file_id)?; continue; }
                if entry.name == ".." { need(entry.file_id == entries[parent].1.identity.file_id)?; continue; }
                let (_, _, expected, kind) = children.iter().find(|(p, name, _, _)| *p == index && *name == entry.name).ok_or(Error::Unsafe)?;
                need(entry.file_id == expected.id && entry.kind == *kind && entries[index].1.identity.volume_serial == expected.volume)?;
            }
        }
        let expected: std::collections::BTreeSet<_> = children.iter().filter(|(p, _, _, _)| *p == index)
            .map(|(_, name, _, _)| name.clone()).chain([".".to_owned(), "..".to_owned()]).collect();
        need(seen == expected)?;
    }
    for (original, before) in &entries { clock.effect()?; need(native.metadata(original)? == *before)?; }
    need(native.mapping(&drive)? == device)?; clock.effect()?;
    if let Some(fixture) = fixture.as_mut() { fixture.verified = true; }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ComKind { Client, Walker, Element, Invoke }
struct ComOriginal {
    pointer: *mut c_void, kind: ComKind, state: SlotState, active: bool, status: i32, release_return: u32,
}
impl ComOriginal {
    fn new(kind: ComKind) -> Self {
        Self { pointer: null_mut(), kind, state: SlotState::Reserved, active: false, status: HRESULT_PENDING, release_return: u32::MAX }
    }
    fn begin(&mut self) -> Result<*mut *mut c_void> {
        need(self.state == SlotState::Reserved)?; self.state = SlotState::Acquiring; self.active = true;
        Ok(&mut self.pointer)
    }
    fn returned(&mut self, status: i32, nullable: bool) -> Result<bool> {
        self.status = status;
        if status == HRESULT_PENDING || status < 0 && !self.pointer.is_null() {
            self.state = SlotState::Unknown; return Err(Error::Unknown);
        }
        self.active = false;
        if !self.pointer.is_null() { self.state = SlotState::Owned; need(status == 0)?; return Ok(true); }
        self.state = SlotState::NoHandle;
        need(status == 0 && nullable)?; Ok(false)
    }
    fn release(&mut self) -> Result<()> {
        match self.state {
            SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
            SlotState::Owned if !self.active => (), _ => return Err(Error::Unknown),
        }
        self.state = SlotState::Closing; self.active = true;
        // Release returns a remaining reference count, NOT an HRESULT or proof
        // that unrelated references vanished. This one owned ref is released.
        self.release_return = unsafe { ((**self.pointer.cast::<*const windows::core::IUnknown_Vtbl>()).Release)(self.pointer) };
        self.active = false; self.state = SlotState::Closed; Ok(())
    }
}
struct UiQuery {
    active: bool, unknown: bool, status: i32, bstr: *mut c_void, array: *mut CO::SAFEARRAY,
    integer: i32, boolean: windows::core::BOOL, hwnd: HWND, control: A::UIA_CONTROLTYPE_ID,
    lower: i32, upper: i32, index: i32, dimensions: u32, element_size: u32, variant: u16,
    values: [i32; 16], destroy_entered: bool, destroy_return: i32,
}
impl UiQuery {
    fn new() -> Self {
        Self { active: false, unknown: false, status: HRESULT_PENDING, bstr: null_mut(), array: null_mut(),
            integer: 0, boolean: windows::core::BOOL(0), hwnd: HWND(null_mut()), control: A::UIA_CONTROLTYPE_ID(0),
            lower: 0, upper: -1, index: 0, dimensions: 0, element_size: 0, variant: 0, values: [0; 16],
            destroy_entered: false, destroy_return: HRESULT_PENDING }
    }
    fn begin(&mut self, clock: &mut Clock) -> Result<()> {
        need(!self.active && !self.unknown)?;
        // The client transaction timeout is 1000ms. Refuse a new provider call
        // unless it fits under the original endpoint; never reset that clock.
        need(clock.remaining_ms()? > 1000)?; self.active = true; self.status = HRESULT_PENDING; Ok(())
    }
    fn returned(&mut self, status: i32, clock: &mut Clock) -> Result<()> {
        self.status = status;
        if status == HRESULT_PENDING { self.unknown = true; return Err(Error::Unknown); }
        self.active = false; clock.effect()?; need(status == 0)
    }
    fn settle(&mut self) -> Result<()> {
        if self.active || self.unknown { return Err(Error::Unknown); }
        if !self.bstr.is_null() {
            self.active = true; unsafe { F::SysFreeString(self.bstr.cast()) };
            self.bstr = null_mut(); self.active = false;
        }
        if !self.array.is_null() {
            if self.destroy_entered { self.unknown = true; return Err(Error::Unknown); }
            self.destroy_entered = true; self.active = true;
            self.destroy_return = unsafe { OLE::SafeArrayDestroy(self.array) };
            if self.destroy_return != 0 { self.unknown = true; return Err(Error::Unknown); }
            self.array = null_mut(); self.active = false;
        }
        Ok(())
    }
}
struct WindowData {
    hwnd: F::HWND, owner: F::HWND, pid: u32, tid: u32, title: [u16; 256], length: i32,
}
impl WindowData {
    fn new() -> Self { Self { hwnd: null_mut(), owner: null_mut(), pid: 0, tid: 0, title: [0; 256], length: 0 } }
    fn title(&self) -> Result<String> {
        need(self.length >= 0 && (self.length as usize) < self.title.len() - 1)?;
        String::from_utf16(&self.title[..self.length as usize]).map_err(|_| Error::Unsafe)
    }
}
struct WindowQuery {
    entries: [WindowData; 32], count: usize, overflow: bool, active: bool, returned: i32, error: u32,
    identity_pid: u32, identity_tid: u32, thread_pid: u32, wait: u32,
    class: [u16; 256], class_length: i32, ok: F::HWND, cancel: F::HWND, cancel_style: isize,
    post_entered: bool, post_return: i32, post_error: u32,
}
unsafe extern "system" fn thread_window(hwnd: F::HWND, raw: isize) -> i32 {
    // EnumThreadWindows synchronously borrows this one registered stable output.
    let query = unsafe { &mut *(raw as *mut WindowQuery) };
    if unsafe { W::IsWindowVisible(hwnd) } == 0 { return 1; }
    if query.count >= query.entries.len() { query.overflow = true; return 0; }
    let entry = &mut query.entries[query.count]; query.count += 1;
    entry.hwnd = hwnd; entry.owner = unsafe { W::GetWindow(hwnd, W::GW_OWNER) };
    entry.tid = unsafe { W::GetWindowThreadProcessId(hwnd, &mut entry.pid) };
    entry.length = unsafe { W::GetWindowTextW(hwnd, entry.title.as_mut_ptr(), entry.title.len() as i32) };
    1
}
impl WindowQuery {
    fn new() -> Self {
        Self { entries: std::array::from_fn(|_| WindowData::new()), count: 0, overflow: false, active: false,
            returned: 0, error: 0, identity_pid: 0, identity_tid: 0, thread_pid: 0, wait: u32::MAX,
            class: [0; 256], class_length: 0, ok: null_mut(), cancel: null_mut(), cancel_style: 0,
            post_entered: false, post_return: 0, post_error: 0 }
    }
    fn original_live(&mut self, launch: &Launch, clock: &mut Clock) -> Result<()> {
        need(launch.facts.created && !launch.facts.failed && !launch.facts.unknown
            && launch.facts.process == SlotState::Owned && launch.facts.thread == SlotState::Owned)?;
        clock.effect()?; self.identity_pid = unsafe { T::GetProcessId(launch.outputs.hProcess) };
        self.identity_tid = unsafe { T::GetThreadId(launch.outputs.hThread) };
        self.thread_pid = unsafe { T::GetProcessIdOfThread(launch.outputs.hThread) };
        need(self.identity_pid == launch.outputs.dwProcessId && self.thread_pid == launch.outputs.dwProcessId
            && self.identity_tid == launch.outputs.dwThreadId)?;
        self.wait = unsafe { T::WaitForSingleObject(launch.outputs.hProcess, 0) };
        clock.effect()?; need(self.wait == F::WAIT_TIMEOUT)
    }
    fn scan(&mut self, launch: &Launch, clock: &mut Clock) -> Result<()> {
        need(!self.active)?; self.original_live(launch, clock)?;
        self.count = 0; self.overflow = false;
        for entry in &mut self.entries { *entry = WindowData::new(); }
        self.active = true;
        self.returned = unsafe { W::EnumThreadWindows(launch.outputs.dwThreadId, Some(thread_window), self as *mut Self as isize) };
        self.error = if self.returned != 0 { 0 } else { unsafe { F::GetLastError() } };
        self.active = false; clock.effect()?; need(self.returned != 0 && !self.overflow)?;
        need(self.entries[..self.count].iter().all(|entry|
            entry.pid == launch.outputs.dwProcessId && entry.tid == launch.outputs.dwThreadId))
    }
    fn root(&mut self, launch: &Launch, main: Option<F::HWND>, clock: &mut Clock) -> Result<Option<F::HWND>> {
        self.scan(launch, clock)?;
        let mut found = None;
        for entry in &self.entries[..self.count] {
            if entry.owner.is_null() {
                need(entry.title()? == "Mobile Release Kit" && found.is_none())?; found = Some(entry.hwnd);
            }
        }
        if let Some(main) = main { need(found == Some(main))?; }
        Ok(found)
    }
}

struct Smoke {
    initialized: bool, init_entered: bool, init_return: i32, uninit_entered: bool, uninit_returned: bool,
    originals: Vec<Box<ComOriginal>>, query: Box<UiQuery>, windows: Box<WindowQuery>,
    client: Option<usize>, walker: Option<usize>, main: Option<(F::HWND, usize, Vec<i32>)>,
    invoke_entered: bool, invoke_return: i32, dashboard_ready: bool, quit_confirmed: bool,
    unknown: bool, settled: bool, _thread: PhantomData<std::rc::Rc<()>>,
}
impl Smoke {
    fn new() -> Self {
        Self { initialized: false, init_entered: false, init_return: HRESULT_PENDING, uninit_entered: false,
            uninit_returned: false, originals: Vec::with_capacity(2048), query: Box::new(UiQuery::new()),
            windows: Box::new(WindowQuery::new()), client: None, walker: None, main: None,
            invoke_entered: false, invoke_return: HRESULT_PENDING, dashboard_ready: false, quit_confirmed: false,
            unknown: false, settled: false, _thread: PhantomData }
    }
    fn reserve(&mut self, kind: ComKind, clock: &mut Clock) -> Result<usize> {
        need(!self.unknown && !self.settled && self.originals.len() < 2048 && clock.remaining_ms()? > 1000)?;
        let index = self.originals.len(); self.originals.push(Box::new(ComOriginal::new(kind))); Ok(index)
    }
    fn pointer(&self, index: usize, kind: ComKind) -> Result<*mut c_void> {
        let original = self.originals.get(index).ok_or(Error::State)?;
        need(original.kind == kind && original.state == SlotState::Owned && !original.active)?; Ok(original.pointer)
    }
    fn client(&self) -> Result<(*mut c_void, &A::IUIAutomation2_Vtbl)> {
        let pointer = self.pointer(self.client.ok_or(Error::State)?, ComKind::Client)?;
        Ok((pointer, unsafe { &**pointer.cast::<*const A::IUIAutomation2_Vtbl>() }))
    }
    fn acquire_return(&mut self, index: usize, status: i32, nullable: bool, clock: &mut Clock) -> Result<bool> {
        let result = self.originals[index].returned(status, nullable);
        self.unknown |= matches!(result, Err(Error::Unknown)); clock.effect()?; result
    }
    fn setup(&mut self, clock: &mut Clock) -> Result<()> {
        need(!self.init_entered)?; clock.effect()?; self.init_entered = true;
        self.init_return = unsafe { CO::CoInitializeEx(null(), CO::COINIT_MULTITHREADED as u32) };
        if self.init_return == HRESULT_PENDING { self.unknown = true; return Err(Error::Unknown); }
        self.initialized = matches!(self.init_return, 0 | 1);
        need(self.initialized)?; clock.effect()?;
        let index = self.reserve(ComKind::Client, clock)?;
        let output = self.originals[index].begin()?;
        let status = unsafe { CO::CoCreateInstance((&A::CUIAutomation8 as *const windows::core::GUID).cast(), null_mut(),
            CO::CLSCTX_INPROC_SERVER, (&A::IUIAutomation2::IID as *const windows::core::GUID).cast(), output) };
        self.acquire_return(index, status, false, clock)?; self.client = Some(index);
        let pointer = self.pointer(index, ComKind::Client)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomation2_Vtbl>() };
        for setter in [table.SetConnectionTimeout, table.SetTransactionTimeout] {
            self.query.begin(clock)?;
            let status = unsafe { setter(pointer, 1000) }.0;
            self.query.returned(status, clock)?;
        }
        let index = self.reserve(ComKind::Walker, clock)?;
        let output = self.originals[index].begin()?;
        let status = unsafe { (table.base__.RawViewWalker)(pointer, output) }.0;
        self.acquire_return(index, status, false, clock)?; self.walker = Some(index); Ok(())
    }
    fn from_window(&mut self, hwnd: F::HWND, clock: &mut Clock) -> Result<usize> {
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.originals[index].begin()?;
        let (pointer, table) = self.client()?;
        let status = unsafe { (table.base__.ElementFromHandle)(pointer, HWND(hwnd), output) }.0;
        self.acquire_return(index, status, false, clock)?; Ok(index)
    }
    fn adjacent(&mut self, element: usize, child: bool, clock: &mut Clock) -> Result<Option<usize>> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let walker = self.pointer(self.walker.ok_or(Error::State)?, ComKind::Walker)?;
        let table = unsafe { &**walker.cast::<*const A::IUIAutomationTreeWalker_Vtbl>() };
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.originals[index].begin()?;
        let status = unsafe { (if child { table.GetFirstChildElement } else { table.GetNextSiblingElement })(walker, pointer, output) }.0;
        Ok(self.acquire_return(index, status, true, clock)?.then_some(index))
    }
    fn name(&mut self, element: usize, clock: &mut Clock) -> Result<String> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        need(self.query.bstr.is_null())?; self.query.begin(clock)?;
        let status = unsafe { (table.CurrentName)(pointer, &mut self.query.bstr) }.0;
        if status != 0 && !self.query.bstr.is_null() { self.query.unknown = true; return Err(Error::Unknown); }
        self.query.returned(status, clock)?;
        let length = unsafe { F::SysStringLen(self.query.bstr.cast()) } as usize;
        need(length <= 1024)?;
        let text = if length == 0 { Ok(String::new()) } else {
            String::from_utf16(unsafe { std::slice::from_raw_parts(self.query.bstr.cast::<u16>(), length) }).map_err(|_| Error::Unsafe)
        };
        self.query.settle()?; clock.effect()?; text
    }
    fn runtime_id(&mut self, element: usize, clock: &mut Clock) -> Result<Vec<i32>> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        need(self.query.array.is_null())?; self.query.destroy_entered = false;
        self.query.begin(clock)?;
        let status = unsafe { (table.GetRuntimeId)(pointer, (&mut self.query.array as *mut *mut CO::SAFEARRAY).cast()) }.0;
        if status != 0 && !self.query.array.is_null() { self.query.unknown = true; return Err(Error::Unknown); }
        self.query.returned(status, clock)?; need(!self.query.array.is_null())?;
        self.query.dimensions = unsafe { OLE::SafeArrayGetDim(self.query.array) };
        self.query.element_size = unsafe { OLE::SafeArrayGetElemsize(self.query.array) };
        need(self.query.dimensions == 1 && self.query.element_size == 4)?;
        self.query.begin(clock)?;
        let status = unsafe { OLE::SafeArrayGetVartype(self.query.array, &mut self.query.variant) };
        self.query.returned(status, clock)?;
        need(self.query.variant == windows_sys::Win32::System::Variant::VT_I4)?;
        self.query.begin(clock)?;
        let status = unsafe { OLE::SafeArrayGetLBound(self.query.array, 1, &mut self.query.lower) };
        self.query.returned(status, clock)?;
        self.query.begin(clock)?;
        let status = unsafe { OLE::SafeArrayGetUBound(self.query.array, 1, &mut self.query.upper) };
        self.query.returned(status, clock)?;
        need(self.query.lower == 0 && (1..=15).contains(&self.query.upper))?;
        for index in 0..=self.query.upper {
            self.query.index = index; self.query.begin(clock)?;
            let status = unsafe { OLE::SafeArrayGetElement(self.query.array, &self.query.index,
                (&mut self.query.values[index as usize] as *mut i32).cast()) };
            self.query.returned(status, clock)?;
        }
        let result = self.query.values[..=self.query.upper as usize].to_vec();
        self.query.settle()?; clock.effect()?; Ok(result)
    }
    fn native_handle(&mut self, element: usize, clock: &mut Clock) -> Result<F::HWND> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.hwnd = HWND(null_mut()); self.query.begin(clock)?;
        let status = unsafe { (table.CurrentNativeWindowHandle)(pointer, &mut self.query.hwnd) }.0;
        self.query.returned(status, clock)?; Ok(self.query.hwnd.0)
    }
    fn enabled_button(&mut self, element: usize, clock: &mut Clock) -> Result<bool> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.control = A::UIA_CONTROLTYPE_ID(0); self.query.begin(clock)?;
        let status = unsafe { (table.CurrentControlType)(pointer, &mut self.query.control) }.0;
        self.query.returned(status, clock)?;
        if self.query.control != A::UIA_ButtonControlTypeId { return Ok(false); }
        self.query.boolean = windows::core::BOOL(0); self.query.begin(clock)?;
        let status = unsafe { (table.CurrentIsEnabled)(pointer, &mut self.query.boolean) }.0;
        self.query.returned(status, clock)?; Ok(self.query.boolean.0 != 0)
    }
    fn bound(&mut self, launch: &Launch, clock: &mut Clock) -> Result<()> {
        let (hwnd, index, expected) = self.main.as_ref().ok_or(Error::State)?;
        let (hwnd, index, expected) = (*hwnd, *index, expected.clone());
        need(self.windows.root(launch, Some(hwnd), clock)? == Some(hwnd)
            && self.native_handle(index, clock)? == hwnd && self.runtime_id(index, clock)? == expected)?;
        let pointer = self.pointer(index, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.integer = 0; self.query.begin(clock)?;
        let status = unsafe { (table.CurrentProcessId)(pointer, &mut self.query.integer) }.0;
        self.query.returned(status, clock)?;
        need(self.query.integer > 0 && self.query.integer as u32 == launch.outputs.dwProcessId)
    }
    fn walk(&mut self, root: usize, clock: &mut Clock) -> Result<Vec<usize>> {
        let mut result = Vec::with_capacity(256); let mut stack = vec![(root, 0usize)];
        while let Some((index, depth)) = stack.pop() {
            need(depth <= 40 && result.len() < 900)?; result.push(index);
            // Follow only this element's children; never a desktop root/sibling
            // outside the caller's admitted main/dialog subtree.
            if let Some(child) = self.adjacent(index, true, clock)? {
                let mut siblings = vec![child]; let mut at = child;
                while let Some(next) = self.adjacent(at, false, clock)? {
                    need(siblings.len() + result.len() < 900)?; siblings.push(next); at = next;
                }
                stack.extend(siblings.into_iter().rev().map(|index| (index, depth + 1)));
            }
        }
        Ok(result)
    }
    fn release_suffix(&mut self, from: usize) -> Result<()> {
        for original in self.originals[from..].iter_mut().rev() { original.release()?; }
        self.originals.truncate(from); Ok(())
    }
    fn observe(&mut self, launch: &Launch, version: &str, clock: &mut Clock) -> Result<()> {
        self.setup(clock)?;
        let hwnd = loop {
            if let Some(hwnd) = self.windows.root(launch, None, clock)? { break hwnd; }
            clock.effect()?; std::thread::sleep(Duration::from_millis(100));
        };
        let element = self.from_window(hwnd, clock)?; let id = self.runtime_id(element, clock)?;
        self.main = Some((hwnd, element, id)); self.bound(launch, clock)?;
        loop {
            self.bound(launch, clock)?; let keep = self.originals.len();
            let elements = self.walk(element, clock)?;
            let mut found = [false; 5]; let expected_version = format!("DESKTOP {version}");
            for index in elements {
                let name = self.name(index, clock)?;
                found[0] |= name == "Good releases start here.";
                found[1] |= name == "Workspace navigation";
                found[2] |= name == "Your next release, organized.";
                found[3] |= name == expected_version;
                if name == "Choose a project" { found[4] |= self.enabled_button(index, clock)?; }
                let lower = name.to_ascii_lowercase();
                need(!["the native service is unavailable", "the field catalogue could not be loaded",
                    "bundled engine unavailable", "the engine is disabled", "browser preview"]
                    .iter().any(|value| lower.contains(value)))?;
                if name.contains("Loading desktop capabilities and the core field catalogue") { found = [false; 5]; break; }
            }
            self.release_suffix(keep)?;
            if found == [true; 5] { self.dashboard_ready = true; break; }
            clock.effect()?; std::thread::sleep(Duration::from_millis(100));
        }
        self.bound(launch, clock)?;
        need(!self.windows.post_entered)?; self.windows.post_entered = true;
        self.windows.post_return = unsafe { W::PostMessageW(hwnd, W::WM_CLOSE, 0, 0) };
        self.windows.post_error = if self.windows.post_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        // Posting is request delivery only, never response or original exit.
        need(self.windows.post_return != 0)?; clock.effect()?;
        let dialog = loop {
            self.bound(launch, clock)?; let mut dialog = None;
            for entry in &self.windows.entries[..self.windows.count] {
                if entry.owner == hwnd {
                    need(entry.title()? == "Quit Mobile Release Kit?" && dialog.is_none())?; dialog = Some(entry.hwnd);
                }
            }
            if let Some(dialog) = dialog { break dialog; }
            clock.effect()?; std::thread::sleep(Duration::from_millis(100));
        };
        self.windows.class_length = unsafe { W::GetClassNameW(dialog, self.windows.class.as_mut_ptr(), 256) };
        need(self.windows.class_length > 0 && self.windows.class_length < 255
            && String::from_utf16(&self.windows.class[..self.windows.class_length as usize]).map_err(|_| Error::Unsafe)? == "#32770")?;
        self.windows.ok = unsafe { W::GetDlgItem(dialog, W::IDOK) };
        self.windows.cancel = unsafe { W::GetDlgItem(dialog, W::IDCANCEL) };
        need(!self.windows.ok.is_null() && !self.windows.cancel.is_null() && self.windows.ok != self.windows.cancel
            && unsafe { W::GetParent(self.windows.ok) } == dialog && unsafe { W::GetParent(self.windows.cancel) } == dialog)?;
        self.windows.cancel_style = unsafe { W::GetWindowLongPtrW(self.windows.cancel, W::GWL_STYLE) };
        need(self.windows.cancel_style & 0x0f == W::BS_DEFPUSHBUTTON as isize)?; clock.effect()?;
        let dialog_element = self.from_window(dialog, clock)?;
        need(self.native_handle(dialog_element, clock)? == dialog)?;
        let dialog_id = self.runtime_id(dialog_element, clock)?;
        let elements = self.walk(dialog_element, clock)?;
        let mut instruction = false; let mut ok = None; let mut cancel = None;
        for index in elements {
            let name = self.name(index, clock)?;
            instruction |= name == "Quit and discard unsaved drafts?";
            if name == "OK" && self.enabled_button(index, clock)? {
                need(ok.is_none() && self.native_handle(index, clock)? == self.windows.ok)?; ok = Some(index);
            }
            if name == "Cancel" && self.enabled_button(index, clock)? {
                need(cancel.is_none() && self.native_handle(index, clock)? == self.windows.cancel)?; cancel = Some(index);
            }
        }
        need(instruction && cancel.is_some())?; let ok = ok.ok_or(Error::Unsafe)?;
        self.bound(launch, clock)?;
        need(unsafe { W::GetWindow(dialog, W::GW_OWNER) } == hwnd && self.runtime_id(dialog_element, clock)? == dialog_id
            && self.native_handle(ok, clock)? == self.windows.ok && self.enabled_button(ok, clock)?)?;
        let pointer = self.pointer(ok, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        let index = self.reserve(ComKind::Invoke, clock)?;
        let output = self.originals[index].begin()?;
        let status = unsafe { (table.GetCurrentPatternAs)(pointer, A::UIA_InvokePatternId, &A::IUIAutomationInvokePattern::IID, output) }.0;
        self.acquire_return(index, status, false, clock)?;
        self.bound(launch, clock)?; need(!self.invoke_entered)?;
        let pointer = self.pointer(index, ComKind::Invoke)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationInvokePattern_Vtbl>() };
        self.query.begin(clock)?; self.invoke_entered = true;
        self.invoke_return = unsafe { (table.Invoke)(pointer) }.0;
        self.query.returned(self.invoke_return, clock)?;
        self.quit_confirmed = true; clock.effect()
    }
    fn settle(&mut self) -> Result<()> {
        if self.settled { return Ok(()); }
        if self.unknown || self.windows.active || self.query.settle().is_err() { self.unknown = true; return Err(Error::Unknown); }
        for original in self.originals.iter_mut().rev() {
            if original.release().is_err() { self.unknown = true; return Err(Error::Unknown); }
        }
        if self.initialized {
            need(!self.uninit_entered)?; self.uninit_entered = true;
            unsafe { CO::CoUninitialize() }; self.uninit_returned = true;
        }
        self.settled = true; Ok(())
    }
    fn passed(&self) -> bool {
        self.dashboard_ready && self.main.is_some() && self.windows.post_entered && self.windows.post_return != 0
            && self.invoke_entered && self.invoke_return == 0 && self.quit_confirmed
            && self.initialized && self.uninit_returned && self.settled && !self.unknown
    }
    fn json(&self) -> Result<String> {
        need(self.passed())?;
        Ok("{\"mainRootBound\":true,\"dashboardReady\":true,\"postCloseCalls\":1,\"invokeCalls\":1,\"nativeQuitConfirmed\":true,\"comOriginalsSettled\":true,\"apartmentDecremented\":true}".to_owned())
    }
}

pub(super) fn run(role: UiRole, entry_tick: u64) -> Result<()> {
    let mut clock = Clock::new(entry_tick)?;
    // This closed route is not any historical Fullwalk/Passive admission.
    let root = fixed_path(&std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_| Error::State)?)?;
    let temp = fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_| Error::State)?)?;
    let run = std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State)?;
    need(decimal(&run) && root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == root)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    role.process_args(&image, true)?;
    let mut book = NativeBook::new(); let mut inventory = NativeBook::new();
    let mut parent_attempted = false; let mut parent_settled = false;
    let mut files: Vec<OriginalFile> = Vec::with_capacity(48);
    let mut creates: Vec<Box<DirectoryCreate>> = Vec::with_capacity(4);
    let mut profile: Option<Profile> = None; let mut fixture = None;
    let mut account: Option<Account> = None; let mut launch: Option<Pin<Box<Launch>>> = None;
    let mut smoke: Option<Smoke> = None;
    let mut trace = InputTrace::default(); let mut transitions = Vec::with_capacity(14);
    let mut request: Option<UiRequest> = None;
    let mut input_stamps = Vec::with_capacity(8);
    let mut request_sha = String::new(); let mut account_sha = String::new();
    let mut child_sha = None; let mut available = None;
    let output = root.join(role.name("output"));
    let mut output_index = None; let mut artifact_index = None; let mut artifact_after = None;
    let mut stage = "ui-parent-context";
    let mut observation = (|| -> Result<()> {
        clock.effect()?;
        need(matches!(book.observe_user_once(), Err(Error::Unsafe)))?;
        let token = book.process_token.ok_or(Error::State)?;
        super::super::hosted_tests::actual_elevated_primary_refusal(&mut book, token)?;
        let parent = parent_user(&mut book)?; clock.effect()?;
        stage = "ui-original-inputs";
        let mut ancestors: Vec<_> = root.ancestors().map(Path::to_path_buf).collect(); ancestors.reverse();
        need(ancestors.len() <= 16)?; let mut root_index = None;
        for path in &ancestors {
            trace.at(InputRole::Ancestor, Some(files.len() as u8));
            let index = input(&mut files, path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL
                | if path == &root { FS::WRITE_DAC } else { 0 }, &mut clock, &mut trace)?;
            if path == &root { root_index = Some(index); }
        }
        trace.at(InputRole::Request, Some(files.len() as u8));
        let request_index = input(&mut files, &root.join(role.name("request.txt")), false,
            FS::FILE_GENERIC_READ, &mut clock, &mut trace)?;
        let request_before = files[request_index].stamp()?;
        let raw = files[request_index].read(LIMIT)?; clock.effect()?;
        let selected = UiRequest::parse(&raw)?; selected.compiled()?; selected.at_root(&root)?;
        need(selected.role == role && selected.run == run && image.to_str() == Some(selected.owner.path.as_str()))?;
        need(files[request_index].stamp()? == request_before)?;
        input_stamps.push((request_index, request_before)); request_sha = digest(&raw)?;
        let mut directories = vec![(root_index.ok_or(Error::State)?, "root")];
        for (label, path) in fixed_directories(&root) {
            trace.at(InputRole::Directory, Some(files.len() as u8));
            let index = input(&mut files, &path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC,
                &mut clock, &mut trace)?;
            directories.push((index, label));
        }
        trace.at(InputRole::Artifact, Some(files.len() as u8));
        let artifact = input(&mut files, Path::new(&selected.app.path), false, FS::FILE_GENERIC_READ | FS::WRITE_DAC,
            &mut clock, &mut trace)?;
        let before = read_hash(&mut files, artifact, selected.app.bytes, &selected.app.sha,
            role != UiRole::Prerequisite, &mut clock, &mut trace)?;
        need(selected.app.matches(&before))?; artifact_index = Some(artifact);
        if role != UiRole::Prerequisite {
            trace.at(InputRole::Artifact, Some(files.len() as u8));
            let index = input(&mut files, &image, false, FS::FILE_GENERIC_READ, &mut clock, &mut trace)?;
            let original = read_hash(&mut files, index, selected.owner.bytes, &selected.owner.sha, false, &mut clock, &mut trace)?;
            need(selected.owner.matches(&original) && (original.volume, original.id) != (before.volume, before.id))?;
            input_stamps.push((index, original));
        } else { need(selected.owner.matches(&before))?; }
        for (name, binding) in [("compile-messages.jsonl", &selected.owner), (role.app_messages(), &selected.app)] {
            // Probe app/owner are the SAME compiler stream, retained once.
            if name == "compile-messages.jsonl" && role == UiRole::Prerequisite && input_stamps.len() == 2 { continue; }
            trace.at(InputRole::Binding, Some(files.len() as u8));
            let index = input(&mut files, &root.join(name), false, FS::FILE_GENERIC_READ, &mut clock, &mut trace)?;
            let before = read_hash(&mut files, index, binding.messages_bytes, &binding.messages_sha, false, &mut clock, &mut trace)?;
            input_stamps.push((index, before));
        }
        if let Some(runtime) = &selected.runtime {
            // Source-bound publication DATA only. Each real application still
            // acquires its own installed runtime and repeats native admission.
            trace.at(InputRole::Binding, Some(files.len() as u8));
            let index = input(&mut files, &root.join("normal-ui-publication.private.json"), false,
                FS::FILE_GENERIC_READ, &mut clock, &mut trace)?;
            let before = read_hash(&mut files, index, runtime.publication_bytes, &runtime.publication_sha, false,
                &mut clock, &mut trace)?; input_stamps.push((index, before));
        }
        stage = "ui-fresh-account-intent"; clock.effect()?;
        account = Some(Account::new()?); let current = account.as_mut().ok_or(Error::State)?;
        let name = String::from_utf16(&current.name[..current.name.len() - 1]).map_err(|_| Error::Unsafe)?;
        let intent = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"role\":\"{}\",\"requestSha256\":\"{}\",\"accountName\":\"{name}\",\"freshAccountIntent\":true,\"fixedNormalUiChildOnly\":true}}\n",
            selected.source, selected.tree, selected.run, role.label(), request_sha);
        write_fixture_record(&root.join(role.name("owner-intent.private.json")), intent.as_bytes(), LIMIT, clock.end)?;
        clock.effect()?; stage = "ui-fresh-account";
        current.create(&parent, clock.start, &mut clock.latched, &mut clock.aggregate)?; clock.effect()?;
        account_sha = digest(&current.sid)?;
        stage = "ui-exact-acl"; trace.at(InputRole::Output, Some(files.len() as u8));
        let out = new_directory(&mut creates, &mut files, &output, &mut clock, &mut trace)?; output_index = Some(out);
        for (index, label) in directories {
            // New UI fixture readers inspect native parent IDs/ACLs. Grant
            // read/traverse ONLY on these five task-owned directories, never
            // RUNNER_TEMP, a Windows path, or an inherited general user tree.
            trace.at(InputRole::AclRoot, Some(index as u8));
            acl(&mut files, index, label, FS::FILE_GENERIC_READ | FS::FILE_TRAVERSE,
                &parent, &current.sid, &mut clock, &mut trace, &mut transitions)?;
        }
        trace.at(InputRole::AclArtifact, Some(artifact as u8));
        acl(&mut files, artifact, "artifact", FS::FILE_GENERIC_READ | FS::FILE_GENERIC_EXECUTE,
            &parent, &current.sid, &mut clock, &mut trace, &mut transitions)?;
        let after = files[artifact].stamp()?; selected.app_after(&after.wire())?; artifact_after = Some(after.clone());
        trace.at(InputRole::AclOutput, Some(out as u8));
        acl(&mut files, out, "normal-ui-output", FS::FILE_GENERIC_READ | FS::FILE_TRAVERSE | FS::FILE_ADD_FILE | FS::FILE_ADD_SUBDIRECTORY,
            &parent, &current.sid, &mut clock, &mut trace, &mut transitions)?;
        if matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss) {
            stage = "ui-synthetic-project";
            fixture = Some(Fixture::create(role, &output, &mut creates, &mut files, &parent, &current.sid,
                &mut clock, &mut trace, &mut transitions)?);
        }
        stage = "ui-profile-prestate";
        profile = Some(Profile::new(current)?); profile.as_mut().ok_or(Error::State)?.prepare(&mut clock)?;
        clock.effect()?;
        super::super::hosted_tests::actual_elevated_primary_refusal(&mut book, token)?;
        need(parent_user(&mut book)? == parent)?;
        parent_attempted = true; parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled();
        need(parent_settled)?; clock.effect()?;
        stage = "ui-original-create";
        launch = Some(Launch::ui(&selected, &after.wire(), std::str::from_utf8(&raw).map_err(|_| Error::Unsafe)?,
            &output, current, &parent, clock.endpoint_tick)?);
        request = Some(selected);
        launch.as_mut().ok_or(Error::State)?.as_mut().enter(current, clock.start, &mut clock.latched, &mut clock.aggregate)?;
        clock.effect()?; stage = "ui-profile-original-binding";
        profile.as_mut().ok_or(Error::State)?.bind_after_logon(&mut clock)?;
        if role == UiRole::NormalSmoke {
            stage = "ui-normal-smoke";
            smoke = Some(Smoke::new());
            smoke.as_mut().ok_or(Error::State)?.observe(launch.as_ref().ok_or(Error::State)?,
                &request.as_ref().ok_or(Error::State)?.app_version, &mut clock)?;
        }
        clock.effect()
    })();
    if let Some(current) = account.as_mut() { current.zero(); }
    // Settle the actual original driver before any original process close. A
    // UIA timeout is failed even if its possibly-effectful operation later acts.
    let smoke_settled = smoke.as_mut().is_none_or(|value| value.settle().is_ok());
    if !smoke_settled || matches!(observation, Err(Error::Unknown)) {
        diagnostic_with_fault(stage, launch.as_deref(), true, trace.first);
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    if let Some(original) = launch.as_mut() {
        if observation.is_err() { unsafe { original.as_mut().get_unchecked_mut() }.facts.failed = true; }
        original.as_mut().finish(clock.start, &mut clock.aggregate);
        if !original.facts.passed() && observation.is_ok() { observation = Err(Error::Unsafe); }
    }
    if !parent_attempted { parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled(); }
    if !parent_settled || launch.as_ref().is_some_and(|value| value.facts.unknown || value.facts.created && !value.facts.signaled) {
        diagnostic_with_fault(stage, launch.as_deref(), true, trace.first);
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    if observation.is_ok() {
        observation = (|| -> Result<()> {
            clock.effect()?; stage = "ui-original-exit-result";
            let selected = request.as_ref().ok_or(Error::State)?;
            let result = if role == UiRole::NormalSmoke {
                need(smoke.as_ref().is_some_and(Smoke::passed))?; None
            } else {
                let index = input(&mut files, &output.join(role.name("result.private.json")), false,
                    FS::FILE_GENERIC_READ, &mut clock, &mut trace)?;
                let raw = files[index].read(LIMIT)?;
                let accepted = selected.accept_child(&raw, &request_sha, &account_sha)?;
                if role == UiRole::Prerequisite { available = Some(accepted); } else { need(accepted)?; }
                child_sha = Some(digest(&raw)?); Some(index)
            };
            need(files[artifact_index.ok_or(Error::State)?].stamp()? == *artifact_after.as_ref().ok_or(Error::State)?)?;
            for (index, stamp) in &input_stamps { clock.effect()?; need(files[*index].stamp()? == *stamp)?; }
            stage = "ui-output-poststate";
            output_poststate(&mut inventory, &mut files, &mut fixture, role, &output,
                output_index.ok_or(Error::State)?, result, &mut clock, &mut trace)?;
            clock.effect()
        })();
    }
    let inventory_settled = inventory.settle_once() == CloseOutcome::Settled && inventory.settled();
    if !inventory_settled || matches!(observation, Err(Error::Unknown)) || !close_files(&mut files) {
        diagnostic_with_fault(stage, launch.as_deref(), true, trace.first);
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    if clock.effect().is_err() { observation = Err(Error::Unsafe); }
    if observation.is_err() {
        if profile.as_mut().is_some_and(|value| value.settle().is_err()) {
            diagnostic_with_fault("ui-profile-original-close", launch.as_deref(), true, trace.first);
            loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
        }
        diagnostic_with_fault(stage, launch.as_deref(), false, trace.first);
        return observation; // Failed process/driver never permits profile/account deletion.
    }
    stage = "ui-profile-retirement";
    let retirement = profile.as_mut().ok_or(Error::State)?.retire(&mut clock);
    if retirement.is_err() {
        if matches!(retirement, Err(Error::Unknown)) || profile.as_mut().is_some_and(|value| value.settle().is_err()) {
            diagnostic_with_fault(stage, launch.as_deref(), true, trace.first);
            loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
        }
        return retirement;
    }
    let current = account.as_mut().ok_or(Error::State)?;
    let retirement = current.retire(clock.start, &mut clock.latched, &mut clock.aggregate);
    if matches!(retirement, Err(Error::Unknown)) {
        diagnostic_with_fault("ui-account-retirement", launch.as_deref(), true, trace.first);
        loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
    }
    retirement?; clock.effect()?;
    let current = account.as_ref().ok_or(Error::State)?; let profile = profile.as_ref().ok_or(Error::State)?;
    let original = launch.as_ref().ok_or(Error::State)?; let selected = request.as_ref().ok_or(Error::State)?;
    need(current.removed && original.facts.passed() && files.iter().all(OriginalFile::is_closed)
        && profile.prestate && profile.exact && profile.hives_unloaded && profile.delete_entered
        && profile.delete_return != 0 && profile.poststate && profile.settled && !profile.unknown
        && fixture.as_ref().is_none_or(|value| value.verified))?;
    let prerequisite = available.map(|value| value.to_string()).unwrap_or_else(|| "null".to_owned());
    let native_sha = child_sha.map(|value| format!("\"{value}\"")).unwrap_or_else(|| "null".to_owned());
    let smoke_json = match smoke.as_ref() { Some(smoke) => smoke.json()?, None => "null".to_owned() };
    let fixture_json = match fixture.as_ref() {
        Some(fixture) => format!("{{\"initialFiles\":{},\"finalFiles\":4,\"immutableFilesVerified\":{},\"labelledCreateNew\":{},\"completeInventoryVerified\":true}}",
            fixture.original_files.len(), fixture.original_files.len(), !fixture.initial_config),
        None => "null".to_owned(),
    };
    let record = format!("{{\"schemaVersion\":1,\"qualificationProfile\":\"windows-normal-project-ui-v1\",\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"role\":\"{}\",\"requestSha256\":\"{}\",\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"ownerArtifactBytes\":{},\"ownerArtifactSha256\":\"{}\",\"ownerCommandSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"ownerTest\":\"{}\",\"childTest\":\"{}\",\"createCalls\":1,\"createReturn\":{},\"createError\":null,\"firstWait\":{},\"exitReturn\":{},\"originalExitCode\":{},\"terminateCalls\":0,\"processCloseReturn\":{},\"threadCloseReturn\":{},\"deadlineLatched\":false,\"unknown\":false,\"parentBookSettled\":true,\"inputOriginals\":{},\"inputOriginalsClosed\":{},\"freshAccountVerified\":true,\"onlyUsersMembership\":true,\"profileAbsentBefore\":true,\"profileOriginalBound\":true,\"profileHivesUnloaded\":true,\"profileDeleteCalls\":1,\"profileDeleteReturn\":{},\"profileAbsentAfter\":true,\"profileOriginalsSettled\":true,\"accountRemovedAfterProfileSettlement\":true,\"outputInventoryVerified\":true,\"observationCompleted\":true,\"prerequisitesAvailable\":{prerequisite},\"verifiedMethods\":{},\"nativeResultSha256\":{native_sha},\"normalSmoke\":{smoke_json},\"fixture\":{fixture_json},\"aclTransitions\":[{}],\"ownerResult\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-owner-exit-zero-required\"}}}}\n",
        selected.source, selected.tree, selected.run, role.label(), request_sha, selected.app.bytes, selected.app.sha,
        selected.app.command_sha, selected.owner.bytes, selected.owner.sha, selected.owner.command_sha, account_sha,
        role.owner(), role.entry(), original.returned, original.first_wait, original.exit_return, original.exit_output,
        original.process_close, original.thread_close, files.len(), files.len(), profile.delete_return,
        if role == UiRole::ProjectDraft { 6 } else { 0 }, transitions.join(","));
    need(record.len() <= OWNER_LIMIT)?; clock.effect()?;
    write_fixture_record(&root.join(role.name("owner-result.private.json")), record.as_bytes(), OWNER_LIMIT, clock.end)?;
    // A pre-close record is never an owner-exit receipt; the separate finalizer
    // still requires this foreground libtest's original zero exit/step closure.
    clock.effect()
}

// Inert regressions. They exercise the actual ownership/result decisions above
// without any account, process, COM, GUI, file, registry, clock or network call.
#[cfg(test)]
mod contract_tests {
    use super::*;

    // All originals below are DATA, never passed to an OS API. Their explicit
    // teardown may free even the deliberately Unknown fixtures; the production
    // retained owner must never use this test-only allocation cleanup.
    struct InertProfile(Profile);
    impl InertProfile {
        fn new() -> Result<Self> {
            let sid = [vec![1, 5, 0, 0, 0, 0, 0, 5],
                [21u32, 1, 2, 3, 1001].into_iter().flat_map(u32::to_le_bytes).collect()].concat();
            let account = Account { name: wide("mrk0123456789abcdef"), password: Box::new([0; 65]),
                users: Vec::new(), sid, absent: u32::MAX, absent_pointer_null: false, add: u32::MAX,
                group_add: false, attempted: false, delete_attempted: false, delete_status: u32::MAX,
                removed: false, queries: Vec::new() };
            let mut fixture = Self(Profile::new(&account)?);
            let profile = &mut fixture.0;
            let original = profile.native.reserve(Kind::Directory, None, "fixture", "fixture".to_owned())?;
            let slot = profile.native.slot_mut(original.index)?;
            slot.state = SlotState::Owned; unsafe { *slot.output.get() = 11usize as F::HANDLE; }
            let metadata = Metadata { identity: FileIdentity { volume_serial: 1, file_id: [1; 16] },
                kind: FileKind::Directory, attributes: FS::FILE_ATTRIBUTE_DIRECTORY, size: 0,
                allocation_size: 0, links: 1, creation: 1, write: 1, change: 1 };
            profile.paths.push(ProfilePath { original, metadata });
            profile.register_absence()?;
            Ok(fixture)
        }
        fn returned(&mut self, epoch: AbsenceEpoch, status: i32, handle: F::HANDLE, io: i32, information: usize) -> Result<()> {
            let native = &self.0.native;
            let [before, after] = &mut self.0.absence;
            let (frame, other) = match epoch { AbsenceEpoch::BeforeLogon => (before, after), AbsenceEpoch::AfterDeletion => (after, before) };
            let frame = unsafe { frame.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
            let other = other.as_ref().ok_or(Error::State)?.as_ref().get_ref();
            frame.claim()?; frame.begin()?; frame.returned = status;
            // No native entry occurred; these pinned cells have no OS borrower.
            unsafe { *frame.output.get() = handle; *frame.iosb.get() = IO::IO_STATUS_BLOCK {
                Anonymous: IO::IO_STATUS_BLOCK_0 { Status: io }, Information: information }; }
            frame.observe_return(native, other)
        }
    }
    impl Drop for InertProfile {
        fn drop(&mut self) {
            for frame in &mut self.0.absence { if let Some(frame) = frame.take() { drop(ManuallyDrop::into_inner(frame)); } }
            if let Some(frame) = self.0.native.active.take() { drop(ManuallyDrop::into_inner(frame)); }
            for slot in self.0.native.slots.drain(..) { drop(ManuallyDrop::into_inner(slot)); }
        }
    }

    #[test]
    fn profile_absence_epochs_do_not_consume_the_single_binding_path() -> Result<()> {
        use AbsenceEpoch::{AfterDeletion, BeforeLogon};
        let mut fixture = InertProfile::new()?;
        let p = &mut fixture.0;
        assert!(p.register_absence().is_err()); // Fixed registration has no reset.
        assert_eq!(p.absence_permitted(BeforeLogon), Ok(()));
        assert!(p.absence_permitted(AfterDeletion).is_err());
        let before = p.absence(BeforeLogon)?; let after = p.absence(AfterDeletion)?;
        assert_ne!(before.output.get(), after.output.get());
        assert_eq!(before.parent_handle, after.parent_handle);
        for frame in [before, after] {
            assert!(std::ptr::eq(frame.attributes.ObjectName, &frame.unicode));
            assert_eq!(frame.unicode.Buffer, frame.name.as_ptr().cast_mut());
            assert_eq!(frame.attributes.RootDirectory, frame.parent_handle);
        }
        let native_count = p.native.slots.len();
        assert_eq!(fixture.returned(BeforeLogon, 0xc0000034u32 as i32, null_mut(), F::STATUS_PENDING, usize::MAX), Ok(()));
        let p = &mut fixture.0;
        assert_eq!(p.native.slots.len(), native_count); // Preabsence spent no binding path.
        assert!(p.absence_permitted(BeforeLogon).is_err());
        assert_eq!(p.absence_mut(BeforeLogon)?.claim(), Err(Error::State));
        p.prestate = true; assert_eq!(p.binding_permitted(), Ok(()));
        let parent = p.paths[0].original.index;
        let canonical = format!("{}\\{}", p.native.slot(parent)?.canonical, p.name);
        let original = p.native.reserve(Kind::Directory, Some(parent), &p.name, canonical.clone())?;
        assert!(matches!(p.native.reserve(Kind::Directory, Some(parent), &p.name, canonical), Err(Error::State)));
        let index = original.index; let slot = p.native.slot_mut(index)?;
        slot.state = SlotState::Owned; unsafe { *slot.output.get() = 42usize as F::HANDLE; }
        p.profile = Some(ProfilePath { original, metadata: p.paths[0].metadata.clone() }); p.exact = true;
        let mut key = Box::new(Key::new(R::HKEY_LOCAL_MACHINE, "inert")); key.state = SlotState::Owned;
        p.mapping = Some(p.keys.len()); p.keys.push(key);
        assert!(p.binding_permitted().is_err());
        assert!(p.absence_permitted(AfterDeletion).is_err());
        p.hives_unloaded = true; p.delete_entered = true; p.delete_return = 1;
        assert!(p.absence_permitted(AfterDeletion).is_err()); // Deletion scalars cannot waive live originals.
        p.native.slot_mut(index)?.state = SlotState::Closed;
        assert!(p.absence_permitted(AfterDeletion).is_err()); // Mapping still live.
        p.keys[p.mapping.ok_or(Error::State)?].state = SlotState::Closed;
        p.delete_return = 0; assert!(p.absence_permitted(AfterDeletion).is_err());
        p.delete_return = 1; p.delete_entered = false; assert!(p.absence_permitted(AfterDeletion).is_err());
        p.delete_entered = true; p.hives_unloaded = false; assert!(p.absence_permitted(AfterDeletion).is_err());
        p.hives_unloaded = true;
        p.delete_entered = true; assert_eq!(p.absence_permitted(AfterDeletion), Ok(()));
        assert_eq!(fixture.returned(AfterDeletion, 0xc0000034u32 as i32, null_mut(), F::STATUS_PENDING, usize::MAX), Ok(()));
        assert!(fixture.0.absence_permitted(AfterDeletion).is_err());
        assert_eq!(fixture.0.absence_mut(AfterDeletion)?.claim(), Err(Error::State));
        assert!(fixture.0.absence_dependents_settled());
        assert_eq!(fixture.0.native.slots.len(), native_count + 1);
        assert!(!fixture.0.native.retiring && !fixture.0.settled); // DATA never manufactures native finality.
        fixture.0.unknown = true; assert_eq!(fixture.0.absence_permitted(AfterDeletion), Err(Error::Unknown));
        let mut wrong_parent = InertProfile::new()?;
        wrong_parent.0.absence_mut(AfterDeletion)?.parent_handle = 12usize as F::HANDLE;
        assert!(wrong_parent.0.absence_permitted(BeforeLogon).is_err());
        Ok(())
    }

    #[test]
    fn profile_absence_results_distinguish_missing_collision_and_unknown() -> Result<()> {
        use AbsenceEpoch::{AfterDeletion, BeforeLogon};
        for (status, handle, io, information, expected, state, absent) in [
            (0xc0000034u32 as i32, 0, F::STATUS_PENDING, usize::MAX, Ok(()), SlotState::NoHandle, true),
            (0xc0000034u32 as i32, 0, F::STATUS_SUCCESS, 0, Ok(()), SlotState::NoHandle, true),
            (0xc000003au32 as i32, 0, F::STATUS_PENDING, usize::MAX, Err(Error::Unsafe), SlotState::NoHandle, false),
            (F::STATUS_ACCESS_DENIED, 0, F::STATUS_PENDING, usize::MAX, Err(Error::Unsafe), SlotState::NoHandle, false),
            (F::STATUS_PENDING, 42, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (1, 42, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (0x80000001u32 as i32, 0, F::STATUS_PENDING, usize::MAX, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_ACCESS_DENIED, 42, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, 0, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, usize::MAX, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, 42, F::STATUS_PENDING, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, 42, F::STATUS_SUCCESS, usize::MAX, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, 11, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unknown), SlotState::Unknown, false),
            (F::STATUS_SUCCESS, 42, F::STATUS_SUCCESS, WP::FILE_OPENED as usize, Err(Error::Unsafe), SlotState::Owned, false),
        ] {
            let mut fixture = InertProfile::new()?;
            assert_eq!(fixture.returned(BeforeLogon, status, handle as F::HANDLE, io, information), expected);
            let p = &mut fixture.0; let frame = p.absence_mut(BeforeLogon)?;
            assert_eq!(frame.state, state); assert_eq!(frame.exact_absence(), absent);
            assert_eq!(frame.claim(), Err(Error::State));
            if state == SlotState::Unknown { assert_eq!(frame.begin_close(), Err(Error::Unknown)); }
            p.prestate = true; assert_eq!(p.binding_permitted().is_ok(), absent);
        }
        // Duplicate exclusion spans the other fixed original, not just NativeBook.
        let mut fixture = InertProfile::new()?;
        assert_eq!(fixture.returned(BeforeLogon, F::STATUS_SUCCESS, 42usize as F::HANDLE, F::STATUS_SUCCESS,
            WP::FILE_OPENED as usize), Err(Error::Unsafe));
        assert_eq!(fixture.returned(AfterDeletion, F::STATUS_SUCCESS, 42usize as F::HANDLE, F::STATUS_SUCCESS,
            WP::FILE_OPENED as usize), Err(Error::Unknown));
        assert_eq!(fixture.0.absence(BeforeLogon)?.state, SlotState::Owned);
        assert_eq!(fixture.0.absence(AfterDeletion)?.state, SlotState::Unknown);
        assert!(!fixture.0.absence_dependents_settled());
        Ok(())
    }

    #[test]
    fn profile_absence_dependents_settle_before_namespace_parents() -> Result<()> {
        use AbsenceEpoch::{AfterDeletion, BeforeLogon};
        let mut pending = InertProfile::new()?;
        let frame = pending.0.absence_mut(BeforeLogon)?; frame.claim()?; frame.begin()?;
        assert!(!pending.0.absence_dependents_settled());
        assert_eq!(pending.0.absence_mut(BeforeLogon)?.begin_close(), Err(Error::Unknown));
        assert!(!pending.0.native.retiring && !pending.0.absence_dependents_settled());
        for success in [false, true] {
            let mut fixture = InertProfile::new()?;
            assert_eq!(fixture.returned(BeforeLogon, F::STATUS_SUCCESS, 42usize as F::HANDLE,
                F::STATUS_SUCCESS, WP::FILE_OPENED as usize), Err(Error::Unsafe));
            let p = &mut fixture.0;
            assert_eq!(p.absence_mut(AfterDeletion)?.begin_close(), Ok(None));
            assert!(!p.absence(AfterDeletion)?.exact_absence()); // Unentered settlement is not absence.
            assert!(!p.absence_dependents_settled()); // Known collision is still held.
            assert_eq!(p.absence_mut(BeforeLogon)?.begin_close(), Ok(Some(42usize as F::HANDLE)));
            assert!(!p.absence_dependents_settled()); // Issuing a close is not its return.
            let frame = p.absence_mut(BeforeLogon)?;
            assert_eq!(frame.close_handle, 42usize as F::HANDLE);
            assert!(frame.close_entered && unsafe { (*frame.output.get()).is_null() });
            frame.close_return = if success { 1 } else { 0 };
            assert_eq!(frame.observe_close(), if success { Ok(()) } else { Err(Error::Unknown) });
            assert_eq!(p.absence_dependents_settled(), success);
            let frame = p.absence_mut(BeforeLogon)?;
            assert_eq!(frame.begin_close(), if success { Ok(None) } else { Err(Error::Unknown) });
            assert!(!p.native.retiring); assert_eq!(p.native.state(&p.paths[0].original)?, SlotState::Owned);
        }
        Ok(())
    }

    #[test]
    fn com_null_end_is_distinct_from_pending_failure_and_contradictory_output() {
        let mut end = ComOriginal::new(ComKind::Element);
        assert!(end.begin().is_ok()); assert_eq!(end.returned(0, true), Ok(false));
        assert_eq!(end.state, SlotState::NoHandle);
        let mut required = ComOriginal::new(ComKind::Element);
        assert!(required.begin().is_ok()); assert!(required.returned(0, false).is_err());
        assert_eq!(required.state, SlotState::NoHandle);
        let mut pending = ComOriginal::new(ComKind::Element);
        assert!(pending.begin().is_ok()); assert_eq!(pending.returned(HRESULT_PENDING, true), Err(Error::Unknown));
        assert!(pending.active); assert_eq!(pending.state, SlotState::Unknown);
        // This is only a scalar DATA fixture. No pointer is dereferenced or
        // released; Unknown forbids adoption of a failed non-null COM output.
        let mut contradictory = ComOriginal::new(ComKind::Element);
        assert!(contradictory.begin().is_ok()); contradictory.pointer = 1usize as *mut c_void;
        assert_eq!(contradictory.returned(0x80004005u32 as i32, true), Err(Error::Unknown));
        assert!(contradictory.active); assert_eq!(contradictory.state, SlotState::Unknown);
    }

    fn request() -> UiRequest {
        let artifact = FullwalkArtifact { path: r"C:\fixture\owner.exe".to_owned(), bytes: 1, sha: "a".repeat(64),
            identity: format!("1:{}:1:1:1:32", "a".repeat(32)), command_sha: "b".repeat(64),
            messages_bytes: 1, messages_sha: "c".repeat(64), argv_sha: "d".repeat(64) };
        UiRequest { role: UiRole::Prerequisite, source: "a".repeat(40), tree: "b".repeat(40), run: "1".to_owned(),
            app: artifact.clone(), owner: artifact, runtime: None, app_version: "0.1.0".to_owned() }
    }

    #[test]
    fn unavailable_probe_is_completed_observation_not_gui_authorization() {
        let request = request(); let digest = "a".repeat(64); let account = "b".repeat(64);
        let unavailable = request.probe_result(&digest, &account, Some("interactive-desktop"), None);
        assert!(unavailable.is_ok());
        if let Ok(unavailable) = unavailable {
            assert_eq!(request.accept_child(unavailable.as_bytes(), &digest, &account), Ok(false));
            assert!(request.accept_child(unavailable.replace("\"available\":false", "\"available\":true").as_bytes(), &digest, &account).is_err());
            assert!(request.accept_child(unavailable.replace("\"originalsSettled\":true", "\"originalsSettled\":false").as_bytes(), &digest, &account).is_err());
            assert!(request.accept_child(unavailable.as_bytes(), &digest, &"c".repeat(64)).is_err());
        }
        assert!(request.probe_result(&digest, &account, Some("cleanup-unknown"), None).is_err());
        assert!(request.probe_result(&digest, &account, None, None).is_err());
        if let Ok(available) = request.probe_result(&digest, &account, None, Some("130.0.1.2")) {
            assert_eq!(request.accept_child(available.as_bytes(), &digest, &account), Ok(true));
        } else { panic!("valid finite observation must encode"); }
    }

    #[test]
    fn native_smoke_never_credits_posting_or_partial_release_as_finality() {
        let mut data = Smoke::new(); assert!(!data.passed());
        data.dashboard_ready = true; data.main = Some((1usize as F::HWND, 0, vec![1, 2]));
        data.windows.post_entered = true; data.windows.post_return = 1;
        assert!(!data.passed());
        data.invoke_entered = true; data.invoke_return = 0; data.quit_confirmed = true;
        assert!(!data.passed());
        data.initialized = true; data.uninit_returned = true; data.settled = true;
        assert!(data.passed()); data.unknown = true; assert!(!data.passed());
        data.unknown = false; data.dashboard_ready = false; assert!(!data.passed());
        // No native initialize/acquire happened. Never invoke settle on DATA.
    }
}
