//! Fixed normal-UI extension of the existing original Account/Launch owner.
//! No general launcher, inherited user environment, shipping switch or fallback.
use super::*;
use crate::ui_startup_data::Word as StartupWord;
use std::{cell::Cell, ffi::c_void, io::Write, marker::PhantomData, path::PathBuf};
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
    fn effect_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        let original = self.effect();
        trace.prerequisite_clock(self.latched);
        trace.prerequisite_result(PrerequisiteCheck::T01, original)
    }
    fn remaining_ms(&mut self) -> Result<u32> {
        self.effect()?;
        let remaining = self.endpoint_tick.checked_sub(unsafe { SI::GetTickCount64() }).ok_or(Error::Unsafe)?;
        need(remaining > 0 && remaining <= 90_000)?; Ok(remaining as u32)
    }
}

// NormalSmoke has no result children. Keep native scratch in the existing
// fresh profile owner, and use the already-present read/traverse-only task root
// as cwd. Profile creation still belongs solely to LOGON_WITH_PROFILE.
fn normal_smoke_profile_directory<'a>(role: UiRole, profile: Option<&'a Profile>, trace: &mut InputTrace) -> Result<Option<&'a Path>> {
    if role != UiRole::NormalSmoke { return Ok(None); }
    let profile = profile.ok_or(Error::Unsafe)?;
    profile.binding_permitted_traced(trace)?;
    need(profile.getter_entered && profile.getter_return != 0
        && profile.units > 1 && profile.units as usize <= profile.directory.len())?;
    let count = profile.directory.iter().position(|unit| *unit == 0).ok_or(Error::Unsafe)?;
    let parent = String::from_utf16(&profile.directory[..count]).map_err(|_| Error::Unsafe)?;
    need(Path::new(&parent).is_absolute() && profile.expected.is_absolute()
        && profile.expected == Path::new(&parent).join(&profile.name))?;
    Ok(Some(profile.expected.as_path()))
}
fn normal_smoke_launch_directories(role: UiRole, app: &str, output: &Path, root: &Path, profile: Option<&Path>,
    pairs: &mut [(String, String)], directory: &mut Vec<u16>) -> Result<()> {
    if role != UiRole::NormalSmoke { return Ok(()); }
    let profile = profile.ok_or(Error::Unsafe)?;
    let root_text = root.to_str().ok_or(Error::Unsafe)?;
    let output_text = output.to_str().ok_or(Error::Unsafe)?;
    let profile_text = profile.to_str().ok_or(Error::Unsafe)?;
    need(root.is_absolute() && output.is_absolute() && profile.is_absolute()
        && output == root.join(role.name("output")) && Path::new(app) == root.join("mobile-release-kit-desktop.exe")
        && !root_text.eq_ignore_ascii_case(output_text) && !root_text.eq_ignore_ascii_case(profile_text)
        && !output_text.eq_ignore_ascii_case(profile_text) && *directory == wide(output_text))?;
    let mut temp = None; let mut tmp = None;
    for (index, (name, value)) in pairs.iter().enumerate() {
        if name.eq_ignore_ascii_case("TEMP") {
            need(temp.is_none() && value.as_str() == output_text)?; temp = Some(index);
        } else if name.eq_ignore_ascii_case("TMP") {
            need(tmp.is_none() && value.as_str() == output_text)?; tmp = Some(index);
        }
    }
    let temp = temp.ok_or(Error::Unsafe)?; let tmp = tmp.ok_or(Error::Unsafe)?;
    // Every refusal is before mutation; retain names/order and every other pair.
    pairs[temp].1 = profile_text.to_owned(); pairs[tmp].1 = profile_text.to_owned();
    *directory = wide(root_text); Ok(())
}

impl Launch {
    fn ui(request: &UiRequest, identity: &str, raw_request: &str, output: &Path, root: &Path, profile: Option<&Profile>,
        account: &Account, parent: &[u8], endpoint: u64) -> Result<Pin<Box<Self>>> {
        Self::ui_traced(request, identity, raw_request, output, root, profile, account, parent, endpoint, &mut InputTrace::default())
    }
    fn ui_traced(request: &UiRequest, identity: &str, raw_request: &str, output: &Path, root: &Path, profile: Option<&Profile>,
        account: &Account, parent: &[u8], endpoint: u64, trace: &mut InputTrace) -> Result<Pin<Box<Self>>> {
        trace.prerequisite_scope(PrerequisiteCheck::D02, |trace| {
            let profile_directory = normal_smoke_profile_directory(request.role, profile, trace)?;
            let binding = Binding { source: request.source.clone(), tree: request.tree.clone(), run: request.run.clone(),
                artifact: request.app.path.clone(), bytes: request.app.bytes, sha: request.app.sha.clone(),
                command_sha: request.app.command_sha.clone(), identity: identity.to_owned() };
            // Reuse the existing checked, explicit Windows system environment and
            // initialized original PI/STARTUPINFO. No ambient user values are added.
            let mut value = Self::new_traced(OwnerVariant::Ordinary, &binding, None, output, account, parent, trace)?;
            let current = unsafe { value.as_mut().get_unchecked_mut() };
            let text = String::from_utf16(&current.environment[..current.environment.len() - 1]).map_err(|_| Error::Unsafe)?;
            let mut pairs: Vec<(String, String)> = text.split('\0').filter(|entry| !entry.is_empty()).map(|entry| {
                entry.split_once('=').map(|(name, value)| (name.to_owned(), value.to_owned())).ok_or(Error::Unsafe)
            }).collect::<Result<_>>()?;
            normal_smoke_launch_directories(request.role, &request.app.path, output, root, profile_directory,
                &mut pairs, &mut current.directory)?;
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
        })
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
    fn open(&mut self, clock: &mut Clock) -> Result<bool> { self.open_traced(clock, &mut InputTrace::default()) }
    fn open_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<bool> {
        trace.prerequisite_scope(PrerequisiteCheck::K01, |trace| {
            need(self.state == SlotState::Reserved)?; clock.effect_traced(trace)?;
            self.state = SlotState::Acquiring; self.active = true;
            self.status = unsafe { R::RegOpenKeyExW(self.root, self.name.as_ptr(), 0,
                R::KEY_READ | R::KEY_WOW64_64KEY, &mut self.handle) };
            if self.status == F::ERROR_SUCCESS && !self.handle.is_null() {
                self.active = false; self.state = SlotState::Owned; clock.effect_traced(trace)?; return Ok(true);
            }
            if self.handle.is_null() && self.status != F::ERROR_SUCCESS && self.status != F::ERROR_IO_PENDING {
                self.active = false; self.state = SlotState::NoHandle;
                if self.status != F::ERROR_FILE_NOT_FOUND {
                    trace.prerequisite_fault(PrerequisiteCheck::K01, Error::Unavailable,
                        PrerequisiteNative::registry(PrerequisiteApi::RegOpenKeyExW, PrerequisiteSelector::None, self.status), None);
                }
                clock.effect_traced(trace)?;
                return if self.status == F::ERROR_FILE_NOT_FOUND { Ok(false) } else { Err(Error::Unavailable) };
            }
            self.state = SlotState::Unknown;
            trace.prerequisite_fault(PrerequisiteCheck::K01, Error::Unknown,
                PrerequisiteNative::registry(PrerequisiteApi::RegOpenKeyExW, PrerequisiteSelector::None, self.status), None);
            Err(Error::Unknown)
        })
    }
    fn profile_path(&mut self, expected: &Path, clock: &mut Clock) -> Result<()> { self.profile_path_traced(expected, clock, &mut InputTrace::default()) }
    fn profile_path_traced(&mut self, expected: &Path, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::K02, |trace| {
            need(self.state == SlotState::Owned && !self.active)?; clock.effect_traced(trace)?;
            self.value_kind = 0; self.value_size = self.value.len() as u32; self.value.fill(0);
            self.active = true;
            self.status = unsafe { R::RegQueryValueExW(self.handle, self.value_name.as_ptr(), null(),
                &mut self.value_kind, self.value.as_mut_ptr(), &mut self.value_size) };
            self.active = self.status == F::ERROR_IO_PENDING;
            if self.active {
                self.state = SlotState::Unknown;
                trace.prerequisite_fault(PrerequisiteCheck::K02, Error::Unknown,
                    PrerequisiteNative::registry(PrerequisiteApi::RegQueryValueExW, PrerequisiteSelector::ProfileImagePath, self.status), None);
                return Err(Error::Unknown);
            }
            clock.effect_traced(trace)?;
            let original = need(self.status == F::ERROR_SUCCESS && matches!(self.value_kind, R::REG_SZ | R::REG_EXPAND_SZ)
                && self.value_size >= 4 && self.value_size as usize <= self.value.len() && self.value_size % 2 == 0);
            trace.prerequisite_native_result(PrerequisiteCheck::K02, original,
                PrerequisiteNative::registry(PrerequisiteApi::RegQueryValueExW, PrerequisiteSelector::ProfileImagePath, self.status), None)?;
            let units: Vec<u16> = self.value[..self.value_size as usize].chunks_exact(2).map(|v| u16::from_le_bytes([v[0], v[1]])).collect();
            need(units.last() == Some(&0) && !units[..units.len() - 1].contains(&0))?;
            let text = String::from_utf16(&units[..units.len() - 1]).map_err(|_| Error::Unsafe)?;
            // REG_EXPAND_SZ is accepted only if already the exact absolute path;
            // no process/user environment expansion or redirected-profile fallback.
            need(fixed_path_traced(&text, trace)? == expected)
        })
    }
    fn close(&mut self) -> Result<()> { self.close_traced(&mut InputTrace::default()) }
    fn close_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::K03, |trace| {
            match self.state {
                SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
                SlotState::Owned if !self.active => (), _ => return Err(Error::Unknown),
            }
            self.state = SlotState::Closing;
            self.status = unsafe { R::RegCloseKey(self.handle) };
            self.state = if self.status == F::ERROR_SUCCESS { SlotState::Closed } else { SlotState::Unknown };
            let original = need(self.state == SlotState::Closed).map_err(|_| Error::Unknown);
            trace.prerequisite_native_result(PrerequisiteCheck::K03, original,
                PrerequisiteNative::registry(PrerequisiteApi::RegCloseKey, PrerequisiteSelector::None, self.status), None)
        })
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
    fn observe_return_traced(&mut self, book: &NativeBook, other: &Absence, returned_observed: bool, trace: &mut InputTrace) -> Result<()> {
        let observed = returned_observed && self.entered && !self.completed && self.state == SlotState::Acquiring;
        let original = self.observe_return(book, other);
        let selector = match self.epoch { AbsenceEpoch::BeforeLogon => PrerequisiteSelector::BeforeLogon, AbsenceEpoch::AfterDeletion => PrerequisiteSelector::AfterDeletion };
        let native = if observed { PrerequisiteNative::nt(PrerequisiteApi::NtCreateFile, selector, self.returned) } else { None };
        trace.prerequisite_native_result(PrerequisiteCheck::B02, original, native, None)
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
    fn observe_close_traced(&mut self, returned_observed: bool, trace: &mut InputTrace) -> Result<()> {
        let observed = returned_observed && self.close_entered && self.state == SlotState::Closing;
        let original = self.observe_close();
        let native = if observed { PrerequisiteNative::boolean(PrerequisiteApi::CloseHandle, PrerequisiteSelector::None, self.close_return, Some(self.close_error)) } else { None };
        trace.prerequisite_native_result(PrerequisiteCheck::B03, original, native, None)
    }
    fn close_once(&mut self) -> Result<()> { self.close_once_traced(&mut InputTrace::default()) }
    fn close_once_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        if prerequisite_result!(trace, B03, self.begin_close())?.is_none() { return Ok(()); }
        // All return/error/input destinations were preregistered in this frame.
        self.close_return = unsafe { F::CloseHandle(self.close_handle) };
        self.close_error = if self.close_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        self.observe_close_traced(true, trace)
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
    fn new(account: &Account) -> Result<Self> { Self::new_traced(account, &mut InputTrace::default()) }
    fn new_traced(account: &Account, trace: &mut InputTrace) -> Result<Self> {
        trace.prerequisite_scope(PrerequisiteCheck::V01, |trace| {
            need(local_account_sid(&account.sid))?;
            let sid = format!("S-1-5-21-{}-{}-{}-{}", decode::u32_at(&account.sid, 12)?,
                decode::u32_at(&account.sid, 16)?, decode::u32_at(&account.sid, 20)?, decode::u32_at(&account.sid, 24)?);
            let name = String::from_utf16(&account.name[..account.name.len() - 1]).map_err(|_| Error::Unsafe)?;
            need(name.len() == 19 && name.starts_with("mrk") && is_hex(&name[3..], 16))?;
            let value = Self { native: NativeBook::new(), paths: Vec::with_capacity(16), absence: [None, None],
                keys: Vec::with_capacity(64), directory: Box::new([0; 1024]), units: 1024,
                getter_entered: false, getter_return: 0, getter_error: 0, sid: wide(&sid), name,
                drive: String::new(), device: String::new(), expected: PathBuf::new(), profile: None,
                mapping: None, root_key: None, prestate: false, exact: false, hives_unloaded: false,
                delete_entered: false, delete_return: 0, delete_error: 0, poststate: false, unknown: false, settled: false };
            value.native.prerequisite_enable_admission(trace);
            Ok(value)
        })
    }
    fn key(&mut self, root: R::HKEY, name: &str, clock: &mut Clock) -> Result<(usize, bool)> { self.key_traced(root, name, clock, &mut InputTrace::default()) }
    fn key_traced(&mut self, root: R::HKEY, name: &str, clock: &mut Clock, trace: &mut InputTrace) -> Result<(usize, bool)> {
        trace.prerequisite_scope(PrerequisiteCheck::V01, |trace| {
            need(self.keys.len() < 64)?;
            let index = self.keys.len(); self.keys.push(Box::new(Key::new(root, name)));
            let opened = self.keys[index].open_traced(clock, trace)?; Ok((index, opened))
        })
    }
    fn sid_name(&self) -> Result<String> { self.sid_name_traced(&mut InputTrace::default()) }
    fn sid_name_traced(&self, trace: &mut InputTrace) -> Result<String> {
        trace.prerequisite_result(PrerequisiteCheck::V01, String::from_utf16(&self.sid[..self.sid.len() - 1]).map_err(|_| Error::Unsafe))
    }
    fn hives_absent(&mut self, clock: &mut Clock) -> Result<bool> { self.hives_absent_traced(clock, &mut InputTrace::default()) }
    fn hives_absent_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<bool> {
        trace.prerequisite_scope(PrerequisiteCheck::V02, |trace| {
            let sid = self.sid_name_traced(trace)?;
            let mut absent = true;
            for name in [sid.clone(), format!("{sid}_Classes")] {
                let (index, present) = self.key_traced(R::HKEY_USERS, &name, clock, trace)?;
                self.keys[index].close_traced(trace)?; absent &= !present;
            }
            Ok(absent)
        })
    }
    fn absence(&self, epoch: AbsenceEpoch) -> Result<&Absence> { self.absence_traced(epoch, &mut InputTrace::default()) }
    fn absence_traced(&self, epoch: AbsenceEpoch, trace: &mut InputTrace) -> Result<&Absence> {
        trace.prerequisite_scope(PrerequisiteCheck::V03, |trace| {
            self.absence[epoch.index()].as_ref().map(|frame| frame.as_ref().get_ref()).ok_or(Error::State)
        })
    }
    fn absence_mut(&mut self, epoch: AbsenceEpoch) -> Result<&mut Absence> { self.absence_mut_traced(epoch, &mut InputTrace::default()) }
    fn absence_mut_traced(&mut self, epoch: AbsenceEpoch, trace: &mut InputTrace) -> Result<&mut Absence> {
        let original = self.absence[epoch.index()].as_mut().map(|frame|
            unsafe { frame.as_mut().get_unchecked_mut() }).ok_or(Error::State);
        trace.prerequisite_result(PrerequisiteCheck::V03, original)
    }
    fn register_absence(&mut self) -> Result<()> { self.register_absence_traced(&mut InputTrace::default()) }
    fn register_absence_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V02, |trace| {
            prerequisite_result!(trace, NB01, self.native.clear())?;
            need(!self.unknown && !self.settled && self.absence.iter().all(Option::is_none)
                && !self.paths.is_empty() && self.paths.len() <= 14 && self.native.slots.len() == self.paths.len())?;
            // Two fixed output originals plus the one future binding count against
            // the SAME existing limits. At most14 parents+2 epochs+1 binding =17.
            let records = self.native.slots.len().checked_add(3).ok_or(Error::Bounds)?;
            if records > MAX_RECORDS || records > MAX_LIVE { return Err(Error::Bounds); }
            let parent = self.paths.last().ok_or(Error::State)?.original.index;
            let handle = prerequisite_result!(trace, NB01, self.native.handle(parent))?;
            let before = prerequisite_result!(trace, B01, Absence::new(AbsenceEpoch::BeforeLogon, parent, handle, &self.name))?;
            let after = prerequisite_result!(trace, B01, Absence::new(AbsenceEpoch::AfterDeletion, parent, handle, &self.name))?;
            self.absence = [Some(ManuallyDrop::new(before)), Some(ManuallyDrop::new(after))];
            Ok(()) // Both fixed frames are owned BEFORE either original call.
        })
    }
    fn absence_permitted(&self, epoch: AbsenceEpoch) -> Result<()> { self.absence_permitted_traced(epoch, &mut InputTrace::default()) }
    fn absence_permitted_traced(&self, epoch: AbsenceEpoch, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V03, |trace| {
            if self.unknown { return Err(Error::Unknown); }
            prerequisite_result!(trace, NB01, self.native.clear())?; need(!self.settled && !self.poststate)?;
            let parent = self.paths.last().ok_or(Error::State)?.original.index;
            let handle = prerequisite_result!(trace, NB01, self.native.handle(parent))?; let name = wide(&self.name);
            for expected in [AbsenceEpoch::BeforeLogon, AbsenceEpoch::AfterDeletion] {
                let frame = self.absence_traced(expected, trace)?;
                need(frame.epoch == expected && frame.parent == parent && frame.parent_handle == handle && frame.name == name)?;
            }
            need(self.absence_traced(epoch, trace)?.unstarted())?;
            match epoch {
                AbsenceEpoch::BeforeLogon => need(!self.prestate && !self.exact && self.profile.is_none()
                    && !self.delete_entered && self.absence_traced(AbsenceEpoch::AfterDeletion, trace)?.unstarted()),
                AbsenceEpoch::AfterDeletion => need(self.prestate && self.exact && self.hives_unloaded
                    && self.absence_traced(AbsenceEpoch::BeforeLogon, trace)?.exact_absence()
                    && self.profile.as_ref().is_some_and(|path| prerequisite_result!(trace, NB01, self.native.state(&path.original)) == Ok(SlotState::Closed))
                    && self.mapping.and_then(|index| self.keys.get(index)).is_some_and(|key| key.state == SlotState::Closed && !key.active)
                    && self.delete_entered && self.delete_return != 0),
            }
        })
    }
    fn binding_permitted(&self) -> Result<()> { self.binding_permitted_traced(&mut InputTrace::default()) }
    fn binding_permitted_traced(&self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V03, |trace| {
            if self.unknown { return Err(Error::Unknown); }
            prerequisite_result!(trace, NB01, self.native.clear())?;
            need(self.prestate && !self.exact && self.profile.is_none() && !self.delete_entered && !self.settled
                && self.absence_traced(AbsenceEpoch::BeforeLogon, trace)?.exact_absence() && self.absence_traced(AbsenceEpoch::AfterDeletion, trace)?.unstarted())
        })
    }
    fn absence_dependents_settled(&self) -> bool {
        self.absence.iter().flatten().all(|frame| frame.settled())
    }
    fn profile_absent(&mut self, epoch: AbsenceEpoch, clock: &mut Clock) -> Result<()> { self.profile_absent_traced(epoch, clock, &mut InputTrace::default()) }
    fn profile_absent_traced(&mut self, epoch: AbsenceEpoch, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V04, |trace| {
            let permission = self.absence_permitted_traced(epoch, trace);
            if matches!(permission, Err(Error::Unknown)) { self.unknown = true; return permission; }
            prerequisite_result!(trace, B01, self.absence_mut_traced(epoch, trace)?.claim())?; // Even a pre-entry refusal spends this fixed epoch.
            permission?; clock.effect_traced(trace)?;
            let native = &self.native;
            let [before, after] = &mut self.absence;
            let (frame, other) = match epoch { AbsenceEpoch::BeforeLogon => (before, after), AbsenceEpoch::AfterDeletion => (after, before) };
            let f = unsafe { frame.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
            let other = other.as_ref().ok_or(Error::State)?.as_ref().get_ref();
            prerequisite_result!(trace, B01, f.begin())?;
            f.returned = unsafe { N::NtCreateFile(f.output.get(), FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE,
                &f.attributes, f.iosb.get(), null(), 0, FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE, N::FILE_OPEN,
                N::FILE_DIRECTORY_FILE | N::FILE_OPEN_REPARSE_POINT | N::FILE_SYNCHRONOUS_IO_NONALERT, null(), 0) };
            let result = f.observe_return_traced(native, other, true, trace);
            self.unknown |= f.state == SlotState::Unknown;
            result?; clock.effect_traced(trace)
        })
    }
    fn prepare(&mut self, clock: &mut Clock) -> Result<()> { self.prepare_traced(clock, &mut InputTrace::default()) }
    fn prepare_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V05, |trace| {
            need(!self.getter_entered)?; clock.effect_traced(trace)?;
            self.getter_entered = true;
            self.getter_return = unsafe { SH::GetProfilesDirectoryW(self.directory.as_mut_ptr(), &mut self.units) };
            self.getter_error = if self.getter_return != 0 { 0 } else { unsafe { F::GetLastError() } };
            let native = PrerequisiteNative::boolean(PrerequisiteApi::GetProfilesDirectoryW, PrerequisiteSelector::None,
                self.getter_return, Some(self.getter_error));
            if self.getter_return == 0 && (self.getter_error == 0 || self.getter_error == F::ERROR_IO_PENDING) {
                trace.prerequisite_fault(PrerequisiteCheck::V05, Error::Unknown, native, None);
                self.unknown = true; return Err(Error::Unknown);
            }
            clock.effect_traced(trace)?;
            trace.prerequisite_native_result(PrerequisiteCheck::V05,
                need(self.getter_return != 0 && self.units > 1 && self.units as usize <= self.directory.len()), native, None)?;
            let count = self.directory.iter().position(|unit| *unit == 0).ok_or(Error::Unsafe)?;
            let path = String::from_utf16(&self.directory[..count]).map_err(|_| Error::Unsafe)?;
            let root = fixed_path_traced(&path, trace)?;
            let (drive, parts) = decode::dos_location(&path)?;
            need(!parts.is_empty() && parts.len() < 14)?;
            trace.prerequisite_check(PrerequisiteCheck::V06);
            self.drive = drive; self.device = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB05, |native| native.mapping(&self.drive))?; clock.effect_traced(trace)?;
            let name = format!("{}\\", self.device);
            let original = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB01, |native| native.reserve(Kind::Directory, None, &name, name.clone()))?;
            // NativeBook keeps the original output even if an error prevents the
            // higher-level metadata record from being added to paths.
            self.native.prerequisite_observe(trace, PrerequisiteCheck::NB02, |native| native.call(Call::Open(original.index), null_mut(), Vec::new()))?;
            clock.effect_traced(trace)?; self.native.prerequisite_observe(trace, PrerequisiteCheck::NB03, |native| native.noninherited(original.index))?; clock.effect_traced(trace)?;
            let metadata = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&original))?; clock.effect_traced(trace)?; self.native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.local_ntfs(&original))?;
            clock.effect_traced(trace)?; self.native.prerequisite_observe(trace, PrerequisiteCheck::NB08, |native| native.security(&original, AuthorityScope::AncestorOutsideVersion))?; clock.effect_traced(trace)?;
            self.paths.push(ProfilePath { original, metadata });
            for name in parts {
                clock.effect_traced(trace)?;
                let original = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.open_child(&self.paths.last().ok_or(Error::State)?.original, &name, FileKind::Directory))?;
                clock.effect_traced(trace)?; let metadata = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&original))?; clock.effect_traced(trace)?;
                self.native.prerequisite_observe(trace, PrerequisiteCheck::NB08, |native| native.security(&original, AuthorityScope::AncestorOutsideVersion))?; clock.effect_traced(trace)?;
                self.paths.push(ProfilePath { original, metadata });
            }
            self.expected = root.join(&self.name);
            self.register_absence_traced(trace)?;
            self.profile_absent_traced(AbsenceEpoch::BeforeLogon, clock, trace)?;
            let (index, present) = self.key_traced(R::HKEY_LOCAL_MACHINE, PROFILE_LIST, clock, trace)?;
            need(present)?; self.root_key = Some(index);
            let handle = self.keys[index].handle;
            let (sid_key, present) = self.key_traced(handle, &self.sid_name_traced(trace)?, clock, trace)?;
            self.keys[sid_key].close_traced(trace)?; need(!present && self.hives_absent_traced(clock, trace)?)?;
            self.prestate = true; clock.effect_traced(trace)
        })
    }
    fn bind_after_logon(&mut self, clock: &mut Clock) -> Result<()> { self.bind_after_logon_traced(clock, &mut InputTrace::default()) }
    fn bind_after_logon_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V07, |trace| {
            self.binding_permitted_traced(trace)?; clock.effect_traced(trace)?;
            let root = &self.paths.last().ok_or(Error::State)?.original;
            let original = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.open_child(root, &self.name, FileKind::Directory))?;
            clock.effect_traced(trace)?; let metadata = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&original))?; clock.effect_traced(trace)?;
            self.native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.local_ntfs(&original))?; clock.effect_traced(trace)?;
            self.profile = Some(ProfilePath { original, metadata });
            let handle = self.keys[self.root_key.ok_or(Error::State)?].handle;
            let (index, present) = self.key_traced(handle, &self.sid_name_traced(trace)?, clock, trace)?;
            need(present)?; self.mapping = Some(index);
            self.keys[index].profile_path_traced(&self.expected, clock, trace)?;
            self.recheck_traced(clock, trace)?; self.exact = true; Ok(())
        })
    }
    fn recheck(&mut self, clock: &mut Clock) -> Result<()> { self.recheck_traced(clock, &mut InputTrace::default()) }
    fn recheck_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V08, |trace| {
            clock.effect_traced(trace)?;
            need(self.native.prerequisite_observe(trace, PrerequisiteCheck::NB05, |native| native.mapping(&self.drive))? == self.device)?;
            for path in &self.paths {
                clock.effect_traced(trace)?;
                let after = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&path.original))?;
                clock.effect_traced(trace)?;
                need(after.identity == path.metadata.identity && after.kind == FileKind::Directory)?;
                self.native.prerequisite_observe(trace, PrerequisiteCheck::NB08, |native| native.security(&path.original, AuthorityScope::AncestorOutsideVersion))?; clock.effect_traced(trace)?;
            }
            if let Some(path) = &self.profile {
                let after = self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&path.original))?;
                clock.effect_traced(trace)?;
                need(after.identity == path.metadata.identity && after.kind == FileKind::Directory)?;
            }
            if let Some(index) = self.mapping { self.keys[index].profile_path_traced(&self.expected, clock, trace)?; }
            clock.effect_traced(trace)
        })
    }
    fn retire(&mut self, clock: &mut Clock) -> Result<()> { self.retire_traced(clock, &mut InputTrace::default()) }
    fn retire_traced(&mut self, clock: &mut Clock, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V09, |trace| {
            need(self.prestate && self.exact && !self.unknown && !self.delete_entered && !self.settled)?;
            // B's genuine application exit already joined its browser/user-data
            // lifetime. LOGON_WITH_PROFILE owns automatic hive unload, not this test.
            for _ in 0..20 {
                if self.hives_absent_traced(clock, trace)? { self.hives_unloaded = true; break; }
                clock.effect_traced(trace)?; std::thread::sleep(Duration::from_millis(250));
            }
            need(self.hives_unloaded)?; self.recheck_traced(clock, trace)?;
            self.keys[self.mapping.ok_or(Error::State)?].close_traced(trace)?;
            self.native.prerequisite_observe(trace, PrerequisiteCheck::NB03, |native| native.close_once(&self.profile.as_ref().ok_or(Error::State)?.original))?;
            // Release the profile child only, not the original namespace parent.
            // DeleteProfileW takes exact owned SID; no alternate path is supplied.
            clock.effect_traced(trace)?; self.delete_entered = true;
            self.delete_return = unsafe { SH::DeleteProfileW(self.sid.as_ptr(), null(), null()) };
            self.delete_error = if self.delete_return != 0 { 0 } else { unsafe { F::GetLastError() } };
            if self.delete_return == 0 {
                self.unknown = true;
                trace.prerequisite_fault(PrerequisiteCheck::V09, Error::Unknown,
                    PrerequisiteNative::boolean(PrerequisiteApi::DeleteProfileW, PrerequisiteSelector::None,
                        self.delete_return, Some(self.delete_error)), None);
                return Err(Error::Unknown);
            }
            trace.prerequisite_check(PrerequisiteCheck::V10);
            clock.effect_traced(trace)?;
            self.profile_absent_traced(AbsenceEpoch::AfterDeletion, clock, trace)?;
            let handle = self.keys[self.root_key.ok_or(Error::State)?].handle;
            let (index, present) = self.key_traced(handle, &self.sid_name_traced(trace)?, clock, trace)?;
            self.keys[index].close_traced(trace)?; need(!present && self.hives_absent_traced(clock, trace)?)?;
            // Recheck surviving namespace originals without reusing the now-closed
            // profile/mapping handles or adopting a replacement profile path.
            need(self.native.prerequisite_observe(trace, PrerequisiteCheck::NB05, |native| native.mapping(&self.drive))? == self.device)?;
            for path in &self.paths { clock.effect_traced(trace)?; need(self.native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&path.original))?.identity == path.metadata.identity)?; }
            self.poststate = true; self.settle_traced(trace)?; clock.effect_traced(trace)
        })
    }
    fn settle(&mut self) -> Result<()> { self.settle_traced(&mut InputTrace::default()) }
    fn settle_traced(&mut self, trace: &mut InputTrace) -> Result<()> {
        trace.prerequisite_scope(PrerequisiteCheck::V11, |trace| {
            if self.settled { return Ok(()); }
            if self.unknown || self.native.is_unknown() || self.absence.iter().flatten().any(|frame| frame.unresolved()) {
                self.unknown = true; return Err(Error::Unknown);
            }
            // These fixed frames are dependents of the original namespace parent,
            // outside the binding path book. Their one closes MUST precede it.
            for frame in self.absence.iter_mut().flatten() {
                let frame = unsafe { frame.as_mut().get_unchecked_mut() };
                if frame.close_once_traced(trace).is_err() { self.unknown = true; return Err(Error::Unknown); }
            }
            if !self.absence_dependents_settled() {
                self.unknown = true;
                trace.prerequisite_fault(PrerequisiteCheck::B03, Error::Unknown, None, None);
                return Err(Error::Unknown);
            }
            for key in self.keys.iter_mut().rev() {
                if key.close_traced(trace).is_err() { self.unknown = true; return Err(Error::Unknown); }
            }
            self.settled = self.native.prerequisite_settle(trace) == CloseOutcome::Settled && self.native.settled();
            if !self.settled { self.unknown = true; return Err(Error::Unknown); }
            // Original native frames have returned and every dependent original is
            // closed before any frame storage is deallocated.
            for frame in &mut self.absence { if let Some(frame) = frame.take() { drop(ManuallyDrop::into_inner(frame)); } }
            Ok(())
        })
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
    trace.prerequisite_scope(PrerequisiteCheck::F01, |trace| {
        need(files.len() < 48)?; clock.effect_traced(trace)?;
        let index = files.len(); files.push(OriginalFile::fixture_new_traced(path, directory, clock.end, trace)?);
        files[index].open_traced(access, false, null(), trace)?;
        files[index].named_traced(path, trace)?; files[index].stamp_traced(trace)?;
        clock.effect_traced(trace)?; Ok(index)
    })
}
fn new_directory(creates: &mut Vec<Box<DirectoryCreate>>, files: &mut Vec<OriginalFile>, path: &Path,
    clock: &mut Clock, trace: &mut InputTrace) -> Result<usize> {
    trace.prerequisite_scope(PrerequisiteCheck::F01, |trace| {
        need(creates.len() < 4)?; clock.effect_traced(trace)?;
        creates.push(Box::new(DirectoryCreate { name: wide(path.to_str().ok_or(Error::Unsafe)?),
            entered: false, returned: 0, error: 0 }));
        let call = creates.last_mut().ok_or(Error::State)?;
        call.entered = true;
        call.returned = unsafe { FS::CreateDirectoryW(call.name.as_ptr(), null()) };
        call.error = if call.returned != 0 { 0 } else { unsafe { F::GetLastError() } };
        if call.returned == 0 {
            trace.prerequisite_fault(PrerequisiteCheck::F01,
                if call.error == 0 || call.error == F::ERROR_IO_PENDING { Error::Unknown } else { Error::Unsafe },
                PrerequisiteNative::boolean(PrerequisiteApi::CreateDirectoryW, PrerequisiteSelector::None, call.returned, Some(call.error)), None);
        }
        if call.returned == 0 && (call.error == 0 || call.error == F::ERROR_IO_PENDING) { return Err(Error::Unknown); }
        // Neither an existing path nor a failed creation is adopted or deleted.
        need(call.returned != 0)?; clock.effect_traced(trace)?;
        input(files, path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC, clock, trace)
    })
}
fn read_hash(files: &mut [OriginalFile], index: usize, bytes: usize, sha: &str, app: bool,
    clock: &mut Clock, trace: &mut InputTrace) -> Result<Stamp> {
    trace.prerequisite_scope(PrerequisiteCheck::F02, |trace| {
        clock.effect_traced(trace)?; let before = files[index].stamp_traced(trace)?;
        let raw = if app { files[index].read_app_traced(trace)? } else { files[index].read_traced(128 << 20, trace)? };
        clock.effect_traced(trace)?; need(raw.len() == bytes)?;
        let actual = if app { digest_app_traced(&raw, trace)? } else { digest_traced(&raw, trace)? };
        clock.effect_traced(trace)?; need(actual == sha && files[index].stamp_traced(trace)? == before)?; Ok(before)
    })
}
fn acl(files: &mut [OriginalFile], index: usize, label: &str, mask: u32, parent: &[u8], account: &[u8],
    clock: &mut Clock, trace: &mut InputTrace, transitions: &mut Vec<String>) -> Result<()> {
    trace.prerequisite_scope(PrerequisiteCheck::F02, |trace| {
        clock.effect_traced(trace)?;
        transitions.push(grant(&mut files[index], label, parent, account, mask,
            clock.start, &mut clock.latched, &mut clock.aggregate, trace)?);
        clock.effect_traced(trace)
    })
}
fn create_fixture_file(files: &mut Vec<OriginalFile>, path: &Path, bytes: &'static [u8], parent: &[u8], account: &[u8],
    clock: &mut Clock, trace: &mut InputTrace, transitions: &mut Vec<String>) -> Result<FixtureFile> {
    need(files.len() < 48)?; clock.effect_traced(trace)?;
    let writer = files.len();
    trace.at(InputRole::Output, Some(writer as u8));
    files.push(OriginalFile::fixture_new_traced(path, false, clock.end, trace)?);
    // The original pre-close stamp needs metadata-read access, not read-data access.
    files[writer].open_traced(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, null(), trace)?;
    files[writer].named_traced(path, trace)?; files[writer].write_fixture_payload(bytes)?;
    let created = files[writer].stamp_traced(trace)?;
    // Do not retain a write-data handle while the ordinary core opens the same
    // immutable file share-read-only. Close it once and authenticate the new
    // read original against the actual CREATE_NEW identity under pinned parents.
    files[writer].close_traced(trace)?; clock.effect_traced(trace)?;
    trace.at(InputRole::Output, Some(files.len() as u8));
    let index = input(files, path, false, FS::FILE_GENERIC_READ | FS::WRITE_DAC, clock, trace)?;
    let reopened = files[index].stamp_traced(trace)?;
    // Windows can publish the final write/change times only when the last
    // write-data handle closes. Identity and bytes are not allowed to change.
    need(reopened.volume == created.volume && reopened.id == created.id && reopened.creation == created.creation
        && reopened.size == bytes.len() as i64 && reopened.size == created.size && reopened.links == 1
        && reopened.attributes == created.attributes && reopened.write >= created.write && reopened.change >= created.change
        && files[index].read_traced(LIMIT, trace)? == bytes)?;
    trace.at(InputRole::AclOutput, Some(index as u8));
    acl(files, index, "synthetic-input", FS::FILE_GENERIC_READ, parent, account, clock, trace, transitions)?;
    trace.at(InputRole::Output, Some(index as u8));
    Ok(FixtureFile { index, stamp: files[index].stamp_traced(trace)?, bytes })
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
    trace: &mut InputTrace, smoke: Option<&Smoke>) -> Result<()> {
    // Observe each original result once; this only narrows the existing first
    // diagnostic. No extra native operation, inventory pass or failure policy.
    macro_rules! output_result {
        ($check:ident, $original:expr) => {
            smoke_result(smoke, SmokePhase::OutputPoststate, SmokeCheck::$check, $original)
        };
    }
    trace.prerequisite_scope(PrerequisiteCheck::O01, |trace| {
        let (drive, parts) = output_result!(OutputDecode, decode::dos_location(output_result!(OutputLocation, output.to_str().ok_or(Error::Unsafe))?))?;
        output_result!(OutputDepth, need(parts.len() < 16))?; output_result!(Clock, clock.effect_traced(trace))?;
        let device = output_result!(OutputDrive, native.prerequisite_observe(trace, PrerequisiteCheck::NB05, |native| native.mapping(&drive)))?; let name = format!("{device}\\");
        let root = output_result!(OutputRootReserve, native.prerequisite_observe(trace, PrerequisiteCheck::NB01, |native| native.reserve(Kind::Directory, None, &name, name.clone())))?;
        output_result!(OutputRootOpen, native.prerequisite_observe(trace, PrerequisiteCheck::NB02, |native| native.call(Call::Open(root.index), null_mut(), Vec::new())))?;
        output_result!(OutputRootNoninherited, native.prerequisite_observe(trace, PrerequisiteCheck::NB03, |native| native.noninherited(root.index)))?; output_result!(OutputFilesystem, native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.local_ntfs(&root)))?;
        let root_metadata = output_result!(OutputRootMetadata, native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&root)))?;
        let mut entries = vec![(root, root_metadata)];
        for name in parts {
            output_result!(Clock, clock.effect_traced(trace))?;
            let original = output_result!(OutputAncestorOpen, native.prerequisite_observe(trace, PrerequisiteCheck::NB06, |native| native.open_child(&output_result!(OutputParentOriginal, entries.last().ok_or(Error::State))?.0, &name, FileKind::Directory)))?;
            let metadata = output_result!(OutputAncestorMetadata, native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(&original)))?; entries.push((original, metadata));
        }
        let at = entries.len() - 1;
        trace.at(InputRole::Output, Some(output_index as u8));
        let output_stamp = output_result!(OutputStamp, files[output_index].stamp_traced(trace))?;
        output_result!(OutputIdentity, need(entries[at].1.identity.volume_serial == output_stamp.volume && entries[at].1.identity.file_id == output_stamp.id))?;
        let mut directories = vec![(at, at - 1)];
        let mut children: Vec<(usize, String, Stamp, FileKind)> = Vec::with_capacity(9);
        if let Some(result) = result_index {
            trace.at(InputRole::Output, Some(result as u8));
            children.push((at, role.name("result.private.json"), files[result].stamp_traced(trace)?, FileKind::File));
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
                clock.effect_traced(trace)?; native.no_alternate_streams(&original)?; clock.effect_traced(trace)?;
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
            clock.effect_traced(trace)?; native.no_alternate_streams(&original)?; clock.effect_traced(trace)?;
            need(metadata.identity.volume_serial == stamp.volume && metadata.identity.file_id == stamp.id
                && native.read_next(&original, LIMIT)? == if fixture.initial_config { UI_FIXTURE_CONFIG } else { UI_FIXTURE_CONFIG_AFTER }
                && native.read_next(&original, 1)?.is_empty())?;
            entries.push((original, metadata));
        } else { output_result!(OutputRole, need(matches!(role, UiRole::Prerequisite | UiRole::NormalSmoke)))?; }
        trace.prerequisite_check(PrerequisiteCheck::O02);
        for (index, parent) in directories {
            trace.prerequisite_check(PrerequisiteCheck::O02);
            let mut seen = std::collections::BTreeSet::new();
            loop {
                output_result!(Clock, clock.effect_traced(trace))?; let Some(batch) = output_result!(OutputEntryBatch, native.prerequisite_observe(trace, PrerequisiteCheck::NB09, |native| native.next_entries(&entries[index].0)))? else { break; };
                for entry in batch {
                    output_result!(OutputEntryAdmission, need(seen.insert(entry.name.clone()) && seen.len() <= 6))?;
                    if entry.name == "." { output_result!(OutputDotIdentity, need(entry.file_id == entries[index].1.identity.file_id))?; continue; }
                    if entry.name == ".." { output_result!(OutputParentIdentity, need(entry.file_id == entries[parent].1.identity.file_id))?; continue; }
                    let (_, _, expected, kind) = output_result!(OutputUnexpectedChild, children.iter().find(|(p, name, _, _)| *p == index && *name == entry.name).ok_or(Error::Unsafe))?;
                    output_result!(OutputEntryBinding, need(entry.file_id == expected.id && entry.kind == *kind && entries[index].1.identity.volume_serial == expected.volume))?;
                }
            }
            trace.prerequisite_check(PrerequisiteCheck::O03);
            let expected: std::collections::BTreeSet<_> = children.iter().filter(|(p, _, _, _)| *p == index)
                .map(|(_, name, _, _)| name.clone()).chain([".".to_owned(), "..".to_owned()]).collect();
            output_result!(OutputRoster, need(seen == expected))?;
        }
        for (original, before) in &entries { output_result!(Clock, clock.effect_traced(trace))?; output_result!(OutputPostMetadata, need(output_result!(OutputPostMetadataRead, native.prerequisite_observe(trace, PrerequisiteCheck::NB07, |native| native.metadata(original)))? == *before))?; }
        output_result!(OutputMappingUnchanged, need(output_result!(OutputFinalDrive, native.prerequisite_observe(trace, PrerequisiteCheck::NB05, |native| native.mapping(&drive)))? == device))?; output_result!(Clock, clock.effect_traced(trace))?;
        if let Some(fixture) = fixture.as_mut() { fixture.verified = true; }
        Ok(())
    })
}

// Qualification-only, same-thread DATA. No caller text or native identity can
// enter this companion diagnostic, and no release/finality decision reads it.
macro_rules! smoke_labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
            const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}
smoke_labels!(SmokePhase {
    Setup => "setup", MainWindow => "main-window", MainBinding => "main-binding",
    Dashboard => "dashboard", CloseRequest => "close-request", QuitDialog => "quit-dialog",
    QuitInvoke => "quit-invoke", ObserveClock => "observation-clock", DriverSettle => "driver-settle",
    OwnerFinality => "owner-finality", OutputPoststate => "output-poststate", Retirement => "retirement",
});
smoke_labels!(SmokeCheck {
    Clock => "original-clock", QueryState => "query-state", QueryBudget => "query-admission-budget",
    QueryPending => "query-pending", ArrayDestroyState => "array-destroy-state", ArrayDestroy => "array-destroy",
    WindowOwnerRead => "window-owner-read", WindowTitleRead => "window-title-read",
    WindowTitleLength => "window-title-length", WindowTitleEncoding => "window-title-encoding",
    WindowQueryIdle => "window-query-idle", ProcessState => "original-process-state",
    ProcessIdentity => "original-process-identity", ProcessLive => "original-process-live",
    WindowEnumeration => "thread-window-enumeration", WindowOverflow => "thread-window-overflow",
    WindowIdentity => "enumerated-window-identity", RootUniqueness => "main-root-uniqueness",
    RootContinuity => "main-root-continuity", ComReserveState => "com-reservation-state",
    ComReserveCapacity => "com-reservation-capacity", ComReserveBudget => "com-reservation-budget",
    ComIndex => "com-original-index", ComState => "com-original-kind-or-state",
    ClientMissing => "client-original-missing", InitializeOnce => "apartment-initialize-once",
    Initialize => "apartment-initialize", ClientAcquireState => "client-acquire-state",
    ClientAcquire => "client-acquire", ConnectionTimeout => "connection-timeout-setting",
    TransactionTimeout => "transaction-timeout-setting", WalkerAcquireState => "walker-acquire-state",
    WalkerAcquire => "raw-view-walker-acquire", WalkerMissing => "walker-original-missing",
    ElementAcquireState => "element-from-window-acquire-state", ElementFromWindow => "element-from-window",
    InitialMainState => "initial-main-acquire-state", InitialMainTail => "initial-main-returned-tail",
    InitialMainTimeoutCount => "initial-main-timeout-count",
    DashboardBindingState => "dashboard-binding-state", DashboardBindingTimeoutCount => "dashboard-binding-timeout-count",
    AdjacentAcquireState => "adjacent-element-acquire-state", FirstChild => "first-child-element",
    NextSibling => "next-sibling-element", NameOutputState => "name-output-state",
    NameContradiction => "name-contradictory-output", CurrentName => "current-name",
    DashboardNameState => "dashboard-name-state",
    NameLength => "name-length", NameEncoding => "name-encoding",
    RuntimeIdOutputState => "runtime-id-output-state", RuntimeIdContradiction => "runtime-id-contradictory-output",
    RuntimeId => "runtime-id", RuntimeIdPresent => "runtime-id-present",
    RuntimeIdDimensions => "runtime-id-dimensions", RuntimeIdElementSize => "runtime-id-element-size",
    RuntimeIdVariantCall => "runtime-id-variant-call", RuntimeIdVariant => "runtime-id-variant",
    RuntimeIdLowerCall => "runtime-id-lower-bound-call", RuntimeIdUpperCall => "runtime-id-upper-bound-call",
    RuntimeIdBounds => "runtime-id-bounds", RuntimeIdElement => "runtime-id-element",
    NativeWindowHandle => "current-native-window-handle", ControlType => "current-control-type",
    IsEnabled => "current-is-enabled", IsOffscreen => "current-is-offscreen", MainMissing => "main-element-missing",
    MainBinding => "main-window-element-binding", ProcessId => "current-process-id",
    MainProcess => "main-element-process-binding", WalkBounds => "walk-depth-or-count",
    SiblingBounds => "walk-sibling-count", ComRelease => "com-original-release-state",
    NativeServiceUnavailable => "native-service-unavailable", CatalogueUnavailable => "field-catalogue-unavailable",
    BundledEngineUnavailable => "bundled-engine-unavailable", EngineDisabled => "engine-disabled",
    BrowserPreview => "browser-preview", PostCloseOnce => "post-close-once", PostClose => "post-close",
    QuitDialogIdentity => "quit-dialog-title-or-uniqueness", QuitClassEncoding => "quit-dialog-class-encoding",
    QuitClass => "quit-dialog-class", QuitTreeState => "quit-logical-tree-state",
    QuitTreeBounds => "quit-logical-tree-bounds", QuitTreeIncomplete => "quit-logical-tree-incomplete",
    QuitRuntime => "quit-logical-runtime-identity", QuitLineage => "quit-logical-ancestry",
    QuitProcess => "quit-logical-process", QuitButtonsDuplicate => "quit-logical-button-duplicate",
    QuitButtonType => "quit-logical-button-name-or-type", QuitButtonEnabled => "quit-logical-button-enabled",
    QuitButtonVisibility => "quit-logical-button-onscreen", QuitButtonsChanged => "quit-logical-retained-pair-changed",
    QuitNativeState => "quit-native-container-state", QuitNativeBounds => "quit-native-container-bounds",
    QuitNativeProcess => "quit-native-container-process", QuitNativeThread => "quit-native-container-thread",
    QuitNativeDescendant => "quit-native-container-descendant", QuitNativeLineage => "quit-native-container-lineage",
    QuitNativeStyle => "quit-native-container-style", QuitNativeChanged => "quit-native-container-changed",
    QuitParentAcquireState => "quit-logical-parent-acquire-state", QuitParentAcquire => "quit-logical-parent-acquire",
    QuitDefault => "quit-default-cancel", QuitDefaultState => "quit-legacy-state-contradiction",
    QuitLegacyAcquireState => "quit-legacy-pattern-acquire-state", QuitOkLegacyAcquire => "quit-ok-legacy-pattern-acquire",
    QuitCancelLegacyAcquire => "quit-cancel-legacy-pattern-acquire", QuitOkLegacyState => "quit-ok-legacy-state",
    QuitCancelLegacyState => "quit-cancel-legacy-state", QuitLegacyChanged => "quit-legacy-state-changed",
    QuitDialogHandle => "quit-dialog-element-handle", QuitInstruction => "quit-instruction-missing",
    QuitOkMissing => "quit-ok-missing", QuitCancelMissing => "quit-cancel-missing",
    QuitBinding => "quit-dialog-original-binding", QuitPatterns => "quit-original-pattern-binding",
    InvokeAcquireState => "invoke-pattern-acquire-state",
    InvokeAcquire => "invoke-pattern-acquire", InvokeOnce => "invoke-once", Invoke => "invoke",
    DriverUnknown => "driver-unknown", WindowQueryActive => "window-query-active",
    QuerySettlement => "query-settlement", UninitializeOnce => "apartment-uninitialize-once",
    OwnerResult => "original-owner-result", ParentSettlement => "parent-book-settlement",
    OwnerFinality => "original-process-finality", RequestMissing => "original-request-missing",
    SmokeFinality => "smoke-finality", ArtifactIndex => "artifact-original-index",
    ArtifactStamp => "artifact-original-stamp", ArtifactExpected => "artifact-expected-stamp",
    ArtifactUnchanged => "artifact-unchanged", InputStamp => "input-original-stamp",
    InputUnchanged => "input-unchanged", OutputIndex => "output-original-index", OutputInventory => "output-inventory",
    OutputLocation => "output-location",
    OutputDecode => "output-location-decode",
    OutputDepth => "output-path-depth",
    OutputDrive => "output-initial-drive",
    OutputRootReserve => "output-root-reserve",
    OutputRootOpen => "output-root-open",
    OutputRootNoninherited => "output-root-noninherited",
    OutputFilesystem => "output-root-filesystem",
    OutputRootMetadata => "output-root-metadata",
    OutputParentOriginal => "output-parent-original",
    OutputAncestorOpen => "output-ancestor-open",
    OutputAncestorMetadata => "output-ancestor-metadata",
    OutputStamp => "output-original-stamp",
    OutputIdentity => "output-original-identity",
    OutputRole => "output-inventory-role",
    OutputEntryBatch => "output-entry-batch",
    OutputEntryAdmission => "output-entry-duplicate-bound",
    OutputDotIdentity => "output-dot-identity",
    OutputParentIdentity => "output-parent-identity",
    OutputUnexpectedChild => "output-unexpected-child",
    OutputEntryBinding => "output-entry-binding",
    OutputRoster => "output-exact-roster",
    OutputPostMetadataRead => "output-post-metadata-read",
    OutputPostMetadata => "output-post-metadata",
    OutputFinalDrive => "output-final-drive",
    OutputMappingUnchanged => "output-mapping-unchanged",
    InventorySettlement => "inventory-settlement", InputClose => "input-original-close",
    ProfileSettlement => "profile-settlement", ProfileRetirement => "profile-retirement",
    AccountRetirement => "account-retirement",
});
smoke_labels!(DashboardStage { Bind => "bind", Walk => "walk", Names => "names", NamesEnded => "names-ended" });
smoke_labels!(DashboardScanEnd { Loading => "loading", Stale => "stale", Exhausted => "exhausted" });
smoke_labels!(DashboardScanHistory { None => "none", LoadingOnly => "loading-only", StaleSeen => "stale-seen", ExhaustedSeen => "exhausted-seen" });
#[derive(Debug, Eq, PartialEq)]
enum DashboardNameRead { Text(String), Invalidated }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DashboardPass { found: [bool; 5], end: Option<DashboardScanEnd> }
impl DashboardPass {
    fn new() -> Self { Self { found: [false; 5], end: None } }
    fn finish(&mut self, end: DashboardScanEnd) {
        if self.end.is_some() { return; }
        self.end = Some(end);
        if end != DashboardScanEnd::Exhausted { self.found = [false; 5]; }
    }
    fn ready(&self) -> bool { self.end == Some(DashboardScanEnd::Exhausted) && self.found == [true; 5] }
}
// Ended scans are not continuous UI state. Masks are observed prefixes;
// an unset button bit does not distinguish absence from a disabled button.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DashboardNames { returned: u16, empty: u16, text_mask: u8 }
impl DashboardNames {
    fn new() -> Self { Self { returned: 0, empty: 0, text_mask: 0 } }
    fn observe(&mut self, name: &str) {
        // Only the existing fully successful name() return reaches this DATA.
        // No name/URL is retained. These finite text categories are not proof
        // of DOM, navigation, control type, provider readiness or finality.
        self.returned = self.returned.saturating_add(1);
        if name.is_empty() { self.empty = self.empty.saturating_add(1); return; }
        self.text_mask |= match name {
            "Mobile Release Kit" => 1,
            "about:blank" => 2,
            "http://tauri.localhost/" => 4,
            "Microsoft Edge WebView2" | "WebView2" => 8,
            "THE KIT FOR A CAREFUL LAUNCH" | "Core-managed builds are disabled" => 16,
            "DESKTOP Not loaded" => 32,
            _ if name.contains("Loading desktop capabilities and the core field catalogue") => 64,
            _ => 128,
        };
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DashboardScan { match_mask: u8, end: DashboardScanEnd, walk_visited: usize, names: DashboardNames }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DashboardProgress {
    stage: DashboardStage, any_walk_completed: bool, current_walk_visited: Option<usize>, current_match_mask: Option<u8>,
    current_names: Option<DashboardNames>, last_scan: Option<DashboardScan>, scan_history: DashboardScanHistory,
}
impl DashboardProgress {
    fn new() -> Self {
        Self { stage: DashboardStage::Bind, any_walk_completed: false, current_walk_visited: None,
            current_match_mask: None, current_names: None, last_scan: None, scan_history: DashboardScanHistory::None }
    }
    fn begin_pass(&mut self) {
        self.stage = DashboardStage::Bind; self.current_walk_visited = None; self.current_match_mask = None; self.current_names = None;
    }
    fn begin_walk(&mut self) { self.stage = DashboardStage::Walk; self.current_walk_visited = Some(0); }
    fn walk_visited(&mut self, visited: usize) { self.current_walk_visited = Some(visited); }
    fn walk_completed(&mut self) { self.any_walk_completed = true; }
    fn begin_names(&mut self) {
        self.stage = DashboardStage::Names; self.current_match_mask = Some(0); self.current_names = Some(DashboardNames::new());
    }
    fn name_returned(&mut self, name: &str) {
        if self.stage == DashboardStage::Names {
            if let Some(names) = &mut self.current_names { names.observe(name); }
        }
    }
    fn matches(&mut self, found: [bool; 5]) {
        // Cumulative observations only: the existing three headings, compiled
        // DESKTOP version, and Choose a project observed as an enabled button.
        self.current_match_mask = Some((found[0] as u8) | ((found[1] as u8) << 1) | ((found[2] as u8) << 2)
            | ((found[3] as u8) << 3) | ((found[4] as u8) << 4));
    }
    fn end_names(&mut self, end: DashboardScanEnd) {
        // A loading/stale break already ended this scan before its found reset; the
        // after-loop exhaustion observation must not replace that original end.
        if self.stage != DashboardStage::Names { return; }
        let (Some(match_mask), Some(walk_visited), Some(names)) =
            (self.current_match_mask, self.current_walk_visited, self.current_names) else { return; };
        self.stage = DashboardStage::NamesEnded; self.last_scan = Some(DashboardScan { match_mask, end, walk_visited, names });
        if end == DashboardScanEnd::Exhausted { self.scan_history = DashboardScanHistory::ExhaustedSeen; }
        else if end == DashboardScanEnd::Stale && self.scan_history != DashboardScanHistory::ExhaustedSeen {
            self.scan_history = DashboardScanHistory::StaleSeen;
        } else if self.scan_history == DashboardScanHistory::None { self.scan_history = DashboardScanHistory::LoadingOnly; }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmokeStatus { Hresult(i32), Win32(u32) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupAvailability { NotSampled, Missing, Invalid, Value }
impl StartupAvailability {
    fn label(self) -> &'static str { match self { Self::NotSampled => "not-sampled", Self::Missing => "missing",
        Self::Invalid => "invalid", Self::Value => "value" } }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupSample { availability: StartupAvailability, last: Option<(StartupWord, SmokePhase)> }
impl StartupSample {
    fn new() -> Self { Self { availability: StartupAvailability::NotSampled, last: None } }
    fn observe(&mut self, raw: u64, phase: SmokePhase) {
        self.availability = if raw == 0 { StartupAvailability::Missing }
            else if let Some(word) = StartupWord::decode(raw) { self.last = Some((word, phase)); StartupAvailability::Value }
            else { StartupAvailability::Invalid };
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuitProgress { scan: u8, visited: u8, closed: u8, match_mask: u8, default_mask: Option<u8> }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SmokeFault {
    phase: SmokePhase, check: SmokeCheck, error: Error, status: Option<SmokeStatus>, dashboard: Option<DashboardProgress>,
    main_binding_timeouts: Option<u16>, dashboard_binding_timeouts: Option<u16>, startup: StartupSample, quit: Option<QuitProgress>,
}
struct SmokeTrace {
    phase: Cell<SmokePhase>, dashboard: Cell<Option<DashboardProgress>>, first: Cell<Option<SmokeFault>>, emitted: Cell<bool>,
    main_binding_timeouts: Cell<u16>, dashboard_binding_timeouts: Cell<u16>, startup: Cell<StartupSample>, quit: Cell<Option<QuitProgress>>,
}
impl SmokeTrace {
    fn new() -> Self {
        Self { phase: Cell::new(SmokePhase::Setup), dashboard: Cell::new(None), first: Cell::new(None), emitted: Cell::new(false),
            main_binding_timeouts: Cell::new(0), dashboard_binding_timeouts: Cell::new(0), startup: Cell::new(StartupSample::new()), quit: Cell::new(None) }
    }
    // The real root() passes one USER32 read; scalar tests pass inert values.
    // Only original in-budget completions can update the sample. This helper
    // never decides root/readiness/finality and never probes after first fault.
    fn sample_startup(&self, read: impl FnOnce() -> u64, mut checkpoint: impl FnMut() -> Result<()>) -> Result<()> {
        if self.first.get().is_some() { return Ok(()); }
        self.result(SmokeCheck::Clock, checkpoint(), None)?;
        let raw = read();
        self.result(SmokeCheck::Clock, checkpoint(), None)?;
        if self.first.get().is_none() {
            let mut sample = self.startup.get(); sample.observe(raw, self.phase.get()); self.startup.set(sample);
        }
        Ok(())
    }
    fn format_startup(output: &mut impl Write, sample: StartupSample) -> std::io::Result<()> {
        write!(output, ",\"startup\":{{\"availability\":\"{}\",\"lastValid\":", sample.availability.label())?;
        match sample.last {
            None => write!(output, "null")?,
            Some((word, phase)) => write!(output,
                "{{\"previous\":{},\"samplePhase\":\"{}\",\"event\":\"{}\",\"detail\":{},\"nativeStage\":\"{}\",\"conditionMask\":{},\"firstRefusal\":{},\"liveMask\":{},\"seenMask\":{}}}",
                sample.availability != StartupAvailability::Value, phase.label(), word.event.label(), word.detail,
                word.stage.label(), word.conditions, word.first_refusal, word.live, word.seen)?,
        }
        write!(output, "}}")
    }
    fn dashboard_begin_pass(&self) {
        if self.phase.get() != SmokePhase::Dashboard { return; }
        let mut dashboard = self.dashboard.get().unwrap_or_else(DashboardProgress::new);
        dashboard.begin_pass(); self.dashboard.set(Some(dashboard));
    }
    fn dashboard_update(&self, update: impl FnOnce(&mut DashboardProgress)) {
        if self.phase.get() != SmokePhase::Dashboard { return; }
        if let Some(mut dashboard) = self.dashboard.get() { update(&mut dashboard); self.dashboard.set(Some(dashboard)); }
    }
    fn result<T>(&self, check: SmokeCheck, result: Result<T>, status: Option<SmokeStatus>) -> Result<T> {
        if let Err(error) = &result {
            if self.first.get().is_none() {
                let phase = self.phase.get();
                let dashboard = if phase == SmokePhase::Dashboard { self.dashboard.get() } else { None };
                let main_binding_timeouts = matches!(phase, SmokePhase::MainBinding | SmokePhase::Dashboard)
                    .then(|| self.main_binding_timeouts.get());
                let dashboard_binding_timeouts = (phase == SmokePhase::Dashboard).then(|| self.dashboard_binding_timeouts.get());
                let quit = if matches!(phase, SmokePhase::QuitDialog | SmokePhase::QuitInvoke) { self.quit.get() } else { None };
                self.first.set(Some(SmokeFault { phase, check, error: *error, status, dashboard,
                    main_binding_timeouts, dashboard_binding_timeouts, startup: self.startup.get(), quit }));
            }
        }
        result
    }
    fn quit_native<T>(&self, result: std::result::Result<T, crate::ui::quit_native::Failure>) -> Result<T> {
        use crate::ui::quit_native::Failure as Q;
        match result {
            Ok(value) => Ok(value),
            Err(failure) => {
                let check = match failure {
                    Q::State => SmokeCheck::QuitNativeState, Q::Bounds => SmokeCheck::QuitNativeBounds,
                    Q::Process => SmokeCheck::QuitNativeProcess, Q::Thread => SmokeCheck::QuitNativeThread,
                    Q::Descendant => SmokeCheck::QuitNativeDescendant, Q::Lineage => SmokeCheck::QuitNativeLineage,
                    Q::Style => SmokeCheck::QuitNativeStyle, Q::Changed => SmokeCheck::QuitNativeChanged,
                };
                let error = match failure { Q::State => Error::State, Q::Bounds => Error::Bounds, _ => Error::Unsafe };
                self.result(check, Err(error), None)
            }
        }
    }
    fn quit_scan_begin(&self) -> Result<()> {
        self.need(SmokeCheck::QuitTreeState, matches!(self.phase.get(), SmokePhase::QuitDialog | SmokePhase::QuitInvoke)
            && self.first.get().is_none() && self.quit.get().is_none_or(|progress| progress.scan == 1))?;
        let scan = if self.quit.get().is_none() { 1 } else { 2 };
        self.quit.set(Some(QuitProgress { scan, visited: 0, closed: 0, match_mask: 0, default_mask: None })); Ok(())
    }
    fn quit_update(&self, update: impl FnOnce(&mut QuitProgress)) {
        if !matches!(self.phase.get(), SmokePhase::QuitDialog | SmokePhase::QuitInvoke) { return; }
        if let Some(mut progress) = self.quit.get() { update(&mut progress); self.quit.set(Some(progress)); }
    }
    fn need(&self, check: SmokeCheck, value: bool) -> Result<()> { self.result(check, need(value), None) }
    fn initial_main_timeout(&self) -> Result<()> {
        let count = self.result(SmokeCheck::InitialMainTimeoutCount,
            self.main_binding_timeouts.get().checked_add(1).ok_or(Error::Bounds), None)?;
        self.main_binding_timeouts.set(count); Ok(())
    }
    fn dashboard_binding_timeout(&self) -> Result<()> {
        let count = self.result(SmokeCheck::DashboardBindingTimeoutCount,
            self.dashboard_binding_timeouts.get().checked_add(1).ok_or(Error::Bounds), None)?;
        self.dashboard_binding_timeouts.set(count); Ok(())
    }
    fn admit_com(&self, unknown: bool, settled: bool, originals: usize, remaining: impl FnOnce() -> Result<u32>) -> Result<()> {
        self.need(SmokeCheck::ComReserveState, !unknown && !settled)?;
        self.need(SmokeCheck::ComReserveCapacity, originals < 2048)?;
        self.need(SmokeCheck::ComReserveBudget, self.result(SmokeCheck::Clock, remaining(), None)? > 1000)
    }
    fn format_names(output: &mut impl Write, names: Option<DashboardNames>) -> std::io::Result<()> {
        match names {
            Some(names) => write!(output, "{{\"returned\":{},\"empty\":{},\"textMask\":{}}}", names.returned, names.empty, names.text_mask),
            None => write!(output, "null"),
        }
    }
    fn format(fault: SmokeFault, raw: &mut [u8]) -> std::io::Result<usize> {
        let mut output = std::io::Cursor::new(raw);
        let error = match fault.error {
            Error::Unavailable => "unavailable", Error::Unsafe => "unsafe", Error::Bounds => "bounds",
            Error::State => "state", Error::Unknown => "unknown",
        };
        write!(output, "MRK_WINDOWS_NORMAL_UI_SMOKE_REFUSED={{\"diagnosticOnly\":true,\"phase\":\"{}\",\"check\":\"{}\",\"error\":\"{error}\",\"nativeStatus\":",
            fault.phase.label(), fault.check.label())?;
        match fault.status {
            Some(SmokeStatus::Hresult(code)) => write!(output, "{{\"domain\":\"hresult\",\"code\":{code}}}")?,
            Some(SmokeStatus::Win32(code)) => write!(output, "{{\"domain\":\"win32\",\"code\":{code}}}")?,
            None => write!(output, "null")?,
        }
        write!(output, ",\"dashboard\":")?;
        match fault.dashboard {
            Some(progress) => {
                write!(output, "{{\"stage\":\"{}\",\"anyWalkCompleted\":{},\"currentWalkVisited\":",
                    progress.stage.label(), progress.any_walk_completed)?;
                match progress.current_walk_visited { Some(count) => write!(output, "{count}")?, None => write!(output, "null")? }
                write!(output, ",\"currentMatchMask\":")?;
                match progress.current_match_mask { Some(mask) => write!(output, "{mask}")?, None => write!(output, "null")? }
                write!(output, ",\"currentNames\":")?;
                Self::format_names(&mut output, progress.current_names)?;
                write!(output, ",\"lastScan\":")?;
                match progress.last_scan {
                    Some(scan) => {
                        write!(output, "{{\"matchMask\":{},\"end\":\"{}\",\"walkVisited\":{},\"names\":",
                            scan.match_mask, scan.end.label(), scan.walk_visited)?;
                        Self::format_names(&mut output, Some(scan.names))?;
                        write!(output, "}}")?;
                    },
                    None => write!(output, "null")?,
                }
                write!(output, ",\"scanHistory\":\"{}\"}}", progress.scan_history.label())?;
            }
            None => write!(output, "null")?,
        }
        if let Some(count) = fault.main_binding_timeouts { write!(output, ",\"mainBindingTimeouts\":{count}")?; }
        if let Some(count) = fault.dashboard_binding_timeouts { write!(output, ",\"dashboardBindingTimeouts\":{count}")?; }
        if let Some(progress) = fault.quit {
            write!(output, ",\"quit\":{{\"scan\":{},\"visited\":{},\"closed\":{},\"matchMask\":{},\"defaultMask\":",
                progress.scan, progress.visited, progress.closed, progress.match_mask)?;
            match progress.default_mask { Some(mask) => write!(output, "{mask}")?, None => write!(output, "null")? }
            write!(output, "}}")?;
        }
        Self::format_startup(&mut output, fault.startup)?;
        writeln!(output, "}}")?; Ok(output.position() as usize)
    }
    fn emit_to(&self, output: &mut impl Write) -> std::io::Result<Option<usize>> {
        self.emit_with_buffer(output, &mut [0u8; 1024])
    }
    fn emit_with_buffer(&self, output: &mut impl Write, raw: &mut [u8]) -> std::io::Result<Option<usize>> {
        let Some(fault) = self.first.get() else { return Ok(None); };
        if self.emitted.replace(true) { return Ok(None); }
        let bytes: &[u8] = match Self::format(fault, raw) {
            Ok(size) => &raw[..size],
            Err(_) => b"MRK_WINDOWS_NORMAL_UI_SMOKE_REFUSED={\"diagnosticOnly\":true,\"diagnosticIncomplete\":true}\n",
        };
        // Exactly one best-effort write. Short/error output is not a receipt,
        // does not retry, and cannot change the original operation's result.
        output.write(bytes).map(Some)
    }
    fn emit(&self) {
        if self.first.get().is_some() && !self.emitted.get() { let _ = self.emit_to(&mut std::io::stdout().lock()); }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ComKind { Client, Walker, Element, Invoke, Legacy }
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
    integer: i32, boolean: windows::core::BOOL, hwnd: HWND, control: A::UIA_CONTROLTYPE_ID, legacy_state: u32,
    lower: i32, upper: i32, index: i32, dimensions: u32, element_size: u32, variant: u16,
    values: [i32; 16], destroy_entered: bool, destroy_return: i32,
}
impl UiQuery {
    fn new() -> Self {
        Self { active: false, unknown: false, status: HRESULT_PENDING, bstr: null_mut(), array: null_mut(),
            integer: 0, boolean: windows::core::BOOL(0), hwnd: HWND(null_mut()), control: A::UIA_CONTROLTYPE_ID(0), legacy_state: u32::MAX,
            lower: 0, upper: -1, index: 0, dimensions: 0, element_size: 0, variant: 0, values: [0; 16],
            destroy_entered: false, destroy_return: HRESULT_PENDING }
    }
    fn begin(&mut self, clock: &mut Clock, trace: &SmokeTrace) -> Result<()> {
        self.begin_with_remaining(|| clock.remaining_ms(), trace)
    }
    fn begin_with_remaining(&mut self, remaining: impl FnOnce() -> Result<u32>, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::QueryState, !self.active && !self.unknown)?;
        // The client transaction timeout is 1000ms. Refuse a new provider call
        // unless it fits under the original endpoint; never reset that clock.
        trace.need(SmokeCheck::QueryBudget, trace.result(SmokeCheck::Clock, remaining(), None)? > 1000)?;
        self.active = true; self.status = HRESULT_PENDING; Ok(())
    }
    fn returned(&mut self, status: i32, clock: &mut Clock, trace: &SmokeTrace, check: SmokeCheck) -> Result<()> {
        self.status = status;
        if status == HRESULT_PENDING {
            self.unknown = true; return trace.result(check, Err(Error::Unknown), Some(SmokeStatus::Hresult(status)));
        }
        self.active = false;
        trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        trace.result(check, need(status == 0), Some(SmokeStatus::Hresult(status)))
    }
    fn settle(&mut self, trace: &SmokeTrace) -> Result<()> {
        if self.active || self.unknown { return trace.result(SmokeCheck::QueryPending, Err(Error::Unknown), None); }
        if !self.bstr.is_null() {
            self.active = true; unsafe { F::SysFreeString(self.bstr.cast()) };
            self.bstr = null_mut(); self.active = false;
        }
        if !self.array.is_null() {
            if self.destroy_entered {
                self.unknown = true; return trace.result(SmokeCheck::ArrayDestroyState, Err(Error::Unknown), None);
            }
            self.destroy_entered = true; self.active = true;
            self.destroy_return = unsafe { OLE::SafeArrayDestroy(self.array) };
            if self.destroy_return != 0 {
                self.unknown = true;
                return trace.result(SmokeCheck::ArrayDestroy, Err(Error::Unknown), Some(SmokeStatus::Hresult(self.destroy_return)));
            }
            self.array = null_mut(); self.active = false;
        }
        Ok(())
    }
}
struct WindowData {
    hwnd: F::HWND, owner: F::HWND, pid: u32, tid: u32, title: [u16; 256], length: i32,
    owner_error: Option<u32>, title_error: Option<u32>,
}
impl WindowData {
    fn new() -> Self {
        Self { hwnd: null_mut(), owner: null_mut(), pid: 0, tid: 0, title: [0; 256], length: 0,
            owner_error: None, title_error: None }
    }
    fn ownerless(&self, trace: &SmokeTrace) -> Result<bool> {
        let error = trace.result(SmokeCheck::WindowOwnerRead, self.owner_error.ok_or(Error::State), None)?;
        trace.result(SmokeCheck::WindowOwnerRead, need(error == 0), Some(SmokeStatus::Win32(error)))?;
        Ok(self.owner.is_null())
    }
    fn title(&self, trace: &SmokeTrace) -> Result<String> {
        let error = trace.result(SmokeCheck::WindowTitleRead, self.title_error.ok_or(Error::State), None)?;
        trace.result(SmokeCheck::WindowTitleRead, need(error == 0), Some(SmokeStatus::Win32(error)))?;
        trace.need(SmokeCheck::WindowTitleLength, self.length >= 0 && (self.length as usize) < self.title.len() - 1)?;
        trace.result(SmokeCheck::WindowTitleEncoding,
            String::from_utf16(&self.title[..self.length as usize]).map_err(|_| Error::Unsafe), None)
    }
}
struct WindowQuery {
    entries: [WindowData; 32], count: usize, overflow: bool, active: bool, returned: i32, error: u32,
    identity_pid: u32, identity_tid: u32, thread_pid: u32, wait: u32,
    class: [u16; 256], class_length: i32,
    post_entered: bool, post_return: i32, post_error: u32,
}
unsafe extern "system" fn thread_window(hwnd: F::HWND, raw: isize) -> i32 {
    // EnumThreadWindows synchronously borrows this one registered stable output.
    let query = unsafe { &mut *(raw as *mut WindowQuery) };
    if unsafe { W::IsWindowVisible(hwnd) } == 0 { return 1; }
    if query.count >= query.entries.len() { query.overflow = true; return 0; }
    let entry = &mut query.entries[query.count]; query.count += 1;
    entry.hwnd = hwnd;
    // NULL/zero may be a successful no-owner/empty-title observation. Retain
    // the error of this exact original call before another API can replace it.
    unsafe { F::SetLastError(F::ERROR_SUCCESS) };
    entry.owner = unsafe { W::GetWindow(hwnd, W::GW_OWNER) };
    entry.owner_error = Some(if entry.owner.is_null() { unsafe { F::GetLastError() } } else { 0 });
    entry.tid = unsafe { W::GetWindowThreadProcessId(hwnd, &mut entry.pid) };
    unsafe { F::SetLastError(F::ERROR_SUCCESS) };
    entry.length = unsafe { W::GetWindowTextW(hwnd, entry.title.as_mut_ptr(), entry.title.len() as i32) };
    entry.title_error = Some(if entry.length == 0 { unsafe { F::GetLastError() } } else { 0 });
    1
}
impl WindowQuery {
    fn new() -> Self {
        Self { entries: std::array::from_fn(|_| WindowData::new()), count: 0, overflow: false, active: false,
            returned: 0, error: 0, identity_pid: 0, identity_tid: 0, thread_pid: 0, wait: u32::MAX,
            class: [0; 256], class_length: 0,
            post_entered: false, post_return: 0, post_error: 0 }
    }
    fn original_live(&mut self, launch: &Launch, clock: &mut Clock, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::ProcessState, launch.facts.created && !launch.facts.failed && !launch.facts.unknown
            && launch.facts.process == SlotState::Owned && launch.facts.thread == SlotState::Owned)?;
        trace.result(SmokeCheck::Clock, clock.effect(), None)?; self.identity_pid = unsafe { T::GetProcessId(launch.outputs.hProcess) };
        self.identity_tid = unsafe { T::GetThreadId(launch.outputs.hThread) };
        self.thread_pid = unsafe { T::GetProcessIdOfThread(launch.outputs.hThread) };
        trace.need(SmokeCheck::ProcessIdentity, self.identity_pid == launch.outputs.dwProcessId && self.thread_pid == launch.outputs.dwProcessId
            && self.identity_tid == launch.outputs.dwThreadId)?;
        self.wait = unsafe { T::WaitForSingleObject(launch.outputs.hProcess, 0) };
        trace.result(SmokeCheck::Clock, clock.effect(), None)?; trace.need(SmokeCheck::ProcessLive, self.wait == F::WAIT_TIMEOUT)
    }
    fn scan(&mut self, launch: &Launch, clock: &mut Clock, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::WindowQueryIdle, !self.active)?; self.original_live(launch, clock, trace)?;
        self.count = 0; self.overflow = false;
        for entry in &mut self.entries { *entry = WindowData::new(); }
        self.active = true;
        self.returned = unsafe { W::EnumThreadWindows(launch.outputs.dwThreadId, Some(thread_window), self as *mut Self as isize) };
        self.error = if self.returned != 0 { 0 } else { unsafe { F::GetLastError() } };
        self.active = false; trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        trace.result(if self.overflow { SmokeCheck::WindowOverflow } else { SmokeCheck::WindowEnumeration },
            need(self.returned != 0 && !self.overflow), if self.overflow { None } else { Some(SmokeStatus::Win32(self.error)) })?;
        trace.need(SmokeCheck::WindowIdentity, self.entries[..self.count].iter().all(|entry|
            entry.pid == launch.outputs.dwProcessId && entry.tid == launch.outputs.dwThreadId))
    }
    fn root(&mut self, launch: &Launch, main: Option<F::HWND>, clock: &mut Clock, trace: &SmokeTrace) -> Result<Option<F::HWND>> {
        self.scan(launch, clock, trace)?;
        let selected = self.select_root(main, trace)?;
        if let Some(hwnd) = selected {
            // Selection stays DATA-only; this is the exact already-checked
            // original process/thread/root, not an enumerated auxiliary HWND.
            trace.sample_startup(|| crate::ui::startup_property(hwnd), || clock.effect())?;
        }
        Ok(selected)
    }
    // DATA selection only, after the original live process/thread and complete
    // bounded scan have been checked. Framework event windows can be visible
    // and ownerless without being main candidates; never choose the first match.
    fn select_root(&self, main: Option<F::HWND>, trace: &SmokeTrace) -> Result<Option<F::HWND>> {
        let mut found = None;
        for entry in &self.entries[..self.count] {
            if entry.ownerless(trace)? && entry.title(trace)? == "Mobile Release Kit" {
                trace.need(SmokeCheck::RootUniqueness, found.is_none())?;
                found = Some(entry.hwnd);
            }
        }
        if let Some(main) = main { trace.need(SmokeCheck::RootContinuity, found == Some(main))?; }
        Ok(found)
    }
}

const QUIT_NODES: usize = 65; // The admitted root plus at most 64 descendants.
const QUIT_DEPTH: usize = 32;
#[derive(Clone, Debug, Eq, PartialEq)]
struct QuitIdentity { runtime: Vec<i32>, process: u32 }
#[derive(Clone, Debug, Eq, PartialEq)]
struct QuitNode {
    element: usize, parent: Option<usize>, parent_probe: Option<usize>, previous: Option<usize>, depth: usize,
    identity: QuitIdentity, name: String, control: i32,
}
#[derive(Clone)]
struct QuitTree { nodes: Vec<QuitNode>, closed: usize }
impl QuitTree {
    fn new() -> Self { Self { nodes: Vec::with_capacity(QUIT_NODES), closed: 0 } }
    fn node(&self, index: usize, trace: &SmokeTrace) -> Result<&QuitNode> {
        trace.result(SmokeCheck::QuitTreeState, self.nodes.get(index).ok_or(Error::State), None)
    }
    fn push(&mut self, node: QuitNode, process: u32, trace: &SmokeTrace) -> Result<usize> {
        trace.result(SmokeCheck::QuitTreeBounds,
            if self.nodes.len() < QUIT_NODES && node.depth <= QUIT_DEPTH { Ok(()) } else { Err(Error::Bounds) }, None)?;
        trace.need(SmokeCheck::QuitRuntime, (2..=16).contains(&node.identity.runtime.len())
            && !self.nodes.iter().any(|old| old.identity.runtime == node.identity.runtime || old.element == node.element))?;
        trace.need(SmokeCheck::QuitProcess, process != 0 && node.identity.process == process)?;
        if self.nodes.is_empty() {
            trace.need(SmokeCheck::QuitLineage, node.parent.is_none() && node.parent_probe.is_none() && node.previous.is_none() && node.depth == 0 && self.closed == 0)?;
        } else {
            let parent = trace.result(SmokeCheck::QuitLineage, node.parent.ok_or(Error::Unsafe), None)?;
            let original = self.node(parent, trace)?;
            trace.need(SmokeCheck::QuitLineage, parent == self.closed && node.parent_probe.is_some() && node.depth == original.depth + 1
                && node.previous == self.nodes.iter().rposition(|old| old.parent == Some(parent)))?;
        }
        let index = self.nodes.len(); self.nodes.push(node);
        trace.quit_update(|progress| {
            progress.visited = self.nodes.len() as u8;
            let node = &self.nodes[index];
            if node.control == A::UIA_ButtonControlTypeId.0 {
                progress.match_mask |= match node.name.as_str() { "OK" => 1, "Cancel" => 2, _ => 0 };
            }
        });
        Ok(index)
    }
    fn close_parent(&mut self, parent: usize, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::QuitTreeState, parent == self.closed && parent < self.nodes.len())?;
        self.closed += 1; trace.quit_update(|progress| progress.closed = self.closed as u8); Ok(())
    }
    fn select(&self, trace: &SmokeTrace) -> Result<[usize; 2]> {
        trace.need(SmokeCheck::QuitTreeIncomplete, !self.nodes.is_empty() && self.closed == self.nodes.len())?;
        let mut selected = [None, None]; let mut instruction = false;
        for (index, node) in self.nodes.iter().enumerate() {
            instruction |= node.name == "Quit and discard unsaved drafts?";
            if node.control != A::UIA_ButtonControlTypeId.0 { continue; }
            let slot = match node.name.as_str() { "OK" => 0, "Cancel" => 1, _ => continue };
            // Count every matching Button before checking enabled/offscreen.
            // A disabled duplicate still makes the complete pair ambiguous.
            trace.need(SmokeCheck::QuitButtonsDuplicate, selected[slot].is_none())?; selected[slot] = Some(index);
        }
        trace.need(SmokeCheck::QuitInstruction, instruction)?;
        let ok = trace.result(SmokeCheck::QuitOkMissing, selected[0].ok_or(Error::Unsafe), None)?;
        let cancel = trace.result(SmokeCheck::QuitCancelMissing, selected[1].ok_or(Error::Unsafe), None)?;
        trace.need(SmokeCheck::QuitRuntime, ok != 0 && cancel != 0 && ok != cancel)?;
        Ok([ok, cancel])
    }
    fn chain(&self, selected: usize, process: u32, trace: &SmokeTrace) -> Result<Vec<usize>> {
        let leaf = self.node(selected, trace)?;
        trace.need(SmokeCheck::QuitLineage, selected != 0 && leaf.depth > 0 && leaf.depth <= QUIT_DEPTH)?;
        let mut chain = Vec::with_capacity(leaf.depth); let mut at = selected;
        while at != 0 {
            trace.result(SmokeCheck::QuitTreeBounds,
                if chain.len() < QUIT_DEPTH { Ok(()) } else { Err(Error::Bounds) }, None)?;
            let node = self.node(at, trace)?;
            trace.need(SmokeCheck::QuitProcess, process != 0 && node.identity.process == process)?;
            let parent = trace.result(SmokeCheck::QuitLineage, node.parent.ok_or(Error::Unsafe), None)?;
            trace.need(SmokeCheck::QuitLineage, parent < at && !chain.contains(&parent))?;
            let original = self.node(parent, trace)?;
            trace.need(SmokeCheck::QuitLineage, node.depth == original.depth + 1)?;
            trace.need(SmokeCheck::QuitRuntime, original.identity.runtime != leaf.identity.runtime
                && !chain.iter().any(|old| self.nodes[*old].identity.runtime == original.identity.runtime))?;
            chain.push(parent); at = parent;
        }
        let root = self.node(0, trace)?;
        trace.need(SmokeCheck::QuitLineage, root.parent.is_none() && root.depth == 0 && chain.len() == leaf.depth)?;
        trace.need(SmokeCheck::QuitProcess, root.identity.process == process)?;
        Ok(chain)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct QuitControlFacts {
    identity: QuitIdentity, name: String, control: i32, enabled: bool, offscreen: bool,
    native: crate::ui::quit_native::Container, ancestors: Vec<QuitIdentity>,
}
impl QuitControlFacts {
    fn valid(&self, expected_name: &str, root: &QuitIdentity, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::QuitButtonType, self.name == expected_name && self.control == A::UIA_ButtonControlTypeId.0)?;
        trace.need(SmokeCheck::QuitRuntime, self.identity.runtime != root.runtime && (2..=16).contains(&self.identity.runtime.len()))?;
        trace.need(SmokeCheck::QuitProcess, root.process != 0 && self.identity.process == root.process
            && self.ancestors.iter().all(|ancestor| ancestor.process == root.process))?;
        trace.need(SmokeCheck::QuitLineage, !self.ancestors.is_empty() && self.ancestors.len() <= QUIT_DEPTH
            && self.ancestors.last() == Some(root))?;
        for (index, ancestor) in self.ancestors.iter().enumerate() {
            trace.need(SmokeCheck::QuitRuntime, (2..=16).contains(&ancestor.runtime.len())
                && ancestor.runtime != self.identity.runtime
                && !self.ancestors[..index].iter().any(|old| old.runtime == ancestor.runtime))?;
        }
        trace.need(SmokeCheck::QuitButtonEnabled, self.enabled)?;
        trace.need(SmokeCheck::QuitButtonVisibility, !self.offscreen)
    }
    fn same(&self, current: &Self, trace: &SmokeTrace) -> Result<()> {
        trace.quit_native(self.native.same(&current.native))?;
        trace.need(SmokeCheck::QuitButtonsChanged, self.identity == current.identity && self.name == current.name
            && self.control == current.control && self.enabled == current.enabled && self.offscreen == current.offscreen
            && self.ancestors == current.ancestors)
    }
}
fn quit_controls_valid(controls: &[QuitControlFacts; 2], root: &QuitIdentity, trace: &SmokeTrace) -> Result<()> {
    controls[0].valid("OK", root, trace)?; controls[1].valid("Cancel", root, trace)?;
    trace.need(SmokeCheck::QuitRuntime, controls[0].identity.runtime != controls[1].identity.runtime)
}
struct QuitScan {
    tree: QuitTree, selected: [usize; 2], controls: [QuitControlFacts; 2],
    parent_probes: [Vec<usize>; 2],
}
impl QuitScan {
    fn elements(&self, trace: &SmokeTrace) -> Result<[usize; 2]> {
        Ok([self.tree.node(self.selected[0], trace)?.element, self.tree.node(self.selected[1], trace)?.element])
    }
    fn same(&self, current: &Self, trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::QuitBinding, self.tree.node(0, trace)?.identity == current.tree.node(0, trace)?.identity)?;
        for index in 0..2 { self.controls[index].same(&current.controls[index], trace)?; }
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct QuitPattern { element: usize, original: usize }
#[derive(Clone, Copy)]
struct QuitPatterns { elements: [usize; 2], legacy: [QuitPattern; 2], invoke: QuitPattern }
impl QuitPatterns {
    fn valid(&self, expected: [usize; 2], trace: &SmokeTrace) -> Result<()> {
        trace.need(SmokeCheck::QuitPatterns, self.elements == expected && expected[0] != expected[1]
            && self.legacy[0].element == expected[0] && self.legacy[1].element == expected[1] && self.invoke.element == expected[0])?;
        let slots = [self.legacy[0].original, self.legacy[1].original, self.invoke.original];
        trace.need(SmokeCheck::QuitPatterns, slots.iter().enumerate().all(|(index, original)|
            !expected.contains(original) && !slots[..index].contains(original)))
    }
}
fn quit_default_states(states: [u32; 2], trace: &SmokeTrace) -> Result<()> {
    // Generated Controls flags are a u32 alias; DEFAULT lives in W. Both
    // namespaces are already enabled, and no Common Controls call is made.
    use windows_sys::Win32::UI::Controls as C;
    let mask = u8::from(states[0] & W::STATE_SYSTEM_DEFAULT != 0) | (u8::from(states[1] & W::STATE_SYSTEM_DEFAULT != 0) << 1);
    trace.quit_update(|progress| progress.default_mask = Some(mask));
    let contradictory = C::STATE_SYSTEM_UNAVAILABLE | C::STATE_SYSTEM_INVISIBLE | C::STATE_SYSTEM_OFFSCREEN;
    trace.need(SmokeCheck::QuitDefaultState, states.iter().all(|state| *state != u32::MAX && *state & contradictory == 0))?;
    trace.need(SmokeCheck::QuitDefault, mask == 2)
}

fn quit_same_defaults(original: [u32; 2], current: [u32; 2], trace: &SmokeTrace) -> Result<()> {
    quit_default_states(current, trace)?; trace.need(SmokeCheck::QuitLegacyChanged, current == original)
}

struct Smoke {
    trace: SmokeTrace,
    initialized: bool, init_entered: bool, init_return: i32, uninit_entered: bool, uninit_returned: bool,
    originals: Vec<Box<ComOriginal>>, query: Box<UiQuery>, windows: Box<WindowQuery>,
    client: Option<usize>, walker: Option<usize>, main: Option<(F::HWND, usize, Vec<i32>)>,
    invoke_entered: bool, invoke_return: i32, dashboard_ready: bool, quit_confirmed: bool,
    unknown: bool, settled: bool, _thread: PhantomData<std::rc::Rc<()>>,
}
impl Smoke {
    fn new() -> Self {
        Self { trace: SmokeTrace::new(), initialized: false, init_entered: false, init_return: HRESULT_PENDING, uninit_entered: false,
            uninit_returned: false, originals: Vec::with_capacity(2048), query: Box::new(UiQuery::new()),
            windows: Box::new(WindowQuery::new()), client: None, walker: None, main: None,
            invoke_entered: false, invoke_return: HRESULT_PENDING, dashboard_ready: false, quit_confirmed: false,
            unknown: false, settled: false, _thread: PhantomData }
    }
    fn reserve(&mut self, kind: ComKind, clock: &mut Clock) -> Result<usize> {
        // Same state/capacity/clock order, one existing clock observation, and
        // no original allocation until all three admission predicates succeed.
        self.trace.admit_com(self.unknown, self.settled, self.originals.len(), || clock.remaining_ms())?;
        let index = self.originals.len(); self.originals.push(Box::new(ComOriginal::new(kind))); Ok(index)
    }
    fn pointer(&self, index: usize, kind: ComKind) -> Result<*mut c_void> {
        let original = self.trace.result(SmokeCheck::ComIndex, self.originals.get(index).ok_or(Error::State), None)?;
        self.trace.need(SmokeCheck::ComState, original.kind == kind && original.state == SlotState::Owned && !original.active)?;
        Ok(original.pointer)
    }
    fn client(&self) -> Result<(*mut c_void, &A::IUIAutomation2_Vtbl)> {
        let pointer = self.pointer(self.trace.result(SmokeCheck::ClientMissing, self.client.ok_or(Error::State), None)?, ComKind::Client)?;
        Ok((pointer, unsafe { &**pointer.cast::<*const A::IUIAutomation2_Vtbl>() }))
    }
    fn acquire_return(&mut self, index: usize, status: i32, nullable: bool, clock: &mut Clock, check: SmokeCheck) -> Result<bool> {
        let result = self.originals[index].returned(status, nullable);
        self.unknown |= matches!(result, Err(Error::Unknown));
        // Record the produced refusal without moving its return before the
        // existing clock. A later clock error still has the same precedence.
        let result = self.trace.result(check, result, Some(SmokeStatus::Hresult(status)));
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; result
    }
    fn setup(&mut self, clock: &mut Clock) -> Result<()> {
        self.trace.need(SmokeCheck::InitializeOnce, !self.init_entered)?;
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; self.init_entered = true;
        self.init_return = unsafe { CO::CoInitializeEx(null(), CO::COINIT_MULTITHREADED as u32) };
        if self.init_return == HRESULT_PENDING {
            self.unknown = true;
            return self.trace.result(SmokeCheck::Initialize, Err(Error::Unknown), Some(SmokeStatus::Hresult(self.init_return)));
        }
        self.initialized = matches!(self.init_return, 0 | 1);
        self.trace.result(SmokeCheck::Initialize, need(self.initialized), Some(SmokeStatus::Hresult(self.init_return)))?;
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        let index = self.reserve(ComKind::Client, clock)?;
        let output = self.trace.result(SmokeCheck::ClientAcquireState, self.originals[index].begin(), None)?;
        let status = unsafe { CO::CoCreateInstance((&A::CUIAutomation8 as *const windows::core::GUID).cast(), null_mut(),
            CO::CLSCTX_INPROC_SERVER, (&A::IUIAutomation2::IID as *const windows::core::GUID).cast(), output) };
        self.acquire_return(index, status, false, clock, SmokeCheck::ClientAcquire)?; self.client = Some(index);
        let pointer = self.pointer(index, ComKind::Client)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomation2_Vtbl>() };
        for (setter, check) in [(table.SetConnectionTimeout, SmokeCheck::ConnectionTimeout),
            (table.SetTransactionTimeout, SmokeCheck::TransactionTimeout)] {
            self.query.begin(clock, &self.trace)?;
            let status = unsafe { setter(pointer, 1000) }.0;
            self.query.returned(status, clock, &self.trace, check)?;
        }
        let index = self.reserve(ComKind::Walker, clock)?;
        let output = self.trace.result(SmokeCheck::WalkerAcquireState, self.originals[index].begin(), None)?;
        let status = unsafe { (table.base__.RawViewWalker)(pointer, output) }.0;
        self.acquire_return(index, status, false, clock, SmokeCheck::WalkerAcquire)?; self.walker = Some(index); Ok(())
    }
    fn from_window(&mut self, hwnd: F::HWND, clock: &mut Clock) -> Result<usize> {
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.trace.result(SmokeCheck::ElementAcquireState, self.originals[index].begin(), None)?;
        let (pointer, table) = self.client()?;
        let status = unsafe { (table.base__.ElementFromHandle)(pointer, HWND(hwnd), output) }.0;
        self.acquire_return(index, status, false, clock, SmokeCheck::ElementFromWindow)?; Ok(index)
    }
    fn initial_main_admitted(&self) -> bool {
        self.trace.phase.get() == SmokePhase::MainBinding && self.main.is_none()
            && self.trace.first.get().is_none() && !self.unknown && !self.settled
    }
    fn initial_main_timeout_status(status: i32) -> bool {
        // Only a completed, returned-NULL initial main lookup may consume
        // either documented timeout representation. This is not a COM retry policy.
        status == A::UIA_E_TIMEOUT as i32
            || status == windows::core::HRESULT::from_win32(F::ERROR_TIMEOUT).0
    }
    fn retire_initial_main_tail(&mut self, index: usize) -> Result<()> {
        self.trace.need(SmokeCheck::InitialMainTail, self.initial_main_admitted()
            && index.checked_add(1) == Some(self.originals.len())
            && self.client.is_none_or(|original| original < index) && self.walker.is_none_or(|original| original < index)
            && self.originals.get(index).is_some_and(|original| original.kind == ComKind::Element
                && original.state == SlotState::NoHandle && !original.active && original.pointer.is_null()
                && Self::initial_main_timeout_status(original.status)))?;
        // Only this completed, returned-NULL tail has no reference to release.
        // Existing accounting must accept it before its storage is discarded.
        self.release_suffix(index)
    }
    fn complete_initial_main(&mut self, index: usize, status: i32,
        after_return_clock: impl FnOnce() -> Result<()>) -> Result<Option<usize>> {
        let admitted = self.initial_main_admitted();
        let original = &mut self.originals[index];
        let acquiring = original.kind == ComKind::Element && original.state == SlotState::Acquiring && original.active;
        let result = original.returned(status, false);
        self.unknown |= matches!(result, Err(Error::Unknown));
        let pending = admitted && acquiring && result == Err(Error::Unsafe) && Self::initial_main_timeout_status(status)
            && original.state == SlotState::NoHandle && !original.active && original.pointer.is_null();
        let result = if pending {
            // Record this observed timeout BEFORE a possible post-call clock
            // refusal snapshots the first fault. Never clear a fatal latch.
            self.trace.initial_main_timeout().map(|()| None)
        } else {
            self.trace.result(SmokeCheck::ElementFromWindow, result.and_then(|present| {
                need(admitted && acquiring && present)?; Ok(Some(index))
            }), Some(SmokeStatus::Hresult(status)))
        };
        self.trace.result(SmokeCheck::Clock, after_return_clock(), None)?;
        let result = result?;
        if result.is_none() { self.retire_initial_main_tail(index)?; }
        Ok(result)
    }
    fn initial_main_from_window(&mut self, hwnd: F::HWND, clock: &mut Clock) -> Result<Option<usize>> {
        self.trace.need(SmokeCheck::InitialMainState, self.initial_main_admitted())?;
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.trace.result(SmokeCheck::ElementAcquireState, self.originals[index].begin(), None)?;
        let (pointer, table) = self.client()?;
        let status = unsafe { (table.base__.ElementFromHandle)(pointer, HWND(hwnd), output) }.0;
        // This is only the first read-only main binding, not a generic UIA
        // retry policy. Other property/dialog/walk/Invoke failures remain terminal.
        self.complete_initial_main(index, status, || clock.effect())
    }
    fn adjacent(&mut self, element: usize, child: bool, clock: &mut Clock) -> Result<Option<usize>> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let walker = self.pointer(self.trace.result(SmokeCheck::WalkerMissing, self.walker.ok_or(Error::State), None)?, ComKind::Walker)?;
        let table = unsafe { &**walker.cast::<*const A::IUIAutomationTreeWalker_Vtbl>() };
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.trace.result(SmokeCheck::AdjacentAcquireState, self.originals[index].begin(), None)?;
        let status = unsafe { (if child { table.GetFirstChildElement } else { table.GetNextSiblingElement })(walker, pointer, output) }.0;
        Ok(self.acquire_return(index, status, true, clock,
            if child { SmokeCheck::FirstChild } else { SmokeCheck::NextSibling })?.then_some(index))
    }
    fn query_name(&mut self, element: usize, clock: &mut Clock) -> Result<i32> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.trace.need(SmokeCheck::NameOutputState, self.query.bstr.is_null())?; self.query.begin(clock, &self.trace)?;
        Ok(unsafe { (table.CurrentName)(pointer, &mut self.query.bstr) }.0)
    }
    fn finish_name(&mut self, status: i32, clock: &mut Clock) -> Result<String> {
        if status != 0 && !self.query.bstr.is_null() {
            self.query.unknown = true;
            return self.trace.result(SmokeCheck::NameContradiction, Err(Error::Unknown), Some(SmokeStatus::Hresult(status)));
        }
        self.query.returned(status, clock, &self.trace, SmokeCheck::CurrentName)?;
        let length = unsafe { F::SysStringLen(self.query.bstr.cast()) } as usize;
        self.trace.need(SmokeCheck::NameLength, length <= 1024)?;
        let text = if length == 0 { Ok(String::new()) } else {
            String::from_utf16(unsafe { std::slice::from_raw_parts(self.query.bstr.cast::<u16>(), length) }).map_err(|_| Error::Unsafe)
        };
        // Conversion already returned, but its Result still follows the same
        // query settlement and clock checks. Neither may replace its first fault.
        let text = self.trace.result(SmokeCheck::NameEncoding, text, None);
        self.query.settle(&self.trace)?; self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; text
    }
    fn name(&mut self, element: usize, clock: &mut Clock) -> Result<String> {
        let status = self.query_name(element, clock)?; self.finish_name(status, clock)
    }
    fn dashboard_name_admitted(&self, element: usize, keep: usize) -> bool {
        let (Some((hwnd, main, id)), Some(client), Some(walker)) =
            (self.main.as_ref(), self.client, self.walker) else { return false; };
        self.trace.phase.get() == SmokePhase::Dashboard
            && self.trace.dashboard.get().is_some_and(|progress| progress.stage == DashboardStage::Names)
            && !hwnd.is_null() && !id.is_empty() && *main < keep && client < keep && walker < keep
            && client != walker && client != *main && walker != *main
            && self.initialized && !self.uninit_entered && !self.uninit_returned
            && self.trace.first.get().is_none() && !self.unknown && !self.settled && !self.windows.active
            && !self.dashboard_ready && !self.quit_confirmed && !self.windows.post_entered && !self.invoke_entered
            // This sole caller's cutoff retains exactly the acquired client,
            // walker and adopted main. A phase/history alone is not a lease.
            && self.originals.get(..keep).is_some_and(|prefix| prefix.iter().enumerate().all(|(index, original)| {
                let kind = if index == client { Some(ComKind::Client) } else if index == walker { Some(ComKind::Walker) }
                    else if index == *main { Some(ComKind::Element) } else { None };
                kind == Some(original.kind) && original.state == SlotState::Owned && !original.active
                    && !original.pointer.is_null() && original.status == 0
            }))
            && element >= keep && self.originals.get(element).is_some_and(|original|
                original.kind == ComKind::Element && original.state == SlotState::Owned && !original.active
                    && !original.pointer.is_null() && original.status == 0)
    }
    fn complete_dashboard_name_stale(&mut self, element: usize, keep: usize, status: i32,
        after_return_clock: impl FnOnce() -> Result<()>) -> Result<bool> {
        if status != A::UIA_E_ELEMENTNOTAVAILABLE as i32 || !self.dashboard_name_admitted(element, keep)
            || !self.query.active || self.query.unknown || self.query.status != HRESULT_PENDING
            || !self.query.bstr.is_null() || !self.query.array.is_null() {
            return Ok(false); // All unrecognized results retain strict name completion.
        }
        self.query.status = status; self.query.active = false;
        // A NULL output owns no string. Record whole-scan invalidation before
        // the original post-call clock can freeze a first-fault snapshot.
        self.trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Stale));
        self.trace.result(SmokeCheck::Clock, after_return_clock(), None)?; Ok(true)
    }
    fn dashboard_name(&mut self, element: usize, keep: usize, clock: &mut Clock) -> Result<DashboardNameRead> {
        // The adopted main is never eligible for the descendant exception.
        if self.main.as_ref().is_some_and(|(_, main, _)| *main == element) {
            return self.name(element, clock).map(DashboardNameRead::Text);
        }
        self.trace.need(SmokeCheck::DashboardNameState, self.dashboard_name_admitted(element, keep))?;
        let status = self.query_name(element, clock)?;
        if self.complete_dashboard_name_stale(element, keep, status, || clock.effect())? {
            self.query.settle(&self.trace)?; Ok(DashboardNameRead::Invalidated)
        } else {
            self.finish_name(status, clock).map(DashboardNameRead::Text)
        }
    }
    fn runtime_id(&mut self, element: usize, clock: &mut Clock) -> Result<Vec<i32>> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.trace.need(SmokeCheck::RuntimeIdOutputState, self.query.array.is_null())?; self.query.destroy_entered = false;
        self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.GetRuntimeId)(pointer, (&mut self.query.array as *mut *mut CO::SAFEARRAY).cast()) }.0;
        if status != 0 && !self.query.array.is_null() {
            self.query.unknown = true;
            return self.trace.result(SmokeCheck::RuntimeIdContradiction, Err(Error::Unknown), Some(SmokeStatus::Hresult(status)));
        }
        self.query.returned(status, clock, &self.trace, SmokeCheck::RuntimeId)?;
        self.trace.need(SmokeCheck::RuntimeIdPresent, !self.query.array.is_null())?;
        self.query.dimensions = unsafe { OLE::SafeArrayGetDim(self.query.array) };
        self.query.element_size = unsafe { OLE::SafeArrayGetElemsize(self.query.array) };
        self.trace.need(if self.query.dimensions != 1 { SmokeCheck::RuntimeIdDimensions } else { SmokeCheck::RuntimeIdElementSize },
            self.query.dimensions == 1 && self.query.element_size == 4)?;
        self.query.begin(clock, &self.trace)?;
        let status = unsafe { OLE::SafeArrayGetVartype(self.query.array, &mut self.query.variant) };
        self.query.returned(status, clock, &self.trace, SmokeCheck::RuntimeIdVariantCall)?;
        self.trace.need(SmokeCheck::RuntimeIdVariant, self.query.variant == windows_sys::Win32::System::Variant::VT_I4)?;
        self.query.begin(clock, &self.trace)?;
        let status = unsafe { OLE::SafeArrayGetLBound(self.query.array, 1, &mut self.query.lower) };
        self.query.returned(status, clock, &self.trace, SmokeCheck::RuntimeIdLowerCall)?;
        self.query.begin(clock, &self.trace)?;
        let status = unsafe { OLE::SafeArrayGetUBound(self.query.array, 1, &mut self.query.upper) };
        self.query.returned(status, clock, &self.trace, SmokeCheck::RuntimeIdUpperCall)?;
        self.trace.need(SmokeCheck::RuntimeIdBounds, self.query.lower == 0 && (1..=15).contains(&self.query.upper))?;
        for index in 0..=self.query.upper {
            self.query.index = index; self.query.begin(clock, &self.trace)?;
            let status = unsafe { OLE::SafeArrayGetElement(self.query.array, &self.query.index,
                (&mut self.query.values[index as usize] as *mut i32).cast()) };
            self.query.returned(status, clock, &self.trace, SmokeCheck::RuntimeIdElement)?;
        }
        let result = self.query.values[..=self.query.upper as usize].to_vec();
        self.query.settle(&self.trace)?; self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; Ok(result)
    }
    fn native_handle(&mut self, element: usize, clock: &mut Clock) -> Result<F::HWND> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.hwnd = HWND(null_mut()); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentNativeWindowHandle)(pointer, &mut self.query.hwnd) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::NativeWindowHandle)?; Ok(self.query.hwnd.0)
    }
    fn dashboard_handle_admitted(&self, hwnd: F::HWND, element: usize) -> bool {
        self.trace.phase.get() == SmokePhase::Dashboard
            && self.trace.dashboard.get().is_some_and(|progress| progress.stage == DashboardStage::Bind)
            && self.main.as_ref().is_some_and(|(main, index, id)| *main == hwnd && !hwnd.is_null() && *index == element && !id.is_empty())
            && self.originals.get(element).is_some_and(|original| original.kind == ComKind::Element
                && original.state == SlotState::Owned && !original.active && !original.pointer.is_null())
            && self.initialized && !self.uninit_entered && !self.uninit_returned
            && self.trace.first.get().is_none() && !self.unknown && !self.settled
            && !self.dashboard_ready && !self.quit_confirmed && !self.windows.post_entered && !self.invoke_entered
    }
    fn complete_dashboard_handle_timeout(&mut self, hwnd: F::HWND, element: usize, status: i32,
        after_return_clock: impl FnOnce() -> Result<()>) -> Result<bool> {
        // Only a returned scalar read at the pre-action main bind is pending.
        // A failed scalar is not an owned HWND/COM output and is never consumed,
        // whether it remained zero or a provider wrote a different value.
        if status != A::UIA_E_TIMEOUT as i32 || !self.dashboard_handle_admitted(hwnd, element)
            || !self.query.active || self.query.unknown || self.query.status != HRESULT_PENDING
            || !self.query.bstr.is_null() || !self.query.array.is_null() {
            return Ok(false); // The caller retains the unchanged generic return path.
        }
        self.query.status = status; self.query.active = false;
        let counted = self.trace.dashboard_binding_timeout();
        // Always check the original clock, even when the counter refuses. A
        // later clock/cleanup error cannot rewrite the first counter refusal.
        self.trace.result(SmokeCheck::Clock, after_return_clock(), None)?;
        counted?; Ok(true)
    }
    fn main_native_handle(&mut self, launch: &Launch, hwnd: F::HWND, element: usize, clock: &mut Clock) -> Result<F::HWND> {
        if self.trace.phase.get() != SmokePhase::Dashboard { return self.native_handle(element, clock); }
        loop {
            self.trace.need(SmokeCheck::DashboardBindingState, self.dashboard_handle_admitted(hwnd, element))?;
            let pointer = self.pointer(element, ComKind::Element)?;
            let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
            self.query.hwnd = HWND(null_mut()); self.query.begin(clock, &self.trace)?;
            let status = unsafe { (table.CurrentNativeWindowHandle)(pointer, &mut self.query.hwnd) }.0;
            if !self.complete_dashboard_handle_timeout(hwnd, element, status, || clock.effect())? {
                self.query.returned(status, clock, &self.trace, SmokeCheck::NativeWindowHandle)?;
                return Ok(self.query.hwnd.0);
            }
            // No reference is replaced or released. Reobserve the same live
            // original process/thread and unique HWND around the bounded wait.
            let same = self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd);
            self.trace.need(SmokeCheck::RootContinuity, same)?;
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
            std::thread::sleep(Duration::from_millis(100));
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
            let same = self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd);
            self.trace.need(SmokeCheck::RootContinuity, same)?;
        }
    }
    fn enabled_button(&mut self, element: usize, clock: &mut Clock) -> Result<bool> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.control = A::UIA_CONTROLTYPE_ID(0); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentControlType)(pointer, &mut self.query.control) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::ControlType)?;
        if self.query.control != A::UIA_ButtonControlTypeId { return Ok(false); }
        self.query.boolean = windows::core::BOOL(0); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentIsEnabled)(pointer, &mut self.query.boolean) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::IsEnabled)?; Ok(self.query.boolean.0 != 0)
    }
    fn bound(&mut self, launch: &Launch, clock: &mut Clock) -> Result<()> {
        let (hwnd, index, expected) = self.trace.result(SmokeCheck::MainMissing, self.main.as_ref().ok_or(Error::State), None)?;
        let (hwnd, index, expected) = (*hwnd, *index, expected.clone());
        let bound = self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd)
            && self.main_native_handle(launch, hwnd, index, clock)? == hwnd && self.runtime_id(index, clock)? == expected;
        self.trace.need(SmokeCheck::MainBinding, bound)?;
        let pointer = self.pointer(index, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.integer = 0; self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentProcessId)(pointer, &mut self.query.integer) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::ProcessId)?;
        self.trace.need(SmokeCheck::MainProcess, self.query.integer > 0 && self.query.integer as u32 == launch.outputs.dwProcessId)
    }
    fn walk(&mut self, root: usize, clock: &mut Clock) -> Result<Vec<usize>> {
        self.trace.dashboard_update(DashboardProgress::begin_walk);
        let mut result = Vec::with_capacity(256); let mut stack = vec![(root, 0usize)];
        while let Some((index, depth)) = stack.pop() {
            self.trace.need(SmokeCheck::WalkBounds, depth <= 40 && result.len() < 900)?; result.push(index);
            self.trace.dashboard_update(|progress| progress.walk_visited(result.len()));
            // Follow only this element's children; never a desktop root/sibling
            // outside the caller's admitted main/dialog subtree.
            if let Some(child) = self.adjacent(index, true, clock)? {
                let mut siblings = vec![child]; let mut at = child;
                while let Some(next) = self.adjacent(at, false, clock)? {
                    self.trace.need(SmokeCheck::SiblingBounds, siblings.len() + result.len() < 900)?; siblings.push(next); at = next;
                }
                stack.extend(siblings.into_iter().rev().map(|index| (index, depth + 1)));
            }
        }
        Ok(result)
    }
    fn release_suffix(&mut self, from: usize) -> Result<()> {
        for original in self.originals[from..].iter_mut().rev() {
            self.trace.result(SmokeCheck::ComRelease, original.release(), None)?;
        }
        self.originals.truncate(from); Ok(())
    }
    fn quit_identity(&mut self, element: usize, clock: &mut Clock) -> Result<QuitIdentity> {
        let runtime = self.runtime_id(element, clock)?;
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.integer = 0; self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentProcessId)(pointer, &mut self.query.integer) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::ProcessId)?;
        self.trace.need(SmokeCheck::QuitProcess, self.query.integer > 0)?;
        Ok(QuitIdentity { runtime, process: self.query.integer as u32 })
    }
    fn quit_control_type(&mut self, element: usize, clock: &mut Clock) -> Result<i32> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.control = A::UIA_CONTROLTYPE_ID(0); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentControlType)(pointer, &mut self.query.control) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::ControlType)?; Ok(self.query.control.0)
    }
    fn quit_parent(&mut self, element: usize, clock: &mut Clock) -> Result<usize> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let walker = self.pointer(self.trace.result(SmokeCheck::WalkerMissing, self.walker.ok_or(Error::State), None)?, ComKind::Walker)?;
        let table = unsafe { &**walker.cast::<*const A::IUIAutomationTreeWalker_Vtbl>() };
        let index = self.reserve(ComKind::Element, clock)?;
        let output = self.trace.result(SmokeCheck::QuitParentAcquireState, self.originals[index].begin(), None)?;
        let status = unsafe { (table.GetParentElement)(walker, pointer, output) }.0;
        self.acquire_return(index, status, false, clock, SmokeCheck::QuitParentAcquire)?; Ok(index)
    }
    fn quit_walk(&mut self, root: usize, process: u32, clock: &mut Clock) -> Result<QuitTree> {
        self.trace.quit_scan_begin()?;
        let mut tree = QuitTree::new();
        let node = QuitNode { element: root, parent: None, parent_probe: None, previous: None, depth: 0,
            identity: self.quit_identity(root, clock)?, name: self.name(root, clock)?, control: self.quit_control_type(root, clock)? };
        tree.push(node, process, &self.trace)?;
        // Every parent is completely closed, including its null child/sibling
        // terminator. Edges and actual GetParentElement identities are retained;
        // no early "found both" return can hide a disabled duplicate or escape.
        while tree.closed < tree.nodes.len() {
            let parent = tree.closed; let parent_element = tree.nodes[parent].element;
            let depth = tree.nodes[parent].depth + 1; let mut previous = None;
            let mut next = self.adjacent(parent_element, true, clock)?;
            while let Some(element) = next {
                self.trace.result(SmokeCheck::QuitTreeBounds,
                    if tree.nodes.len() < QUIT_NODES && depth <= QUIT_DEPTH { Ok(()) } else { Err(Error::Bounds) }, None)?;
                let probe = self.quit_parent(element, clock)?;
                let actual_parent = self.quit_identity(probe, clock)?;
                self.trace.need(SmokeCheck::QuitLineage, actual_parent == tree.nodes[parent].identity)?;
                let node = QuitNode { element, parent: Some(parent), parent_probe: Some(probe), previous, depth,
                    identity: self.quit_identity(element, clock)?, name: self.name(element, clock)?,
                    control: self.quit_control_type(element, clock)? };
                previous = Some(tree.push(node, process, &self.trace)?);
                next = self.adjacent(element, false, clock)?;
            }
            tree.close_parent(parent, &self.trace)?;
        }
        Ok(tree)
    }
    fn quit_native_container(&mut self, handle: F::HWND, dialog: F::HWND, launch: &Launch, clock: &mut Clock)
        -> Result<crate::ui::quit_native::Container> {
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        let result = self.trace.quit_native(crate::ui::quit_native::observe(
            handle, dialog, launch.outputs.dwProcessId, launch.outputs.dwThreadId));
        // Preserve the native refusal as first fault, including when the
        // original endpoint also refuses after this bounded synchronous read.
        let returned_clock = self.trace.result(SmokeCheck::Clock, clock.effect(), None);
        let value = result?; returned_clock?; Ok(value)
    }
    fn quit_control(&mut self, tree: &QuitTree, selected: usize, expected_name: &str, dialog: F::HWND,
        launch: &Launch, clock: &mut Clock) -> Result<(QuitControlFacts, Vec<usize>)> {
        let node = tree.node(selected, &self.trace)?;
        let element = node.element;
        let identity = self.quit_identity(element, clock)?;
        let name = self.name(element, clock)?; let control = self.quit_control_type(element, clock)?;
        self.trace.need(SmokeCheck::QuitButtonsChanged, identity == node.identity && name == node.name && control == node.control)?;
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        self.query.boolean = windows::core::BOOL(0); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentIsEnabled)(pointer, &mut self.query.boolean) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::IsEnabled)?; let enabled = self.query.boolean.0 != 0;
        self.query.boolean = windows::core::BOOL(1); self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentIsOffscreen)(pointer, &mut self.query.boolean) }.0;
        self.query.returned(status, clock, &self.trace, SmokeCheck::IsOffscreen)?; let offscreen = self.query.boolean.0 != 0;
        let native_handle = self.native_handle(element, clock)?;
        let native = self.quit_native_container(native_handle, dialog, launch, clock)?;
        let chain = tree.chain(selected, launch.outputs.dwProcessId, &self.trace)?;
        let mut ancestors = Vec::with_capacity(chain.len()); let mut probes = Vec::with_capacity(chain.len()); let mut at = selected;
        for parent in chain {
            let current = tree.node(at, &self.trace)?; let expected = tree.node(parent, &self.trace)?;
            let original_probe = self.trace.result(SmokeCheck::QuitLineage, current.parent_probe.ok_or(Error::State), None)?;
            let retained_parent = self.quit_identity(expected.element, clock)?;
            let retained_probe = self.quit_identity(original_probe, clock)?;
            let probe = self.quit_parent(current.element, clock)?;
            let actual_parent = self.quit_identity(probe, clock)?;
            self.trace.need(SmokeCheck::QuitLineage, retained_parent == expected.identity
                && retained_probe == expected.identity && actual_parent == expected.identity)?;
            ancestors.push(expected.identity.clone()); probes.push(probe); at = parent;
        }
        let facts = QuitControlFacts { identity, name, control, enabled, offscreen, native, ancestors };
        facts.valid(expected_name, &tree.node(0, &self.trace)?.identity, &self.trace)?;
        Ok((facts, probes))
    }
    fn quit_scan(&mut self, root: usize, dialog: F::HWND, launch: &Launch, clock: &mut Clock) -> Result<QuitScan> {
        let tree = self.quit_walk(root, launch.outputs.dwProcessId, clock)?;
        let selected = tree.select(&self.trace)?;
        let (ok, ok_probes) = self.quit_control(&tree, selected[0], "OK", dialog, launch, clock)?;
        let (cancel, cancel_probes) = self.quit_control(&tree, selected[1], "Cancel", dialog, launch, clock)?;
        let controls = [ok, cancel]; quit_controls_valid(&controls, &tree.node(0, &self.trace)?.identity, &self.trace)?;
        Ok(QuitScan { tree, selected, controls, parent_probes: [ok_probes, cancel_probes] })
    }
    fn quit_bound(&mut self, launch: &Launch, main: F::HWND, dialog: F::HWND, root: usize,
        expected: &QuitIdentity, clock: &mut Clock) -> Result<()> {
        self.bound(launch, clock)?;
        let mut selected = None;
        for entry in &self.windows.entries[..self.windows.count] {
            if entry.owner == main {
                self.trace.need(SmokeCheck::QuitDialogIdentity, selected.is_none() && entry.hwnd == dialog
                    && entry.title(&self.trace)? == "Quit Mobile Release Kit?")?;
                selected = Some(entry.hwnd);
            }
        }
        self.trace.need(SmokeCheck::QuitBinding, selected == Some(dialog))?;
        self.windows.class_length = unsafe { W::GetClassNameW(dialog, self.windows.class.as_mut_ptr(), 256) };
        self.trace.need(SmokeCheck::QuitClass, self.windows.class_length > 0 && self.windows.class_length < 255
            && self.trace.result(SmokeCheck::QuitClassEncoding,
                String::from_utf16(&self.windows.class[..self.windows.class_length as usize]).map_err(|_| Error::Unsafe), None)? == "#32770")?;
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        let handle = self.native_handle(root, clock)?; let identity = self.quit_identity(root, clock)?;
        self.trace.need(SmokeCheck::QuitBinding, handle == dialog && identity == *expected && identity.process == launch.outputs.dwProcessId)
    }
    fn quit_legacy_pattern(&mut self, element: usize, clock: &mut Clock, check: SmokeCheck) -> Result<QuitPattern> {
        let pointer = self.pointer(element, ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        let original = self.reserve(ComKind::Legacy, clock)?;
        let output = self.trace.result(SmokeCheck::QuitLegacyAcquireState, self.originals[original].begin(), None)?;
        let status = unsafe { (table.GetCurrentPatternAs)(pointer, A::UIA_LegacyIAccessiblePatternId,
            &A::IUIAutomationLegacyIAccessiblePattern::IID, output) }.0;
        self.acquire_return(original, status, false, clock, check)?; Ok(QuitPattern { element, original })
    }
    fn quit_legacy_state(&mut self, pattern: QuitPattern, clock: &mut Clock, check: SmokeCheck) -> Result<u32> {
        let pointer = self.pointer(pattern.original, ComKind::Legacy)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationLegacyIAccessiblePattern_Vtbl>() };
        // Exact generated 0.61.3 signature: CurrentState(*mut c_void, *mut u32).
        // Scalar storage is registered in the same pending-aware UiQuery owner.
        self.query.legacy_state = u32::MAX; self.query.begin(clock, &self.trace)?;
        let status = unsafe { (table.CurrentState)(pointer, &mut self.query.legacy_state) }.0;
        self.query.returned(status, clock, &self.trace, check)?; Ok(self.query.legacy_state)
    }
    fn quit_requery_originals(&mut self, original: &QuitScan, dialog: F::HWND, launch: &Launch, clock: &mut Clock) -> Result<()> {
        for (index, name) in ["OK", "Cancel"].into_iter().enumerate() {
            self.trace.need(SmokeCheck::QuitLineage, original.parent_probes[index].len() == original.controls[index].ancestors.len())?;
            for (probe, expected) in original.parent_probes[index].iter().zip(&original.controls[index].ancestors) {
                let actual = self.quit_identity(*probe, clock)?;
                self.trace.need(SmokeCheck::QuitLineage, actual == *expected)?;
            }
            let (current, _observation_probes) = self.quit_control(&original.tree, original.selected[index], name, dialog, launch, clock)?;
            // New read-only COM observations stay in self.originals. Never
            // substitute them for this pair's original elements or patterns.
            original.controls[index].same(&current, &self.trace)?;
        }
        Ok(())
    }
    fn observe(&mut self, launch: &Launch, version: &str, clock: &mut Clock) -> Result<()> {
        self.trace.phase.set(SmokePhase::Setup);
        self.setup(clock)?;
        self.trace.phase.set(SmokePhase::MainWindow);
        let hwnd = loop {
            if let Some(hwnd) = self.windows.root(launch, None, clock, &self.trace)? { break hwnd; }
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; std::thread::sleep(Duration::from_millis(100));
        };
        self.trace.phase.set(SmokePhase::MainBinding);
        let element = loop {
            // root(Some) refuses a missing, additional or replacement root
            // after checking the SAME original live process/thread handles.
            let _ = self.windows.root(launch, Some(hwnd), clock, &self.trace)?;
            if let Some(element) = self.initial_main_from_window(hwnd, clock)? { break element; }
            let _ = self.windows.root(launch, Some(hwnd), clock, &self.trace)?;
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
            std::thread::sleep(Duration::from_millis(100));
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        };
        let id = self.runtime_id(element, clock)?;
        self.main = Some((hwnd, element, id)); self.bound(launch, clock)?;
        self.trace.phase.set(SmokePhase::Dashboard);
        loop {
            self.trace.dashboard_begin_pass();
            self.bound(launch, clock)?; let keep = self.originals.len();
            let elements = self.walk(element, clock)?;
            self.trace.dashboard_update(DashboardProgress::walk_completed);
            let mut pass = DashboardPass::new(); let expected_version = format!("DESKTOP {version}");
            self.trace.dashboard_update(DashboardProgress::begin_names);
            for index in elements {
                let name = match self.dashboard_name(index, keep, clock)? {
                    DashboardNameRead::Text(name) => name,
                    DashboardNameRead::Invalidated => { pass.finish(DashboardScanEnd::Stale); break; }
                };
                self.trace.dashboard_update(|progress| progress.name_returned(&name));
                pass.found[0] |= name == "Good releases start here.";
                pass.found[1] |= name == "Workspace navigation";
                pass.found[2] |= name == "Your next release, organized.";
                pass.found[3] |= name == expected_version;
                self.trace.dashboard_update(|progress| progress.matches(pass.found));
                if name == "Choose a project" { pass.found[4] |= self.enabled_button(index, clock)?; }
                self.trace.dashboard_update(|progress| progress.matches(pass.found));
                let lower = name.to_ascii_lowercase();
                let unavailable = [
                    ("the native service is unavailable", SmokeCheck::NativeServiceUnavailable),
                    ("the field catalogue could not be loaded", SmokeCheck::CatalogueUnavailable),
                    ("bundled engine unavailable", SmokeCheck::BundledEngineUnavailable),
                    ("the engine is disabled", SmokeCheck::EngineDisabled),
                    ("browser preview", SmokeCheck::BrowserPreview),
                ].into_iter().find(|(value, _)| lower.contains(value)).map(|(_, check)| check);
                if let Some(check) = unavailable { self.trace.need(check, false)?; }
                if name.contains("Loading desktop capabilities and the core field catalogue") {
                    self.trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Loading));
                    pass.finish(DashboardScanEnd::Loading); break;
                }
            }
            self.trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Exhausted));
            pass.finish(DashboardScanEnd::Exhausted);
            self.release_suffix(keep)?;
            if pass.ready() { self.dashboard_ready = true; break; }
            let stale = pass.end == Some(DashboardScanEnd::Stale);
            if stale {
                // Retire the entire known suffix before reobserving the same
                // original owner/root. The next pass repeats complete bound().
                let same = self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd);
                self.trace.need(SmokeCheck::RootContinuity, same)?;
            }
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; std::thread::sleep(Duration::from_millis(100));
            if stale { self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; }
        }
        self.trace.phase.set(SmokePhase::CloseRequest);
        self.bound(launch, clock)?;
        self.trace.need(SmokeCheck::PostCloseOnce, !self.windows.post_entered)?; self.windows.post_entered = true;
        self.windows.post_return = unsafe { W::PostMessageW(hwnd, W::WM_CLOSE, 0, 0) };
        self.windows.post_error = if self.windows.post_return != 0 { 0 } else { unsafe { F::GetLastError() } };
        // Posting is request delivery only, never response or original exit.
        self.trace.result(SmokeCheck::PostClose, need(self.windows.post_return != 0), Some(SmokeStatus::Win32(self.windows.post_error)))?;
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        self.trace.phase.set(SmokePhase::QuitDialog);
        let dialog = loop {
            self.bound(launch, clock)?; let mut dialog = None;
            for entry in &self.windows.entries[..self.windows.count] {
                if entry.owner == hwnd {
                    self.trace.need(SmokeCheck::QuitDialogIdentity,
                        entry.title(&self.trace)? == "Quit Mobile Release Kit?" && dialog.is_none())?;
                    dialog = Some(entry.hwnd);
                }
            }
            if let Some(dialog) = dialog { break dialog; }
            self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; std::thread::sleep(Duration::from_millis(100));
        };
        self.windows.class_length = unsafe { W::GetClassNameW(dialog, self.windows.class.as_mut_ptr(), 256) };
        self.trace.need(SmokeCheck::QuitClass, self.windows.class_length > 0 && self.windows.class_length < 255
            && self.trace.result(SmokeCheck::QuitClassEncoding,
                String::from_utf16(&self.windows.class[..self.windows.class_length as usize]).map_err(|_| Error::Unsafe), None)? == "#32770")?;
        self.trace.result(SmokeCheck::Clock, clock.effect(), None)?;
        // Bind once from the admitted native TaskDialog. Logical control
        // identity does not depend on native child IDs, classes or HWND layout.
        let dialog_element = self.from_window(dialog, clock)?;
        let dialog_bound = self.native_handle(dialog_element, clock)? == dialog;
        self.trace.need(SmokeCheck::QuitDialogHandle, dialog_bound)?;
        let dialog_identity = self.quit_identity(dialog_element, clock)?;
        self.trace.need(SmokeCheck::QuitProcess, dialog_identity.process == launch.outputs.dwProcessId)?;
        self.quit_bound(launch, hwnd, dialog, dialog_element, &dialog_identity, clock)?;
        let buttons = self.quit_scan(dialog_element, dialog, launch, clock)?;
        self.trace.need(SmokeCheck::QuitBinding, buttons.tree.node(0, &self.trace)?.identity == dialog_identity)?;
        let elements = buttons.elements(&self.trace)?;
        let legacy = [
            self.quit_legacy_pattern(elements[0], clock, SmokeCheck::QuitOkLegacyAcquire)?,
            self.quit_legacy_pattern(elements[1], clock, SmokeCheck::QuitCancelLegacyAcquire)?,
        ];
        let default_states = [
            self.quit_legacy_state(legacy[0], clock, SmokeCheck::QuitOkLegacyState)?,
            self.quit_legacy_state(legacy[1], clock, SmokeCheck::QuitCancelLegacyState)?,
        ];
        quit_default_states(default_states, &self.trace)?;
        self.trace.phase.set(SmokePhase::QuitInvoke);
        let pointer = self.pointer(elements[0], ComKind::Element)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationElement_Vtbl>() };
        let index = self.reserve(ComKind::Invoke, clock)?;
        let output = self.trace.result(SmokeCheck::InvokeAcquireState, self.originals[index].begin(), None)?;
        let status = unsafe { (table.GetCurrentPatternAs)(pointer, A::UIA_InvokePatternId, &A::IUIAutomationInvokePattern::IID, output) }.0;
        self.acquire_return(index, status, false, clock, SmokeCheck::InvokeAcquire)?;
        let patterns = QuitPatterns { elements, legacy, invoke: QuitPattern { element: elements[0], original: index } };
        patterns.valid(buttons.elements(&self.trace)?, &self.trace)?;
        self.quit_bound(launch, hwnd, dialog, dialog_element, &dialog_identity, clock)?;
        // Exactly one complete second scan, solely to compare. Every new COM
        // output (including null terminators and parent probes) remains within
        // the same 2048-slot owner; none can replace the original action pair.
        let current = self.quit_scan(dialog_element, dialog, launch, clock)?;
        buttons.same(&current, &self.trace)?;
        self.quit_bound(launch, hwnd, dialog, dialog_element, &dialog_identity, clock)?;
        self.quit_requery_originals(&buttons, dialog, launch, clock)?;
        let current_states = [
            self.quit_legacy_state(patterns.legacy[0], clock, SmokeCheck::QuitOkLegacyState)?,
            self.quit_legacy_state(patterns.legacy[1], clock, SmokeCheck::QuitCancelLegacyState)?,
        ];
        quit_same_defaults(default_states, current_states, &self.trace)?;
        patterns.valid(buttons.elements(&self.trace)?, &self.trace)?;
        self.trace.need(SmokeCheck::InvokeOnce, !self.invoke_entered)?;
        let pointer = self.pointer(index, ComKind::Invoke)?;
        let table = unsafe { &**pointer.cast::<*const A::IUIAutomationInvokePattern_Vtbl>() };
        self.query.begin(clock, &self.trace)?; self.invoke_entered = true;
        self.invoke_return = unsafe { (table.Invoke)(pointer) }.0;
        self.query.returned(self.invoke_return, clock, &self.trace, SmokeCheck::Invoke)?;
        self.quit_confirmed = true; self.trace.result(SmokeCheck::Clock, clock.effect(), None)
    }
    fn settle(&mut self) -> Result<()> {
        self.trace.phase.set(SmokePhase::DriverSettle);
        if self.settled { return Ok(()); }
        if self.unknown || self.windows.active || self.query.settle(&self.trace).is_err() {
            let check = if self.unknown { SmokeCheck::DriverUnknown }
                else if self.windows.active { SmokeCheck::WindowQueryActive } else { SmokeCheck::QuerySettlement };
            self.unknown = true; return self.trace.result(check, Err(Error::Unknown), None);
        }
        for original in self.originals.iter_mut().rev() {
            if self.trace.result(SmokeCheck::ComRelease, original.release(), None).is_err() {
                self.unknown = true; return Err(Error::Unknown);
            }
        }
        if self.initialized {
            self.trace.need(SmokeCheck::UninitializeOnce, !self.uninit_entered)?; self.uninit_entered = true;
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

fn smoke_result<T>(smoke: Option<&Smoke>, phase: SmokePhase, check: SmokeCheck, result: Result<T>) -> Result<T> {
    match smoke {
        Some(smoke) => { smoke.trace.phase.set(phase); smoke.trace.result(check, result, None) },
        None => result,
    }
}
fn diagnostic_smoke(stage: &'static str, launch: Option<&Launch>, unknown: bool,
    fault: Option<InputFault>, smoke: Option<&Smoke>) {
    if let Some(smoke) = smoke { smoke.trace.emit(); }
    diagnostic_with_fault(stage, launch, unknown, fault);
}

const PREREQUISITE_FAULT_PREFIX: &str = "MRK_WINDOWS_UI_PREREQUISITE_FAULT_V1=";
const PREREQUISITE_FAULT_FRAME_MAX_BYTES: usize = 664;
const PREREQUISITE_FAULT_BUFFER_BYTES: usize = 2048;
const PREREQUISITE_OWNER: &str = "ordinary_owner::hosted_normal_ui_prerequisite_original_handle_contract";
#[derive(Clone, Copy)]
struct PrerequisiteBindings<'a> { source: &'a str, tree: &'a str, run: &'a str }
impl<'a> PrerequisiteBindings<'a> {
    fn source(value: &str) -> bool { is_hex(value, 40) && value.bytes().any(|byte| byte != b'0') }
    fn new(source: Option<&'a str>, tree: Option<&'a str>, run: Option<&'a str>) -> Self {
        Self { source: source.filter(|value| Self::source(value)).unwrap_or("unavailable"),
            tree: tree.filter(|value| Self::source(value)).unwrap_or("unavailable"),
            run: run.filter(|value| decimal(value)).unwrap_or("unavailable") }
    }
    fn valid(self) -> bool {
        [self.source, self.tree].into_iter().all(|value| value == "unavailable" || Self::source(value))
            && (self.run == "unavailable" || decimal(self.run))
    }
}
struct PrerequisiteFrame<'a> { bytes: &'a mut [u8], used: usize }
impl std::fmt::Write for PrerequisiteFrame<'_> {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(std::fmt::Error)?;
        if end > self.bytes.len() || !value.is_ascii() { return Err(std::fmt::Error); }
        self.bytes[self.used..end].copy_from_slice(value.as_bytes()); self.used = end; Ok(())
    }
}
fn prerequisite_error_label(error: Error) -> &'static str {
    match error { Error::Unavailable => "Unavailable", Error::Unsafe => "Unsafe",
        Error::Bounds => "Bounds", Error::State => "State", Error::Unknown => "Unknown" }
}
fn prerequisite_fault_frame(record: PrerequisiteRecord, returned: Error, binding: PrerequisiteBindings<'_>, output: &mut [u8]) -> Option<usize> {
    use std::fmt::Write as _;
    let first = record.first?;
    if !binding.valid() || first.native.is_some_and(|value| !value.valid()) { return None; }
    let unannotated = first.check == PrerequisiteCheck::U01;
    if unannotated != (first.stage == PrerequisiteStage::Escape)
        || unannotated && (first.native.is_some() || first.detail.is_some()) { return None; }
    let (detail_prefix, detail) = first.detail.map(PrerequisiteDetail::labels).unwrap_or(("", "none"));
    if detail_prefix.len() + detail.len() > 64 || !detail_prefix.is_ascii() || !detail.is_ascii() { return None; }
    let native = first.native;
    let mut frame = PrerequisiteFrame { bytes: output, used: 0 };
    write!(&mut frame, "\n{PREREQUISITE_FAULT_PREFIX}source={};tree={};run={};attempt=1;owner={PREREQUISITE_OWNER};mode=prerequisite-only;stage={};check={};detail={detail_prefix}{detail};first={};returned={};api={};selector={};kind={};value=",
        binding.source, binding.tree, binding.run, first.stage.label(), first.check.label(),
        prerequisite_error_label(first.error), prerequisite_error_label(returned),
        native.map(|value| value.api.label()).unwrap_or("none"),
        native.map(|value| value.selector.label()).unwrap_or("none"),
        native.map(|value| value.kind.label()).unwrap_or("none")).ok()?;
    match native.and_then(|value| value.value) { Some(value) => write!(&mut frame, "{value}").ok()?, None => frame.write_str("none").ok()? }
    write!(&mut frame, ";status={};code=", native.map(|value| value.status.label()).unwrap_or("none")).ok()?;
    match native.and_then(|value| value.code) { Some(value) => write!(&mut frame, "{value}").ok()?, None => frame.write_str("none").ok()? }
    write!(&mut frame, ";clock={};coverage={};end=1\n", record.clock.label(), if unannotated { "unannotated" } else { "mapped" }).ok()?;
    (frame.used <= PREREQUISITE_FAULT_FRAME_MAX_BYTES).then_some(frame.used)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrerequisiteWrite { Full, Short, Zero, Interrupted, Error, Overreported }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrerequisiteFlush { Ok, Interrupted, Error }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrerequisiteDelivery {
    NotNeeded, EncodingFailed, Attempted { write: PrerequisiteWrite, flush: PrerequisiteFlush },
}
impl PrerequisiteDelivery {
    fn locally_complete(self) -> bool {
        match self {
            Self::NotNeeded | Self::EncodingFailed => false,
            Self::Attempted { write, flush } => {
                let full = match write { PrerequisiteWrite::Full => true,
                    PrerequisiteWrite::Short | PrerequisiteWrite::Zero | PrerequisiteWrite::Interrupted
                    | PrerequisiteWrite::Error | PrerequisiteWrite::Overreported => false };
                let flushed = match flush { PrerequisiteFlush::Ok => true,
                    PrerequisiteFlush::Interrupted | PrerequisiteFlush::Error => false };
                full && flushed
            },
        }
    }
}
fn prerequisite_sink(output: &mut impl Write, frame: &[u8]) -> PrerequisiteDelivery {
    let written = output.write(frame); // One attempt, never write_all/retry.
    // A returned short/zero/error/Interrupted/overreported write still gets its
    // one flush. This is finite work, NOT a bounded synchronous wall time.
    let flushed = output.flush();
    let write = match written {
        Ok(count) if count == frame.len() => PrerequisiteWrite::Full,
        Ok(0) => PrerequisiteWrite::Zero, Ok(count) if count < frame.len() => PrerequisiteWrite::Short,
        Ok(_) => PrerequisiteWrite::Overreported,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => PrerequisiteWrite::Interrupted,
        Err(_) => PrerequisiteWrite::Error,
    };
    let flush = match flushed { Ok(()) => PrerequisiteFlush::Ok,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => PrerequisiteFlush::Interrupted,
        Err(_) => PrerequisiteFlush::Error };
    PrerequisiteDelivery::Attempted { write, flush }
}
fn prerequisite_returned(role: UiRole, original: Result<()>, trace: &mut InputTrace,
    binding: PrerequisiteBindings<'_>, output: &mut impl Write) -> (Result<()>, PrerequisiteDelivery) {
    let error = match original {
        Ok(()) => return (original, PrerequisiteDelivery::NotNeeded),
        Err(error) if role == UiRole::Prerequisite => error,
        Err(_) => return (original, PrerequisiteDelivery::NotNeeded),
    };
    // A genuine returned escape is visible as unannotated, never assigned a
    // guessed stage/API from a last status. Earlier genuine first stays immutable.
    trace.prerequisite_fault(PrerequisiteCheck::U01, error, None, None);
    let mut bytes = [0u8; PREREQUISITE_FAULT_BUFFER_BYTES];
    let length = trace.prerequisite.and_then(|record| prerequisite_fault_frame(record, error, binding, &mut bytes));
    let delivery = match length { Some(length) => prerequisite_sink(output, &bytes[..length]),
        None => PrerequisiteDelivery::EncodingFailed };
    (original, delivery) // Delivery has no native Error/Unknown/park authority.
}
pub(super) fn run(role: UiRole, entry_tick: u64) -> Result<()> {
    // This optional fixed DATA record exists before the original first Clock.
    let mut trace = InputTrace::prerequisite_only(role == UiRole::Prerequisite);
    let original = run_prerequisite_traced(role, entry_tick, &mut trace);
    if role != UiRole::Prerequisite || original.is_ok() { return original; }
    // Standard Write facade for the already-owned harness stdout. No new file,
    // HANDLE, alternate sink or close, and no additional owner-clock sample.
    let mut output = std::io::stdout().lock();
    let (original, delivery) = prerequisite_returned(role, original, &mut trace,
        PrerequisiteBindings::new(option_env!("GITHUB_SHA"), option_env!("MRK_WINDOWS_SOURCE_TREE"), option_env!("GITHUB_RUN_ID")), &mut output);
    let _local_delivery_complete = delivery.locally_complete();
    original
}

fn run_prerequisite_traced(role: UiRole, entry_tick: u64, trace: &mut InputTrace) -> Result<()> {
    let mut clock = prerequisite_result!(trace, E01, Clock::new(entry_tick))?;
    trace.prerequisite_clock(clock.latched);
    trace.prerequisite_check(PrerequisiteCheck::E02);
    // This closed route is not any historical Fullwalk/Passive admission.
    let root = prerequisite_result!(trace, E02, fixed_path_traced(&prerequisite_result!(trace, E02, std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_| Error::State))?, trace))?;
    let temp = prerequisite_result!(trace, E02, fixed_path_traced(&prerequisite_result!(trace, E02, std::env::var("RUNNER_TEMP").map_err(|_| Error::State))?, trace))?;
    let run = prerequisite_result!(trace, E02, std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State))?;
    trace.prerequisite_check(PrerequisiteCheck::E03);
    prerequisite_result!(trace, E03, need(decimal(&run) && root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|error| {
            trace.prerequisite_fault(PrerequisiteCheck::E03, Error::Unavailable,
                PrerequisiteNative::io(PrerequisiteApi::CurrentDir, &error), None);
            Error::Unavailable
        })? == root))?;
    trace.prerequisite_check(PrerequisiteCheck::E04);
    let image = std::env::current_exe().map_err(|error| {
        trace.prerequisite_fault(PrerequisiteCheck::E04, Error::Unavailable,
            PrerequisiteNative::io(PrerequisiteApi::CurrentExe, &error), None);
        Error::Unavailable
    })?;
    prerequisite_result!(trace, E04, role.process_args_traced(&image, true, trace))?;
    let mut book = NativeBook::new(); let mut inventory = NativeBook::new();
    inventory.prerequisite_enable_admission(trace);
    let mut parent_attempted = false; let mut parent_settled = false;
    let mut files: Vec<OriginalFile> = Vec::with_capacity(48);
    let mut creates: Vec<Box<DirectoryCreate>> = Vec::with_capacity(4);
    let mut profile: Option<Profile> = None; let mut fixture = None;
    let mut account: Option<Account> = None; let mut launch: Option<Pin<Box<Launch>>> = None;
    let mut smoke: Option<Smoke> = None;
    let mut transitions = Vec::with_capacity(14);
    let mut request: Option<UiRequest> = None;
    let mut input_stamps = Vec::with_capacity(8);
    let mut request_sha = String::new(); let mut account_sha = String::new();
    let mut child_sha = None; let mut available = None;
    let output = root.join(role.name("output"));
    let mut output_index = None; let mut artifact_index = None; let mut artifact_after = None;
    let mut stage = "ui-parent-context";
    trace.prerequisite_at(PrerequisiteStage::ParentInput, PrerequisiteCheck::P01);
    let observation = (|| -> Result<()> {
        clock.effect_traced(trace)?;
        let mut staged = trace.prerequisite_staged();
        let original = book.prerequisite_observe(&mut staged, PrerequisiteCheck::NB10, |book| book.observe_user_once().map(|_| ()));
        need(trace.prerequisite_expected(PrerequisiteCheck::P01, original, Error::Unsafe, staged))?;
        let token = book.process_token.ok_or(Error::State)?;
        trace.prerequisite_check(PrerequisiteCheck::P02);
        super::super::hosted_tests::actual_elevated_primary_refusal_traced(&mut book, token, trace)?;
        let parent = parent_user_traced(&mut book, trace)?; clock.effect_traced(trace)?;
        stage = "ui-original-inputs";
        trace.prerequisite_check(PrerequisiteCheck::P03);
        let mut ancestors: Vec<_> = root.ancestors().map(Path::to_path_buf).collect(); ancestors.reverse();
        need(ancestors.len() <= 16)?; let mut root_index = None;
        for path in &ancestors {
            trace.at(InputRole::Ancestor, Some(files.len() as u8));
            let index = input(&mut files, path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL
                | if path == &root { FS::WRITE_DAC } else { 0 }, &mut clock, trace)?;
            if path == &root { root_index = Some(index); }
        }
        trace.prerequisite_check(PrerequisiteCheck::P04);
        trace.at(InputRole::Request, Some(files.len() as u8));
        let request_index = input(&mut files, &root.join(role.name("request.txt")), false,
            FS::FILE_GENERIC_READ, &mut clock, trace)?;
        let request_before = files[request_index].stamp_traced(trace)?;
        let raw = files[request_index].read_traced(LIMIT, trace)?; clock.effect_traced(trace)?;
        let selected = UiRequest::parse_traced(&raw, trace)?; selected.compiled_traced(trace)?; selected.at_root_traced(&root, trace)?;
        need(selected.role == role && selected.run == run && image.to_str() == Some(selected.owner.path.as_str()))?;
        need(files[request_index].stamp_traced(trace)? == request_before)?;
        input_stamps.push((request_index, request_before)); request_sha = digest_traced(&raw, trace)?;
        trace.prerequisite_check(PrerequisiteCheck::P05);
        let mut directories = vec![(root_index.ok_or(Error::State)?, "root")];
        for (label, path) in fixed_directories(&root) {
            trace.at(InputRole::Directory, Some(files.len() as u8));
            let index = input(&mut files, &path, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC,
                &mut clock, trace)?;
            directories.push((index, label));
        }
        trace.at(InputRole::Artifact, Some(files.len() as u8));
        let artifact = input(&mut files, Path::new(&selected.app.path), false, FS::FILE_GENERIC_READ | FS::WRITE_DAC,
            &mut clock, trace)?;
        trace.prerequisite_check(PrerequisiteCheck::P06);
        let before = read_hash(&mut files, artifact, selected.app.bytes, &selected.app.sha,
            role != UiRole::Prerequisite, &mut clock, trace)?;
        need(selected.app.matches(&before))?; artifact_index = Some(artifact);
        if role != UiRole::Prerequisite {
            trace.at(InputRole::Artifact, Some(files.len() as u8));
            let index = input(&mut files, &image, false, FS::FILE_GENERIC_READ, &mut clock, trace)?;
            let original = read_hash(&mut files, index, selected.owner.bytes, &selected.owner.sha, false, &mut clock, trace)?;
            need(selected.owner.matches(&original) && (original.volume, original.id) != (before.volume, before.id))?;
            input_stamps.push((index, original));
        } else { need(selected.owner.matches(&before))?; }
        for (name, binding) in [("compile-messages.jsonl", &selected.owner), (role.app_messages(), &selected.app)] {
            // Probe app/owner are the SAME compiler stream, retained once.
            if name == "compile-messages.jsonl" && role == UiRole::Prerequisite && input_stamps.len() == 2 { continue; }
            trace.at(InputRole::Binding, Some(files.len() as u8));
            let index = input(&mut files, &root.join(name), false, FS::FILE_GENERIC_READ, &mut clock, trace)?;
            let before = read_hash(&mut files, index, binding.messages_bytes, &binding.messages_sha, false, &mut clock, trace)?;
            input_stamps.push((index, before));
        }
        if let Some(runtime) = &selected.runtime {
            // Source-bound publication DATA only. Each real application still
            // acquires its own installed runtime and repeats native admission.
            trace.at(InputRole::Binding, Some(files.len() as u8));
            let index = input(&mut files, &root.join("normal-ui-publication.private.json"), false,
                FS::FILE_GENERIC_READ, &mut clock, trace)?;
            let before = read_hash(&mut files, index, runtime.publication_bytes, &runtime.publication_sha, false,
                &mut clock, trace)?; input_stamps.push((index, before));
        }
        trace.prerequisite_at(PrerequisiteStage::AccountProfile, PrerequisiteCheck::A01);
        trace.at(InputRole::Parent, None);
        stage = "ui-fresh-account-intent"; clock.effect_traced(trace)?;
        account = Some(Account::new_traced(trace)?); let current = account.as_mut().ok_or(Error::State)?;
        let name = String::from_utf16(&current.name[..current.name.len() - 1]).map_err(|_| Error::Unsafe)?;
        let intent = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"role\":\"{}\",\"requestSha256\":\"{}\",\"accountName\":\"{name}\",\"freshAccountIntent\":true,\"fixedNormalUiChildOnly\":true}}\n",
            selected.source, selected.tree, selected.run, role.label(), request_sha);
        trace.at(InputRole::Output, None);
        write_fixture_record_traced(&root.join(role.name("owner-intent.private.json")), intent.as_bytes(), LIMIT, clock.end, trace)?;
        clock.effect_traced(trace)?; stage = "ui-fresh-account";
        trace.at(InputRole::Parent, None);
        current.create_traced(&parent, clock.start, &mut clock.latched, &mut clock.aggregate, trace)?; clock.effect_traced(trace)?;
        account_sha = digest_traced(&current.sid, trace)?;
        trace.prerequisite_check(PrerequisiteCheck::A02);
        stage = "ui-exact-acl"; trace.at(InputRole::Output, Some(files.len() as u8));
        let out = new_directory(&mut creates, &mut files, &output, &mut clock, trace)?; output_index = Some(out);
        for (index, label) in directories {
            // New UI fixture readers inspect native parent IDs/ACLs. Grant
            // read/traverse ONLY on these five task-owned directories, never
            // RUNNER_TEMP, a Windows path, or an inherited general user tree.
            trace.at(InputRole::AclRoot, Some(index as u8));
            acl(&mut files, index, label, FS::FILE_GENERIC_READ | FS::FILE_TRAVERSE,
                &parent, &current.sid, &mut clock, trace, &mut transitions)?;
        }
        trace.at(InputRole::AclArtifact, Some(artifact as u8));
        acl(&mut files, artifact, "artifact", FS::FILE_GENERIC_READ | FS::FILE_GENERIC_EXECUTE,
            &parent, &current.sid, &mut clock, trace, &mut transitions)?;
        let after = files[artifact].stamp_traced(trace)?; selected.app_after_traced(&after.wire(), trace)?; artifact_after = Some(after.clone());
        trace.at(InputRole::AclOutput, Some(out as u8));
        acl(&mut files, out, "normal-ui-output", FS::FILE_GENERIC_READ | FS::FILE_TRAVERSE | FS::FILE_ADD_FILE | FS::FILE_ADD_SUBDIRECTORY,
            &parent, &current.sid, &mut clock, trace, &mut transitions)?;
        if matches!(role, UiRole::ProjectDraft | UiRole::QuitPassive | UiRole::DocumentLoss) {
            stage = "ui-synthetic-project";
            fixture = Some(Fixture::create(role, &output, &mut creates, &mut files, &parent, &current.sid,
                &mut clock, trace, &mut transitions)?);
        }
        trace.prerequisite_check(PrerequisiteCheck::A03);
        stage = "ui-profile-prestate";
        profile = Some(Profile::new_traced(current, trace)?); profile.as_mut().ok_or(Error::State)?.prepare_traced(&mut clock, trace)?;
        clock.effect_traced(trace)?;
        super::super::hosted_tests::actual_elevated_primary_refusal_traced(&mut book, token, trace)?;
        need(parent_user_traced(&mut book, trace)? == parent)?;
        parent_attempted = true; parent_settled = book.prerequisite_settle(trace) == CloseOutcome::Settled && book.settled();
        need(parent_settled)?; clock.effect_traced(trace)?;
        trace.prerequisite_at(PrerequisiteStage::Launch, PrerequisiteCheck::L01);
        stage = "ui-original-create";
        launch = Some(Launch::ui_traced(&selected, &after.wire(), std::str::from_utf8(&raw).map_err(|_| Error::Unsafe)?,
            &output, &root, profile.as_ref(), current, &parent, clock.endpoint_tick, trace)?);
        request = Some(selected);
        launch.as_mut().ok_or(Error::State)?.as_mut().enter_traced(current, clock.start, &mut clock.latched, &mut clock.aggregate, trace)?;
        clock.effect_traced(trace)?; stage = "ui-profile-original-binding";
        profile.as_mut().ok_or(Error::State)?.bind_after_logon_traced(&mut clock, trace)?;
        if role == UiRole::NormalSmoke {
            stage = "ui-normal-smoke";
            smoke = Some(Smoke::new());
            smoke.as_mut().ok_or(Error::State)?.observe(launch.as_ref().ok_or(Error::State)?,
                &request.as_ref().ok_or(Error::State)?.app_version, &mut clock)?;
        }
        trace.prerequisite_check(PrerequisiteCheck::L02);
        smoke_result(smoke.as_ref(), SmokePhase::ObserveClock, SmokeCheck::Clock, clock.effect_traced(trace))
    })();
    let mut observation = trace.prerequisite_current(observation);
    if let Some(current) = account.as_mut() { current.zero(); }
    // Settle the actual original driver before any original process close.
    // Only returned-NULL initial-main acquisition and the pre-action main-HWND
    // scalar read may wait for readiness; a returned stale descendant name may
    // invalidate one current pre-action scan. Other/later/effectful UIA failures
    // remain terminal even if a provider later acts.
    let smoke_settled = smoke.as_mut().is_none_or(|value| value.settle().is_ok());
    if !smoke_settled || matches!(observation, Err(Error::Unknown)) {
        trace.prerequisite_fault(PrerequisiteCheck::L04, Error::Unknown, None, None);
        diagnostic_smoke(stage, launch.as_deref(), true, trace.first, smoke.as_ref());
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    trace.prerequisite_at(PrerequisiteStage::Launch, PrerequisiteCheck::L03);
    if let Some(original) = launch.as_mut() {
        if observation.is_err() { unsafe { original.as_mut().get_unchecked_mut() }.facts.failed = true; }
        original.as_mut().finish_traced(clock.start, &mut clock.aggregate, trace);
        if !original.facts.passed() && observation.is_ok() {
            observation = prerequisite_result!(trace, L03, smoke_result(smoke.as_ref(), SmokePhase::OwnerFinality, SmokeCheck::OwnerResult, Err(Error::Unsafe)));
        }
    }
    trace.prerequisite_check(PrerequisiteCheck::L04);
    if !parent_attempted { parent_settled = book.prerequisite_settle(trace) == CloseOutcome::Settled && book.settled(); }
    if !parent_settled || launch.as_ref().is_some_and(|value| value.facts.unknown || value.facts.created && !value.facts.signaled) {
        trace.prerequisite_fault(PrerequisiteCheck::L04, Error::Unknown, None, None);
        let _ = smoke_result::<()>(smoke.as_ref(), SmokePhase::OwnerFinality,
            if !parent_settled { SmokeCheck::ParentSettlement } else { SmokeCheck::OwnerFinality }, Err(Error::Unknown));
        diagnostic_smoke(stage, launch.as_deref(), true, trace.first, smoke.as_ref());
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    if observation.is_ok() {
        trace.prerequisite_at(PrerequisiteStage::ChildOutput, PrerequisiteCheck::C01);
        observation = (|| -> Result<()> {
            smoke_result(smoke.as_ref(), SmokePhase::OwnerFinality, SmokeCheck::Clock, clock.effect_traced(trace))?;
            stage = "ui-original-exit-result";
            let selected = smoke_result(smoke.as_ref(), SmokePhase::OwnerFinality, SmokeCheck::RequestMissing,
                request.as_ref().ok_or(Error::State))?;
            let result = if role == UiRole::NormalSmoke {
                smoke_result(smoke.as_ref(), SmokePhase::OwnerFinality, SmokeCheck::SmokeFinality,
                    need(smoke.as_ref().is_some_and(Smoke::passed)))?; None
            } else {
                trace.at(InputRole::Output, Some(files.len() as u8));
                let index = input(&mut files, &output.join(role.name("result.private.json")), false,
                    FS::FILE_GENERIC_READ, &mut clock, trace)?;
                let raw = files[index].read_traced(LIMIT, trace)?;
                let accepted = selected.accept_child_traced(&raw, &request_sha, &account_sha, trace)?;
                if role == UiRole::Prerequisite { available = Some(accepted); } else { need(accepted)?; }
                child_sha = Some(digest_traced(&raw, trace)?); Some(index)
            };
            trace.prerequisite_check(PrerequisiteCheck::C02);
            let index = smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::ArtifactIndex,
                artifact_index.ok_or(Error::State))?;
            trace.at(InputRole::Artifact, Some(index as u8));
            let stamp = smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::ArtifactStamp, files[index].stamp_traced(trace))?;
            let expected = smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::ArtifactExpected,
                artifact_after.as_ref().ok_or(Error::State))?;
            smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::ArtifactUnchanged, need(stamp == *expected))?;
            for (index, stamp) in &input_stamps {
                trace.at(InputRole::Binding, Some(*index as u8));
                smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::Clock, clock.effect_traced(trace))?;
                let current = smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::InputStamp, files[*index].stamp_traced(trace))?;
                smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::InputUnchanged, need(current == *stamp))?;
            }
            trace.prerequisite_check(PrerequisiteCheck::C03);
            stage = "ui-output-poststate";
            smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::OutputInventory,
                output_poststate(&mut inventory, &mut files, &mut fixture, role, &output,
                    smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::OutputIndex,
                        output_index.ok_or(Error::State))?, result, &mut clock, trace, smoke.as_ref()))?;
            smoke_result(smoke.as_ref(), SmokePhase::OutputPoststate, SmokeCheck::Clock, clock.effect_traced(trace))
        })();
        observation = trace.prerequisite_current(observation);
    }
    trace.prerequisite_at(PrerequisiteStage::Settlement, PrerequisiteCheck::S01);
    let inventory_settled = inventory.prerequisite_settle(trace) == CloseOutcome::Settled && inventory.settled();
    if !inventory_settled || matches!(observation, Err(Error::Unknown)) || !close_files_traced(&mut files, trace) {
        trace.prerequisite_fault(PrerequisiteCheck::S01, Error::Unknown, None, None);
        let _ = smoke_result::<()>(smoke.as_ref(), SmokePhase::OutputPoststate,
            if !inventory_settled { SmokeCheck::InventorySettlement }
            else if matches!(observation, Err(Error::Unknown)) { SmokeCheck::OwnerFinality } else { SmokeCheck::InputClose },
            Err(Error::Unknown));
        diagnostic_smoke(stage, launch.as_deref(), true, trace.first, smoke.as_ref());
        loop { std::thread::park(); std::hint::black_box((&mut smoke, &mut launch, &mut profile, &mut account,
            &mut book, &mut inventory, &mut files, &mut creates, &request, &fixture)); }
    }
    trace.prerequisite_check(PrerequisiteCheck::S02);
    if smoke_result(smoke.as_ref(), SmokePhase::OwnerFinality, SmokeCheck::Clock, clock.effect_traced(trace)).is_err() {
        observation = Err(Error::Unsafe);
    }
    if observation.is_err() {
        if profile.as_mut().is_some_and(|value| smoke_result(smoke.as_ref(), SmokePhase::Retirement,
            SmokeCheck::ProfileSettlement, value.settle_traced(trace)).is_err()) {
            diagnostic_smoke("ui-profile-original-close", launch.as_deref(), true, trace.first, smoke.as_ref());
            loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
        }
        if role != UiRole::Prerequisite { diagnostic_smoke(stage, launch.as_deref(), false, trace.first, smoke.as_ref()); }
        return observation; // Failed process/driver never permits profile/account deletion.
    }
    trace.prerequisite_at(PrerequisiteStage::Retirement, PrerequisiteCheck::R01);
    stage = "ui-profile-retirement";
    let retirement = smoke_result(smoke.as_ref(), SmokePhase::Retirement, SmokeCheck::ProfileRetirement,
        prerequisite_result!(trace, R01, profile.as_mut().ok_or(Error::State))?.retire_traced(&mut clock, trace));
    let retirement = trace.prerequisite_result(PrerequisiteCheck::R01, retirement);
    if retirement.is_err() {
        if matches!(retirement, Err(Error::Unknown)) || profile.as_mut().is_some_and(|value| smoke_result(smoke.as_ref(),
            SmokePhase::Retirement, SmokeCheck::ProfileSettlement, value.settle_traced(trace)).is_err()) {
            diagnostic_smoke(stage, launch.as_deref(), true, trace.first, smoke.as_ref());
            loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
        }
        return retirement;
    }
    trace.prerequisite_check(PrerequisiteCheck::R02);
    let current = prerequisite_result!(trace, R02, account.as_mut().ok_or(Error::State))?;
    let retirement = smoke_result(smoke.as_ref(), SmokePhase::Retirement, SmokeCheck::AccountRetirement,
        current.retire_traced(clock.start, &mut clock.latched, &mut clock.aggregate, trace));
    let retirement = trace.prerequisite_result(PrerequisiteCheck::R02, retirement);
    if matches!(retirement, Err(Error::Unknown)) {
        diagnostic_smoke("ui-account-retirement", launch.as_deref(), true, trace.first, smoke.as_ref());
        loop { std::thread::park(); std::hint::black_box((&mut profile, &mut account, &mut launch, &mut files, &mut smoke)); }
    }
    retirement?; clock.effect_traced(trace)?;
    trace.prerequisite_at(PrerequisiteStage::Final, PrerequisiteCheck::Z01);
    let current = prerequisite_result!(trace, Z01, account.as_ref().ok_or(Error::State))?;
    let profile = prerequisite_result!(trace, Z01, profile.as_ref().ok_or(Error::State))?;
    let original = prerequisite_result!(trace, Z01, launch.as_ref().ok_or(Error::State))?;
    let selected = prerequisite_result!(trace, Z01, request.as_ref().ok_or(Error::State))?;
    prerequisite_result!(trace, Z01, need(current.removed && original.facts.passed() && files.iter().all(OriginalFile::is_closed)
        && profile.prestate && profile.exact && profile.hives_unloaded && profile.delete_entered
        && profile.delete_return != 0 && profile.poststate && profile.settled && !profile.unknown
        && fixture.as_ref().is_none_or(|value| value.verified)))?;
    trace.prerequisite_check(PrerequisiteCheck::Z02);
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
    prerequisite_result!(trace, Z02, need(record.len() <= OWNER_LIMIT))?; clock.effect_traced(trace)?;
    trace.at(InputRole::Output, None);
    write_fixture_record_traced(&root.join(role.name("owner-result.private.json")), record.as_bytes(), OWNER_LIMIT, clock.end, trace)?;
    // A pre-close record is never an owner-exit receipt; the separate finalizer
    // still requires this foreground libtest's original zero exit/step closure.
    clock.effect_traced(trace)
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

    fn prerequisite_trace(stage: PrerequisiteStage, check: PrerequisiteCheck) -> InputTrace {
        let mut trace = InputTrace::prerequisite_only(true);
        trace.prerequisite_at(stage, check);
        trace.at(InputRole::Parent, None);
        trace
    }
    fn prerequisite_first(trace: &InputTrace) -> PrerequisiteFault {
        trace.prerequisite.expect("enabled DATA").first.expect("actual rejecting decision")
    }
    fn prerequisite_bindings() -> PrerequisiteBindings<'static> {
        PrerequisiteBindings::new(Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), Some("99999999999999999999"))
    }
    struct PrerequisiteOutput {
        write: PrerequisiteWrite, flush: PrerequisiteFlush,
        calls: Vec<&'static str>, bytes: Vec<u8>,
    }
    impl PrerequisiteOutput {
        fn new(write: PrerequisiteWrite, flush: PrerequisiteFlush) -> Self {
            Self { write, flush, calls: Vec::new(), bytes: Vec::new() }
        }
    }
    impl Write for PrerequisiteOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls.push("write"); self.bytes.extend_from_slice(bytes);
            match self.write {
                PrerequisiteWrite::Full => Ok(bytes.len()), PrerequisiteWrite::Short => Ok(bytes.len() - 1),
                PrerequisiteWrite::Zero => Ok(0), PrerequisiteWrite::Overreported => Ok(bytes.len() + 1),
                PrerequisiteWrite::Interrupted => Err(std::io::ErrorKind::Interrupted.into()),
                PrerequisiteWrite::Error => Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.calls.push("flush");
            match self.flush {
                PrerequisiteFlush::Ok => Ok(()),
                PrerequisiteFlush::Interrupted => Err(std::io::ErrorKind::Interrupted.into()),
                PrerequisiteFlush::Error => Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
    fn prerequisite_created_process() -> Result<ProcessFacts> {
        let mut facts = ProcessFacts::new();
        facts.begin()?; facts.creation(true, 0, (11, 12, 17, 18), false)?;
        Ok(facts)
    }

    #[test]
    fn prerequisite_first_fault_covers_return_routes_and_expected_negatives() -> Result<()> {
        use PrerequisiteCheck as C; use PrerequisiteStage as G;
        let mut disabled = InputTrace::default();
        assert_eq!(disabled.prerequisite_result::<()>(C::E02, Err(Error::State)), Err(Error::State));
        assert!(disabled.prerequisite.is_none());
        // Exercise real rejecting helper Results across the finite owner families,
        // not just check-enum enumeration. No helper below can enter an OS API.
        let mut entry = prerequisite_trace(G::Entry, C::E02);
        assert!(fixed_path_traced("not-an-absolute-path", &mut entry).is_err());
        assert_eq!((prerequisite_first(&entry).stage, prerequisite_first(&entry).check), (G::Entry, C::F03));
        let mut parent = prerequisite_trace(G::ParentInput, C::P04);
        assert!(UiRequest::parse_traced(b"malformed\n", &mut parent).is_err());
        assert_eq!((prerequisite_first(&parent).stage, prerequisite_first(&parent).check), (G::ParentInput, C::Q01));
        let mut account = prerequisite_trace(G::AccountProfile, C::A02);
        assert!(AclImage::parse_traced(&[], &mut account).is_err());
        assert_eq!((prerequisite_first(&account).stage, prerequisite_first(&account).check), (G::AccountProfile, C::G01));
        let mut launch = prerequisite_trace(G::Launch, C::L03);
        let mut facts = ProcessFacts::new();
        let original = facts.wait(F::WAIT_FAILED, false);
        assert_eq!(prerequisite_process_decision(&mut launch, C::D04, original, (false, false), &facts, None), Err(Error::State));
        assert_eq!((prerequisite_first(&launch).stage, prerequisite_first(&launch).check), (G::Launch, C::D04));
        let request = request(); let digest = "a".repeat(64); let sid = "b".repeat(64);
        let mut child = prerequisite_trace(G::ChildOutput, C::C01);
        assert!(request.accept_child_traced(b"not-json", &digest, &sid, &mut child).is_err());
        assert_eq!((prerequisite_first(&child).stage, prerequisite_first(&child).check), (G::ChildOutput, C::Q05));
        let mut settlement = prerequisite_trace(G::Settlement, C::S01);
        let mut key = Key::new(R::HKEY_LOCAL_MACHINE, "inert"); key.state = SlotState::Unknown;
        assert_eq!(key.close_traced(&mut settlement), Err(Error::Unknown));
        assert_eq!((prerequisite_first(&settlement).stage, prerequisite_first(&settlement).check), (G::Settlement, C::K03));
        let fixture = InertProfile::new()?;
        let mut retirement = prerequisite_trace(G::Retirement, C::R01);
        assert_eq!(fixture.0.absence_permitted_traced(AbsenceEpoch::AfterDeletion, &mut retirement), Err(Error::Unsafe));
        assert_eq!((prerequisite_first(&retirement).stage, prerequisite_first(&retirement).check), (G::Retirement, C::V03));
        let mut finality = prerequisite_trace(G::Final, C::Z01);
        assert_eq!(finality.prerequisite_result(C::Z01, need(facts.passed())), Err(Error::Unsafe));
        assert_eq!((prerequisite_first(&finality).stage, prerequisite_first(&finality).check), (G::Final, C::Z01));
        for trace in [&entry, &parent, &account, &launch, &child, &settlement, &retirement, &finality] {
            assert!(prerequisite_first(trace).native.is_none());
        }
        let mut expected = prerequisite_trace(G::ParentInput, C::P01);
        expected.record(InputCheck::ParentPrimary, Some(InputStatus::Win32(5)));
        assert!(expected.prerequisite.expect("enabled").first.is_none()); // Nonzero alone is not failure.
        for error in [Error::Unsafe, Error::State] {
            let mut local = expected.prerequisite_staged();
            let original = local.prerequisite_result::<()>(C::NB11, Err(error));
            assert!(expected.prerequisite_expected(C::P01, original, error, local));
            assert!(expected.prerequisite.expect("enabled").first.is_none());
        }
        let unavailable = request.probe_result(&digest, &sid, Some("interactive-desktop"), None, None)?;
        assert_eq!(request.accept_child_traced(unavailable.as_bytes(), &digest, &sid, &mut expected), Ok(false));
        assert!(expected.prerequisite.expect("enabled").first.is_none());
        let mut local = expected.prerequisite_staged();
        let native = PrerequisiteNative::boolean(PrerequisiteApi::OpenThreadToken, PrerequisiteSelector::None, 0, Some(5));
        let original = local.prerequisite_native_result::<()>(C::NB02, Err(Error::Unavailable), native, None);
        assert!(!expected.prerequisite_expected(C::P01, original, Error::Unsafe, local));
        let first = prerequisite_first(&expected);
        assert_eq!((first.error, first.native), (Error::Unavailable, native));
        let mut local = expected.prerequisite_staged();
        let original = local.prerequisite_result::<()>(C::HT01, Err(Error::State));
        assert!(expected.prerequisite_expected(C::P02, original, Error::State, local));
        assert_eq!(prerequisite_first(&expected), first); // Discarding local never clears parent.
        let mut unexpected_ok = prerequisite_trace(G::ParentInput, C::P01);
        let local = unexpected_ok.prerequisite_staged();
        assert!(!unexpected_ok.prerequisite_expected(C::P01, Ok(()), Error::Unsafe, local));
        assert_eq!(prerequisite_first(&unexpected_ok).error, Error::Unsafe);
        assert!(prerequisite_first(&unexpected_ok).native.is_none());
        let mut escape = InputTrace::prerequisite_only(true);
        let mut output = PrerequisiteOutput::new(PrerequisiteWrite::Full, PrerequisiteFlush::Ok);
        assert_eq!(prerequisite_returned(UiRole::Prerequisite, Err(Error::Bounds), &mut escape,
            prerequisite_bindings(), &mut output).0, Err(Error::Bounds));
        assert_eq!((prerequisite_first(&escape).stage, prerequisite_first(&escape).check), (G::Escape, C::U01));
        Ok(())
    }

    #[test]
    fn prerequisite_first_fault_survives_secondary_clock_and_status_reuse() -> Result<()> {
        use PrerequisiteCheck as C; use PrerequisiteStage as G;
        let mut key = Key::new(R::HKEY_LOCAL_MACHINE, "inert");
        key.status = 5;
        let mut file = OriginalFile::new(Path::new(r"C:\inert\file"), false)?;
        file.body().error = 32;
        let mut buffer = NetBuffer::new(); buffer.status = u32::MAX;
        let rows = [
            (C::K02, PrerequisiteNative::registry(PrerequisiteApi::RegQueryValueExW, PrerequisiteSelector::ProfileImagePath, key.status)),
            (C::F05, PrerequisiteNative::boolean(PrerequisiteApi::ReadFile, PrerequisiteSelector::None, 0, Some(file.body().error))),
            (C::N04, PrerequisiteNative::net(PrerequisiteApi::NetUserGetInfo, PrerequisiteSelector::UserInfo23, buffer.status)),
        ];
        for (check, native) in rows {
            let mut trace = prerequisite_trace(G::AccountProfile, check);
            assert_eq!(trace.prerequisite_native_result::<()>(check, Err(Error::Unavailable), native, None), Err(Error::Unavailable));
            let first = prerequisite_first(&trace);
            key.status = 0; file.body().error = 0; buffer.status = 0; buffer.release_status = 0;
            trace.prerequisite_clock(true);
            assert_eq!(trace.prerequisite_result::<()>(C::T01, Err(Error::Unsafe)), Err(Error::Unsafe));
            assert_eq!(trace.prerequisite_native_result::<()>(C::N02, Err(Error::Unknown),
                PrerequisiteNative::net(PrerequisiteApi::NetApiBufferFree, PrerequisiteSelector::None, 5), None), Err(Error::Unknown));
            assert_eq!(prerequisite_first(&trace), first);
            let mut out = [0u8; PREREQUISITE_FAULT_BUFFER_BYTES];
            let n = prerequisite_fault_frame(trace.prerequisite.expect("enabled"), Error::Unsafe, prerequisite_bindings(), &mut out).expect("closed frame");
            let text = std::str::from_utf8(&out[..n]).expect("ASCII");
            assert!(text.contains(";first=Unavailable;returned=Unsafe;"));
            assert!(text.contains(";clock=last-latched;"));
        }
        // The original short-circuit clock rejects before any query predicate:
        // a later native-looking scalar must not become the primary.
        let mut trace = prerequisite_trace(G::Launch, C::K02);
        let right_hand = Cell::new(false);
        let decision = (|| -> Result<()> {
            trace.prerequisite_result(C::T01, need(false))?;
            right_hand.set(true); need(false)
        })();
        assert_eq!(decision, Err(Error::Unsafe)); assert!(!right_hand.get());
        let _ = trace.prerequisite_native_result::<()>(C::K02, Err(Error::Unsafe),
            PrerequisiteNative::registry(PrerequisiteApi::RegQueryValueExW, PrerequisiteSelector::ProfileImagePath, 5), None);
        assert_eq!(prerequisite_first(&trace).check, C::T01);
        assert!(prerequisite_first(&trace).native.is_none());
        Ok(())
    }

    #[test]
    fn prerequisite_native_statuses_require_original_completed_observations() -> Result<()> {
        use PrerequisiteCheck as C; use PrerequisiteStage as G;
        // These pairs represent returned scalar DATA, never native invocations.
        for (call, returned, api, selector) in [
            (Call::ThreadToken(0), Returned::Boolean(0, 5), PrerequisiteApi::OpenThreadToken, PrerequisiteSelector::None),
            (Call::Info(FS::FileIdInfo, 0), Returned::Boolean(0, u32::MAX), PrerequisiteApi::GetFileInformationByHandleEx, PrerequisiteSelector::FileIdInfo),
            (Call::Mapping, Returned::Count(0, 5), PrerequisiteApi::QueryDosDeviceW, PrerequisiteSelector::None),
            (Call::Open(0), Returned::Nt(i32::MIN), PrerequisiteApi::NtCreateFile, PrerequisiteSelector::None),
            (Call::VolumeDevice, Returned::Nt(i32::MAX), PrerequisiteApi::NtQueryVolumeInformationFile, PrerequisiteSelector::FileFsDeviceInformation),
            (Call::Token(S::TokenVirtualizationEnabled), Returned::Boolean(0, 5), PrerequisiteApi::GetTokenInformation, PrerequisiteSelector::TokenVirtualizationEnabled),
        ] {
            let native = prerequisite_native_pair(call, returned).expect("actual rejecting pair");
            assert_eq!((native.api, native.selector), (api, selector)); assert!(native.valid());
            let mut book = NativeBook::new();
            let mut trace = prerequisite_trace(G::ParentInput, C::NB10);
            let original = book.prerequisite_observe(&mut trace, C::NB10, |book| {
                book.prerequisite_capture(call, returned); Err::<(), _>(Error::Unavailable)
            });
            assert_eq!(original, Err(Error::Unavailable)); assert_eq!(prerequisite_first(&trace).native, Some(native));
        }
        for (call, returned) in [
            (Call::ThreadToken(0), Returned::Boolean(0, F::ERROR_NO_TOKEN)),
            (Call::Entries, Returned::Boolean(0, F::ERROR_NO_MORE_FILES)),
            (Call::Architecture, Returned::Boolean(-1, u32::MAX)),
            (Call::Mapping, Returned::Count(12, u32::MAX)),
            (Call::Open(0), Returned::Nt(0)),
            (Call::Architecture, Returned::Nt(-1)), // Wrong pair, not merely a signed integer.
            (Call::Open(0), Returned::Boolean(0, 5)),
            (Call::Info(-1, 0), Returned::Boolean(0, 5)),
            (Call::Token(-1), Returned::Boolean(0, 5)),
            (Call::Folder, Returned::Hresult(i32::MIN)),
        ] { assert!(prerequisite_native_pair(call, returned).is_none()); }
        for (call, check, admission, operation) in [
            (Call::DriveType, C::NB05, AdmissionCheck::DriveType, AdmissionOp::Mapping),
            (Call::FileType, C::NB07, AdmissionCheck::FileType, AdmissionOp::Metadata),
        ] {
            let mut book = NativeBook::new();
            let mut trace = prerequisite_trace(G::AccountProfile, check);
            book.prerequisite_enable_admission(&trace);
            let original = book.prerequisite_observe(&mut trace, check, |book| {
                book.prerequisite_capture(call, Returned::Scalar(u32::MAX));
                book.admission.at(operation).need(false, admission)
            });
            assert_eq!(original, Err(Error::Unsafe));
            let first = prerequisite_first(&trace);
            assert_eq!((first.check, first.native, first.detail), (check, None, Some(PrerequisiteDetail::Admission(admission))));
        }
        let mut book = NativeBook::new();
        book.first_unavailable = Some((Call::Architecture, Returned::Boolean(0, 5)));
        book.prerequisite_capture(Call::Architecture, Returned::Boolean(0, 5));
        let mut trace = prerequisite_trace(G::ParentInput, C::NB01);
        assert_eq!(book.prerequisite_observe(&mut trace, C::NB01, |_| Err::<(), _>(Error::State)), Err(Error::State));
        assert!(book.prerequisite_returned.get().is_none()); assert!(book.first_unavailable.is_some());
        assert!(prerequisite_first(&trace).native.is_none()); // Unentered guard cannot inherit earlier status.
        let mut descriptor = PrerequisiteNative::boolean(PrerequisiteApi::InitializeSecurityDescriptor, PrerequisiteSelector::None, 0, None).expect("BOOL");
        assert!(descriptor.valid()); descriptor.status = PrerequisiteStatus::Win32; descriptor.code = Some(5);
        assert!(!descriptor.valid()); // These descriptor calls never read ambient LastError.
        for value in [i32::MIN, i32::MAX] {
            assert!(PrerequisiteNative::nt(PrerequisiteApi::BCryptGenRandom, PrerequisiteSelector::None, value).expect("NT").valid());
            let error = std::io::Error::from_raw_os_error(value);
            let fact = PrerequisiteNative::io(PrerequisiteApi::CurrentExe, &error).expect("returned io error");
            assert_eq!(fact.code, Some(i64::from(value))); assert!(fact.valid());
        }
        let no_os = std::io::Error::from(std::io::ErrorKind::Other);
        let fact = PrerequisiteNative::io(PrerequisiteApi::CurrentDir, &no_os).expect("returned io error");
        assert_eq!((fact.status, fact.code), (PrerequisiteStatus::None, None)); assert!(fact.valid());
        assert!(PrerequisiteNative::net(PrerequisiteApi::NetUserDel, PrerequisiteSelector::None, u32::MAX).expect("NetAPI").valid());
        assert_eq!(PrerequisiteNative::wait(PrerequisiteSelector::FirstWait, F::WAIT_TIMEOUT, 5).expect("wait").code, None);
        assert_eq!(PrerequisiteNative::wait(PrerequisiteSelector::SettleWait, F::WAIT_FAILED, 5).expect("wait").code, Some(5));
        assert!(PrerequisiteNative::boolean(PrerequisiteApi::ReadFile, PrerequisiteSelector::None, 1, Some(5)).is_none());
        assert!(PrerequisiteNative::exit(0).is_none());
        // Absence's initial STATUS_PENDING and close-zero are not observed returns.
        let mut fixture = InertProfile::new()?;
        let native = &fixture.0.native;
        let [before, after] = &mut fixture.0.absence;
        let frame = unsafe { before.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
        let other = after.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        let mut absent = prerequisite_trace(G::AccountProfile, C::V04);
        assert_eq!(frame.observe_return_traced(native, other, false, &mut absent), Err(Error::State));
        assert!(prerequisite_first(&absent).native.is_none());
        let mut close = prerequisite_trace(G::Settlement, C::B03);
        assert_eq!(frame.observe_close_traced(false, &mut close), Err(Error::State));
        assert!(prerequisite_first(&close).native.is_none());
        Ok(())
    }

    #[test]
    fn prerequisite_frame_is_closed_bounded_and_binding_exact() {
        use PrerequisiteCheck as C; use PrerequisiteStage as G;
        let mut trace = prerequisite_trace(G::AccountProfile, C::N03);
        let _ = trace.prerequisite_native_result::<()>(C::N03, Err(Error::Unavailable),
            PrerequisiteNative::nt(PrerequisiteApi::BCryptGenRandom, PrerequisiteSelector::None, i32::MIN),
            Some(PrerequisiteDetail::Admission(AdmissionCheck::ManifestReportedSize)));
        let mut record = trace.prerequisite.expect("enabled");
        let mut output = [0u8; PREREQUISITE_FAULT_BUFFER_BYTES];
        for native in [
            PrerequisiteNative::nt(PrerequisiteApi::BCryptGenRandom, PrerequisiteSelector::None, i32::MIN),
            PrerequisiteNative::net(PrerequisiteApi::NetUserGetLocalGroups, PrerequisiteSelector::LocalGroups0, u32::MAX),
            PrerequisiteNative::boolean(PrerequisiteApi::GetFileInformationByHandleEx, PrerequisiteSelector::FileIdExtdDirectoryInfo, 0, Some(u32::MAX)),
            PrerequisiteNative::boolean(PrerequisiteApi::GetTokenInformation, PrerequisiteSelector::TokenVirtualizationEnabled, 0, Some(u32::MAX)),
            PrerequisiteNative::wait(PrerequisiteSelector::SettleWait, F::WAIT_FAILED, u32::MAX),
            PrerequisiteNative::exit(u32::MAX), None,
        ] {
            record.first.as_mut().expect("first").native = native;
            let length = prerequisite_fault_frame(record, Error::Unavailable, prerequisite_bindings(), &mut output).expect("legal maxima");
            assert!(length <= PREREQUISITE_FAULT_FRAME_MAX_BYTES && length <= 664);
            let text = std::str::from_utf8(&output[..length]).expect("ASCII").to_owned();
            assert!(text.starts_with("\nMRK_WINDOWS_UI_PREREQUISITE_FAULT_V1=source=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;"));
            assert!(text.contains(";run=99999999999999999999;attempt=1;"));
            assert!(text.ends_with(";coverage=mapped;end=1\n"));
            let payload = text.trim_matches('\n').strip_prefix(PREREQUISITE_FAULT_PREFIX).expect("prefix");
            assert_eq!(payload.split(';').map(|part| part.split_once('=').expect("pair").0).collect::<Vec<_>>(),
                ["source", "tree", "run", "attempt", "owner", "mode", "stage", "check", "detail", "first", "returned",
                 "api", "selector", "kind", "value", "status", "code", "clock", "coverage", "end"]);
            for bound in [0, 1, length - 1] {
                assert!(prerequisite_fault_frame(record, Error::Unavailable, prerequisite_bindings(), &mut output[..bound]).is_none());
            }
        }
        let unavailable = PrerequisiteBindings::new(Some(r"C:\private-account"), Some("0000000000000000000000000000000000000000"), Some("01"));
        let length = prerequisite_fault_frame(record, Error::Unsafe, unavailable, &mut output).expect("explicit unavailable");
        let text = std::str::from_utf8(&output[..length]).expect("ASCII");
        assert!(text.contains("source=unavailable;tree=unavailable;run=unavailable;"));
        for private in ["private-account", "C:\\", "password", "handle=", "pid=", "accountName"] { assert!(!text.contains(private)); }
        for bad in ["", "0", "01", "+1", "-1", "1\n", "100000000000000000000", "1;end=1"] {
            assert_eq!(PrerequisiteBindings::new(None, None, Some(bad)).run, "unavailable");
        }
        let mut invalid = record;
        invalid.first.as_mut().expect("first").native = Some(PrerequisiteNative {
            api: PrerequisiteApi::GetExitCodeProcess, selector: PrerequisiteSelector::None,
            kind: PrerequisiteKind::Exit, value: Some(i64::from(u32::MAX) + 1),
            status: PrerequisiteStatus::None, code: None });
        assert!(prerequisite_fault_frame(invalid, Error::Unsafe, prerequisite_bindings(), &mut output).is_none());
        invalid = record; invalid.first.as_mut().expect("first").check = C::U01;
        assert!(prerequisite_fault_frame(invalid, Error::Unsafe, prerequisite_bindings(), &mut output).is_none());
        let forged = PrerequisiteBindings { source: "private", tree: "unavailable", run: "unavailable" };
        assert!(prerequisite_fault_frame(record, Error::Unsafe, forged, &mut output).is_none());
    }

    #[test]
    fn prerequisite_diagnostic_sink_checks_one_write_one_flush_without_outcome_change() {
        for write in [PrerequisiteWrite::Full, PrerequisiteWrite::Short, PrerequisiteWrite::Zero,
            PrerequisiteWrite::Interrupted, PrerequisiteWrite::Error, PrerequisiteWrite::Overreported] {
            for flush in [PrerequisiteFlush::Ok, PrerequisiteFlush::Interrupted, PrerequisiteFlush::Error] {
                let mut trace = prerequisite_trace(PrerequisiteStage::Entry, PrerequisiteCheck::E02);
                let original = trace.prerequisite_result::<()>(PrerequisiteCheck::E02, Err(Error::State));
                let first = prerequisite_first(&trace);
                let mut output = PrerequisiteOutput::new(write, flush);
                let (returned, delivery) = prerequisite_returned(UiRole::Prerequisite, original, &mut trace, prerequisite_bindings(), &mut output);
                assert_eq!(returned, original); assert_eq!(prerequisite_first(&trace), first);
                assert_eq!(delivery, PrerequisiteDelivery::Attempted { write, flush });
                assert_eq!(delivery.locally_complete(), write == PrerequisiteWrite::Full && flush == PrerequisiteFlush::Ok);
                assert_eq!(output.calls, ["write", "flush"]);
                assert!(output.bytes.starts_with(b"\nMRK_WINDOWS_UI_PREREQUISITE_FAULT_V1="));
                assert!(output.bytes.ends_with(b";end=1\n"));
            }
        }
        let mut trace = prerequisite_trace(PrerequisiteStage::Entry, PrerequisiteCheck::E02);
        let original = trace.prerequisite_result::<()>(PrerequisiteCheck::E02, Err(Error::State));
        let mut output = PrerequisiteOutput::new(PrerequisiteWrite::Full, PrerequisiteFlush::Ok);
        let invalid = PrerequisiteBindings { source: "not-a-binding", tree: "unavailable", run: "1" };
        let (returned, delivery) = prerequisite_returned(UiRole::Prerequisite, original, &mut trace, invalid, &mut output);
        assert_eq!(returned, original); assert_eq!(delivery, PrerequisiteDelivery::EncodingFailed);
        assert!(output.calls.is_empty() && output.bytes.is_empty());
    }

    #[test]
    fn prerequisite_return_guard_keeps_unknown_and_deadline_semantics() -> Result<()> {
        for (role, original) in [(UiRole::Prerequisite, Ok(())), (UiRole::NormalSmoke, Err(Error::Unknown)),
            (UiRole::ProjectDraft, Err(Error::Unavailable))] {
            let mut trace = InputTrace::prerequisite_only(role == UiRole::Prerequisite);
            let mut output = PrerequisiteOutput::new(PrerequisiteWrite::Full, PrerequisiteFlush::Ok);
            let (returned, delivery) = prerequisite_returned(role, original, &mut trace, prerequisite_bindings(), &mut output);
            assert_eq!(returned, original); assert_eq!(delivery, PrerequisiteDelivery::NotNeeded);
            assert!(output.calls.is_empty() && output.bytes.is_empty());
        }
        for clock in [PrerequisiteClock::NotCreated, PrerequisiteClock::LastUnlatched, PrerequisiteClock::LastLatched] {
            let mut trace = prerequisite_trace(PrerequisiteStage::Entry, PrerequisiteCheck::E03);
            let mut latched = false;
            if clock != PrerequisiteClock::NotCreated {
                let elapsed = if clock == PrerequisiteClock::LastLatched { Duration::from_secs(NATIVE_SECONDS) } else { Duration::ZERO };
                let _ = next_effect(elapsed, &mut latched); trace.prerequisite_clock(latched);
                if latched { assert_eq!(next_effect(Duration::ZERO, &mut latched), Err(Error::Unsafe)); }
            }
            let error = std::io::Error::from_raw_os_error(5);
            let original = trace.prerequisite_native_result::<()>(PrerequisiteCheck::E03, Err(Error::Unavailable),
                PrerequisiteNative::io(PrerequisiteApi::CurrentDir, &error), None);
            let mut output = PrerequisiteOutput::new(PrerequisiteWrite::Error, PrerequisiteFlush::Error);
            let (returned, _) = prerequisite_returned(UiRole::Prerequisite, original, &mut trace, prerequisite_bindings(), &mut output);
            assert_eq!(returned, original); assert_eq!(output.calls, ["write", "flush"]);
            assert_eq!(trace.prerequisite.expect("enabled").clock, clock);
            assert!(std::str::from_utf8(&output.bytes).expect("ASCII").contains(&format!(";clock={};", clock.label())));
        }
        // Pending ownership has no original body return to give the guard.
        // Neither a prior first fault nor diagnostic DATA settles that original.
        let mut fixture = InertProfile::new()?;
        let native = &fixture.0.native; let [before, after] = &mut fixture.0.absence;
        let frame = unsafe { before.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
        let other = after.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        frame.claim()?; frame.begin()?;
        let mut trace = prerequisite_trace(PrerequisiteStage::AccountProfile, PrerequisiteCheck::B02);
        let mut output = PrerequisiteOutput::new(PrerequisiteWrite::Full, PrerequisiteFlush::Ok);
        assert_eq!(frame.observe_return_traced(native, other, true, &mut trace), Err(Error::Unknown));
        assert_eq!(frame.begin_close(), Err(Error::Unknown));
        assert!(frame.unresolved() && !frame.settled());
        assert!(output.calls.is_empty()); // No forced body return and no sink attempt.
        // If and only if an outer body genuinely returned Unknown, the guard
        // itself still cannot change it into another Error or native cleanup.
        let (returned, _) = prerequisite_returned(UiRole::Prerequisite, Err(Error::Unknown), &mut trace, prerequisite_bindings(), &mut output);
        assert_eq!(returned, Err(Error::Unknown)); assert!(frame.unresolved() && !frame.settled());
        Ok(())
    }

    #[test]
    fn prerequisite_helper_decisions_preserve_native_control_flow() -> Result<()> {
        use PrerequisiteCheck as C; use PrerequisiteStage as G;
        let mut facts = prerequisite_created_process()?;
        let mut trace = prerequisite_trace(G::Launch, C::D04);
        let before = (facts.failed, facts.unknown);
        let original = facts.wait(F::WAIT_TIMEOUT, false);
        assert_eq!(prerequisite_process_decision(&mut trace, C::D04, original, before, &facts,
            PrerequisiteNative::wait(PrerequisiteSelector::FirstWait, F::WAIT_TIMEOUT, u32::MAX)), Err(Error::Unsafe));
        assert!(facts.failed && !facts.unknown && !facts.signaled);
        let first = prerequisite_first(&trace); facts.begin_terminate()?;
        assert_eq!(facts.wait(F::WAIT_OBJECT_0, true), Ok(()));
        assert_eq!(prerequisite_first(&trace), first); assert!(facts.terminated && !facts.passed());
        let mut exited = prerequisite_created_process()?; exited.wait(F::WAIT_OBJECT_0, false)?;
        let before = (exited.failed, exited.unknown);
        let mut trace = prerequisite_trace(G::Launch, C::D05);
        let original = exited.exited(true, 37);
        assert_eq!(prerequisite_process_decision(&mut trace, C::D05, original, before, &exited, PrerequisiteNative::exit(37)), Ok(()));
        assert!(exited.failed && !exited.unknown); assert_eq!(prerequisite_first(&trace).error, Error::Unsafe);
        assert_eq!(prerequisite_first(&trace).native.expect("actual exit").kind, PrerequisiteKind::Exit);
        let mut guarded = prerequisite_trace(G::Launch, C::D05);
        let original = exited.exited(false, u32::MAX); // Repeat is State, not a failed query.
        assert_eq!(prerequisite_process_decision(&mut guarded, C::D05, original, (true, false), &exited,
            PrerequisiteNative::boolean(PrerequisiteApi::GetExitCodeProcess, PrerequisiteSelector::None, 0, Some(5))), Err(Error::State));
        assert!(prerequisite_first(&guarded).native.is_none());
        exited.begin_close(true)?;
        let before = (exited.failed, exited.unknown); let original = exited.closed(true, false);
        let _ = prerequisite_process_decision(&mut trace, C::D05, original, before, &exited,
            PrerequisiteNative::boolean(PrerequisiteApi::CloseHandle, PrerequisiteSelector::ThreadClose, 0, Some(6)));
        assert!(exited.unknown); assert_eq!(exited.thread, SlotState::Unknown);
        assert_eq!(prerequisite_first(&trace).native.expect("first exit").value, Some(37));
        let mut buffer = NetBuffer::new(); buffer.status = NM::NERR_UserNotFound;
        let mut trace = prerequisite_trace(G::AccountProfile, C::N02);
        assert_eq!(buffer.free_traced(&mut trace), Ok(())); // Precise absence: no native free.
        assert!(buffer.released && buffer.release_attempted && trace.prerequisite.expect("enabled").first.is_none());
        assert_eq!(buffer.free_traced(&mut trace), Err(Error::State));
        assert!(prerequisite_first(&trace).native.is_none());
        let mut range = prerequisite_trace(G::AccountProfile, C::N01);
        assert!(buffer.range_traced(null(), 1, &mut range).is_err());
        assert_eq!(prerequisite_first(&range).check, C::N01);
        let mut file = OriginalFile::new(Path::new(r"C:\inert\file"), false)?;
        let mut trace = prerequisite_trace(G::AccountProfile, C::F06);
        assert_eq!(file.descriptor_traced(&mut trace), Err(Error::State)); // Reserved: before any call.
        assert_eq!(prerequisite_first(&trace).detail, Some(PrerequisiteDetail::Input(InputCheck::DescriptorState)));
        assert!(!file.body().active && file.body().handle.is_null());
        assert!(prerequisite_first(&trace).native.is_none());
        let mut fixture = InertProfile::new()?;
        let mut permission = prerequisite_trace(G::Launch, C::V03);
        assert_eq!(fixture.0.binding_permitted_traced(&mut permission), fixture.0.binding_permitted());
        assert_eq!(prerequisite_first(&permission).check, C::V03);
        let native = &fixture.0.native; let [before, after] = &mut fixture.0.absence;
        let frame = unsafe { before.as_mut().ok_or(Error::State)?.as_mut().get_unchecked_mut() };
        let other = after.as_ref().ok_or(Error::State)?.as_ref().get_ref();
        frame.claim()?; frame.begin()?; frame.returned = 0xc0000034u32 as i32;
        let mut absence = prerequisite_trace(G::AccountProfile, C::V04);
        assert_eq!(frame.observe_return_traced(native, other, true, &mut absence), Ok(()));
        assert!(frame.exact_absence() && frame.settled());
        assert!(absence.prerequisite.expect("enabled").first.is_none()); // Error IOSB sentinels never read.
        assert_eq!(frame.claim(), Err(Error::State)); assert_eq!(frame.begin_close(), Ok(None));
        assert!(absence.prerequisite.expect("enabled").first.is_none());
        Ok(())
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
        let unavailable = request.probe_result(&digest, &account, Some("interactive-desktop"), None, None);
        assert!(unavailable.is_ok());
        if let Ok(unavailable) = unavailable {
            assert_eq!(request.accept_child(unavailable.as_bytes(), &digest, &account), Ok(false));
            assert!(request.accept_child(unavailable.replace("\"available\":false", "\"available\":true").as_bytes(), &digest, &account).is_err());
            assert!(request.accept_child(unavailable.replace("\"originalsSettled\":true", "\"originalsSettled\":false").as_bytes(), &digest, &account).is_err());
            assert!(request.accept_child(unavailable.as_bytes(), &digest, &"c".repeat(64)).is_err());
        }
        assert!(request.probe_result(&digest, &account, Some("cleanup-unknown"), None, None).is_err());
        assert!(request.probe_result(&digest, &account, None, None, None).is_err());
        if let Ok(available) = request.probe_result(&digest, &account, None, Some("130.0.1.2"), None) {
            assert_eq!(request.accept_child(available.as_bytes(), &digest, &account), Ok(true));
        } else { panic!("valid finite observation must encode"); }
        crate::ui::prerequisite_refusal_contract(&request);
    }

    // Only scalar DATA enters the production selector. These borrowed-looking
    // fixture HWNDs never go to a native API, COM, scan, or native cleanup.
    fn main_window_selection_contract() {
        fn row(hwnd: usize, owner: usize, title: &str) -> WindowData {
            let mut value = WindowData::new();
            value.hwnd = hwnd as F::HWND; value.owner = owner as F::HWND;
            let units: Vec<u16> = title.encode_utf16().collect();
            assert!(units.len() < value.title.len() - 1);
            value.title[..units.len()].copy_from_slice(&units); value.length = units.len() as i32;
            value.owner_error = Some(0); value.title_error = Some(0); value
        }
        fn windows(rows: Vec<WindowData>) -> WindowQuery {
            let mut value = WindowQuery::new(); assert!(rows.len() <= value.entries.len());
            value.count = rows.len();
            for (to, from) in value.entries.iter_mut().zip(rows) { *to = from; }
            value
        }
        fn accepts(rows: Vec<WindowData>, bound: Option<usize>, expected: Option<usize>) {
            let trace = SmokeTrace::new();
            assert_eq!(windows(rows).select_root(bound.map(|hwnd| hwnd as F::HWND), &trace),
                Ok(expected.map(|hwnd| hwnd as F::HWND)));
            assert!(trace.first.get().is_none());
        }
        fn refuses(rows: Vec<WindowData>, bound: Option<usize>, error: Error, check: SmokeCheck, status: Option<SmokeStatus>) {
            let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::MainWindow);
            assert_eq!(windows(rows).select_root(bound.map(|hwnd| hwnd as F::HWND), &trace), Err(error));
            assert_eq!(trace.first.get(), Some(SmokeFault { phase: SmokePhase::MainWindow, check, error, status,
                dashboard: None, main_binding_timeouts: None, dashboard_binding_timeouts: None, startup: StartupSample::new(), quit: None }));
        }
        let title = "Mobile Release Kit";
        accepts(vec![], None, None);
        accepts(vec![row(2, 0, ""), row(3, 0, "Other"), row(4, 1, title)], None, None);
        accepts(vec![row(2, 0, "mobile release kit")], None, None);
        accepts(vec![row(2, 1, title), row(1, 0, title)], None, Some(1));
        for first in [true, false] {
            for bound in [None, Some(1)] {
                let auxiliary = row(2, 0, ""); let main = row(1, 0, title);
                accepts(if first { vec![auxiliary, main] } else { vec![main, auxiliary] }, bound, Some(1));
            }
            // A failed possible second candidate must not become an empty
            // noncandidate, regardless of enumeration order or the other row.
            let mut failed = row(2, 0, ""); failed.title_error = Some(5);
            let main = row(1, 0, title);
            refuses(if first { vec![failed, main] } else { vec![main, failed] }, None,
                Error::Unsafe, SmokeCheck::WindowTitleRead, Some(SmokeStatus::Win32(5)));
        }
        for duplicate in [1, 2] {
            for bound in [None, Some(1)] {
                refuses(vec![row(1, 0, title), row(duplicate, 0, title)], bound,
                    Error::Unsafe, SmokeCheck::RootUniqueness, None);
            }
        }
        for rows in [vec![], vec![row(2, 0, "")], vec![row(1, 0, "Other")],
            vec![row(1, 2, title)], vec![row(2, 0, title)]] {
            refuses(rows, Some(1), Error::Unsafe, SmokeCheck::RootContinuity, None);
        }
        for text in ["", title] {
            let mut failed = row(2, 0, text); failed.owner_error = Some(6);
            // The owner fault belongs to this row and precedes even a different
            // captured title error; neither is taken from the valid main row.
            failed.title_error = Some(5);
            refuses(vec![row(1, 0, title), failed], None,
                Error::Unsafe, SmokeCheck::WindowOwnerRead, Some(SmokeStatus::Win32(6)));
        }
        let mut missing = row(2, 1, title); missing.owner_error = None;
        refuses(vec![missing], None, Error::State, SmokeCheck::WindowOwnerRead, None);
        let mut missing = row(2, 0, ""); missing.title_error = None;
        refuses(vec![row(1, 0, title), missing], None, Error::State, SmokeCheck::WindowTitleRead, None);
        for length in [-1, 255] {
            let mut malformed = row(2, 0, "Other"); malformed.length = length;
            refuses(vec![row(1, 0, title), malformed], None,
                Error::Unsafe, SmokeCheck::WindowTitleLength, None);
        }
        let mut malformed = row(2, 0, ""); malformed.title[0] = 0xd800; malformed.length = 1;
        refuses(vec![row(1, 0, title), malformed], None,
            Error::Unsafe, SmokeCheck::WindowTitleEncoding, None);

        let mut failed = row(2, 0, ""); failed.title_error = Some(5);
        let mut query = windows(vec![row(1, 0, title), failed]);
        let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::MainWindow);
        assert_eq!(query.select_root(None, &trace), Err(Error::Unsafe));
        let first = trace.first.get().unwrap();
        assert_eq!(first.check, SmokeCheck::WindowTitleRead); assert_eq!(first.status, Some(SmokeStatus::Win32(5)));
        query.entries[1].title_error = Some(0);
        assert_eq!(query.select_root(None, &trace), Ok(Some(1usize as F::HWND)));
        query.entries[0].owner_error = Some(6);
        assert_eq!(query.select_root(None, &trace), Err(Error::Unsafe));
        assert_eq!(trace.first.get(), Some(first)); // Later status/success cannot rewrite the original fault.
    }

    fn initial_main_readiness_contract() {
        // Only scalar output/clock DATA is supplied. No client, window, native
        // clock or fake COM pointer is invoked; never settle the fake pointers.
        fn fixture() -> Smoke {
            let mut smoke = Smoke::new(); smoke.trace.phase.set(SmokePhase::MainBinding);
            smoke.originals.push(Box::new(ComOriginal::new(ComKind::Client)));
            smoke.originals.push(Box::new(ComOriginal::new(ComKind::Walker)));
            smoke.client = Some(0); smoke.walker = Some(1); smoke
        }
        fn begin(smoke: &mut Smoke, pointer: usize) -> usize {
            let index = smoke.originals.len(); smoke.originals.push(Box::new(ComOriginal::new(ComKind::Element)));
            let original = &mut smoke.originals[index];
            assert_eq!(original.state, SlotState::Reserved); assert_eq!(original.status, HRESULT_PENDING);
            assert!(original.pointer.is_null() && !original.active);
            assert!(original.begin().is_ok()); original.pointer = pointer as *mut c_void; index
        }
        let timeout = A::UIA_E_TIMEOUT as i32; assert_eq!(timeout as u32, 0x80131505);
        let win32_timeout = windows::core::HRESULT::from_win32(F::ERROR_TIMEOUT).0;
        assert_eq!(win32_timeout as u32, 0x800705b4);
        let mut smoke = fixture(); let calls = Cell::new(0);
        let prefix = [&*smoke.originals[0] as *const ComOriginal, &*smoke.originals[1] as *const ComOriginal];
        for (count, status) in [(1, timeout), (2, win32_timeout)] {
            let index = begin(&mut smoke, 0);
            assert_eq!(smoke.complete_initial_main(index, status, || { calls.set(calls.get() + 1); Ok(()) }), Ok(None));
            assert_eq!(smoke.originals.len(), 2); assert_eq!(smoke.trace.main_binding_timeouts.get(), count);
            assert_eq!([&*smoke.originals[0] as *const ComOriginal, &*smoke.originals[1] as *const ComOriginal], prefix);
            assert!(smoke.trace.first.get().is_none() && smoke.main.is_none() && !smoke.dashboard_ready);
            assert!(!smoke.windows.post_entered && !smoke.invoke_entered && !smoke.quit_confirmed && !smoke.passed());
        }
        let index = begin(&mut smoke, 1);
        assert_eq!(smoke.complete_initial_main(index, 0, || { calls.set(calls.get() + 1); Ok(()) }), Ok(Some(index)));
        assert_eq!(calls.get(), 3); assert_eq!(smoke.originals[index].state, SlotState::Owned);
        assert_eq!(smoke.trace.main_binding_timeouts.get(), 2); assert_eq!(smoke.originals.len(), 3);
        // A success-shaped element output is still not runtime-ID/PID binding,
        // dashboard observation or quit/finality. The fake owned ref is not released.
        assert!(smoke.main.is_none() && !smoke.dashboard_ready && !smoke.passed());

        for (status, pointer, expected, state, active) in [
            (0x80004005u32 as i32, 0, Error::Unsafe, SlotState::NoHandle, false),
            (F::ERROR_TIMEOUT as i32, 0, Error::Unsafe, SlotState::NoHandle, false),
            (timeout, 1, Error::Unknown, SlotState::Unknown, true),
            (win32_timeout, 1, Error::Unknown, SlotState::Unknown, true),
            (HRESULT_PENDING, 0, Error::Unknown, SlotState::Unknown, true),
            (0, 0, Error::Unsafe, SlotState::NoHandle, false),
            (1, 0, Error::Unsafe, SlotState::NoHandle, false),
            (1, 1, Error::Unsafe, SlotState::Owned, false),
        ] {
            let mut smoke = fixture(); let index = begin(&mut smoke, pointer); let calls = Cell::new(0);
            assert_eq!(smoke.complete_initial_main(index, status, || { calls.set(calls.get() + 1); Ok(()) }), Err(expected));
            assert_eq!(calls.get(), 1); assert_eq!(smoke.originals.len(), 3);
            assert_eq!(smoke.originals[index].state, state); assert_eq!(smoke.originals[index].active, active);
            assert_eq!(smoke.unknown, expected == Error::Unknown); assert_eq!(smoke.trace.main_binding_timeouts.get(), 0);
            let fault = smoke.trace.first.get().unwrap(); assert_eq!(fault.check, SmokeCheck::ElementFromWindow);
            assert_eq!(fault.status, Some(SmokeStatus::Hresult(status))); assert_eq!(fault.main_binding_timeouts, Some(0));
        }
        for timeout in [timeout, win32_timeout] {
            for denied in 0..8 {
                let mut smoke = fixture(); let index = begin(&mut smoke, 0);
                match denied {
                    0 => smoke.trace.phase.set(SmokePhase::Dashboard),
                    1 => smoke.trace.phase.set(SmokePhase::QuitDialog),
                    2 => smoke.trace.phase.set(SmokePhase::QuitInvoke),
                    3 => smoke.main = Some((1usize as F::HWND, 0, vec![1])),
                    4 => smoke.unknown = true,
                    5 => smoke.settled = true,
                    6 => { let _ = smoke.trace.result::<()>(SmokeCheck::Clock, Err(Error::Unsafe), None); },
                    7 => smoke.originals[index].kind = ComKind::Walker,
                    _ => unreachable!(),
                }
                let prior = smoke.trace.first.get(); let calls = Cell::new(0);
                assert_eq!(smoke.complete_initial_main(index, timeout, || { calls.set(calls.get() + 1); Ok(()) }), Err(Error::Unsafe));
                assert_eq!(calls.get(), 1); assert_eq!(smoke.trace.main_binding_timeouts.get(), 0);
                assert_eq!(smoke.originals.len(), 3); if prior.is_some() { assert_eq!(smoke.trace.first.get(), prior); }
            }
            let mut not_begun = fixture(); not_begun.originals.push(Box::new(ComOriginal::new(ComKind::Element)));
            assert_eq!(not_begun.complete_initial_main(2, timeout, || Ok(())), Err(Error::Unsafe));
            assert_eq!(not_begun.trace.main_binding_timeouts.get(), 0);
        }

        // The completed pending observation is counted before a refusing clock;
        // no tail is discarded on that error and a later fault cannot rewrite it.
        for timeout in [timeout, win32_timeout] {
            let mut late = fixture(); let index = begin(&mut late, 0); let calls = Cell::new(0);
            assert_eq!(late.complete_initial_main(index, timeout, || { calls.set(calls.get() + 1); Err(Error::Unsafe) }), Err(Error::Unsafe));
            assert_eq!(calls.get(), 1); assert_eq!(late.originals.len(), 3);
            assert_eq!(late.originals[index].state, SlotState::NoHandle);
            let first = late.trace.first.get().unwrap(); assert_eq!(first.check, SmokeCheck::Clock);
            assert_eq!(first.status, None); assert_eq!(first.main_binding_timeouts, Some(1));
            late.trace.main_binding_timeouts.set(9); late.trace.phase.set(SmokePhase::DriverSettle);
            let _ = late.trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None);
            assert_eq!(late.trace.first.get(), Some(first)); let mut output = Vec::new(); late.trace.emit_to(&mut output).unwrap();
            assert!(std::str::from_utf8(&output).unwrap().contains("\"mainBindingTimeouts\":1"));
            assert_eq!(late.trace.emit_to(&mut Vec::new()).unwrap(), None);
        }
        for (status, pointer, expected_state, expected_first) in [
            (0, 1, SlotState::Owned, SmokeCheck::Clock),
            (HRESULT_PENDING, 0, SlotState::Unknown, SmokeCheck::ElementFromWindow),
        ] {
            let mut smoke = fixture(); let index = begin(&mut smoke, pointer);
            assert_eq!(smoke.complete_initial_main(index, status, || Err(Error::Unsafe)), Err(Error::Unsafe));
            assert_eq!(smoke.originals.len(), 3); assert_eq!(smoke.originals[index].state, expected_state);
            assert_eq!(smoke.trace.first.get().unwrap().check, expected_first);
            assert_eq!(smoke.trace.main_binding_timeouts.get(), 0); assert!(smoke.main.is_none() && !smoke.passed());
        }

        for timeout in [timeout, win32_timeout] {
            let mut exhausted = fixture(); let index = begin(&mut exhausted, 0);
            assert_eq!(exhausted.complete_initial_main(index, timeout, || Ok(())), Ok(None));
            assert_eq!(exhausted.trace.admit_com(false, false, exhausted.originals.len(), || Ok(1000)), Err(Error::Unsafe));
            let fault = exhausted.trace.first.get().unwrap(); assert_eq!(fault.check, SmokeCheck::ComReserveBudget);
            assert_eq!(fault.main_binding_timeouts, Some(1)); assert!(!exhausted.initial_main_admitted());
        }

        let mut overflow = fixture(); overflow.trace.main_binding_timeouts.set(u16::MAX);
        let index = begin(&mut overflow, 0); let calls = Cell::new(0);
        assert_eq!(overflow.complete_initial_main(index, timeout, || { calls.set(calls.get() + 1); Ok(()) }), Err(Error::Bounds));
        assert_eq!(calls.get(), 1); assert_eq!(overflow.originals.len(), 3);
        assert_eq!(overflow.trace.main_binding_timeouts.get(), u16::MAX);
        let fault = overflow.trace.first.get().unwrap(); assert_eq!(fault.check, SmokeCheck::InitialMainTimeoutCount);
        assert_eq!(fault.main_binding_timeouts, Some(u16::MAX)); let mut raw = [0u8; 512];
        let size = SmokeTrace::format(fault, &mut raw).unwrap(); assert!(size <= 512);
        assert!(std::str::from_utf8(&raw[..size]).unwrap().contains("\"mainBindingTimeouts\":65535"));

        for denied in 0..6 {
            let mut smoke = fixture(); let index = begin(&mut smoke, 0);
            assert_eq!(smoke.originals[index].returned(timeout, false), Err(Error::Unsafe));
            let retire = match denied {
                0 => 0, // Never truncate a client/walker prefix.
                1 => { smoke.originals.push(Box::new(ComOriginal::new(ComKind::Element))); index },
                2 => { smoke.originals[index].active = true; index },
                3 => { smoke.originals[index].state = SlotState::Owned; smoke.originals[index].pointer = 1usize as *mut c_void; index },
                4 => { smoke.originals[index].status = F::ERROR_TIMEOUT as i32; index },
                5 => { smoke.originals[index].status = 0x80004005u32 as i32; index },
                _ => unreachable!(),
            };
            let count = smoke.originals.len(); assert_eq!(smoke.retire_initial_main_tail(retire), Err(Error::Unsafe));
            assert_eq!(smoke.originals.len(), count); // No release of the fake pointer or prefix.
        }
    }

    fn dashboard_main_handle_readiness_contract() {
        // Scalar/state DATA only. These fake original addresses are never
        // dereferenced, released, queried or used to enter native settlement.
        fn fixture() -> Smoke {
            let mut smoke = Smoke::new(); smoke.initialized = true;
            smoke.trace.phase.set(SmokePhase::Dashboard); smoke.trace.dashboard_begin_pass();
            let mut original = Box::new(ComOriginal::new(ComKind::Element));
            original.state = SlotState::Owned; original.pointer = 1usize as *mut c_void;
            smoke.originals.push(original); smoke.main = Some((2usize as F::HWND, 0, vec![42, 1]));
            smoke.query.active = true; smoke
        }
        let hwnd = 2usize as F::HWND; let timeout = A::UIA_E_TIMEOUT as i32;
        let mut smoke = fixture(); let main = smoke.main.clone();
        let original = &*smoke.originals[0] as *const ComOriginal;
        let calls = Cell::new(0);
        for (count, scalar) in [(1, 0), (2, 3)] {
            smoke.query.active = true; smoke.query.status = HRESULT_PENDING; smoke.query.hwnd = HWND(scalar as *mut c_void);
            assert_eq!(smoke.complete_dashboard_handle_timeout(hwnd, 0, timeout,
                || { calls.set(calls.get() + 1); Ok(()) }), Ok(true));
            assert!(!smoke.query.active && !smoke.query.unknown); assert_eq!(smoke.query.status, timeout);
            assert_eq!(smoke.query.hwnd.0, scalar as *mut c_void); // Ignored scalar, not owned output.
            assert_eq!(smoke.trace.dashboard_binding_timeouts.get(), count);
            assert_eq!(smoke.main, main); assert_eq!(smoke.originals.len(), 1);
            assert_eq!(&*smoke.originals[0] as *const ComOriginal, original);
            assert!(smoke.trace.first.get().is_none() && !smoke.dashboard_ready && !smoke.quit_confirmed
                && !smoke.windows.post_entered && !smoke.invoke_entered && !smoke.passed());
        }
        assert_eq!(calls.get(), 2); assert_eq!(smoke.trace.main_binding_timeouts.get(), 0);
        // Success and all other results still require the original generic
        // return/binding path. The completion helper cannot consume them.
        for status in [0, 1, HRESULT_PENDING, 0x80004005u32 as i32, A::UIA_E_ELEMENTNOTAVAILABLE as i32] {
            smoke.query.active = true; smoke.query.status = HRESULT_PENDING; smoke.query.hwnd = HWND(hwnd);
            assert_eq!(smoke.complete_dashboard_handle_timeout(hwnd, 0, status,
                || { calls.set(calls.get() + 1); Ok(()) }), Ok(false));
            assert!(smoke.query.active); assert_eq!(smoke.query.status, HRESULT_PENDING);
            assert_eq!(smoke.trace.dashboard_binding_timeouts.get(), 2); assert_eq!(calls.get(), 2);
            assert!(!smoke.dashboard_ready && !smoke.passed());
        }

        for (remaining, expected, fault) in [
            (Ok(999), Err(Error::Unsafe), Some(SmokeCheck::QueryBudget)),
            (Ok(1000), Err(Error::Unsafe), Some(SmokeCheck::QueryBudget)),
            (Err(Error::Unsafe), Err(Error::Unsafe), Some(SmokeCheck::Clock)),
            (Ok(1001), Ok(()), None),
        ] {
            let mut smoke = fixture(); let calls = Cell::new(0);
            assert_eq!(smoke.complete_dashboard_handle_timeout(hwnd, 0, timeout, || Ok(())), Ok(true));
            assert_eq!(smoke.query.begin_with_remaining(|| { calls.set(calls.get() + 1); remaining }, &smoke.trace), expected);
            assert_eq!(calls.get(), 1); assert_eq!(smoke.query.active, expected.is_ok());
            assert_eq!(smoke.query.status, if expected.is_ok() { HRESULT_PENDING } else { timeout });
            assert_eq!(smoke.trace.first.get().map(|first| first.check), fault);
            assert_eq!(smoke.trace.dashboard_binding_timeouts.get(), 1); assert!(!smoke.dashboard_ready && !smoke.passed());
        }

        for denied in 0..28 {
            let mut smoke = fixture(); let mut requested = hwnd; let mut element = 0;
            match denied {
                0 => smoke.trace.phase.set(SmokePhase::MainBinding),
                1 => smoke.trace.phase.set(SmokePhase::QuitDialog),
                2 => smoke.trace.phase.set(SmokePhase::QuitInvoke),
                3 => smoke.dashboard_ready = true,
                4 => smoke.windows.post_entered = true,
                5 => smoke.invoke_entered = true,
                6 => smoke.quit_confirmed = true,
                7 => smoke.unknown = true,
                8 => smoke.settled = true,
                9 => { let _ = smoke.trace.result::<()>(SmokeCheck::Clock, Err(Error::Unsafe), None); },
                10 => smoke.originals[0].state = SlotState::Unknown,
                11 => smoke.originals[0].active = true,
                12 => smoke.originals[0].kind = ComKind::Walker,
                13 => smoke.originals[0].pointer = null_mut(),
                14 => smoke.main = None,
                15 => element = 1,
                16 => requested = 3usize as F::HWND,
                17 => smoke.main.as_mut().unwrap().2.clear(),
                18 => smoke.initialized = false,
                19 => smoke.uninit_entered = true,
                20 => smoke.uninit_returned = true,
                21 => smoke.query.active = false,
                22 => smoke.query.unknown = true,
                23 => smoke.query.bstr = 1usize as *mut c_void,
                24 => smoke.query.array = 1usize as *mut CO::SAFEARRAY,
                25 => smoke.query.status = 0,
                26 => smoke.trace.dashboard_update(DashboardProgress::begin_walk),
                27 => smoke.trace.dashboard.set(None),
                _ => unreachable!(),
            }
            let first = smoke.trace.first.get(); let active = smoke.query.active; let status = smoke.query.status;
            let calls = Cell::new(0);
            assert_eq!(smoke.complete_dashboard_handle_timeout(requested, element, timeout,
                || { calls.set(calls.get() + 1); Ok(()) }), Ok(false));
            assert_eq!(calls.get(), 0); assert_eq!(smoke.query.active, active); assert_eq!(smoke.query.status, status);
            assert_eq!(smoke.trace.first.get(), first); assert_eq!(smoke.trace.dashboard_binding_timeouts.get(), 0);
            assert_eq!(smoke.originals.len(), 1); assert!(!smoke.passed());
        }

        let mut late = fixture(); let calls = Cell::new(0);
        assert_eq!(late.complete_dashboard_handle_timeout(hwnd, 0, timeout,
            || { calls.set(calls.get() + 1); Err(Error::Unsafe) }), Err(Error::Unsafe));
        assert_eq!(calls.get(), 1); assert!(!late.query.active); assert_eq!(late.query.status, timeout);
        let first = late.trace.first.get().unwrap(); assert_eq!(first.check, SmokeCheck::Clock);
        assert_eq!(first.dashboard_binding_timeouts, Some(1)); assert_eq!(first.main_binding_timeouts, Some(0));
        assert!(!late.dashboard_handle_admitted(hwnd, 0) && !late.passed());
        late.trace.dashboard_binding_timeouts.set(8); late.trace.phase.set(SmokePhase::DriverSettle);
        let _ = late.trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None);
        assert_eq!(late.trace.first.get(), Some(first)); let mut output = Vec::new(); late.trace.emit_to(&mut output).unwrap();
        assert!(std::str::from_utf8(&output).unwrap().contains("\"dashboardBindingTimeouts\":1"));
        assert_eq!(late.trace.emit_to(&mut Vec::new()).unwrap(), None);

        for clock_result in [Ok(()), Err(Error::Unsafe)] {
            let mut overflow = fixture(); overflow.trace.dashboard_binding_timeouts.set(u16::MAX);
            let calls = Cell::new(0);
            assert_eq!(overflow.complete_dashboard_handle_timeout(hwnd, 0, timeout,
                || { calls.set(calls.get() + 1); clock_result }), clock_result.and(Err(Error::Bounds)));
            assert_eq!(calls.get(), 1); assert!(!overflow.query.active && !overflow.passed());
            let first = overflow.trace.first.get().unwrap(); assert_eq!(first.check, SmokeCheck::DashboardBindingTimeoutCount);
            assert_eq!(first.dashboard_binding_timeouts, Some(u16::MAX));
            let mut raw = [0u8; 1024]; let size = SmokeTrace::format(first, &mut raw).unwrap(); assert!(size <= 1024);
        }
        let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::QuitDialog); trace.dashboard_binding_timeouts.set(8);
        let _ = trace.result::<()>(SmokeCheck::NativeWindowHandle, Err(Error::Unsafe), Some(SmokeStatus::Hresult(timeout)));
        assert_eq!(trace.first.get().unwrap().dashboard_binding_timeouts, None);

        // Bind the scalar pending->status0 cases above to the real caller's
        // strict success path, not a second simulated identity oracle. Native
        // API/provider/GUI success still requires the actual hosted UI run.
        let source = include_str!("ordinary_owner_ui.rs");
        fn block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            source.split_once(start).unwrap().1.split_once(end).unwrap().0
        }
        let main = block(source, "    fn main_native_handle(", "    fn enabled_button(");
        assert!(main.contains("if self.trace.phase.get() != SmokePhase::Dashboard { return self.native_handle(element, clock); }"));
        assert!(main.contains("if !self.complete_dashboard_handle_timeout(hwnd, element, status, || clock.effect())? {\n                self.query.returned(status, clock, &self.trace, SmokeCheck::NativeWindowHandle)?;\n                return Ok(self.query.hwnd.0);"));
        assert!(main.contains("self.query.begin(clock, &self.trace)?;"));
        assert_eq!(main.matches("self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd)").count(), 2);
        let bound = block(source, "    fn bound(", "    fn walk(");
        assert!(bound.contains("self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd)\n            && self.main_native_handle(launch, hwnd, index, clock)? == hwnd && self.runtime_id(index, clock)? == expected"));
        assert!(bound.contains("self.trace.need(SmokeCheck::MainBinding, bound)?;"));
        assert!(bound.contains("self.query.returned(status, clock, &self.trace, SmokeCheck::ProcessId)?;"));
        assert!(bound.contains("self.trace.need(SmokeCheck::MainProcess, self.query.integer > 0 && self.query.integer as u32 == launch.outputs.dwProcessId)"));
        let observe = block(source, "    fn observe(&mut self, launch:", "    fn settle(&mut self)");
        assert!(observe.contains("self.bound(launch, clock)?; let keep = self.originals.len();"));
        assert!(observe.contains("if pass.ready() { self.dashboard_ready = true; break; }"));
        assert!(observe.contains("self.trace.phase.set(SmokePhase::CloseRequest);\n        self.bound(launch, clock)?;"));
        let completion = block(source, "    fn complete_dashboard_handle_timeout(", "    fn main_native_handle(");
        for forbidden in ["self.main =", "self.dashboard_ready =", "self.quit_confirmed =", "self.windows.post_entered =", "self.invoke_entered ="] {
            assert!(!completion.contains(forbidden) && !main.contains(forbidden));
        }
    }

    fn dashboard_stale_name_contract() {
        // DATA only: none of these fake original pointers is queried,
        // dereferenced or released. The production helpers own the policy.
        fn fixture() -> Smoke {
            let mut smoke = Smoke::new(); smoke.initialized = true;
            for (index, kind) in [ComKind::Client, ComKind::Walker, ComKind::Element, ComKind::Element].into_iter().enumerate() {
                let mut original = Box::new(ComOriginal::new(kind));
                original.pointer = (index + 1) as *mut c_void; original.state = SlotState::Owned; original.status = 0;
                smoke.originals.push(original);
            }
            smoke.client = Some(0); smoke.walker = Some(1); smoke.main = Some((5usize as F::HWND, 2, vec![42, 1]));
            smoke.trace.phase.set(SmokePhase::Dashboard); smoke.trace.dashboard_begin_pass();
            smoke.trace.dashboard_update(DashboardProgress::begin_walk);
            smoke.trace.dashboard_update(|progress| progress.walk_visited(2));
            smoke.trace.dashboard_update(DashboardProgress::walk_completed);
            smoke.trace.dashboard_update(DashboardProgress::begin_names);
            smoke.query.active = true; smoke
        }
        let stale = A::UIA_E_ELEMENTNOTAVAILABLE as i32;
        assert_eq!(stale, 0x80040201u32 as i32);
        let mut smoke = fixture(); let main = smoke.main.clone();
        let originals: Vec<_> = smoke.originals.iter().map(|value| &**value as *const ComOriginal).collect();
        smoke.trace.dashboard_update(|progress| {
            progress.name_returned("Workspace navigation"); progress.matches([false, true, false, false, false]);
        });
        let calls = Cell::new(0);
        assert_eq!(smoke.complete_dashboard_name_stale(3, 3, stale, || { calls.set(calls.get() + 1); Ok(()) }), Ok(true));
        assert_eq!(calls.get(), 1); assert_eq!(smoke.query.status, stale);
        assert!(!smoke.query.active && !smoke.query.unknown && smoke.query.bstr.is_null() && smoke.query.array.is_null());
        let progress = smoke.trace.dashboard.get().unwrap();
        assert_eq!(progress.stage, DashboardStage::NamesEnded);
        assert_eq!(progress.last_scan.unwrap().end, DashboardScanEnd::Stale);
        assert_eq!(progress.last_scan.unwrap().match_mask, 2); assert_eq!(progress.last_scan.unwrap().names.returned, 1);
        assert_eq!(progress.scan_history, DashboardScanHistory::StaleSeen);
        assert_eq!(smoke.main, main);
        assert_eq!(smoke.originals.iter().map(|value| &**value as *const ComOriginal).collect::<Vec<_>>(), originals);
        assert!(smoke.trace.first.get().is_none() && !smoke.dashboard_ready && !smoke.windows.post_entered
            && !smoke.invoke_entered && !smoke.quit_confirmed && !smoke.passed());

        for status in [0, 1, HRESULT_PENDING, A::UIA_E_TIMEOUT as i32, 0x80004005u32 as i32] {
            let mut smoke = fixture(); let before = smoke.trace.dashboard.get(); let calls = Cell::new(0);
            assert_eq!(smoke.complete_dashboard_name_stale(3, 3, status, || { calls.set(calls.get() + 1); Ok(()) }), Ok(false));
            assert_eq!(calls.get(), 0); assert!(smoke.query.active); assert_eq!(smoke.query.status, HRESULT_PENDING);
            assert_eq!(smoke.trace.dashboard.get(), before); assert!(smoke.trace.first.get().is_none() && !smoke.passed());
        }
        for denied in 0..44 {
            let mut smoke = fixture(); let mut element = 3; let mut keep = 3;
            match denied {
                0 => smoke.trace.phase.set(SmokePhase::MainBinding),
                1 => smoke.trace.phase.set(SmokePhase::QuitDialog),
                2 => smoke.trace.phase.set(SmokePhase::QuitInvoke),
                3 => smoke.dashboard_ready = true,
                4 => smoke.windows.post_entered = true,
                5 => smoke.invoke_entered = true,
                6 => smoke.quit_confirmed = true,
                7 => smoke.unknown = true,
                8 => smoke.settled = true,
                9 => { let _ = smoke.trace.result::<()>(SmokeCheck::Clock, Err(Error::Unsafe), None); },
                10 => smoke.originals[3].state = SlotState::Unknown,
                11 => smoke.originals[3].active = true,
                12 => smoke.originals[3].kind = ComKind::Walker,
                13 => smoke.originals[3].pointer = null_mut(),
                14 => smoke.main = None,
                15 => element = 2, // Adopted main.
                16 => element = 0, // Retained client, never a current descendant.
                17 => element = 4,
                18 => keep = 2, // Cannot retire the main.
                19 => keep = 4, // Target outside this alleged fresh suffix.
                20 => keep = usize::MAX,
                21 => smoke.main.as_mut().unwrap().2.clear(),
                22 => smoke.initialized = false,
                23 => smoke.uninit_entered = true,
                24 => smoke.uninit_returned = true,
                25 => smoke.query.active = false,
                26 => smoke.query.unknown = true,
                27 => smoke.query.bstr = 1usize as *mut c_void,
                28 => smoke.query.array = 1usize as *mut CO::SAFEARRAY,
                29 => smoke.query.status = 0,
                30 => smoke.trace.dashboard_begin_pass(),
                31 => smoke.trace.dashboard.set(None),
                32 => smoke.client = None,
                33 => smoke.walker = None,
                34 => smoke.client = Some(1),
                35 => smoke.originals[0].state = SlotState::NoHandle,
                36 => smoke.originals[1].active = true,
                37 => smoke.originals[2].pointer = null_mut(),
                38 => smoke.windows.active = true,
                39 => smoke.originals[3].status = 1,
                40 => smoke.originals[0].kind = ComKind::Element,
                41 => smoke.originals[3].state = SlotState::Closed,
                42 => smoke.originals[3].state = SlotState::NoHandle,
                43 => {
                    let mut extra = Box::new(ComOriginal::new(ComKind::Element));
                    extra.pointer = 6usize as *mut c_void; extra.state = SlotState::Owned; extra.status = 0;
                    smoke.originals.push(extra); keep = 4; element = 4; // Arbitrary extra retained prefix.
                },
                _ => unreachable!(),
            }
            let first = smoke.trace.first.get(); let progress = smoke.trace.dashboard.get();
            let active = smoke.query.active; let status = smoke.query.status; let count = smoke.originals.len();
            let calls = Cell::new(0);
            assert_eq!(smoke.complete_dashboard_name_stale(element, keep, stale,
                || { calls.set(calls.get() + 1); Ok(()) }), Ok(false));
            assert_eq!(calls.get(), 0); assert_eq!(smoke.query.active, active); assert_eq!(smoke.query.status, status);
            assert_eq!(smoke.trace.first.get(), first); assert_eq!(smoke.trace.dashboard.get(), progress);
            assert_eq!(smoke.originals.len(), count); assert!(!smoke.passed());
        }

        // These are the same per-pass finish/ready methods used by observe,
        // not a second readiness oracle. No stale prefix can survive a break.
        for found in [[false, true, false, false, false], [true; 5]] {
            let mut pass = DashboardPass::new(); pass.found = found; assert!(!pass.ready());
            pass.finish(DashboardScanEnd::Stale); assert_eq!(pass.found, [false; 5]); assert!(!pass.ready());
            pass.finish(DashboardScanEnd::Exhausted); assert_eq!(pass.end, Some(DashboardScanEnd::Stale));
            assert!(!pass.ready());
            let mut next = DashboardPass::new(); next.found = found.map(|value| !value);
            next.finish(DashboardScanEnd::Exhausted); assert!(!next.ready());
        }
        let mut loading = DashboardPass::new(); loading.found = [true; 5];
        loading.finish(DashboardScanEnd::Loading); loading.finish(DashboardScanEnd::Exhausted); assert!(!loading.ready());
        let mut ready = DashboardPass::new(); ready.found = [true; 5]; assert!(!ready.ready());
        ready.finish(DashboardScanEnd::Exhausted); assert!(ready.ready());

        let mut history = DashboardProgress::new();
        for (end, expected) in [
            (DashboardScanEnd::Stale, DashboardScanHistory::StaleSeen),
            (DashboardScanEnd::Loading, DashboardScanHistory::StaleSeen),
            (DashboardScanEnd::Exhausted, DashboardScanHistory::ExhaustedSeen),
            (DashboardScanEnd::Stale, DashboardScanHistory::ExhaustedSeen),
        ] {
            history.begin_pass(); history.begin_walk(); history.walk_visited(2); history.walk_completed(); history.begin_names();
            history.end_names(end); let original = history;
            history.end_names(DashboardScanEnd::Exhausted);
            assert_eq!(history, original); assert_eq!(history.scan_history, expected);
            assert_eq!(history.last_scan.unwrap().end, end);
        }

        // Actual retirement helper, but suffix slots are non-owning DATA.
        // The retained fake owned prefix is never included or released.
        let mut retirement = fixture(); retirement.query.active = false;
        retirement.originals[3].state = SlotState::NoHandle; retirement.originals[3].pointer = null_mut();
        retirement.originals.push(Box::new(ComOriginal::new(ComKind::Element)));
        assert_eq!(retirement.release_suffix(3), Ok(())); assert_eq!(retirement.originals.len(), 3);
        assert_eq!(retirement.main, Some((5usize as F::HWND, 2, vec![42, 1])));
        let mut blocked = fixture(); blocked.query.active = false; blocked.originals[3].state = SlotState::Unknown;
        assert_eq!(blocked.release_suffix(3), Err(Error::Unknown)); assert_eq!(blocked.originals.len(), 4);
        assert_eq!(blocked.trace.first.get().unwrap().check, SmokeCheck::ComRelease); assert!(!blocked.passed());

        let mut late = fixture(); let calls = Cell::new(0);
        assert_eq!(late.complete_dashboard_name_stale(3, 3, stale,
            || { calls.set(calls.get() + 1); Err(Error::Unsafe) }), Err(Error::Unsafe));
        assert_eq!(calls.get(), 1); assert!(!late.query.active); assert_eq!(late.query.status, stale);
        let first = late.trace.first.get().unwrap(); assert_eq!(first.check, SmokeCheck::Clock);
        assert_eq!(first.dashboard.unwrap().last_scan.unwrap().end, DashboardScanEnd::Stale);
        late.trace.phase.set(SmokePhase::DriverSettle);
        let _ = late.trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None);
        assert_eq!(late.trace.first.get(), Some(first));
        let mut raw = [0u8; 1024]; let size = SmokeTrace::format(first, &mut raw).unwrap();
        let text = std::str::from_utf8(&raw[..size]).unwrap();
        assert!(text.contains("\"end\":\"stale\"") && text.contains("\"scanHistory\":\"stale-seen\""));
        assert!(!late.passed());
        for (remaining, expected) in [
            (Ok(999), Err(Error::Unsafe)), (Ok(1000), Err(Error::Unsafe)),
            (Err(Error::Unsafe), Err(Error::Unsafe)), (Ok(1001), Ok(())),
        ] {
            let mut smoke = fixture(); let calls = Cell::new(0);
            assert_eq!(smoke.complete_dashboard_name_stale(3, 3, stale, || Ok(())), Ok(true));
            assert_eq!(smoke.query.begin_with_remaining(|| { calls.set(calls.get() + 1); remaining }, &smoke.trace), expected);
            assert_eq!(calls.get(), 1); assert_eq!(smoke.query.active, expected.is_ok());
            assert_eq!(smoke.query.status, if expected.is_ok() { HRESULT_PENDING } else { stale });
            assert!(!smoke.dashboard_ready && !smoke.passed());
        }

        // Bind the DATA cases to the real strict call, fresh current walk,
        // invalidation break and exact suffix retirement before owner recheck.
        // Provider success and actual COM release still need the native run.
        let source = include_str!("ordinary_owner_ui.rs");
        fn block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            source.split_once(start).unwrap().1.split_once(end).unwrap().0
        }
        let strict = block(source, "    fn name(&mut self, element:", "    fn dashboard_name_admitted(");
        assert!(strict.contains("let status = self.query_name(element, clock)?; self.finish_name(status, clock)"));
        let query = block(source, "    fn query_name(", "    fn finish_name(");
        assert_eq!(query.matches("(table.CurrentName)").count(), 1);
        assert!(query.contains("self.query.begin(clock, &self.trace)?;"));
        let finish = block(source, "    fn finish_name(", "    fn name(&mut self, element:");
        assert!(finish.contains("if status != 0 && !self.query.bstr.is_null()"));
        assert!(finish.contains("self.query.returned(status, clock, &self.trace, SmokeCheck::CurrentName)?;"));
        assert!(finish.contains("length <= 1024") && finish.contains("String::from_utf16"));
        assert!(finish.contains("self.query.settle(&self.trace)?; self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; text"));
        let wrapper = block(source, "    fn dashboard_name(&mut self,", "    fn runtime_id(");
        assert!(wrapper.contains("return self.name(element, clock).map(DashboardNameRead::Text);"));
        assert!(wrapper.contains("self.trace.need(SmokeCheck::DashboardNameState, self.dashboard_name_admitted(element, keep))?;"));
        assert!(wrapper.contains("self.finish_name(status, clock).map(DashboardNameRead::Text)"));
        assert!(wrapper.contains("self.query.settle(&self.trace)?; Ok(DashboardNameRead::Invalidated)"));
        let observe = block(source, "    fn observe(&mut self, launch:", "    fn settle(&mut self)");
        assert_eq!(observe.matches("self.dashboard_name(index, keep, clock)?").count(), 1);
        let dashboard = block(observe, "        self.trace.phase.set(SmokePhase::Dashboard);",
            "        self.trace.phase.set(SmokePhase::CloseRequest);");
        assert!(dashboard.contains("self.bound(launch, clock)?; let keep = self.originals.len();\n            let elements = self.walk(element, clock)?;"));
        assert!(dashboard.contains("let mut pass = DashboardPass::new();"));
        assert!(dashboard.contains("DashboardNameRead::Invalidated => { pass.finish(DashboardScanEnd::Stale); break; }"));
        let released = dashboard.split_once("self.release_suffix(keep)?;").unwrap().1;
        assert!(released.contains("if pass.ready() { self.dashboard_ready = true; break; }"));
        assert!(released.contains("self.windows.root(launch, Some(hwnd), clock, &self.trace)? == Some(hwnd)"));
        assert!(released.contains("if stale { self.trace.result(SmokeCheck::Clock, clock.effect(), None)?; }"));
        // Quit names remain strict in the logical-control walk and requery.
        let quit_walk = block(source, "    fn quit_walk(", "    fn quit_native_container(");
        assert!(quit_walk.contains("name: self.name(root, clock)?"));
        assert!(quit_walk.contains("name: self.name(element, clock)?"));
        let quit_control = block(source, "    fn quit_control(", "    fn quit_scan(");
        assert!(quit_control.contains("let name = self.name(element, clock)?;"));
        assert!(!quit_walk.contains("self.dashboard_name(") && !quit_control.contains("self.dashboard_name("));
        assert!(observe.contains("self.trace.phase.set(SmokePhase::CloseRequest);\n        self.bound(launch, clock)?;"));
        let completion = block(source, "    fn complete_dashboard_name_stale(", "    fn dashboard_name(&mut self,");
        for forbidden in ["self.main =", "self.dashboard_ready =", "self.quit_confirmed =", "self.windows.post_entered =", "self.invoke_entered ="] {
            assert!(!completion.contains(forbidden) && !wrapper.contains(forbidden));
        }
    }

    fn dashboard_name_observation_contract() {
        for (name, mask) in [
            ("Mobile Release Kit", 1), ("about:blank", 2), ("http://tauri.localhost/", 4),
            ("Microsoft Edge WebView2", 8), ("WebView2", 8),
            ("THE KIT FOR A CAREFUL LAUNCH", 16), ("Core-managed builds are disabled", 16),
            ("DESKTOP Not loaded", 32),
            ("Loading desktop capabilities and the core field catalogue", 64),
            ("Before Loading desktop capabilities and the core field catalogue After", 64),
            ("Mobile Release Kit extra", 128), ("about:blank/extra", 128),
            ("http://tauri.localhost/other", 128), ("webview2", 128), (" ", 128),
            ("Fixture owner detail — not for diagnostics", 128),
        ] {
            let mut names = DashboardNames::new(); names.observe(name);
            assert_eq!(names, DashboardNames { returned: 1, empty: 0, text_mask: mask });
            let mut output = Vec::new(); SmokeTrace::format_names(&mut output, Some(names)).unwrap();
            let text = std::str::from_utf8(&output).unwrap();
            assert_eq!(text, format!("{{\"returned\":1,\"empty\":0,\"textMask\":{mask}}}"));
            assert!(!text.contains(name));
        }
        let mut names = DashboardNames::new(); names.observe(""); names.observe("");
        assert_eq!(names, DashboardNames { returned: 2, empty: 2, text_mask: 0 });
        names.observe("about:blank"); names.observe("WebView2"); names.observe("unclassified fixture");
        assert_eq!(names, DashboardNames { returned: 5, empty: 2, text_mask: 138 });
        let mut saturated = DashboardNames { returned: u16::MAX, empty: u16::MAX, text_mask: 255 };
        saturated.observe(""); saturated.observe("unclassified fixture");
        assert_eq!(saturated, DashboardNames { returned: u16::MAX, empty: u16::MAX, text_mask: 255 });

        // Diagnostic updates outside the existing successful Names phase do
        // nothing. Current prefixes never replace an earlier ended scan.
        let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::Dashboard); trace.dashboard_begin_pass();
        trace.dashboard_update(|progress| progress.name_returned("about:blank"));
        assert_eq!(trace.dashboard.get().unwrap().current_names, None);
        trace.dashboard_update(DashboardProgress::begin_walk);
        trace.dashboard_update(|progress| { progress.walk_visited(3); progress.name_returned("about:blank"); });
        assert_eq!(trace.dashboard.get().unwrap().current_names, None);
        trace.dashboard_update(DashboardProgress::walk_completed); trace.dashboard_update(DashboardProgress::begin_names);
        trace.dashboard_update(|progress| { progress.name_returned(""); progress.name_returned("about:blank"); });
        trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Loading));
        let ended = trace.dashboard.get().unwrap();
        assert_eq!(ended.last_scan.unwrap().names, DashboardNames { returned: 2, empty: 1, text_mask: 2 });
        assert_eq!(ended.last_scan.unwrap().walk_visited, 3);
        trace.dashboard_update(|progress| { progress.name_returned("WebView2"); progress.end_names(DashboardScanEnd::Exhausted); });
        assert_eq!(trace.dashboard.get(), Some(ended));
        trace.dashboard_begin_pass(); assert_eq!(trace.dashboard.get().unwrap().current_names, None);
        trace.dashboard_update(DashboardProgress::begin_walk); trace.dashboard_update(|progress| progress.walk_visited(1));
        trace.dashboard_update(DashboardProgress::walk_completed); trace.dashboard_update(DashboardProgress::begin_names);
        trace.dashboard_update(|progress| progress.name_returned("WebView2"));
        let prefix = trace.dashboard.get().unwrap();
        assert_eq!(prefix.current_names, Some(DashboardNames { returned: 1, empty: 0, text_mask: 8 }));
        assert_eq!(prefix.last_scan, ended.last_scan);
        trace.main_binding_timeouts.set(7);
        assert_eq!(trace.result::<()>(SmokeCheck::CurrentName, Err(Error::Unsafe), None), Err(Error::Unsafe));
        let first = trace.first.get().unwrap();
        assert_eq!(first.dashboard, Some(prefix)); assert_eq!(first.main_binding_timeouts, Some(7));
        trace.dashboard_update(|progress| { progress.name_returned("later fixture"); progress.end_names(DashboardScanEnd::Exhausted); });
        trace.main_binding_timeouts.set(8); trace.phase.set(SmokePhase::DriverSettle);
        assert_eq!(trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None), Err(Error::Unknown));
        assert_eq!(trace.first.get(), Some(first));
    }

    fn startup_diagnostic_contract() {
        use crate::ui_startup_data::{Event, NativeError, NativeMark, Stage};
        crate::ui_startup_data::scalar_contract();
        let mut word = StartupWord::default();
        word.native(3, NativeMark { stage: Stage::FolderMatch, part: 0, error: Some(NativeError::Data) });
        let raw = word.encode().unwrap(); let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::MainBinding);
        let reads = Cell::new(0);
        assert_eq!(trace.sample_startup(|| { reads.set(reads.get() + 1); raw }, || Ok(())), Ok(()));
        let valid = trace.startup.get(); assert_eq!(valid.last, Some((word, SmokePhase::MainBinding)));
        trace.phase.set(SmokePhase::Dashboard);
        for (value, availability) in [(0, StartupAvailability::Missing), (1, StartupAvailability::Invalid)] {
            assert_eq!(trace.sample_startup(|| value, || Ok(())), Ok(()));
            assert_eq!(trace.startup.get().availability, availability); assert_eq!(trace.startup.get().last, valid.last);
        }
        let previous = trace.startup.get(); let checkpoints = Cell::new(0);
        assert_eq!(trace.sample_startup(|| { reads.set(reads.get() + 1); raw }, || {
            checkpoints.set(checkpoints.get() + 1); if checkpoints.get() == 2 { Err(Error::Unsafe) } else { Ok(()) }
        }), Err(Error::Unsafe));
        assert_eq!(reads.get(), 2); assert_eq!(trace.startup.get(), previous);
        let fault = trace.first.get().unwrap(); assert_eq!(fault.startup, previous); assert_eq!(fault.check, SmokeCheck::Clock);
        assert_eq!(trace.sample_startup(|| panic!("no read after refusal"), || panic!("no renewed budget")), Ok(()));
        trace.startup.set(valid); assert_eq!(trace.first.get(), Some(fault));
        let expired = SmokeTrace::new();
        assert_eq!(expired.sample_startup(|| panic!("expired read"), || Err(Error::Unsafe)), Err(Error::Unsafe));
        assert_eq!(expired.startup.get(), StartupSample::new());
        let mut raw_text = [0u8; 1024]; let size = SmokeTrace::format(fault, &mut raw_text).unwrap();
        let text = std::str::from_utf8(&raw_text[..size]).unwrap();
        assert!(text.contains("\"availability\":\"invalid\"")); assert!(text.contains("\"previous\":true"));
        assert!(text.contains("\"event\":\"native-refused\"")); assert!(text.contains("\"nativeStage\":\"folder-match\""));
        assert_eq!(word.event, Event::NativeRefused);
        // No native call is made for these fake-handle/finality DATA fixtures.
        for value in [0, 1, raw, StartupWord::default().encode().unwrap()] {
            let smoke = Smoke::new(); let before = smoke.passed();
            assert_eq!(smoke.trace.sample_startup(|| value, || Ok(())), Ok(())); assert_eq!(smoke.passed(), before);
        }
    }

    fn quit_logical_controls_contract() {
        use windows_sys::Win32::UI::Controls as C;
        let containers = crate::ui::quit_native::contract(); crate::ui::QuitAction::contract();
        // Inert scalar/runtime-ID/borrowed-handle fixtures only. These exercise
        // the production selection, chain, state, identity and one-shot gates;
        // no UIA/native provider, HWND query, release or finality is fabricated.
        fn trace() -> SmokeTrace {
            let value = SmokeTrace::new(); value.phase.set(SmokePhase::QuitDialog);
            value.quit_scan_begin().expect("first inert scan"); value
        }
        fn node(index: usize, name: &str, parent: Option<usize>, previous: Option<usize>, depth: usize) -> QuitNode {
            QuitNode { element: index + 10, parent, parent_probe: parent.map(|_| index + 100), previous, depth,
                identity: QuitIdentity { runtime: vec![42, index as i32 + 1], process: 17 }, name: name.to_owned(),
                control: if matches!(name, "OK" | "Cancel") { A::UIA_ButtonControlTypeId.0 } else { 0 } }
        }
        fn fixture() -> (QuitTree, SmokeTrace) {
            let trace = trace(); let mut tree = QuitTree::new();
            tree.push(node(0, "Quit Mobile Release Kit?", None, None, 0), 17, &trace).expect("inert root");
            for (offset, name) in ["OK", "Cancel", "Quit and discard unsaved drafts?", "extra"].into_iter().enumerate() {
                let index = offset + 1;
                tree.push(node(index, name, Some(0), (index > 1).then_some(index - 1), 1), 17, &trace).expect("inert child");
            }
            while tree.closed < tree.nodes.len() { tree.close_parent(tree.closed, &trace).expect("inert complete edge"); }
            (tree, trace)
        }
        let (tree, progress) = fixture(); assert_eq!(tree.select(&progress), Ok([1, 2]));
        assert_eq!(tree.chain(1, 17, &progress), Ok(vec![0])); assert_eq!(tree.chain(2, 17, &progress), Ok(vec![0]));
        assert_eq!(progress.quit.get(), Some(QuitProgress { scan: 1, visited: 5, closed: 5, match_mask: 3, default_mask: None }));
        let root = tree.nodes[0].identity.clone();
        let control = |position: usize, native: crate::ui::quit_native::Container| {
            let node = &tree.nodes[position];
            QuitControlFacts { identity: node.identity.clone(), name: node.name.clone(), control: node.control,
                enabled: true, offscreen: false, native, ancestors: vec![root.clone()] }
        };
        for (ok, cancel) in [(0, 0), (1, 1), (2, 3), (0, 2)] {
            let pair = [control(1, containers[ok].clone()), control(2, containers[cancel].clone())];
            assert_eq!(quit_controls_valid(&pair, &root, &trace()), Ok(()));
        } // Windowless, shared root container, native direct/nested and mixed.
        let controls = [control(1, containers[0].clone()), control(2, containers[0].clone())];
        let mut invalid = Vec::new();
        let mut value = controls.clone(); value[0].enabled = false; invalid.push((value, SmokeCheck::QuitButtonEnabled));
        let mut value = controls.clone(); value[1].offscreen = true; invalid.push((value, SmokeCheck::QuitButtonVisibility));
        let mut value = controls.clone(); value[0].name = "other".to_owned(); invalid.push((value, SmokeCheck::QuitButtonType));
        let mut value = controls.clone(); value[1].control = 0; invalid.push((value, SmokeCheck::QuitButtonType));
        let mut value = controls.clone(); value[0].identity.process += 1; invalid.push((value, SmokeCheck::QuitProcess));
        let mut value = controls.clone(); value[1].ancestors[0].process += 1; invalid.push((value, SmokeCheck::QuitProcess));
        let mut value = controls.clone(); value[0].ancestors.clear(); invalid.push((value, SmokeCheck::QuitLineage));
        let mut value = controls.clone(); value[1].ancestors[0].runtime[1] += 10; invalid.push((value, SmokeCheck::QuitLineage));
        let mut value = controls.clone(); value[1].ancestors.push(root.clone()); invalid.push((value, SmokeCheck::QuitRuntime));
        let mut value = controls.clone(); value[0].identity.runtime = root.runtime.clone(); invalid.push((value, SmokeCheck::QuitRuntime));
        let mut value = controls.clone(); value[1].identity.runtime = value[0].identity.runtime.clone(); invalid.push((value, SmokeCheck::QuitRuntime));
        for (pair, check) in invalid {
            let trace = trace(); let mut effects = 0;
            let result = (|| { quit_controls_valid(&pair, &root, &trace)?; effects += 1; Ok(()) })();
            assert_eq!(result, Err(Error::Unsafe)); assert_eq!(effects, 0); assert_eq!(trace.first.get().unwrap().check, check);
        }

        for (position, name, control_type, check) in [
            (1, "other", A::UIA_ButtonControlTypeId.0, SmokeCheck::QuitOkMissing),
            (2, "other", A::UIA_ButtonControlTypeId.0, SmokeCheck::QuitCancelMissing),
            (1, "OK", 0, SmokeCheck::QuitOkMissing),
            (4, "OK", A::UIA_ButtonControlTypeId.0, SmokeCheck::QuitButtonsDuplicate),
            (4, "Cancel", A::UIA_ButtonControlTypeId.0, SmokeCheck::QuitButtonsDuplicate),
        ] {
            let (mut value, trace) = fixture(); value.nodes[position].name = name.to_owned(); value.nodes[position].control = control_type;
            // Selection has no enabled-state filter: even an unusable duplicate
            // refuses before any selected control state or action is queried.
            assert_eq!(value.select(&trace), Err(Error::Unsafe)); assert_eq!(trace.first.get().unwrap().check, check);
        }
        let (mut incomplete, incomplete_trace) = fixture(); incomplete.closed -= 1;
        assert_eq!(incomplete.select(&incomplete_trace), Err(Error::Unsafe));
        assert_eq!(incomplete_trace.first.get().unwrap().check, SmokeCheck::QuitTreeIncomplete);
        let (mut root_button, root_button_trace) = fixture(); root_button.nodes[0].name = "OK".to_owned();
        root_button.nodes[0].control = A::UIA_ButtonControlTypeId.0; root_button.nodes[1].name = "other".to_owned();
        assert_eq!(root_button.select(&root_button_trace), Err(Error::Unsafe));
        assert_eq!(root_button_trace.first.get().unwrap().check, SmokeCheck::QuitRuntime);

        for (change, check, error) in [
            (0, SmokeCheck::QuitRuntime, Error::Unsafe), (1, SmokeCheck::QuitRuntime, Error::Unsafe),
            (2, SmokeCheck::QuitProcess, Error::Unsafe), (3, SmokeCheck::QuitLineage, Error::Unsafe),
            (4, SmokeCheck::QuitLineage, Error::Unsafe), (5, SmokeCheck::QuitTreeBounds, Error::Bounds),
        ] {
            let trace = trace(); let mut value = QuitTree::new(); let root = node(0, "root", None, None, 0);
            value.push(root.clone(), 17, &trace).unwrap(); let mut child = node(1, "OK", Some(0), None, 1);
            match change {
                0 => child.identity.runtime = root.identity.runtime, 1 => child.element = root.element,
                2 => child.identity.process += 1, 3 => child.previous = Some(0),
                4 => child.parent_probe = None, 5 => child.depth = QUIT_DEPTH + 1, _ => unreachable!(),
            }
            assert_eq!(value.push(child, 17, &trace), Err(error)); assert_eq!(trace.first.get().unwrap().check, check);
        }
        for (change, check) in [(0, SmokeCheck::QuitLineage), (1, SmokeCheck::QuitLineage), (2, SmokeCheck::QuitLineage),
            (3, SmokeCheck::QuitProcess), (4, SmokeCheck::QuitRuntime)] {
            let (mut value, trace) = fixture();
            match change {
                0 => value.nodes[1].parent = None, 1 => value.nodes[1].parent = Some(usize::MAX),
                2 => value.nodes[1].parent = Some(1), 3 => value.nodes[0].identity.process += 1,
                4 => value.nodes[0].identity.runtime = value.nodes[1].identity.runtime.clone(), _ => unreachable!(),
            }
            assert_eq!(value.chain(1, 17, &trace), Err(Error::Unsafe)); assert_eq!(trace.first.get().unwrap().check, check);
        }
        let count_trace = trace(); let mut bounded = QuitTree::new();
        bounded.push(node(0, "root", None, None, 0), 17, &count_trace).unwrap();
        for index in 1..QUIT_NODES {
            bounded.push(node(index, "extra", Some(0), (index > 1).then_some(index - 1), 1), 17, &count_trace).unwrap();
        }
        assert_eq!(bounded.push(node(QUIT_NODES, "overflow", Some(0), Some(QUIT_NODES - 1), 1), 17, &count_trace), Err(Error::Bounds));
        let depth_trace = trace(); let mut deep = QuitTree::new(); deep.push(node(0, "root", None, None, 0), 17, &depth_trace).unwrap();
        for depth in 1..=QUIT_DEPTH {
            deep.push(node(depth, "extra", Some(depth - 1), None, depth), 17, &depth_trace).unwrap();
            deep.close_parent(depth - 1, &depth_trace).unwrap();
        }
        assert_eq!(deep.chain(QUIT_DEPTH, 17, &depth_trace).unwrap().len(), QUIT_DEPTH);
        assert_eq!(deep.push(node(QUIT_DEPTH + 1, "overflow", Some(QUIT_DEPTH), None, QUIT_DEPTH + 1), 17, &depth_trace), Err(Error::Bounds));

        let original = QuitScan { tree: tree.clone(), selected: [1, 2], controls: controls.clone(), parent_probes: [vec![201], vec![202]] };
        let mut observed_tree = tree.clone();
        for node in &mut observed_tree.nodes { node.element += 1000; node.parent_probe = node.parent_probe.map(|value| value + 1000); }
        let current = QuitScan { tree: observed_tree, selected: [1, 2], controls: controls.clone(), parent_probes: [vec![1201], vec![1202]] };
        assert_eq!(original.same(&current, &trace()), Ok(()));
        let elements = original.elements(&trace()).unwrap(); assert_ne!(elements, current.elements(&trace()).unwrap());
        let patterns = QuitPatterns { elements, legacy: [QuitPattern { element: elements[0], original: 301 },
            QuitPattern { element: elements[1], original: 302 }], invoke: QuitPattern { element: elements[0], original: 303 } };
        assert_eq!(patterns.valid(elements, &trace()), Ok(()));
        assert_eq!(patterns.valid(current.elements(&trace()).unwrap(), &trace()), Err(Error::Unsafe)); // Compare, never adopt.
        for change in 0..5 {
            let mut replaced = patterns;
            match change {
                0 => replaced.elements.swap(0, 1), 1 => replaced.legacy[0].element = elements[1],
                2 => replaced.invoke.element = elements[1], 3 => replaced.legacy[0].original = replaced.invoke.original,
                4 => replaced.invoke.original = elements[0], _ => unreachable!(),
            }
            let trace = trace(); let mut effects = 0;
            let result = (|| { replaced.valid(elements, &trace)?; effects += 1; Ok(()) })();
            assert_eq!(result, Err(Error::Unsafe)); assert_eq!(effects, 0); assert_eq!(trace.first.get().unwrap().check, SmokeCheck::QuitPatterns);
        }
        for change in 0..7 {
            let mut changed = controls[0].clone();
            match change {
                0 => changed.identity.runtime[1] += 10, 1 => changed.identity.process += 1,
                2 => changed.name = "other".to_owned(), 3 => changed.control = 0, 4 => changed.enabled = false,
                5 => changed.offscreen = true, 6 => changed.ancestors.insert(0, QuitIdentity { runtime: vec![42, 99], process: 17 }),
                _ => unreachable!(),
            }
            let trace = trace(); assert_eq!(controls[0].same(&changed, &trace), Err(Error::Unsafe));
            assert_eq!(trace.first.get().unwrap().check, SmokeCheck::QuitButtonsChanged);
        }
        let mut changed = controls[0].clone(); changed.native = containers[1].clone(); let native_trace = trace();
        assert_eq!(controls[0].same(&changed, &native_trace), Err(Error::Unsafe));
        assert_eq!(native_trace.first.get().unwrap().check, SmokeCheck::QuitNativeChanged);

        for (states, check) in [
            ([0, W::STATE_SYSTEM_DEFAULT], None),
            ([0, 0], Some(SmokeCheck::QuitDefault)), ([W::STATE_SYSTEM_DEFAULT; 2], Some(SmokeCheck::QuitDefault)),
            ([W::STATE_SYSTEM_DEFAULT, 0], Some(SmokeCheck::QuitDefault)),
            ([u32::MAX, W::STATE_SYSTEM_DEFAULT], Some(SmokeCheck::QuitDefaultState)),
            ([0, u32::MAX], Some(SmokeCheck::QuitDefaultState)),
            ([C::STATE_SYSTEM_UNAVAILABLE, W::STATE_SYSTEM_DEFAULT], Some(SmokeCheck::QuitDefaultState)),
            ([0, W::STATE_SYSTEM_DEFAULT | C::STATE_SYSTEM_INVISIBLE], Some(SmokeCheck::QuitDefaultState)),
            ([0, W::STATE_SYSTEM_DEFAULT | C::STATE_SYSTEM_OFFSCREEN], Some(SmokeCheck::QuitDefaultState)),
        ] {
            let trace = trace(); let mut effects = 0;
            let result = (|| { quit_default_states(states, &trace)?; effects += 1; Ok(()) })();
            assert_eq!(result, if check.is_none() { Ok(()) } else { Err(Error::Unsafe) });
            assert_eq!(effects, usize::from(check.is_none())); assert_eq!(trace.first.get().map(|fault| fault.check), check);
        }
        let defaults = [0, W::STATE_SYSTEM_DEFAULT]; assert_eq!(quit_same_defaults(defaults, defaults, &trace()), Ok(()));
        let changed_trace = trace();
        assert_eq!(quit_same_defaults(defaults, [W::STATE_SYSTEM_FOCUSED, W::STATE_SYSTEM_DEFAULT], &changed_trace), Err(Error::Unsafe));
        assert_eq!(changed_trace.first.get().unwrap().check, SmokeCheck::QuitLegacyChanged);
        for (status, pointer, expected) in [
            (0, 0usize, Err(Error::Unsafe)), (0, 1, Ok(true)), (-1, 0, Err(Error::Unsafe)),
            (-1, 1, Err(Error::Unknown)), (HRESULT_PENDING, 0, Err(Error::Unknown)), (HRESULT_PENDING, 1, Err(Error::Unknown)),
        ] {
            let trace = trace(); let mut original = ComOriginal::new(ComKind::Legacy); original.begin().unwrap();
            original.pointer = pointer as *mut c_void;
            assert_eq!(trace.result(SmokeCheck::QuitOkLegacyAcquire, original.returned(status, false), Some(SmokeStatus::Hresult(status))), expected);
            // Fake pointers never enter native acquisition, Release or settle.
            if expected.is_err() { assert_eq!(trace.first.get().unwrap().check, SmokeCheck::QuitOkLegacyAcquire); }
        }
        progress.phase.set(SmokePhase::QuitInvoke); progress.quit_scan_begin().unwrap();
        assert_eq!(progress.quit.get().unwrap().scan, 2); assert_eq!(progress.quit_scan_begin(), Err(Error::Unsafe));
        let first = progress.first.get().unwrap(); assert_eq!(first.check, SmokeCheck::QuitTreeState);
        progress.quit_update(|value| { value.visited = 65; value.closed = 65; value.match_mask = 3; value.default_mask = Some(2); });
        progress.phase.set(SmokePhase::DriverSettle); let _ = progress.result::<()>(SmokeCheck::Clock, Err(Error::Unknown), None);
        assert_eq!(progress.first.get(), Some(first)); let mut text = Vec::new(); progress.emit_to(&mut text).unwrap();
        assert!(text.len() <= 1024 && std::str::from_utf8(&text).unwrap().contains("\"quit\":{\"scan\":2,\"visited\":0,\"closed\":0,\"matchMask\":0,\"defaultMask\":null}"));
        assert_eq!(progress.emit_to(&mut text).unwrap(), None);
        // Source wiring complements the real predicates; it is not evidence
        // about this machine's TaskDialog provider or process finality.
        let source = include_str!("ordinary_owner_ui.rs");
        let observe = source.split_once("    fn observe(&mut self, launch:").unwrap().1.split_once("    fn settle(&mut self)").unwrap().0;
        assert_eq!(observe.matches("self.quit_scan(dialog_element, dialog, launch, clock)?").count(), 2);
        assert_eq!(observe.matches("(table.Invoke)(pointer)").count(), 1);
        assert!(observe.contains("self.quit_requery_originals(&buttons, dialog, launch, clock)?;"));
        assert!(observe.contains("let pointer = self.pointer(index, ComKind::Invoke)?;"));
        assert!(observe.contains("self.query.begin(clock, &self.trace)?; self.invoke_entered = true;"));
    }

    // DATA-only coverage for the precise common-path output-inventory labels.
    // This neither runs native inventory nor substitutes for its Windows route.
    fn normal_smoke_launch_directory_contract() -> Result<()> {
        // Original slots and absence completions are inert DATA, never OS calls.
        fn prepared() -> Result<InertProfile> {
            let mut fixture = InertProfile::new()?;
            fixture.returned(AbsenceEpoch::BeforeLogon, 0xc0000034u32 as i32, null_mut(), F::STATUS_PENDING, usize::MAX)?;
            let p = &mut fixture.0; let parent = wide(r"C:\Users");
            p.directory[..parent.len()].copy_from_slice(&parent); p.units = parent.len() as u32;
            p.getter_entered = true; p.getter_return = 1; p.prestate = true;
            p.expected = Path::new(r"C:\Users").join(&p.name); Ok(fixture)
        }
        let role = UiRole::NormalSmoke;
        assert_eq!(normal_smoke_profile_directory(role, None, &mut InputTrace::default()), Err(Error::Unsafe));
        let unprepared = InertProfile::new()?;
        assert!(normal_smoke_profile_directory(role, Some(&unprepared.0), &mut InputTrace::default()).is_err());
        let fixture = prepared()?; let profile = fixture.0.expected.clone();
        assert_eq!(normal_smoke_profile_directory(role, Some(&fixture.0), &mut InputTrace::default()), Ok(Some(profile.as_path())));
        for invalid in 0..11 {
            let mut fixture = prepared()?;
            match invalid {
                0 => fixture.0.unknown = true,
                1 => fixture.0.prestate = false,
                2 => fixture.0.exact = true,
                3 => fixture.0.delete_entered = true,
                4 => fixture.0.settled = true,
                5 => fixture.0.getter_entered = false,
                6 => fixture.0.getter_return = 0,
                7 => fixture.0.units = 0,
                8 => fixture.0.expected = Path::new(r"C:\Elsewhere").join(&fixture.0.name),
                9 => fixture.0.expected = PathBuf::from(&fixture.0.name),
                _ => fixture.0.absence_mut(AbsenceEpoch::AfterDeletion)?.claim()?,
            }
            assert_eq!(normal_smoke_profile_directory(role, Some(&fixture.0), &mut InputTrace::default()),
                Err(if invalid == 0 { Error::Unknown } else { Error::Unsafe }));
        }
        let mut bound = prepared()?;
        let parent = bound.0.paths[0].original.index;
        let canonical = format!("{}\\{}", bound.0.native.slot(parent)?.canonical, bound.0.name);
        let original = bound.0.native.reserve(Kind::Directory, Some(parent), &bound.0.name, canonical)?;
        let slot = bound.0.native.slot_mut(original.index)?;
        slot.state = SlotState::Owned; unsafe { *slot.output.get() = 42usize as F::HANDLE; }
        bound.0.profile = Some(ProfilePath { original, metadata: bound.0.paths[0].metadata.clone() });
        assert_eq!(normal_smoke_profile_directory(role, Some(&bound.0), &mut InputTrace::default()), Err(Error::Unsafe));

        let root = PathBuf::from(r"D:\mrk\root"); let output = root.join(role.name("output"));
        let app = root.join("mobile-release-kit-desktop.exe"); let app_text = app.to_str().ok_or(Error::Unsafe)?;
        let output_text = output.to_str().ok_or(Error::Unsafe)?;
        let baseline = vec![
            ("SystemRoot".to_owned(), r"C:\Windows".to_owned()),
            ("TEMP".to_owned(), output_text.to_owned()), ("TMP".to_owned(), output_text.to_owned()),
            ("MRK_WINDOWS_ORDINARY_OUTPUT".to_owned(), output_text.to_owned()),
            ("MRK_WINDOWS_NORMAL_UI_OUTPUT".to_owned(), output_text.to_owned()),
            ("unchanged".to_owned(), "sentinel=value".to_owned()),
        ];
        let initial_directory = wide(output_text);
        for (temp, tmp) in [("TEMP", "TMP"), ("tEmP", "tMp")] {
            let mut values = baseline.clone(); values[1].0 = temp.to_owned(); values[2].0 = tmp.to_owned();
            let mut expected = values.clone(); let mut directory = initial_directory.clone();
            expected[1].1 = profile.to_str().ok_or(Error::Unsafe)?.to_owned(); expected[2].1 = expected[1].1.clone();
            normal_smoke_launch_directories(role, app_text, &output, &root, Some(&profile), &mut values, &mut directory)?;
            assert_eq!(values, expected); assert_eq!(directory, wide(root.to_str().ok_or(Error::Unsafe)?));
            assert_eq!(values[4], baseline[4]); // The explicitly named result-output directory is not scratch.
        }
        for (key, mixed) in [("TEMP", "tEmP"), ("TMP", "tMp")] {
            for invalid in 0..5 {
                let mut values = baseline.clone();
                match invalid {
                    0 => values.retain(|(name, _)| !name.eq_ignore_ascii_case(key)),
                    1 => values.push((key.to_owned(), output_text.to_owned())),
                    2 => values.push((key.to_ascii_lowercase(), output_text.to_owned())),
                    3 => values.push((mixed.to_owned(), output_text.to_owned())),
                    _ => values.iter_mut().find(|(name, _)| name.as_str() == key).ok_or(Error::State)?.1 = "wrong".to_owned(),
                }
                let expected = values.clone(); let mut directory = initial_directory.clone();
                assert_eq!(normal_smoke_launch_directories(role, app_text, &output, &root, Some(&profile), &mut values, &mut directory),
                    Err(Error::Unsafe));
                assert_eq!(values, expected); assert_eq!(directory, initial_directory);
            }
        }
        for (bad_app, bad_output, bad_root, bad_profile) in [
            (root.join("other.exe"), output.clone(), root.clone(), Some(profile.clone())),
            (app.clone(), root.join("other-output"), root.clone(), Some(profile.clone())),
            (app.clone(), output.clone(), root.join("other-root"), Some(profile.clone())),
            (app.clone(), root.clone(), root.clone(), Some(profile.clone())),
            (app.clone(), output.clone(), root.clone(), Some(root.clone())),
            (app.clone(), output.clone(), root.clone(), Some(output.clone())),
            (app.clone(), output.clone(), root.clone(), Some(PathBuf::from(r"d:\MRK\ROOT"))),
            (app.clone(), output.clone(), root.clone(), Some(PathBuf::from("relative-profile"))),
            (app.clone(), output.clone(), PathBuf::from("relative-root"), Some(profile.clone())),
            (app.clone(), PathBuf::from("relative-output"), root.clone(), Some(profile.clone())),
            (app.clone(), output.clone(), root.clone(), None),
        ] {
            let mut values = baseline.clone(); let mut directory = initial_directory.clone();
            assert_eq!(normal_smoke_launch_directories(role, bad_app.to_str().ok_or(Error::Unsafe)?, &bad_output, &bad_root,
                bad_profile.as_deref(), &mut values, &mut directory), Err(Error::Unsafe));
            assert_eq!(values, baseline); assert_eq!(directory, initial_directory);
        }
        let mut values = baseline.clone(); let mut directory = wide(root.to_str().ok_or(Error::Unsafe)?);
        let wrong_directory = directory.clone();
        assert_eq!(normal_smoke_launch_directories(role, app_text, &output, &root, Some(&profile), &mut values, &mut directory),
            Err(Error::Unsafe));
        assert_eq!(values, baseline); assert_eq!(directory, wrong_directory);
        let mut unknown = prepared()?; unknown.0.unknown = true;
        for role in [UiRole::Prerequisite, UiRole::ProjectDraft, UiRole::QuitPassive, UiRole::DocumentLoss] {
            assert_eq!(normal_smoke_profile_directory(role, None, &mut InputTrace::default()), Ok(None));
            assert_eq!(normal_smoke_profile_directory(role, Some(&unknown.0), &mut InputTrace::default()), Ok(None));
            for unused in [None, Some(Path::new("relative-unused-profile"))] {
                let mut values = baseline.clone(); let mut directory = initial_directory.clone();
                normal_smoke_launch_directories(role, "unused-app", Path::new("unused-output"), Path::new("unused-root"),
                    unused, &mut values, &mut directory)?;
                assert_eq!(values, baseline); assert_eq!(directory, initial_directory);
            }
        }
        Ok(())
    }

    fn output_inventory_diagnostic_contract() {
        let source = include_str!("ordinary_owner_ui.rs");
        let inventory = source.split_once("fn output_poststate(").unwrap().1
            .split_once("// Qualification-only, same-thread DATA.").unwrap().0;
        assert!(inventory.contains("trace: &mut InputTrace, smoke: Option<&Smoke>) -> Result<()> {"));
        assert_eq!(inventory.matches("smoke_result(smoke, SmokePhase::OutputPoststate, SmokeCheck::$check, $original)").count(), 1);
        for name in [
            "OutputLocation",
            "OutputDecode",
            "OutputDepth",
            "OutputDrive",
            "OutputRootReserve",
            "OutputRootOpen",
            "OutputRootNoninherited",
            "OutputFilesystem",
            "OutputRootMetadata",
            "OutputParentOriginal",
            "OutputAncestorOpen",
            "OutputAncestorMetadata",
            "OutputStamp",
            "OutputIdentity",
            "OutputRole",
            "OutputEntryBatch",
            "OutputEntryAdmission",
            "OutputDotIdentity",
            "OutputParentIdentity",
            "OutputUnexpectedChild",
            "OutputEntryBinding",
            "OutputRoster",
            "OutputPostMetadataRead",
            "OutputPostMetadata",
            "OutputFinalDrive",
            "OutputMappingUnchanged",
        ] {
            assert_eq!(inventory.matches(&format!("output_result!({name},")).count(), 1, "{name}");
        }
        assert_eq!(inventory.matches("native.next_entries(&entries[index].0)").count(), 1);
        for predicate in [
            "need(parts.len() < 16)",
            "need(seen.insert(entry.name.clone()) && seen.len() <= 6)",
            "need(entry.file_id == entries[index].1.identity.file_id)",
            "need(entry.file_id == entries[parent].1.identity.file_id)",
            "children.iter().find(|(p, name, _, _)| *p == index && *name == entry.name).ok_or(Error::Unsafe)",
            "need(entry.file_id == expected.id && entry.kind == *kind && entries[index].1.identity.volume_serial == expected.volume)",
            ".map(|(_, name, _, _)| name.clone()).chain([\".\".to_owned(), \"..\".to_owned()]).collect()",
            "need(seen == expected)",
        ] { assert!(inventory.contains(predicate), "{predicate}"); }
        let owner = source.split_once("fn run_prerequisite_traced(").unwrap().1
            .split_once("    trace.prerequisite_at(PrerequisiteStage::Settlement").unwrap().0;
        assert_eq!(owner.matches("output_poststate(").count(), 1);
        assert!(owner.contains("output_index.ok_or(Error::State))?, result, &mut clock, trace, smoke.as_ref()))?;"));
        for error in [Error::Unavailable, Error::Unsafe, Error::Bounds, Error::State, Error::Unknown] {
            let smoke = Smoke::new(); // No initialize/acquire/settle or native call.
            assert_eq!(smoke_result(Some(&smoke), SmokePhase::OutputPoststate, SmokeCheck::OutputUnexpectedChild, Ok(7u8)), Ok(7));
            assert!(smoke.trace.first.get().is_none());
            let original = smoke_result::<()>(Some(&smoke), SmokePhase::OutputPoststate, SmokeCheck::OutputUnexpectedChild, Err(error));
            assert_eq!(original, Err(error));
            let first = smoke.trace.first.get().unwrap();
            assert_eq!((first.phase, first.check, first.error, first.status),
                (SmokePhase::OutputPoststate, SmokeCheck::OutputUnexpectedChild, error, None));
            assert_eq!(smoke_result(Some(&smoke), SmokePhase::OutputPoststate, SmokeCheck::OutputInventory, original), Err(error));
            assert_eq!(smoke_result::<()>(Some(&smoke), SmokePhase::Retirement, SmokeCheck::ProfileRetirement, Err(Error::Unknown)), Err(Error::Unknown));
            assert_eq!(smoke.trace.first.get(), Some(first));
            assert_eq!(smoke_result::<()>(None, SmokePhase::OutputPoststate, SmokeCheck::OutputUnexpectedChild, Err(error)), Err(error));
        }
    }

    fn fixture_writer_contract() {
        // Inspect only the real publisher, never this test's own source literals.
        // The hosted ProjectDraft owner supplies the actual Windows access proof.
        let source = include_str!("ordinary_owner_ui.rs");
        let publisher = source.split_once("fn create_fixture_file(").unwrap().1
            .split_once("\nimpl Fixture {").unwrap().0;
        assert_eq!(publisher.matches(".open_traced(").count(), 1);
        assert_eq!(publisher.matches("clock.effect_traced(trace)?").count(), 2);
        let mut remaining = publisher;
        for operation in [
            "need(files.len() < 48)?;",
            "let writer = files.len();",
            "trace.at(InputRole::Output, Some(writer as u8));",
            "files.push(OriginalFile::fixture_new_traced(path, false, clock.end, trace)?);",
            "files[writer].open_traced(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, null(), trace)?;",
            "files[writer].named_traced(path, trace)?;",
            "files[writer].write_fixture_payload(bytes)?;",
            "let created = files[writer].stamp_traced(trace)?;",
            "files[writer].close_traced(trace)?;",
            "trace.at(InputRole::Output, Some(files.len() as u8));",
            "let index = input(files, path, false, FS::FILE_GENERIC_READ | FS::WRITE_DAC, clock, trace)?;",
            "let reopened = files[index].stamp_traced(trace)?;",
            concat!("need(reopened.volume == created.volume && reopened.id == created.id && reopened.creation == created.creation\n",
                "        && reopened.size == bytes.len() as i64 && reopened.size == created.size && reopened.links == 1\n",
                "        && reopened.attributes == created.attributes && reopened.write >= created.write && reopened.change >= created.change\n",
                "        && files[index].read_traced(LIMIT, trace)? == bytes)?;"),
            "trace.at(InputRole::AclOutput, Some(index as u8));",
            "acl(files, index, \"synthetic-input\", FS::FILE_GENERIC_READ, parent, account, clock, trace, transitions)?;",
            "trace.at(InputRole::Output, Some(index as u8));",
            "Ok(FixtureFile { index, stamp: files[index].stamp_traced(trace)?, bytes })",
        ] {
            assert_eq!(publisher.matches(operation).count(), 1, "{operation}");
            remaining = remaining.split_once(operation)
                .unwrap_or_else(|| panic!("publisher operation missing or out of order: {operation}")).1;
        }
    }

    #[test]
    fn native_smoke_never_credits_posting_or_partial_release_as_finality() {
        main_window_selection_contract(); initial_main_readiness_contract(); dashboard_main_handle_readiness_contract();
        dashboard_name_observation_contract(); dashboard_stale_name_contract();
        startup_diagnostic_contract();
        quit_logical_controls_contract();
        normal_smoke_launch_directory_contract().expect("closed normal-smoke directory routing");
        output_inventory_diagnostic_contract();
        fixture_writer_contract();
        // Actual finite native-containment routing; no native call is entered.
        use crate::ui::quit_native::Failure as Q;
        for (failure, check, error) in [
            (Q::State, SmokeCheck::QuitNativeState, Error::State),
            (Q::Bounds, SmokeCheck::QuitNativeBounds, Error::Bounds),
            (Q::Process, SmokeCheck::QuitNativeProcess, Error::Unsafe),
            (Q::Thread, SmokeCheck::QuitNativeThread, Error::Unsafe),
            (Q::Descendant, SmokeCheck::QuitNativeDescendant, Error::Unsafe),
            (Q::Lineage, SmokeCheck::QuitNativeLineage, Error::Unsafe),
            (Q::Style, SmokeCheck::QuitNativeStyle, Error::Unsafe),
            (Q::Changed, SmokeCheck::QuitNativeChanged, Error::Unsafe),
        ] {
            let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::QuitDialog);
            let mut effects = 0;
            let result: Result<()> = (|| { trace.quit_native::<()>(Err(failure))?; effects += 1; Ok(()) })();
            assert_eq!(result, Err(error)); assert_eq!(effects, 0);
            let first = trace.first.get().expect("actual refusing decision");
            assert_eq!((first.phase, first.check, first.error), (SmokePhase::QuitDialog, check, error));
            assert_eq!(first.status, None); assert_eq!(first.dashboard, None);
            assert_eq!(trace.quit_native::<()>(Err(Q::Changed)), Err(Error::Unsafe));
            assert_eq!(trace.first.get(), Some(first));
        }
        // Actual admission helper, inert Results/counters only: no native clock,
        // output reservation, HWND/COM call or cleanup is entered by these cases.
        for (unknown, settled, count, remaining, expected, check, expected_calls) in [
            (true, false, 2048, Ok(1000), Err(Error::Unsafe), Some(SmokeCheck::ComReserveState), 0),
            (false, true, 2048, Ok(1000), Err(Error::Unsafe), Some(SmokeCheck::ComReserveState), 0),
            (true, true, 2048, Err(Error::Unknown), Err(Error::Unsafe), Some(SmokeCheck::ComReserveState), 0),
            (false, false, 2048, Err(Error::Unknown), Err(Error::Unsafe), Some(SmokeCheck::ComReserveCapacity), 0),
            (false, false, 2047, Ok(1000), Err(Error::Unsafe), Some(SmokeCheck::ComReserveBudget), 1),
            (false, false, 2047, Ok(1001), Ok(()), None, 1),
            (false, false, 0, Ok(1001), Ok(()), None, 1),
            (false, false, 2047, Err(Error::Bounds), Err(Error::Bounds), Some(SmokeCheck::Clock), 1),
        ] {
            let trace = SmokeTrace::new(); let calls = Cell::new(0);
            let result = trace.admit_com(unknown, settled, count, || { calls.set(calls.get() + 1); remaining });
            assert_eq!(result, expected); assert_eq!(calls.get(), expected_calls);
            assert_eq!(trace.first.get().map(|fault| fault.check), check);
            if let Some(first) = trace.first.get() {
                assert_eq!(Some(first.error), result.err()); assert_eq!(first.status, None); assert_eq!(first.dashboard, None);
            }
        }
        let prior = SmokeTrace::new(); let calls = Cell::new(0);
        assert_eq!(prior.result::<()>(SmokeCheck::CurrentName, Err(Error::Unknown), None), Err(Error::Unknown));
        let original_fault = prior.first.get();
        assert_eq!(prior.admit_com(false, false, 2047, || { calls.set(calls.get() + 1); Ok(1000) }), Err(Error::Unsafe));
        assert_eq!(calls.get(), 1); assert_eq!(prior.first.get(), original_fault);

        let progress_trace = SmokeTrace::new();
        assert_eq!(progress_trace.dashboard.get(), None);
        progress_trace.dashboard_begin_pass(); progress_trace.dashboard_update(DashboardProgress::begin_walk);
        assert_eq!(progress_trace.dashboard.get(), None); // Not yet in dashboard.
        progress_trace.phase.set(SmokePhase::Dashboard);
        progress_trace.dashboard_update(DashboardProgress::begin_walk);
        assert_eq!(progress_trace.dashboard.get(), None); // No pass has begun.
        progress_trace.dashboard_begin_pass();
        let initial = progress_trace.dashboard.get().unwrap();
        assert_eq!(initial.stage, DashboardStage::Bind); assert!(!initial.any_walk_completed);
        assert_eq!(initial.current_walk_visited, None); assert_eq!(initial.current_match_mask, None); assert_eq!(initial.current_names, None);
        assert_eq!(initial.last_scan, None); assert_eq!(initial.scan_history, DashboardScanHistory::None);
        progress_trace.dashboard_update(DashboardProgress::begin_walk);
        assert_eq!(progress_trace.dashboard.get().unwrap().current_walk_visited, Some(0));
        progress_trace.dashboard_update(|progress| progress.walk_visited(17));
        let partial_walk = progress_trace.dashboard.get().unwrap();
        assert_eq!(partial_walk.stage, DashboardStage::Walk); assert_eq!(partial_walk.current_walk_visited, Some(17));
        assert!(!partial_walk.any_walk_completed); assert_eq!(partial_walk.current_match_mask, None);
        assert_eq!(progress_trace.admit_com(false, false, 2047, || Ok(1000)), Err(Error::Unsafe));
        let frozen = progress_trace.first.get().unwrap();
        assert_eq!(frozen.dashboard, Some(partial_walk)); assert_eq!(frozen.check, SmokeCheck::ComReserveBudget);
        progress_trace.dashboard_update(DashboardProgress::walk_completed);
        progress_trace.dashboard_update(DashboardProgress::begin_names);
        let names = progress_trace.dashboard.get().unwrap();
        assert_eq!(names.stage, DashboardStage::Names); assert!(names.any_walk_completed);
        assert_eq!(names.current_match_mask, Some(0)); assert_eq!(names.last_scan, None);
        for bit in 0..5 {
            let mut found = [false; 5]; found[bit] = true;
            progress_trace.dashboard_update(|progress| progress.matches(found));
            assert_eq!(progress_trace.dashboard.get().unwrap().current_match_mask, Some(1u8 << bit));
        }
        let mut found = [true; 5]; progress_trace.dashboard_update(|progress| progress.matches(found));
        progress_trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Loading));
        found = [false; 5]; assert_eq!(found, [false; 5]); // Existing loading reset, after snapshot.
        let loading = progress_trace.dashboard.get().unwrap();
        assert_eq!(loading.stage, DashboardStage::NamesEnded); assert_eq!(loading.current_match_mask, Some(31));
        assert_eq!(loading.last_scan, Some(DashboardScan { match_mask: 31, end: DashboardScanEnd::Loading,
            walk_visited: 17, names: DashboardNames::new() }));
        assert_eq!(loading.scan_history, DashboardScanHistory::LoadingOnly);
        progress_trace.dashboard_update(|progress| progress.end_names(DashboardScanEnd::Exhausted));
        assert_eq!(progress_trace.dashboard.get(), Some(loading)); // A loading end is not exhausted.
        for (end, found, mask, history) in [
            (DashboardScanEnd::Loading, [false, true, false, false, false], 2, DashboardScanHistory::LoadingOnly),
            (DashboardScanEnd::Exhausted, [true, false, true, false, false], 5, DashboardScanHistory::ExhaustedSeen),
            (DashboardScanEnd::Loading, [false; 5], 0, DashboardScanHistory::ExhaustedSeen),
        ] {
            let previous = progress_trace.dashboard.get().unwrap(); progress_trace.dashboard_begin_pass();
            let reset = progress_trace.dashboard.get().unwrap();
            assert_eq!(reset.stage, DashboardStage::Bind); assert!(reset.any_walk_completed);
            assert_eq!(reset.current_walk_visited, None); assert_eq!(reset.current_match_mask, None); assert_eq!(reset.current_names, None);
            assert_eq!(reset.last_scan, previous.last_scan); assert_eq!(reset.scan_history, previous.scan_history);
            progress_trace.dashboard_update(DashboardProgress::begin_walk);
            progress_trace.dashboard_update(|progress| progress.walk_visited(900));
            progress_trace.dashboard_update(DashboardProgress::walk_completed);
            progress_trace.dashboard_update(DashboardProgress::begin_names);
            assert_eq!(progress_trace.dashboard.get().unwrap().current_match_mask, Some(0));
            progress_trace.dashboard_update(|progress| progress.matches(found));
            let prefix = progress_trace.dashboard.get().unwrap();
            assert_eq!(prefix.current_walk_visited, Some(900)); assert_eq!(prefix.current_match_mask, Some(mask));
            assert_eq!(prefix.last_scan, previous.last_scan); assert_eq!(prefix.scan_history, previous.scan_history);
            progress_trace.dashboard_update(|progress| progress.end_names(end));
            let ended = progress_trace.dashboard.get().unwrap();
            assert_eq!(ended.last_scan, Some(DashboardScan { match_mask: mask, end, walk_visited: 900, names: DashboardNames::new() }));
            assert_eq!(ended.scan_history, history);
        }
        progress_trace.phase.set(SmokePhase::DriverSettle);
        assert_eq!(progress_trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None), Err(Error::Unknown));
        assert_eq!(progress_trace.first.get(), Some(frozen)); // Copy, not a view of later progress/cleanup.
        let mut frozen_output = Vec::new(); progress_trace.emit_to(&mut frozen_output).unwrap();
        let frozen_text = std::str::from_utf8(&frozen_output).unwrap();
        assert!(frozen_text.contains("\"stage\":\"walk\",\"anyWalkCompleted\":false,\"currentWalkVisited\":17"));
        assert!(frozen_text.contains("\"currentMatchMask\":null,\"currentNames\":null,\"lastScan\":null,\"scanHistory\":\"none\""));
        assert!(frozen_text.contains("\"mainBindingTimeouts\":0"));
        // First four bits are retained before the existing possibly failing
        // enabled-button query. A later fifth-bit observation cannot backfill it.
        let prefix = SmokeTrace::new(); prefix.phase.set(SmokePhase::Dashboard); prefix.dashboard_begin_pass();
        prefix.dashboard_update(DashboardProgress::begin_walk); prefix.dashboard_update(|progress| progress.walk_visited(1));
        prefix.dashboard_update(DashboardProgress::walk_completed); prefix.dashboard_update(DashboardProgress::begin_names);
        prefix.dashboard_update(|progress| { progress.name_returned("Choose a project"); progress.matches([true, true, true, true, false]); });
        assert_eq!(prefix.result::<()>(SmokeCheck::IsEnabled, Err(Error::Unsafe), None), Err(Error::Unsafe));
        prefix.dashboard_update(|progress| progress.matches([true; 5]));
        assert_eq!(prefix.dashboard.get().unwrap().current_match_mask, Some(31));
        assert_eq!(prefix.first.get().unwrap().dashboard.unwrap().current_match_mask, Some(15));
        assert_eq!(prefix.first.get().unwrap().dashboard.unwrap().current_names,
            Some(DashboardNames { returned: 1, empty: 0, text_mask: 128 }));
        for phase in SmokePhase::ALL.iter().copied().filter(|phase| *phase != SmokePhase::Dashboard) {
            let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::Dashboard); trace.dashboard_begin_pass();
            trace.dashboard_update(|progress| *progress = loading); trace.main_binding_timeouts.set(7); trace.phase.set(phase);
            trace.dashboard_begin_pass(); trace.dashboard_update(DashboardProgress::begin_walk);
            assert_eq!(trace.dashboard.get(), Some(loading));
            assert_eq!(trace.result::<()>(SmokeCheck::ComRelease, Err(Error::Unknown), None), Err(Error::Unknown));
            assert_eq!(trace.first.get().unwrap().dashboard, None);
            assert_eq!(trace.first.get().unwrap().main_binding_timeouts, (phase == SmokePhase::MainBinding).then_some(7));
            let mut output = Vec::new(); trace.emit_to(&mut output).unwrap();
            assert!(std::str::from_utf8(&output).unwrap().contains("\"dashboard\":null"));
            assert_eq!(std::str::from_utf8(&output).unwrap().contains("\"mainBindingTimeouts\""), phase == SmokePhase::MainBinding);
        }
        let mut data = Smoke::new(); assert!(!data.passed());
        data.trace.phase.set(SmokePhase::Dashboard); data.trace.dashboard_begin_pass();
        data.trace.dashboard_update(|progress| *progress = loading);
        assert_eq!(data.trace.dashboard.get().unwrap().current_match_mask, Some(31));
        assert!(!data.passed()); // A diagnostic all-match mask grants no finality.
        data.dashboard_ready = true; data.main = Some((1usize as F::HWND, 0, vec![1, 2]));
        data.windows.post_entered = true; data.windows.post_return = 1;
        assert!(!data.passed());
        data.invoke_entered = true; data.invoke_return = 0; data.quit_confirmed = true;
        assert!(!data.passed());
        data.initialized = true; data.uninit_returned = true; data.settled = true;
        assert!(data.passed());
        for raw in [0, 1, StartupWord::default().encode().unwrap()] {
            assert_eq!(data.trace.sample_startup(|| raw, || Ok(())), Ok(())); assert!(data.passed());
        }
        data.unknown = true; assert!(!data.passed());
        data.unknown = false; data.dashboard_ready = false; assert!(!data.passed());
        // No native initialize/acquire happened. Never invoke settle on DATA.

        let _ = data.trace.result::<()>(SmokeCheck::CurrentName, Err(Error::Unsafe), Some(SmokeStatus::Hresult(i32::MIN)));
        assert!(!data.passed()); data.dashboard_ready = true; assert!(data.passed());
        // Diagnostic DATA neither grants nor revokes the existing finality.
        data.unknown = true; assert!(!data.passed());
        let no_fault = SmokeTrace::new(); let mut silence = Vec::new();
        assert_eq!(no_fault.result(SmokeCheck::Clock, Ok(7u8), None), Ok(7));
        assert_eq!(no_fault.emit_to(&mut silence).unwrap(), None);
        assert!(silence.is_empty() && !no_fault.emitted.get() && no_fault.first.get().is_none());

        for error in [Error::Unavailable, Error::Unsafe, Error::Bounds, Error::State, Error::Unknown] {
            let trace = SmokeTrace::new(); trace.phase.set(SmokePhase::Dashboard);
            let saved = Cell::new(i32::MIN);
            assert_eq!(trace.result::<u8>(SmokeCheck::CurrentName, Err(error), Some(SmokeStatus::Hresult(saved.get()))), Err(error));
            let first = SmokeFault { phase: SmokePhase::Dashboard, check: SmokeCheck::CurrentName,
                error, status: Some(SmokeStatus::Hresult(i32::MIN)), dashboard: None, main_binding_timeouts: Some(0),
                dashboard_binding_timeouts: Some(0), startup: StartupSample::new(), quit: None };
            saved.set(0); trace.phase.set(SmokePhase::DriverSettle);
            assert_eq!(trace.result(SmokeCheck::Clock, Ok(false), None), Ok(false));
            assert_eq!(trace.result::<()>(SmokeCheck::ArrayDestroy, Err(Error::Unknown), Some(SmokeStatus::Hresult(saved.get()))), Err(Error::Unknown));
            assert_eq!(trace.first.get(), Some(first));
        }
        // Actual ComOriginal DATA result, but invented later clock Result:
        // acquisition failure is first; the later clock still controls return.
        let early = SmokeTrace::new(); let mut original = ComOriginal::new(ComKind::Element);
        assert!(original.begin().is_ok());
        let mut late_checked = false;
        let returned = (|| -> Result<bool> {
            let result = early.result(SmokeCheck::ElementFromWindow,
                original.returned(HRESULT_PENDING, false), Some(SmokeStatus::Hresult(HRESULT_PENDING)));
            late_checked = true;
            early.result(SmokeCheck::Clock, Err::<(), _>(Error::Unsafe), None)?;
            result
        })();
        assert!(late_checked); assert_eq!(returned, Err(Error::Unsafe));
        assert_eq!(early.first.get().unwrap().check, SmokeCheck::ElementFromWindow);
        assert_eq!(early.first.get().unwrap().error, Error::Unknown);
        // Returned query status is not a refusing predicate before its original
        // clock check. Do not mislabel a clock error with a saved HRESULT.
        let clock_first = SmokeTrace::new();
        let returned = (|| -> Result<()> {
            clock_first.result(SmokeCheck::Clock, Err(Error::Unsafe), None)?;
            clock_first.result(SmokeCheck::CurrentName, need(false), Some(SmokeStatus::Hresult(i32::MIN)))
        })();
        assert_eq!(returned, Err(Error::Unsafe));
        assert_eq!(clock_first.first.get().unwrap().check, SmokeCheck::Clock);
        assert_eq!(clock_first.first.get().unwrap().status, None);
        // Real inert UTF-16 conversion; invented settlement/clock Results only.
        let conversion = SmokeTrace::new(); let mut clock_reached = false;
        let returned = (|| -> Result<String> {
            let text = conversion.result(SmokeCheck::NameEncoding,
                String::from_utf16(&[0xd800]).map_err(|_| Error::Unsafe), None);
            conversion.result(SmokeCheck::ArrayDestroy, Err::<(), _>(Error::Unknown), Some(SmokeStatus::Hresult(-1)))?;
            clock_reached = true; conversion.result(SmokeCheck::Clock, Ok(()), None)?;
            text
        })();
        assert_eq!(returned, Err(Error::Unknown)); assert!(!clock_reached);
        assert_eq!(conversion.first.get().unwrap().check, SmokeCheck::NameEncoding);
        assert_eq!(conversion.first.get().unwrap().error, Error::Unsafe);
        assert_eq!(conversion.first.get().unwrap().status, None);

        use crate::ui_startup_data::{Event as StartupEvent, Stage as StartupStage};
        // All finite v1 event/detail/stage combinations, including native slot
        // part1 and multi-digit details. Other fields use simultaneous maxima.
        // The selected widest VALID word is rendered by the production formatter.
        let mut widest_word = StartupWord::default(); let mut widest_fields = 0;
        for event in (0..64).filter_map(StartupEvent::from_code) {
            for detail in 0..64 {
                for stage in (0..64).filter_map(StartupStage::from_code) {
                    let word = StartupWord { conditions: (1 << 26) - 1, event, detail, stage,
                        first_refusal: event.refused(), live: 7, seen: 15 };
                    if word.encode().is_some() {
                        let fields = event.label().len() + stage.label().len() + 1 + usize::from(detail >= 10)
                            + if event.refused() { 4 } else { 5 };
                        if fields > widest_fields { widest_word = word; widest_fields = fields; }
                    }
                }
            }
        }
        assert!(widest_fields != 0 && widest_word.encode().is_some());
        let longest_phase = *SmokePhase::ALL.iter().max_by_key(|value| value.label().len()).unwrap();
        let longest_check = *SmokeCheck::ALL.iter().max_by_key(|value| value.label().len()).unwrap();
        for label in SmokePhase::ALL.iter().map(|value| value.label()).chain(SmokeCheck::ALL.iter().map(|value| value.label()))
            .chain(DashboardStage::ALL.iter().map(|value| value.label())).chain(DashboardScanEnd::ALL.iter().map(|value| value.label()))
            .chain(DashboardScanHistory::ALL.iter().map(|value| value.label())) {
            assert!(label.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'-'));
        }
        // Conservative combinations include nullable current fields and false
        // (longer than true), even when not jointly reachable in production.
        let widest_names = DashboardNames { returned: u16::MAX, empty: u16::MAX, text_mask: u8::MAX };
        let widest_dashboard = DashboardProgress { stage: DashboardStage::NamesEnded, any_walk_completed: false,
            current_walk_visited: Some(usize::MAX), current_match_mask: Some(u8::MAX), current_names: Some(widest_names),
            last_scan: Some(DashboardScan { match_mask: u8::MAX, end: DashboardScanEnd::Exhausted, walk_visited: usize::MAX, names: widest_names }),
            scan_history: DashboardScanHistory::ExhaustedSeen };
        let nullable_dashboard = DashboardProgress { current_walk_visited: None, current_match_mask: None, current_names: None, ..widest_dashboard };
        // "null" is longer than the largest numeric u8 mask, while full
        // counts/name statistics are longer than their nullable alternatives.
        let null_mask_dashboard = DashboardProgress { current_match_mask: None, ..widest_dashboard };
        for dashboard in [None, Some(widest_dashboard), Some(nullable_dashboard), Some(null_mask_dashboard)] {
            for status in [None, Some(SmokeStatus::Hresult(i32::MIN)), Some(SmokeStatus::Hresult(i32::MAX)),
                Some(SmokeStatus::Win32(u32::MAX))] {
                let fault = SmokeFault { phase: longest_phase, check: longest_check, error: Error::Unavailable, status, dashboard,
                    main_binding_timeouts: Some(u16::MAX), dashboard_binding_timeouts: Some(u16::MAX), startup: StartupSample {
                        availability: StartupAvailability::Missing, last: Some((widest_word, longest_phase)) }, quit: None };
                let mut raw = [0u8; 1024]; let size = SmokeTrace::format(fault, &mut raw).unwrap();
                let text = std::str::from_utf8(&raw[..size]).unwrap();
                assert!(size <= 1024 && text.is_ascii() && text.ends_with("}\n") && text.lines().count() == 1);
                assert!(text.starts_with("MRK_WINDOWS_NORMAL_UI_SMOKE_REFUSED={\"diagnosticOnly\":true,"));
                let expected_status = match status {
                    None => "\"nativeStatus\":null".to_owned(),
                    Some(SmokeStatus::Hresult(code)) => format!("\"nativeStatus\":{{\"domain\":\"hresult\",\"code\":{code}}}"),
                    Some(SmokeStatus::Win32(code)) => format!("\"nativeStatus\":{{\"domain\":\"win32\",\"code\":{code}}}"),
                };
                assert!(text.contains(&expected_status));
                match dashboard {
                    Some(progress) => {
                        assert!(text.contains("\"stage\":\"names-ended\",\"anyWalkCompleted\":false"));
                        let expected_count = progress.current_walk_visited.map(|count| count.to_string()).unwrap_or_else(|| "null".to_owned());
                        assert!(text.contains(&format!("\"currentWalkVisited\":{expected_count}")));
                        assert!(text.contains(if progress.current_match_mask.is_some() { "\"currentMatchMask\":255" } else { "\"currentMatchMask\":null" }));
                        assert!(text.contains(if progress.current_names.is_some() {
                            "\"currentNames\":{\"returned\":65535,\"empty\":65535,\"textMask\":255}"
                        } else { "\"currentNames\":null" }));
                        assert!(text.contains(&format!("\"lastScan\":{{\"matchMask\":255,\"end\":\"exhausted\",\"walkVisited\":{},\"names\":{{\"returned\":65535,\"empty\":65535,\"textMask\":255}}}},\"scanHistory\":\"exhausted-seen\"", usize::MAX)));
                    }
                    None => assert!(text.contains("\"dashboard\":null")),
                }
                assert!(text.contains("\"mainBindingTimeouts\":65535"));
                for forbidden in ["account", "Sid", "handle", "processId", "path", "title", "credential", "sourceSha"] {
                    assert!(!text.contains(&format!("\"{forbidden}\":")));
                }
                assert!(SmokeTrace::format(fault, &mut [0u8; 8]).is_err());
            }
        }
        struct Sink { calls: usize, fail: bool, short: bool, bytes: Vec<u8> }
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.fail { return Err(std::io::ErrorKind::Other.into()); }
                let count = if self.short { bytes.len() - 1 } else { bytes.len() };
                self.bytes.extend_from_slice(&bytes[..count]); Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> { panic!("diagnostic must not add a flush"); }
        }
        // Exercise the SAME production latch/format/fallback/one-write path
        // with an insufficient inert buffer; no native API or extra emission.
        let trace = SmokeTrace::new();
        let mut sink = Sink { calls: 0, fail: false, short: false, bytes: Vec::new() };
        let _ = trace.result::<()>(SmokeCheck::Clock, Err(Error::Unsafe), None);
        let fallback = b"MRK_WINDOWS_NORMAL_UI_SMOKE_REFUSED={\"diagnosticOnly\":true,\"diagnosticIncomplete\":true}\n";
        assert_eq!(trace.emit_with_buffer(&mut sink, &mut [0u8; 8]).unwrap(), Some(fallback.len()));
        assert_eq!(sink.bytes.as_slice(), fallback); assert_eq!(sink.calls, 1);
        assert_eq!(trace.emit_to(&mut sink).unwrap(), None); assert_eq!(sink.calls, 1);
        for (fail, short) in [(false, false), (false, true), (true, false)] {
            let trace = SmokeTrace::new(); let mut sink = Sink { calls: 0, fail, short, bytes: Vec::new() };
            assert_eq!(trace.emit_to(&mut sink).unwrap(), None); assert_eq!(sink.calls, 0);
            trace.phase.set(SmokePhase::Dashboard); trace.dashboard.set(Some(widest_dashboard)); trace.main_binding_timeouts.set(u16::MAX);
            trace.startup.set(StartupSample { availability: StartupAvailability::Missing, last: Some((widest_word, longest_phase)) });
            let result = trace.result::<()>(SmokeCheck::PostClose, Err(Error::Unsafe), Some(SmokeStatus::Win32(u32::MAX)));
            let written = trace.emit_to(&mut sink);
            assert_eq!(written.is_err(), fail); assert_eq!(result, Err(Error::Unsafe));
            assert_eq!(sink.calls, 1); assert!(trace.emitted.get());
            assert_eq!(trace.emit_to(&mut sink).unwrap(), None); assert_eq!(sink.calls, 1);
            if !fail { assert_eq!(sink.bytes.ends_with(b"\n"), !short); }
            assert!(sink.bytes.len() <= 1024);
        }
    }
}
