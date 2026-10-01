//! Closed metadata-image-loader resource DATA. No DLL loading or image permit.
//!
//! Standard NativeBook remains48. The one opt-in constructor freezes the complete
//! proved selected catalog before any native work. This module deliberately has
//! NO production profile: the bridge binary/PE+Python closure has not been made.
//! Synthetic unit DATA cannot populate COMPILED or authorize a native owner.
use super::{AceFact, Arena, Error, Result, SecurityFacts, Sid, SlotState, SystemImage, MAX_ORIGINALS, BUFFER, counts_live};
use std::mem::size_of;

pub const CATALOG_COUNT: usize = 40;
pub const SECURITY_BYTES: usize = 16 * 1024 * 1024;
pub const DIRECTORY_ENVELOPE: usize = 12;
const LEGACY_SELECTED: usize = 3;
const OS_ORIGINALS: usize = 31;
const TOKEN_ORIGINALS: usize = 2;
const MAX_CLOSURE_EDGES: usize = 2048;
const MAX_ACES: usize = 2048;
const MAX_SID_BYTES: usize = 68;

macro_rules! payloads {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u8)]
        pub enum Payload { $($variant),+ }
        impl Payload {
            pub const ALL: [Self; CATALOG_COUNT] = [$(Self::$variant),+];
            pub fn name(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            pub fn from_name(name: &str) -> Option<Self> {
                // Exact spelling only: a case alias is NOT another input.
                Self::ALL.iter().copied().find(|item| item.name() == name)
            }
            pub(super) fn bit(self) -> u64 { 1u64 << self as u8 }
            pub fn ordinal(self) -> usize { self as usize }
        }
    };
}
payloads! {
    License => "python/LICENSE.txt", Asyncio => "python/_asyncio.pyd",
    Bz2 => "python/_bz2.pyd", Ctypes => "python/_ctypes.pyd",
    Decimal => "python/_decimal.pyd", ElementTree => "python/_elementtree.pyd",
    Hashlib => "python/_hashlib.pyd", Lzma => "python/_lzma.pyd",
    Multiprocessing => "python/_multiprocessing.pyd", Overlapped => "python/_overlapped.pyd",
    Queue => "python/_queue.pyd", RemoteDebugging => "python/_remote_debugging.pyd",
    Socket => "python/_socket.pyd", SqliteExtension => "python/_sqlite3.pyd",
    Ssl => "python/_ssl.pyd", Uuid => "python/_uuid.pyd", Wmi => "python/_wmi.pyd",
    ZoneInfo => "python/_zoneinfo.pyd", Zstd => "python/_zstd.pyd",
    LibCrypto => "python/libcrypto-3.dll", LibFfi => "python/libffi-8.dll",
    LibSsl => "python/libssl-3.dll", LibTomMath => "python/libtommath.dll",
    PyExpat => "python/pyexpat.pyd", PythonCatalog => "python/python.cat",
    Python => "python/python.exe", Python3 => "python/python3.dll",
    PythonPath => "python/python314._pth", Python314 => "python/python314.dll",
    PythonZip => "python/python314.zip", PythonWindowed => "python/pythonw.exe",
    Select => "python/select.pyd", Sqlite => "python/sqlite3.dll",
    Unicode => "python/unicodedata.pyd", VcRuntime => "python/vcruntime140.dll",
    VcRuntime1 => "python/vcruntime140_1.dll", WinSound => "python/winsound.pyd",
    Bootstrap => "config_edit_bootstrap.py", Core => "core.zip",
    Bridge => "python/mrk_image_writer_native.dll",
}
pub const REQUIRED: [Payload; 9] = [
    Payload::Bootstrap, Payload::Core, Payload::Python, Payload::Python314,
    Payload::PythonPath, Payload::PythonZip, Payload::Ctypes, Payload::LibFfi, Payload::Bridge,
];
const CATALOG_MASK: u64 = (1u64 << CATALOG_COUNT) - 1;
fn required_mask() -> u64 { REQUIRED.iter().fold(0, |bits, item| bits | item.bit()) }

// These are the unchanged supplier pins, not a new publisher or supplier ZIP.
// The three non-supplier pins must come from the separately reviewed image
// profile. No sample hash here can be a production core/bootstrap/bridge pin.
pub(super) const SUPPLIER: [(&str, u64, &str); 37] = [
    ("python/LICENSE.txt", 35407, "935cf13e19f8c31b497d20b05d73623431a226b230c3599bc30fa3348979bc68"),
    ("python/_asyncio.pyd", 78048, "f9594a2a4f45570dbfdf1f3471194ae7b27dc117c54b9af6bc22df9c93830f8b"),
    ("python/_bz2.pyd", 88288, "b938073c85cf6b9fe80556d7899ed1901e5e60b7adea2832442376239fb36b36"),
    ("python/_ctypes.pyd", 142560, "408cc4e7a22ffa418ca52f5e13fe9268a3c50a2bc9de02b0530b555ef591bc5a"),
    ("python/_decimal.pyd", 291552, "bc3a61685825ae37a4cd2b2b87fa27af12e01575c4f920788ea806e6781a2c79"),
    ("python/_elementtree.pyd", 138976, "d8a17f9c831e313b440e19e0d26e6c0e7ed830ff1f657887cbc26664d6ef4973"),
    ("python/_hashlib.pyd", 69344, "5933ef5eda7c0bca0b3874a6e2c5f13b91b8f2cfc29bc46160df3212a1dbee79"),
    ("python/_lzma.pyd", 160992, "d2abf8db7fb0cf6285663b177991691a41b37e215c3d71fd087a98d8ec1bee63"),
    ("python/_multiprocessing.pyd", 38624, "cea83c9bf3131d079c20066b626f67ab33021b476777be2d7be26d1fa5e4eb66"),
    ("python/_overlapped.pyd", 58080, "1d7028683e6ec50c159139238f90a6c8431ece139a4764900ca11c941ba05d46"),
    ("python/_queue.pyd", 36576, "2fd8668f52b34d0e71ae48784bd2e7d35e5d99df6f641edb0fc279235a187c8e"),
    ("python/_remote_debugging.pyd", 93408, "32b58c85e29ecc2378eddfe367745998fdb131e1ab6bb84d54e16f33806b584c"),
    ("python/_socket.pyd", 87776, "02265dd0d0287f3ffd287ea5d8e3c918a5a056e8ef2c4529857f5e84ec9e2519"),
    ("python/_sqlite3.pyd", 132832, "ec9694e5929747e93e05bc32427d24350dc4de5074b61a37bc961c3048794a67"),
    ("python/_ssl.pyd", 190688, "4cfb154c7cc525d57020c0e64f2dd876a78b46cd38419446392478de6b7b13b8"),
    ("python/_uuid.pyd", 28384, "fbfd7fe8583b346ba20b174b2510c0830237f5092bdf9fc26da9d6b25b018385"),
    ("python/_wmi.pyd", 40160, "b6fd41f079da0c0054829855360e88b8b762f5c42bb474c2fa02eae367839ad2"),
    ("python/_zoneinfo.pyd", 51936, "07469c7fc221663e423a2e6023a5b2ead3b10d0b40eb297887f4447a1ff1b2a3"),
    ("python/_zstd.pyd", 503520, "33c6eca99470c3eb9d776b617c550ad41b002a668336f062a9ab7be677a7409a"),
    ("python/libcrypto-3.dll", 6242552, "53c529145339fb042a3dcd3a09c2d7753204f8b4fc79d99e0d31e69a33985958"),
    ("python/libffi-8.dll", 39696, "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"),
    ("python/libssl-3.dll", 1329912, "b17a87979862d19241edc4318f967e24c3ec356ed6c2368f561179fab2311001"),
    ("python/libtommath.dll", 95456, "bf18448a56de62e56adb5a50040c08648f0bcf556217de90eca283490ee8c0c3"),
    ("python/pyexpat.pyd", 222944, "e34347c4e11b2ecc57df2ce1627ba7f98fd076e9df59951e9034f5aa8e95a2fc"),
    ("python/python.cat", 600973, "bd98c1a5acc6dc6850425221a755506571eac182cb0aa85f2f45a9a077a3c71b"),
    ("python/python.exe", 106208, "4942b86a6597e5aee0128daa00050ed79bc21f6e709a78eb19cbfeb0c2f39ac9"),
    ("python/python3.dll", 73952, "6c45910e7c82617ca6360820de861699cc99f9efee434df290aa4c6e38f39886"),
    ("python/python314._pth", 80, "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c"),
    ("python/python314.dll", 6785760, "0f9857ffdfe010fe6b99328d58c2e3c7472ce75f336bf9c2ad9bd5bca3bce700"),
    ("python/python314.zip", 4138882, "5a7a66daf1a2c2e3c8d7a4a0d095685ec301efc3ef28cc2419e3041bf5729b65"),
    ("python/pythonw.exe", 104672, "c197268f7e7cf2848b8c1ae59bbd0e0c14defe668a2d365302137ea929b47769"),
    ("python/select.pyd", 33504, "722328e7fad8048057fc966474ba73966d2ceebaa32e7344cce09640ab4dc9bd"),
    ("python/sqlite3.dll", 1584864, "d3e60dd22e62c9fbdb64b31b1b8c48782e1d4958d04d0bf830cffd31ace3275f"),
    ("python/unicodedata.pyd", 759008, "280b09bd97b598d18c0ed9542dc18ed35fa57a16e84f8e65fd9c6e96516c28d6"),
    ("python/vcruntime140.dll", 178616, "d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7"),
    ("python/vcruntime140_1.dll", 50112, "a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e"),
    ("python/winsound.pyd", 32992, "6a27340660de89d5da59445a77ac6b08d471e373304ce7294c198238f09f2dc2"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Architecture { Data, X64Pe }
fn architecture(payload: Payload) -> Architecture {
    match payload {
        Payload::License | Payload::PythonCatalog | Payload::PythonPath
        | Payload::PythonZip | Payload::Bootstrap | Payload::Core => Architecture::Data,
        _ => Architecture::X64Pe,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Artifact<'a> { name: &'a str, bytes: u64, sha256: &'a str, architecture: Architecture }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum EdgeKind { StaticImport, DelayImport, DynamicInput }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ClosureEdge<'a> { source: &'a str, kind: EdgeKind, target: &'a str }
#[derive(Clone, Copy)]
struct Closure<'a> {
    // Separate exact proof bindings: a source import expectation is not a PE
    // import table, and direct imports alone do not prove delay/dynamic inputs.
    fingerprint: &'a str, pe_imports: &'a str, delay_imports: &'a str, dynamic_inputs: &'a str,
    rows: &'a [Artifact<'a>], edges: &'a [ClosureEdge<'a>],
}
struct Profile<'a> {
    target: &'a str, manifest: &'a str, protocol: &'a str,
    extras: [Artifact<'a>; 3], // bootstrap, core, separately pinned actual bridge
    closure: Closure<'a>,
}
const TARGET: &str = "x86_64-pc-windows-msvc";
static COMPILED: Option<Profile<'static>> = None;

fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn artifact_pin<'a>(profile: &'a Profile<'a>, payload: Payload) -> Result<Artifact<'a>> {
    if payload.ordinal() < SUPPLIER.len() {
        let (name, bytes, sha256) = SUPPLIER[payload.ordinal()];
        if name != payload.name() { return Err(Error::State); }
        Ok(Artifact { name, bytes, sha256, architecture: architecture(payload) })
    } else {
        let item = *profile.extras.get(payload.ordinal() - SUPPLIER.len()).ok_or(Error::State)?;
        if item.name != payload.name() || item.architecture != architecture(payload)
            || item.bytes == 0 || item.bytes > super::MAX_FILE_BYTES || !sha(item.sha256) {
            return Err(Error::Unsafe);
        }
        Ok(item)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenCount { mask: u64, selected: usize, limit: usize }
impl FrozenCount {
    fn from_mask(mask: u64) -> Result<Self> {
        if mask & !CATALOG_MASK != 0 || mask & required_mask() != required_mask() {
            return Err(Error::Unsafe);
        }
        let selected = usize::try_from(mask.count_ones()).map_err(|_| Error::Bounds)?;
        let envelope = MAX_ORIGINALS.checked_sub(LEGACY_SELECTED)
            .and_then(|n| n.checked_sub(OS_ORIGINALS))
            .and_then(|n| n.checked_sub(TOKEN_ORIGINALS)).ok_or(Error::Bounds)?;
        if envelope != DIRECTORY_ENVELOPE || SystemImage::ALL.len() != OS_ORIGINALS
            || !(REQUIRED.len()..=CATALOG_COUNT).contains(&selected) { return Err(Error::Bounds); }
        let limit = MAX_ORIGINALS.checked_sub(LEGACY_SELECTED)
            .and_then(|n| n.checked_add(selected)).ok_or(Error::Bounds)?;
        Ok(Self { mask, selected, limit })
    }
    fn peak(self, directories: usize) -> Result<usize> {
        let peak = directories.checked_add(self.selected)
            .and_then(|n| n.checked_add(OS_ORIGINALS))
            .and_then(|n| n.checked_add(TOKEN_ORIGINALS)).ok_or(Error::Bounds)?;
        if directories > DIRECTORY_ENVELOPE || peak > self.limit { Err(Error::Bounds) } else { Ok(peak) }
    }
}
fn validate_closure(profile: &Profile<'_>, closure: &Closure<'_>) -> Result<FrozenCount> {
    if profile.target != TARGET || !sha(profile.manifest) || !sha(profile.protocol)
        || [closure.fingerprint, closure.pe_imports, closure.delay_imports, closure.dynamic_inputs]
            .iter().any(|value| !sha(value))
        || closure.rows.len() > CATALOG_COUNT || closure.edges.len() > MAX_CLOSURE_EDGES {
        return Err(Error::Unsafe);
    }
    for payload in [Payload::Bootstrap, Payload::Core, Payload::Bridge] { artifact_pin(profile, payload)?; }
    let mut mask = 0u64;
    for row in closure.rows {
        let payload = Payload::from_name(row.name).ok_or(Error::Unsafe)?;
        if mask & payload.bit() != 0 || *row != artifact_pin(profile, payload)? { return Err(Error::Unsafe); }
        mask |= payload.bit();
    }
    let counted = FrozenCount::from_mask(mask)?;
    let mut previous = None;
    for edge in closure.edges {
        if previous.is_some_and(|prior| prior >= *edge) { return Err(Error::Unsafe); }
        previous = Some(*edge);
        let source = Payload::from_name(edge.source).ok_or(Error::Unsafe)?;
        if mask & source.bit() == 0 { return Err(Error::Unsafe); }
        if let Some(target) = Payload::from_name(edge.target) {
            if mask & target.bit() == 0 { return Err(Error::Unsafe); }
        } else if !SystemImage::ALL.iter().any(|image| image.name() == edge.target) {
            // API-set resolution, if needed, must be represented by the actual
            // proved physical OS input and bound by the PE proof fingerprint.
            return Err(Error::Unsafe);
        }
    }
    // A larger cap cannot admit an arbitrary catalog superset: every extra
    // selected input must be reachable from the required startup/import roots.
    let mut reachable = required_mask();
    for _ in 0..CATALOG_COUNT {
        let before = reachable;
        for edge in closure.edges {
            let source = Payload::from_name(edge.source).ok_or(Error::Unsafe)?;
            if reachable & source.bit() != 0 {
                if let Some(target) = Payload::from_name(edge.target) { reachable |= target.bit(); }
            }
        }
        if reachable == before { break; }
    }
    if reachable != mask { return Err(Error::Unsafe); }
    Ok(counted)
}
fn admit_profile(profile: &Profile<'_>, actual: &Closure<'_>) -> Result<FrozenCount> {
    let expected = validate_closure(profile, &profile.closure)?;
    let observed = validate_closure(profile, actual)?;
    if expected != observed || actual.fingerprint != profile.closure.fingerprint
        || actual.pe_imports != profile.closure.pe_imports || actual.delay_imports != profile.closure.delay_imports
        || actual.dynamic_inputs != profile.closure.dynamic_inputs
        || actual.rows != profile.closure.rows || actual.edges != profile.closure.edges {
        return Err(Error::Unsafe);
    }
    Ok(observed)
}

/// Closed compile-bound DATA, not a launch/profile qualification. No integer,
/// caller row list, environment variable or public test constructor produces it.
pub struct ImageLoaderSelection {
    profile: Option<&'static Profile<'static>>,
    count: FrozenCount,
}
impl ImageLoaderSelection {
    pub fn compiled() -> Result<Self> {
        let profile = COMPILED.as_ref().ok_or(Error::Unavailable)?;
        let count = admit_profile(profile, &profile.closure)?;
        Ok(Self { profile: Some(profile), count })
    }
    pub(super) fn production_bound(&self) -> bool {
        match (self.profile, COMPILED.as_ref()) {
            (Some(actual), Some(compiled)) => std::ptr::eq(actual, compiled),
            _ => false,
        }
    }
    pub fn selected_count(&self) -> usize { self.count.selected }
    pub fn selected_mask(&self) -> u64 { self.count.mask }
    pub fn live_limit(&self) -> usize { self.count.limit }
    pub fn peak(&self, directories: usize) -> Result<usize> { self.count.peak(directories) }
    pub fn selected(&self) -> impl Iterator<Item = Payload> + '_ {
        Payload::ALL.into_iter().filter(|item| self.count.mask & item.bit() != 0)
    }
    pub fn contains(&self, item: Payload) -> bool { self.count.mask & item.bit() != 0 }
    pub fn retained_path(&self, path: &str) -> bool {
        self.selected().any(|item| item.name() == path
            || item.name().strip_prefix(path).is_some_and(|tail| tail.starts_with('/')))
    }
    pub fn matches_version(&self, target: &str, manifest: &str, protocol: &str) -> bool {
        self.production_bound() && self.profile.is_some_and(|profile|
            profile.target == target && profile.manifest == manifest && profile.protocol == protocol)
    }
    pub fn closure_fingerprint(&self) -> Result<&'static str> {
        Ok(self.profile.ok_or(Error::Unavailable)?.closure.fingerprint)
    }
    pub fn verify_inventory_file(&self, path: &str, bytes: u64, hash: &str) -> Result<()> {
        let payload = Payload::from_name(path).ok_or(Error::Unsafe)?;
        let pin = artifact_pin(self.profile.ok_or(Error::Unavailable)?, payload)?;
        if bytes == pin.bytes && hash == pin.sha256 { Ok(()) } else { Err(Error::Unsafe) }
    }
    pub fn compile_resource_facts(&self) -> Result<CompileResourceFacts> {
        let profile = self.profile.ok_or(Error::Unavailable)?;
        Ok(CompileResourceFacts {
            selected: self.count.selected, live_limit: self.count.limit,
            catalog_members: CATALOG_COUNT, closure_rows: profile.closure.rows.len(),
            closure_edges: profile.closure.edges.len(), closure_edge_bound: MAX_CLOSURE_EDGES,
            // Static text/tables have no per-book Vec allocation. Report their
            // actual in-object layouts separately from referenced static bytes.
            selection_inline_bytes: size_of::<Self>(), row_layout_bytes: size_of::<Artifact<'static>>(),
            edge_layout_bytes: size_of::<ClosureEdge<'static>>(),
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileResourceFacts {
    pub selected: usize, pub live_limit: usize, pub catalog_members: usize,
    pub closure_rows: usize, pub closure_edges: usize, pub closure_edge_bound: usize,
    pub selection_inline_bytes: usize, pub row_layout_bytes: usize, pub edge_layout_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WalkPhase { Inventory, Loader, Ready, Refused }
/// Image-only phase DATA retained in the same WindowsVersionBook. Its callers
/// supply facts from original records/EOF, not public success receipts.
pub struct ImageWalk {
    selected_mask: u64, attempted: u64, os_attempted: u32,
    transient: bool, phase: WalkPhase, first: Option<Error>,
}
impl ImageWalk {
    pub fn new(selection: &ImageLoaderSelection) -> Self {
        Self { selected_mask: selection.count.mask, attempted: 0, os_attempted: 0,
            transient: false, phase: WalkPhase::Inventory, first: None }
    }
    fn healthy(&self) -> Result<()> { self.first.map_or(Ok(()), Err) }
    fn refusal<T>(&mut self, error: Error) -> Result<T> {
        if self.first.is_none() { self.first = Some(error); }
        self.phase = WalkPhase::Refused;
        Err(self.first.unwrap_or(error))
    }
    pub fn before_directory(&mut self) -> Result<()> {
        self.healthy()?;
        if self.transient || !matches!(self.phase, WalkPhase::Inventory | WalkPhase::Loader) {
            return self.refusal(Error::State);
        }
        // No new directory after the OS-image phase begins. All original
        // known-location/legacy parents are acquired before its first file.
        if self.os_attempted != 0 { return self.refusal(Error::State); }
        Ok(())
    }
    pub fn before_payload(&mut self, selected: Option<Payload>) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || self.transient { return self.refusal(Error::State); }
        match selected {
            Some(payload) if self.selected_mask & payload.bit() != 0 && self.attempted & payload.bit() == 0 => {
                self.attempted |= payload.bit();
            },
            Some(_) => return self.refusal(Error::State),
            None => self.transient = true,
        }
        Ok(()) // attempt frozen BEFORE the original acquisition; never retried
    }
    pub fn transient_closed(&mut self, actual: SlotState) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || !self.transient || actual != SlotState::Closed {
            return self.refusal(Error::State);
        }
        self.transient = false; Ok(())
    }
    pub fn enter_loader(&mut self, inventory_eof: bool, observed_selected_mask: u64,
        nonselected_still_live: bool) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Inventory || self.transient || !inventory_eof
            || nonselected_still_live || observed_selected_mask != self.selected_mask
            || self.attempted != self.selected_mask {
            return self.refusal(Error::State);
        }
        self.phase = WalkPhase::Loader; Ok(())
    }
    pub fn before_os(&mut self, image: SystemImage) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Loader || self.transient { return self.refusal(Error::State); }
        let ordinal = SystemImage::ALL.iter().position(|prior| *prior == image).ok_or(Error::State)?;
        let bit = 1u32.checked_shl(u32::try_from(ordinal).map_err(|_| Error::Bounds)?).ok_or(Error::Bounds)?;
        if self.os_attempted & bit != 0 { return self.refusal(Error::State); }
        self.os_attempted |= bit; Ok(())
    }
    pub fn ready(&mut self, all_originals_admitted: bool) -> Result<()> {
        self.healthy()?;
        if self.phase != WalkPhase::Loader || self.os_attempted != (1u32 << OS_ORIGINALS) - 1
            || !all_originals_admitted { return self.refusal(Error::State); }
        self.phase = WalkPhase::Ready; Ok(())
    }
    pub fn is_ready(&self) -> bool { self.first.is_none() && self.phase == WalkPhase::Ready }
}

/// Not a whole-process heap measurement. This independent image-only16MiB
/// ceiling counts ALL retained security facts plus a simultaneous new decoding
/// and its query/transient reservation. The child's16MiB is not pooled here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityResourceFacts {
    pub retained_bytes: usize, pub decoded_reservation: usize,
    pub query_reservation: usize, pub simultaneous_peak: usize, pub ceiling: usize,
    pub ace_layout_bytes: usize, pub security_layout_bytes: usize,
}
#[derive(Clone, Copy)]
pub(super) struct SecurityReservation { pub facts: SecurityResourceFacts }
fn security_storage(facts: &SecurityFacts) -> Result<usize> {
    size_of::<SecurityFacts>().checked_add(facts.retained_heap_bytes().ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)
}
fn security_total(retained: usize, observation: usize, working: usize) -> Result<usize> {
    let total = retained.checked_add(observation).and_then(|n| n.checked_add(working)).ok_or(Error::Bounds)?;
    if total > SECURITY_BYTES { Err(Error::Bounds) } else { Ok(total) }
}
impl SecurityReservation {
    pub(super) fn reserve<'a>(retained: impl Iterator<Item = &'a SecurityFacts>) -> Result<Self> {
        let mut retained_bytes = 0usize;
        for item in retained {
            retained_bytes = retained_bytes.checked_add(security_storage(item)?).ok_or(Error::Bounds)?;
        }
        // Maximum accepted decoder allocation capacities, NOT lengths or a host
        // layout guess. Each actual allocation is checked inside the shared
        // security decoder before it adopts it; a larger allocator capacity
        // refuses before any next native entry. Owner+temporary group coexist.
        let decoded_reservation = MAX_ACES.checked_mul(size_of::<AceFact>().checked_add(MAX_SID_BYTES).ok_or(Error::Bounds)?)
            .and_then(|n| n.checked_add(2 * MAX_SID_BYTES))
            .and_then(|n| n.checked_add(size_of::<SecurityFacts>()))
            .and_then(|n| n.checked_add(size_of::<Sid>())).ok_or(Error::Bounds)?;
        // Arena contains the original64KiB raw query; it is not copied out.
        // Count the complete target SDK arena layout, not just transferred bytes.
        let query_reservation = size_of::<Arena>();
        if query_reservation < BUFFER { return Err(Error::State); }
        let simultaneous_peak = security_total(retained_bytes, decoded_reservation, query_reservation)?;
        Ok(Self { facts: SecurityResourceFacts {
            retained_bytes, decoded_reservation, query_reservation, simultaneous_peak,
            ceiling: SECURITY_BYTES, ace_layout_bytes: size_of::<AceFact>(),
            security_layout_bytes: size_of::<SecurityFacts>(),
        } })
    }
    pub(super) fn admit_observed(&self, observed: &SecurityFacts) -> Result<()> {
        let actual = security_storage(observed)?;
        if actual > self.facts.decoded_reservation { return Err(Error::Bounds); }
        security_total(self.facts.retained_bytes, actual, self.facts.query_reservation).map(|_| ())
    }
}

impl super::NativeBook {
    /// The original book's measured slot/name/token/frame capacities. This is
    /// DATA only; it neither samples native state nor admits a new operation.
    pub fn metadata_images_resource_facts(&self) -> Result<NativeResourceFacts> {
        let selection = self.metadata_images_selection().ok_or(Error::State)?;
        Ok(NativeResourceFacts {
            selected: selection.selected_count(), live_limit: selection.live_limit(),
            live_originals: self.slots.iter().filter(|slot| counts_live(slot.state)).count(),
            lifetime_records: self.slots.len(), file_attempts: self.slots.iter().filter(|slot| slot.kind == super::Kind::File).count(),
            entries: self.entries, read_bytes: self.bytes_read,
            retained_native_heap_bytes: self.public_image_retained_heap_bytes().ok_or(Error::Bounds)?,
            // Same existing bounded helper: nine worst-case simultaneous native
            // observation arenas/token scratch, separately from ACL accounting.
            native_working_reservation: self.public_image_transient_bytes(true).ok_or(Error::Bounds)?,
            native_book_inline_bytes: size_of::<Self>(),
            maximum_records: super::MAX_RECORDS, maximum_files: super::MAX_FILES,
            maximum_entries: super::MAX_ENTRIES, maximum_file_bytes: super::MAX_FILE_BYTES,
            maximum_read_bytes: super::MAX_TOTAL_BYTES,
        })
    }
    pub fn metadata_images_location_storage(&self, locations: &super::KnownLocations) -> Result<usize> {
        if self.metadata_images_selection().is_none() { return Err(Error::State); }
        let mut bytes = size_of::<super::KnownLocations>();
        for location in [&locations.program_files, &locations.windows, &locations.system] {
            if !std::sync::Arc::ptr_eq(&self.identity, &location.book) { return Err(Error::State); }
            for value in [&location.path, &location.drive, &location.device] {
                bytes = bytes.checked_add(value.capacity()).ok_or(Error::Bounds)?;
            }
            bytes = bytes.checked_add(location.components.capacity().checked_mul(size_of::<String>()).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            for component in &location.components { bytes = bytes.checked_add(component.capacity()).ok_or(Error::Bounds)?; }
        }
        Ok(bytes)
    }
    pub fn metadata_images_security_facts<'a>(&self, retained: impl Iterator<Item = &'a SecurityFacts>)
        -> Result<SecurityResourceFacts> {
        if self.metadata_images_selection().is_none() { return Err(Error::State); }
        Ok(SecurityReservation::reserve(retained)?.facts)
    }
    /// ONLY this method may query security on an image-purpose book. Its one
    /// caller passes every still-present Record.security from that original
    /// WindowsVersionBook; the returned new facts coexist with all old facts.
    pub fn metadata_images_security<'a>(&mut self, original: &super::Original, scope: super::AuthorityScope,
        retained: impl Iterator<Item = &'a SecurityFacts>) -> Result<SecurityFacts> {
        self.clear()?;
        if self.metadata_images_selection().is_none() { return Err(Error::State); }
        let reservation = self.capacity_result(SecurityReservation::reserve(retained))?;
        let index = self.index(original)?;
        let kind = match self.slot(index)?.kind {
            super::Kind::Directory => super::FileKind::Directory,
            super::Kind::File => super::FileKind::File, _ => return Err(Error::State),
        };
        // Reservation precedes allocation/registration/entry. Unknown keeps the
        // entered native Arena in this SAME book; no budget code takes it away.
        let returned = self.original_call(index, super::Call::Security)?;
        let trace = self.admission.at(match scope {
            super::AuthorityScope::AncestorOutsideVersion => super::AdmissionOp::SecurityAncestor,
            super::AuthorityScope::ImmutableVersion => super::AdmissionOp::SecurityVersion,
        });
        let decoded = super::security::Observed::new(trace).image_descriptor(
            returned.bytes_in(returned.count_in(trace)?, trace)?, kind, scope, reservation.facts.decoded_reservation);
        let observed = self.capacity_result(decoded)?;
        self.capacity_result(reservation.admit_observed(&observed))?;
        Ok(observed) // actual capacities checked before the caller's next method
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeResourceFacts {
    pub selected: usize, pub live_limit: usize, pub live_originals: usize,
    pub lifetime_records: usize, pub file_attempts: usize, pub entries: usize, pub read_bytes: u64,
    pub retained_native_heap_bytes: usize, pub native_working_reservation: usize,
    pub native_book_inline_bytes: usize, pub maximum_records: usize, pub maximum_files: usize,
    pub maximum_entries: usize, pub maximum_file_bytes: u64, pub maximum_read_bytes: u64,
}

#[cfg(test)]
#[path = "image_loader_budget_tests.rs"]
mod tests;
