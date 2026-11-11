// Shared unchanged policy DATA. Included at the original installed_runtime path;
// no descriptor owner, consumer permit, native acquisition or application graph.

const TARGET: &str = "x86_64-unknown-linux-gnu";

pub(crate) const MANIFEST_LIMIT: usize = 1024 * 1024;

const MOUNTINFO_LIMIT: usize = 1024 * 1024;

const STATUS_LIMIT: usize = 64 * 1024;

const MAP_LIMIT: usize = 4096;

const OS_RELEASE_LIMIT: usize = 64 * 1024;

const FILE_LIMIT: u64 = 512 * 1024 * 1024;

const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;

const FILE_COUNT: usize = 2048;

pub(crate) const ENTRY_COUNT: usize = 8192;

pub(crate) const TREE_DEPTH: usize = 16;

pub(crate) const INITIAL_USER_INODE: u64 = 0xefff_fffd;

pub(crate) const INITIAL_PID_INODE: u64 = 0xefff_fffc;

type AdmissionResult<T> = Result<T, AdmissionFailure>;

/// Bounded, path-free reasons. None is authority to fall back or elevate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionFailure {
    UnsupportedPlatform, MissingCompileAnchor, Stopped, Deadline,
    NativeUnavailable, NativeDenied, Namespace, Mount, Ownership,
    ExtendedAttributes, IdentityChanged, Manifest, Inventory, Bounds,
    AlreadyUsed, Interrupted, CloseUncertain, LedgerInvariant,
    TransferUnavailable, DestinationOccupied,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) device: u64, pub(crate) inode: u64, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32, links: u64,
    size: i64, mtime: i64, mtime_nsec: u64, ctime: i64, ctime_nsec: u64,
}

impl Identity {
    pub(crate) fn of(stat: &Stat) -> Self {
        Self { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
            uid: stat.st_uid, gid: stat.st_gid, links: stat.st_nlink, size: stat.st_size,
            mtime: stat.st_mtime, mtime_nsec: stat.st_mtime_nsec,
            ctime: stat.st_ctime, ctime_nsec: stat.st_ctime_nsec }
    }
    fn device_pair(self) -> AdmissionResult<(u32, u32)> {
        Ok((u32::try_from(nix::sys::stat::major(self.device)).map_err(|_| AdmissionFailure::Mount)?,
            u32::try_from(nix::sys::stat::minor(self.device)).map_err(|_| AdmissionFailure::Mount)?))
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Credentials { uid: u32, gid: u32, pid: u32, tid: u32 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32, protocol: u32, core_version: String, target: String,
    core_sha256: String, protocol_sha256: String, inventory_sha256: String,
    files: Vec<PayloadFile>,
}

// The publisher hashes compact, sorted-key JSON in this exact field order.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadFile { pub(crate) path: String, pub(crate) sha256: String, pub(crate) size: u64 }

pub(crate) struct Inventory { pub(crate) files: Vec<PayloadFile>, pub(crate) directories: BTreeSet<String> }


pub(crate) fn ordinary_identity(identity: Identity, kind: FileType) -> bool {
    let forbidden = Mode::WGRP | Mode::WOTH | Mode::SUID | Mode::SGID | Mode::SVTX;
    FileType::from_raw_mode(identity.mode) == kind && identity.inode != 0
        && identity.links != 0 && identity.size >= 0
        && identity.mtime_nsec < 1_000_000_000 && identity.ctime_nsec < 1_000_000_000
        && !Mode::from_raw_mode(identity.mode).intersects(forbidden)
        && (kind != FileType::RegularFile || identity.links == 1)
}

pub(crate) fn protected_identity(identity: Identity, kind: FileType, size: Option<u64>) -> bool {
    ordinary_identity(identity, kind) && identity.uid == 0 && identity.gid == 0
        && size.is_none_or(|expected| u64::try_from(identity.size).ok() == Some(expected))
}

pub(crate) fn known_mount_attributes(attributes: u64) -> bool {
    attributes & !mount::KNOWN_ATTRIBUTES == 0 && attributes & mount::ID_MAPPED == 0
        && attributes & (mount::NO_ATIME | mount::STRICT_ATIME) != (mount::NO_ATIME | mount::STRICT_ATIME)
}

pub(crate) fn protected_mount(observation: mount::MountObservation) -> bool {
    matches!(observation.filesystem_magic(), mount::EXT4_MAGIC | mount::XFS_MAGIC)
        && known_mount_attributes(observation.attributes()) && observation.attributes() & mount::NO_EXEC == 0
}


// All helpers below are pure bounded data validation, NOT alternate admission,
// resource constructors, close receipts, installed paths or native test hooks.
pub(crate) fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}

fn digest(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }

pub(crate) fn parse_inventory(bytes: &[u8], protocol_anchor: &str) -> AdmissionResult<Inventory> {
    if bytes.len() > MANIFEST_LIMIT || !sha(protocol_anchor) { return Err(AdmissionFailure::Manifest); }
    let manifest: Manifest = serde_json::from_value(strict_json(bytes).map_err(|_| AdmissionFailure::Manifest)?)
        .map_err(|_| AdmissionFailure::Manifest)?;
    validate_inventory(manifest, protocol_anchor)
}

fn validate_inventory(manifest: Manifest, protocol_anchor: &str) -> AdmissionResult<Inventory> {
    if manifest.schema_version != 1 || manifest.protocol != PROTOCOL || manifest.core_version != CORE_VERSION
        || manifest.target != TARGET || manifest.target != COMPILED_TARGET || manifest.protocol_sha256 != protocol_anchor
        || !sha(&manifest.core_sha256) || !sha(&manifest.inventory_sha256)
        || manifest.files.is_empty() || manifest.files.len() > FILE_COUNT {
        return Err(AdmissionFailure::Manifest);
    }
    let encoded_inventory = serde_json::to_vec(&manifest.files).map_err(|_| AdmissionFailure::Manifest)?;
    if encoded_inventory.len() > MANIFEST_LIMIT || digest(&encoded_inventory) != manifest.inventory_sha256 {
        return Err(AdmissionFailure::Manifest);
    }
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut previous: Option<&str> = None;
    let mut total = 0u64;
    for file in &manifest.files {
        if !safe_payload_path(&file.path) || file.path == "manifest.json" || !sha(&file.sha256)
            || file.size > FILE_LIMIT
            || file.path == "github-ca.pem" && (file.size == 0 || file.size > GITHUB_CA_LIMIT)
            || previous.is_some_and(|name| name >= file.path.as_str())
            || !names.insert(file.path.clone()) {
            return Err(AdmissionFailure::Manifest);
        }
        total = total.checked_add(file.size).ok_or(AdmissionFailure::Bounds)?;
        if total > TOTAL_LIMIT { return Err(AdmissionFailure::Bounds); }
        if file.path == "core.zip" && file.sha256 != manifest.core_sha256 { return Err(AdmissionFailure::Manifest); }
        previous = Some(&file.path);
        let mut relative = file.path.as_str();
        while let Some((parent, _)) = relative.rsplit_once('/') {
            directories.insert(parent.to_owned());
            if directories.len() + manifest.files.len() + 1 > ENTRY_COUNT { return Err(AdmissionFailure::Bounds); }
            relative = parent;
        }
    }
    for required in REQUIRED_RUNTIME_RESOURCES {
        if !names.contains(required) { return Err(AdmissionFailure::Manifest); }
    }
    let mut folded = BTreeSet::new();
    folded.insert("manifest.json".to_owned());
    for name in names.iter().chain(directories.iter()) {
        // Reject directory/file conflicts AND case aliases at ANY inventory
        // level, not just case-folded final payload leaves.
        if !folded.insert(name.to_ascii_lowercase()) { return Err(AdmissionFailure::Manifest); }
    }
    Ok(Inventory { files: manifest.files, directories })
}

pub(crate) fn supported_kernel(sysname: &[u8], machine: &[u8], release: &[u8]) -> bool {
    if sysname != b"Linux" || machine != b"x86_64" { return false; }
    // Exactly one source-reviewed Azure ABI, plus the existing GA 6.8 rule.
    // This name check is NOT boot provenance or runtime qualification. All
    // native observations and consumer gates remain independently required.
    if release == b"6.17.0-1022-azure" { return true; }
    let Some(abi) = release.strip_prefix(b"6.8.0-").and_then(|value| value.strip_suffix(b"-generic")) else { return false; };
    !abi.is_empty() && abi.len() <= 10 && abi[0] != b'0' && abi.iter().all(u8::is_ascii_digit)
}

fn numeric<const N: usize>(value: &str) -> AdmissionResult<[u64; N]> {
    let mut result = [0; N];
    let mut fields = value.split_ascii_whitespace();
    for destination in &mut result {
        let field = fields.next().ok_or(AdmissionFailure::Namespace)?;
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) { return Err(AdmissionFailure::Namespace); }
        *destination = field.parse().map_err(|_| AdmissionFailure::Namespace)?;
    }
    if fields.next().is_some() { return Err(AdmissionFailure::Namespace); }
    Ok(result)
}

pub(crate) fn initial_id_map(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.len() > MAP_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if numeric::<3>(text)? != [0, 0, 4_294_967_295] { return Err(AdmissionFailure::Namespace); }
    Ok(())
}

fn single_field<T>(slot: &mut Option<T>, value: T) -> AdmissionResult<()> {
    if slot.is_some() { return Err(AdmissionFailure::Namespace); }
    *slot = Some(value);
    Ok(())
}

fn capability_value(value: &str) -> AdmissionResult<u64> {
    let value = value.trim_matches(|character: char| character.is_ascii_whitespace());
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(AdmissionFailure::Namespace); }
    u64::from_str_radix(value, 16).map_err(|_| AdmissionFailure::Namespace)
}

fn inspect_status(bytes: &[u8], actual: Credentials) -> AdmissionResult<()> {
    if bytes.len() > STATUS_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if text.contains('\0') || !text.ends_with('\n') { return Err(AdmissionFailure::Namespace); }
    let (mut uid, mut gid, mut pid, mut tgid, mut nspid, mut nstgid) = (None, None, None, None, None, None);
    let (mut effective, mut permitted, mut inheritable, mut ambient) = (None, None, None, None);
    for line in text.lines() {
        let (key, value) = line.split_once(':').ok_or(AdmissionFailure::Namespace)?;
        match key {
            "Uid" => single_field(&mut uid, numeric::<4>(value)?)?,
            "Gid" => single_field(&mut gid, numeric::<4>(value)?)?,
            "Pid" => single_field(&mut pid, numeric::<1>(value)?[0])?,
            "Tgid" => single_field(&mut tgid, numeric::<1>(value)?[0])?,
            "NSpid" => single_field(&mut nspid, numeric::<1>(value)?[0])?,
            "NStgid" => single_field(&mut nstgid, numeric::<1>(value)?[0])?,
            "CapEff" => single_field(&mut effective, capability_value(value)?)?,
            "CapPrm" => single_field(&mut permitted, capability_value(value)?)?,
            "CapInh" => single_field(&mut inheritable, capability_value(value)?)?,
            "CapAmb" => single_field(&mut ambient, capability_value(value)?)?,
            // The inherited bounding SET may be nonzero in an ordinary process;
            // it is not an actually effective/permitted/inheritable capability.
            "CapBnd" => { capability_value(value)?; }
            _ => {}
        }
    }
    if uid != Some([u64::from(actual.uid); 4]) || gid != Some([u64::from(actual.gid); 4])
        || pid != Some(u64::from(actual.tid)) || tgid != Some(u64::from(actual.pid))
        || nspid != pid || nstgid != tgid
        || effective != Some(0) || permitted != Some(0) || inheritable != Some(0) || ambient != Some(0) {
        return Err(AdmissionFailure::Namespace);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RootMount { pub(crate) old_id: u32, pub(crate) device: (u32, u32), pub(crate) magic: u64 }

fn mount_number(value: &str) -> AdmissionResult<u32> {
    let number = numeric::<1>(value)?[0];
    u32::try_from(number).map_err(|_| AdmissionFailure::Namespace)
}

// Validate kernel mountinfo's ONLY four escaped path characters. In particular
// '\057' cannot conceal an alternative spelling of '/'. Never unescape and
// then treat an ambiguous/relative name as evidence of the original root.
fn mount_path(path: &str) -> bool {
    if !path.starts_with('/') { return false; }
    let bytes = path.as_bytes();
    let mut position = 0;
    while position < bytes.len() {
        match bytes[position] {
            b'\\' => {
                let Some(escape) = bytes.get(position + 1..position + 4) else { return false; };
                if !matches!(escape, b"040" | b"011" | b"012" | b"134") { return false; }
                position += 4;
            }
            byte if byte.is_ascii_control() || byte.is_ascii_whitespace() => return false,
            _ => position += 1,
        }
    }
    true
}

pub(crate) fn parse_root_mount(bytes: &[u8]) -> AdmissionResult<RootMount> {
    if bytes.len() > MOUNTINFO_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::Namespace)?;
    if text.contains('\0') || !text.ends_with('\n') { return Err(AdmissionFailure::Namespace); }
    let mut root = None;
    let mut ids = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if index >= ENTRY_COUNT { return Err(AdmissionFailure::Bounds); }
        if line.is_empty() || line.bytes().any(|byte| byte.is_ascii_control()) { return Err(AdmissionFailure::Namespace); }
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.iter().any(|field| field.is_empty()) { return Err(AdmissionFailure::Namespace); }
        let separator = fields.iter().position(|field| *field == "-").ok_or(AdmissionFailure::Namespace)?;
        if separator < 6 || fields.len() != separator + 4 { return Err(AdmissionFailure::Namespace); }
        let id = mount_number(fields[0])?;
        let parent = mount_number(fields[1])?;
        let (major, minor) = fields[2].split_once(':').ok_or(AdmissionFailure::Namespace)?;
        let device = (mount_number(major)?, mount_number(minor)?);
        if id == 0 || parent == 0 || !ids.insert(id) || !mount_path(fields[3]) || !mount_path(fields[4]) {
            return Err(AdmissionFailure::Namespace);
        }
        let mut optional_tags = 0u8;
        for field in &fields[6..separator] {
            let (tag, number) = match field.split_once(':') {
                Some((tag, number)) => (tag, Some(mount_number(number)?)),
                None => (*field, None),
            };
            let bit = match (tag, number) {
                ("shared", Some(number)) if number != 0 => 1,
                ("master", Some(number)) if number != 0 => 2,
                ("propagate_from", Some(number)) if number != 0 => 4,
                ("unbindable", None) => 8,
                _ => return Err(AdmissionFailure::Namespace),
            };
            if optional_tags & bit != 0 { return Err(AdmissionFailure::Namespace); }
            optional_tags |= bit;
        }
        // mountinfo's first per-mount option is exactly ro or rw. No option
        // string (including an absent IDMAP marker) replaces real statmount.
        if !matches!(fields[5].split(',').next(), Some("ro" | "rw")) {
            return Err(AdmissionFailure::Namespace);
        }
        if fields[4] != "/" { continue; }
        if fields[3] != "/" || root.is_some() { return Err(AdmissionFailure::Namespace); }
        let magic = match fields[separator + 1] {
            "ext4" => mount::EXT4_MAGIC, "xfs" => mount::XFS_MAGIC,
            _ => return Err(AdmissionFailure::Mount),
        };
        root = Some(RootMount { old_id: id, device, magic });
    }
    root.ok_or(AdmissionFailure::Namespace)
}

fn release_value(value: &str) -> AdmissionResult<&str> {
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = value.as_bytes()[0] as char;
        if value.len() < 2 || !value.ends_with(quote) { return Err(AdmissionFailure::UnsupportedPlatform); }
        let inner = &value[1..value.len() - 1];
        if inner.chars().any(|character| matches!(character, '"' | '\'' | '\\')) { return Err(AdmissionFailure::UnsupportedPlatform); }
        Ok(inner)
    } else if value.is_empty() || value.chars().any(|character| character.is_whitespace() || matches!(character, '"' | '\'' | '\\')) {
        Err(AdmissionFailure::UnsupportedPlatform)
    } else { Ok(value) }
}

pub(crate) fn ubuntu_2404(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.len() > OS_RELEASE_LIMIT { return Err(AdmissionFailure::Bounds); }
    let text = std::str::from_utf8(bytes).map_err(|_| AdmissionFailure::UnsupportedPlatform)?;
    if text.contains('\0') { return Err(AdmissionFailure::UnsupportedPlatform); }
    let mut keys = BTreeSet::new();
    let (mut id, mut version) = (None, None);
    for (index, line) in text.lines().enumerate() {
        if index >= 1024 { return Err(AdmissionFailure::Bounds); }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let (key, value) = line.split_once('=').ok_or(AdmissionFailure::UnsupportedPlatform)?;
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !keys.insert(key) { return Err(AdmissionFailure::UnsupportedPlatform); }
        match key {
            "ID" => id = Some(release_value(value)?),
            "VERSION_ID" => version = Some(release_value(value)?),
            _ => {}
        }
    }
    if id != Some("ubuntu") || version != Some("24.04") { return Err(AdmissionFailure::UnsupportedPlatform); }
    Ok(())
}

