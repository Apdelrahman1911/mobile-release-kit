//! Closed selection/maintenance DATA. None of these records is native custody.
//! A confirmed preview, saved record or matching digest alone authorizes nothing.
use std::collections::BTreeMap;

pub const TARGET: &str = "x86_64-pc-windows-msvc";
pub const SHORTCUT: &str = "Mobile Release Kit.lnk";
pub const REGISTRATION: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MobileReleaseKit";
pub const PROFILE_LIMIT: usize = 8192;
pub const LINK_LIMIT: usize = 64 * 1024;
pub const REGISTRY_LIMIT: usize = 64 * 1024;
pub const RECORD_LIMIT: usize = 512 * 1024;
pub const OUTPUT_LIMIT: u64 = 8 * 1024 * 1024;
pub const MAX_RECORDS: usize = 24;
pub const MAX_VALUES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode { InstallActivated, RepairSameImage, RemoveSelection, RecoverPrevious, RecoverCurrent }
impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::InstallActivated => "install-activated",
            Self::RepairSameImage => "verify-and-restore-launch-entries",
            Self::RemoveSelection => "remove-launch-entries",
            Self::RecoverPrevious => "recover-previous-launch-selection",
            Self::RecoverCurrent => "recover-current-launch-selection",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::InstallActivated => "Select the verified application",
            Self::RepairSameImage => "Verify this installation and restore missing launch entries",
            Self::RemoveSelection => "Remove launch entries",
            Self::RecoverPrevious => "Restore the previous verified launch selection",
            Self::RecoverCurrent => "Complete the current verified launch selection",
        }
    }
    pub fn selects_image(self) -> bool { self != Self::RemoveSelection }
    pub fn recovery(self) -> bool { matches!(self, Self::RecoverPrevious | Self::RecoverCurrent) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Fresh, Observed, RegistryStaged, BackupIntentFlushed, BackupReturned,
    SelectIntentFlushed, SelectReturned, RegistryIntentFlushed, RegistryReturned, Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition { Unchanged, Selected, LaunchEntriesRemoved, Partial, Unknown }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputKind { CreatedDirectory, CreatedFile, Rename }
/// Actual attempted fixed-path effects, not permission to remove any path.
/// A returned failure does not make an existing occupant task-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputObservation {
    pub kind: OutputKind, pub path: String, pub destination: Option<String>,
    pub native_return: Option<(i32, u32)>,
}
/// Observation DATA only. The native owner keeps the actual originals separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub mode: Mode,
    pub stage: Stage,
    pub disposition: Disposition,
    pub first_failure: Option<&'static str>,
    pub old_move_entered: bool,
    pub new_move_entered: bool,
    pub registry_commit_entered: bool,
    pub registry_committed: bool,
    pub native_closed: bool,
    pub old_move_native: Option<(i32, u32)>,
    pub new_move_native: Option<(i32, u32)>,
    pub registry_native: Option<(i32, u32)>,
    pub os_flush_acknowledged_records: usize,
    pub completely_closed_records: usize,
    /// Bit positions are PHASES order. Returned outcomes need not be persisted after STOP.
    pub completely_closed_phase_mask: u8,
    pub outputs: Vec<OutputObservation>,
    pub write_count_unknown: bool,
    pub output_bytes_charged: u64,
    pub output_bytes_confirmed: u64,
    pub retained_image_bytes_observed: Option<u64>,
    pub controller_finality_required: bool,
    pub shipping_installer_enabled: bool,
}
impl Report {
    pub fn new(mode: Mode) -> Self {
        Self { mode, stage: Stage::Fresh, disposition: Disposition::Unchanged,
            first_failure: None, old_move_entered: false, new_move_entered: false,
            registry_commit_entered: false, registry_committed: false, native_closed: false,
            old_move_native: None, new_move_native: None, registry_native: None,
            os_flush_acknowledged_records: 0, completely_closed_records: 0, completely_closed_phase_mask: 0,
            outputs: Vec::new(), write_count_unknown: false, output_bytes_charged: 0,
            output_bytes_confirmed: 0, retained_image_bytes_observed: None,
            controller_finality_required: true, shipping_installer_enabled: false }
    }
    pub(crate) fn fail(&mut self, cause: &'static str, unknown: bool) {
        if self.first_failure.is_none() { self.first_failure = Some(cause); }
        self.disposition = if unknown || self.disposition == Disposition::Unknown { Disposition::Unknown }
            else if self.old_move_entered || self.new_move_entered || self.registry_commit_entered {
                Disposition::Partial
            } else { Disposition::Unchanged };
    }
    pub(crate) fn charge(&mut self, bytes: usize) -> bool {
        let Some(total) = self.output_bytes_charged.checked_add(bytes as u64) else { return false; };
        if total > OUTPUT_LIMIT { return false; }
        self.output_bytes_charged = total; true
    }
}

/// Plain expected DATA. Production derives it from the existing compiled PROFILE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageData {
    pub image: String,
    pub runtime: String,
    pub core_version: String,
    pub profile: Vec<u8>,
    pub input_hashes: [String; 54],
    pub input_sizes: [u64; 54],
    pub helper: String,
}
impl ImageData {
    pub fn shape_valid(&self) -> bool {
        digest(&self.image) && digest(&self.runtime) && digest(&self.helper)
            && !self.profile.is_empty() && self.profile.len() <= PROFILE_LIMIT
            && version(&self.core_version)
            && self.input_hashes.iter().all(|s| digest(s))
            && self.input_sizes.iter().all(|n| *n > 0 && *n <= 512 * 1024 * 1024)
            && self.input_hashes[7] == self.runtime && self.input_hashes[47] == self.helper
            && self.input_sizes[7] <= 1024 * 1024
            && self.input_sizes[47] <= 256 * 1024 * 1024 && self.input_sizes[48] <= 256 * 1024 * 1024
            && self.input_sizes[50] <= 4 * 1024 * 1024 && self.input_sizes[51] <= 4 * 1024 * 1024
            && self.input_sizes[..47].iter().try_fold(0u64, |sum, n| sum.checked_add(*n))
                .and_then(|n| n.checked_mul(2)).is_some_and(|n| n <= 1024 * 1024 * 1024)
            && self.input_sizes[..52].iter().try_fold(0u64, |sum, n| sum.checked_add(*n))
                .is_some_and(|n| n <= 1024 * 1024 * 1024)
            && self.input_sizes[52] <= 16 * 1024 && self.input_sizes[53] <= 1024 * 1024
    }
}

/// Remove only authenticates ownership of launch entries and protected provenance.
/// Requiring damaged payload bytes here would make safe removal impossible.
pub fn payload_verification_required(mode: Mode, applying: bool) -> bool {
    match mode { Mode::RemoveSelection => false, Mode::InstallActivated => applying, _ => true }
}

pub fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
}
pub fn native_dos_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1..3] == *b":\\"
        && value.encode_utf16().count() < 8192 && !value.contains(['\0', '\r', '\n', '%', '/', '"'])
        && value[3..].split('\\').all(|part| !part.is_empty() && part != "." && part != ".."
            && !part.ends_with([' ', '.']) && !part.contains(':'))
}
pub fn shell_target(program_files: &str, image: &str) -> Option<String> {
    if !native_dos_path(program_files) || !digest(image) { return None; }
    let result = format!(r"{program_files}\Mobile Release Kit\installer-input\{TARGET}\{image}\shell\mobile-release-kit-desktop.exe");
    native_dos_path(&result).then_some(result)
}
pub fn image_hint_from_target(program_files: &str, target: &str) -> Option<String> {
    if !native_dos_path(target) { return None; }
    let prefix = format!(r"{program_files}\Mobile Release Kit\installer-input\{TARGET}\");
    let image = target.strip_prefix(&prefix)?.strip_suffix(r"\shell\mobile-release-kit-desktop.exe")?;
    (digest(image) && shell_target(program_files, image).as_deref() == Some(target)).then(|| image.to_owned())
}
pub fn recovery_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryValue { pub kind: u32, pub bytes: Vec<u8> }
pub type Registration = BTreeMap<String, RegistryValue>;
fn text(value: &str) -> RegistryValue {
    RegistryValue { kind: 1, bytes: value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() }
}
fn one() -> RegistryValue { RegistryValue { kind: 4, bytes: 1u32.to_le_bytes().to_vec() } }

/// No uninstall command is fabricated before the retained maintenance bridge exists.
pub fn registration(program_files: &str, image: &ImageData) -> Option<Registration> {
    if !image.shape_valid() { return None; }
    let shell = shell_target(program_files, &image.image)?;
    let rows = [
        ("DisplayName", text("Mobile Release Kit")),
        ("DisplayVersion", text(&image.core_version)),
        ("Publisher", text("Mobile Release Kit")),
        ("InstallLocation", text(&format!(r"{program_files}\Mobile Release Kit"))),
        ("DisplayIcon", text(&format!("{shell},0"))),
        ("MRKImage", text(&image.image)),
        ("MRKRuntime", text(&image.runtime)),
        ("MRKProfileSha256", text(&image.image)),
        ("MRKMaintenanceScope", text("verified-launch-entries-only;retained-payloads")),
        ("NoModify", one()), ("NoRepair", one()), ("NoRemove", one()),
    ];
    Some(rows.into_iter().map(|(name, value)| (name.to_owned(), value)).collect())
}
pub fn registry_text(value: &RegistryValue) -> Option<String> {
    if value.kind != 1 || value.bytes.len() < 2 || value.bytes.len() % 2 != 0
        || value.bytes.len() > 32 * 1024 { return None; }
    let words: Vec<_> = value.bytes.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    if words.last() != Some(&0) || words[..words.len()-1].contains(&0) { return None; }
    String::from_utf16(&words[..words.len()-1]).ok()
}
pub fn image_hint_from_registration(value: &Registration) -> Option<String> {
    let image = registry_text(value.get("MRKImage")?)?;
    (digest(&image) && registry_text(value.get("MRKProfileSha256")?)? == image).then_some(image)
}
pub fn registration_shape(value: &Registration) -> bool {
    const NAMES: [&str; 12] = ["DisplayName", "DisplayVersion", "Publisher", "InstallLocation",
        "DisplayIcon", "MRKImage", "MRKRuntime", "MRKProfileSha256", "MRKMaintenanceScope",
        "NoModify", "NoRepair", "NoRemove"];
    value.len() == NAMES.len() && NAMES.iter().all(|name| value.contains_key(*name))
        && value.iter().all(|(name, value)| if name.starts_with("No") {
            value == &one()
        } else { registry_text(value).is_some() })
        && value.values().try_fold(0usize, |n, v| n.checked_add(v.bytes.len()))
            .is_some_and(|n| n <= REGISTRY_LIMIT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preview {
    pub mode: Mode,
    pub before_image: Option<String>,
    pub after_image: Option<String>,
    pub runtime: Option<String>,
    pub core_version: Option<String>,
    pub shortcut_path: String,
    pub registration_path: &'static str,
    /// Equality expectation only: the native apply owner MUST freshly observe it.
    pub observation_sha256: String,
    pub preserved_paths: Vec<String>,
    pub retained_image_bytes_observed: Option<u64>,
    pub warning: &'static str,
}
pub const RECOVERY_WARNING: &str =
    "Launch entries can be partially changed if Windows refuses a later step. \
     Existing application images, runtime files, projects, credentials and evidence remain retained. \
     Recovery requires a new preview and verification; this is not a full uninstall.";

/// Closed binary storage, not a replayable command. Fields are length framed and
/// ordering is exact; duplicate/unknown/truncated records cannot authorize recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecord {
    pub mode: Mode,
    pub phase: &'static str,
    pub run: String,
    pub image: String,
    pub before_image: Option<String>,
    pub observation: String,
    pub old_file_descriptor: Vec<u8>,
    pub new_file_descriptor: Vec<u8>,
    pub old_link: Vec<u8>,
    pub new_link: Vec<u8>,
    pub old_registry: Registration,
    pub new_registry: Registration,
    pub old_registry_security: Vec<u8>,
    pub new_registry_security: Vec<u8>,
    pub prior_returns: Vec<u8>,
}
pub const PHASES: [&str; 7] = ["prepared", "before-old-move", "old-move-returned",
    "before-new-move", "new-move-returned", "before-registry-commit", "registry-returned"];
fn field(output: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    if bytes.len() > RECORD_LIMIT || output.len().checked_add(bytes.len()+4)? > RECORD_LIMIT { return None; }
    output.extend(u32::try_from(bytes.len()).ok()?.to_le_bytes()); output.extend(bytes); Some(())
}
fn registration_bytes(value: &Registration) -> Option<Vec<u8>> {
    if value.len() > MAX_VALUES { return None; }
    let mut out = Vec::new(); out.extend(u32::try_from(value.len()).ok()?.to_le_bytes());
    for (name, value) in value {
        if name.is_empty() || name.len() > 64 || value.bytes.len() > REGISTRY_LIMIT { return None; }
        field(&mut out, name.as_bytes())?; out.extend(value.kind.to_le_bytes()); field(&mut out, &value.bytes)?;
    }
    (out.len() <= REGISTRY_LIMIT).then_some(out)
}
impl RecoveryRecord {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !PHASES.contains(&self.phase) || !recovery_id(&self.run) || !digest(&self.image)
            || self.before_image.as_ref().is_some_and(|s| !digest(s)) || !digest(&self.observation)
            || self.old_link.len() > LINK_LIMIT || self.new_link.len() > LINK_LIMIT
            || self.old_file_descriptor.len() > REGISTRY_LIMIT || self.new_file_descriptor.len() > REGISTRY_LIMIT
            || self.old_registry_security.len() > REGISTRY_LIMIT || self.new_registry_security.len() > REGISTRY_LIMIT
            || self.prior_returns.len() > 4096
            || (!self.old_registry.is_empty() && !registration_shape(&self.old_registry))
            || (!self.new_registry.is_empty() && !registration_shape(&self.new_registry)) { return None; }
        let mut out = b"MRK_SELECTION_RECOVERY_V1\0".to_vec();
        for bytes in [self.mode.name().as_bytes(), self.phase.as_bytes(), self.run.as_bytes(),
            self.image.as_bytes(), self.before_image.as_deref().unwrap_or("").as_bytes(), self.observation.as_bytes(),
            &self.old_file_descriptor, &self.new_file_descriptor, &self.old_link, &self.new_link,
            &registration_bytes(&self.old_registry)?, &registration_bytes(&self.new_registry)?,
            &self.old_registry_security, &self.new_registry_security, &self.prior_returns] {
            field(&mut out, bytes)?;
        }
        Some(out)
    }
}


struct Fields<'a> { raw: &'a [u8], at: usize }
impl<'a> Fields<'a> {
    fn u32(&mut self) -> Option<u32> {
        let end = self.at.checked_add(4)?;
        let bytes: [u8; 4] = self.raw.get(self.at..end)?.try_into().ok()?;
        self.at = end; Some(u32::from_le_bytes(bytes))
    }
    fn next(&mut self, limit: usize) -> Option<&'a [u8]> {
        let count = usize::try_from(self.u32()?).ok()?;
        if count > limit { return None; }
        let end = self.at.checked_add(count)?;
        let value = self.raw.get(self.at..end)?; self.at = end; Some(value)
    }
    fn text(&mut self, limit: usize) -> Option<&'a str> {
        std::str::from_utf8(self.next(limit)?).ok()
    }
    fn ended(&self) -> bool { self.at == self.raw.len() }
}
fn decode_registration(raw: &[u8]) -> Option<Registration> {
    if raw.len() > REGISTRY_LIMIT { return None; }
    let mut input = Fields { raw, at: 0 };
    let count = usize::try_from(input.u32()?).ok()?;
    if count > MAX_VALUES { return None; }
    let mut out = Registration::new();
    for _ in 0..count {
        let name = input.text(64)?.to_owned();
        let kind = input.u32()?;
        let bytes = input.next(REGISTRY_LIMIT)?.to_vec();
        if name.is_empty() || out.insert(name, RegistryValue { kind, bytes }).is_some() { return None; }
    }
    (input.ended() && registration_bytes(&out)?.as_slice() == raw
        && (out.is_empty() || registration_shape(&out))).then_some(out)
}
impl RecoveryRecord {
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() > RECORD_LIMIT { return None; }
        let body = raw.strip_prefix(b"MRK_SELECTION_RECOVERY_V1\0")?;
        let mut fields = Fields { raw: body, at: 0 };
        let mode_text = fields.text(64)?;
        let mode = [Mode::InstallActivated, Mode::RepairSameImage, Mode::RemoveSelection,
            Mode::RecoverPrevious, Mode::RecoverCurrent].into_iter().find(|m| m.name() == mode_text)?;
        let phase_text = fields.text(32)?;
        let phase = *PHASES.iter().find(|p| **p == phase_text)?;
        let run = fields.text(32)?.to_owned();
        let image = fields.text(64)?.to_owned();
        let before = fields.text(64)?;
        let before_image = (!before.is_empty()).then(|| before.to_owned());
        let observation = fields.text(64)?.to_owned();
        let value = Self {
            mode, phase, run, image, before_image, observation,
            old_file_descriptor: fields.next(REGISTRY_LIMIT)?.to_vec(),
            new_file_descriptor: fields.next(REGISTRY_LIMIT)?.to_vec(),
            old_link: fields.next(LINK_LIMIT)?.to_vec(),
            new_link: fields.next(LINK_LIMIT)?.to_vec(),
            old_registry: decode_registration(fields.next(REGISTRY_LIMIT)?)?,
            new_registry: decode_registration(fields.next(REGISTRY_LIMIT)?)?,
            old_registry_security: fields.next(REGISTRY_LIMIT)?.to_vec(),
            new_registry_security: fields.next(REGISTRY_LIMIT)?.to_vec(),
            prior_returns: fields.next(4096)?.to_vec(),
        };
        // A digest alone never turns a noncanonical or extra-field record into
        // recovery input. The native owner additionally verifies the ORIGINAL.
        (fields.ended() && value.encode()?.as_slice() == raw).then_some(value)
    }
}

/// Actual caller-recorded stage order, not a native execution plan.
pub fn next_stage(old: Stage, next: Stage, old_present: bool, selects: bool) -> bool {
    use Stage::*;
    matches!((old, next), (Fresh, Observed) | (Observed, RegistryStaged)
        | (RegistryStaged, BackupIntentFlushed) | (BackupIntentFlushed, BackupReturned)
        | (SelectIntentFlushed, SelectReturned) | (RegistryIntentFlushed, RegistryReturned)
        | (RegistryReturned, Closed))
        || (!old_present && old == RegistryStaged
            && next == if selects { SelectIntentFlushed } else { RegistryIntentFlushed })
        || (old == BackupReturned && next == if selects { SelectIntentFlushed } else { RegistryIntentFlushed })
        || (selects && old == SelectReturned && next == RegistryIntentFlushed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_target_never_accepts_arguments_network_or_expansion() {
        let image = "a".repeat(64);
        let target = shell_target(r"C:\Program Files", &image);
        assert!(target.is_some());
        assert_eq!(image_hint_from_target(r"C:\Program Files", target.as_deref().unwrap_or("")), Some(image));
        for path in [r"\\server\share", r"%ProgramFiles%", r"C:\x\..\y", "C:\\x\" --bad", r"C:/x"] {
            assert!(!native_dos_path(path)); assert!(shell_target(path, &"a".repeat(64)).is_none());
        }
    }
    #[test]
    fn attempted_effect_never_becomes_unchanged_or_complete_on_late_failure() {
        let mut report = Report::new(Mode::InstallActivated);
        report.fail("preview-changed", false);
        assert_eq!(report.disposition, Disposition::Unchanged);
        report.old_move_entered = true; report.fail("registry-commit", false);
        assert_eq!(report.disposition, Disposition::Partial);
        assert_eq!(report.first_failure, Some("preview-changed"));
        report.fail("close", true); assert_eq!(report.disposition, Disposition::Unknown);
        report.fail("later-known", false); assert_eq!(report.disposition, Disposition::Unknown);
        assert!(!report.native_closed); assert!(report.controller_finality_required);
    }
    #[test]
    fn output_charge_precedes_confirmation_and_does_not_recover_failed_budget() {
        let mut report = Report::new(Mode::RepairSameImage);
        assert!(report.charge(OUTPUT_LIMIT as usize)); assert!(!report.charge(1));
        assert_eq!(report.output_bytes_charged, OUTPUT_LIMIT);
        assert_eq!(report.output_bytes_confirmed, 0);
    }
    #[test]
    fn removal_does_not_depend_on_payload_health_but_repair_and_recovery_do() {
        for applying in [false, true] {
            assert!(!payload_verification_required(Mode::RemoveSelection, applying));
            for mode in [Mode::RepairSameImage, Mode::RecoverPrevious, Mode::RecoverCurrent] {
                assert!(payload_verification_required(mode, applying));
            }
        }
        assert!(!payload_verification_required(Mode::InstallActivated, false));
        assert!(payload_verification_required(Mode::InstallActivated, true));
    }
    #[test]
    fn close_and_registry_finality_cannot_be_skipped() {
        assert!(!next_stage(Stage::Observed, Stage::SelectReturned, false, true));
        assert!(!next_stage(Stage::SelectReturned, Stage::Closed, true, true));
        assert!(next_stage(Stage::BackupReturned, Stage::RegistryIntentFlushed, true, false));
        assert!(!next_stage(Stage::BackupReturned, Stage::Closed, true, false));
    }

    #[test]
    fn recovery_records_reject_truncation_extra_fields_and_unframed_changes() {
        let record = RecoveryRecord {
            mode: Mode::RemoveSelection, phase: "prepared", run: "a".repeat(32),
            image: "b".repeat(64), before_image: Some("b".repeat(64)), observation: "c".repeat(64),
            old_file_descriptor: vec![1], new_file_descriptor: Vec::new(),
            old_link: vec![1, 2, 3], new_link: Vec::new(), old_registry: Registration::new(),
            new_registry: Registration::new(), old_registry_security: Vec::new(),
            new_registry_security: Vec::new(), prior_returns: Vec::new(),
        };
        let Some(bytes) = record.encode() else { panic!("bounded fixture record"); };
        assert_eq!(RecoveryRecord::decode(&bytes), Some(record));
        assert!(RecoveryRecord::decode(&bytes[..bytes.len()-1]).is_none());
        let mut extra = bytes.clone(); extra.push(0);
        assert!(RecoveryRecord::decode(&extra).is_none());
        let mut bad = bytes; bad[0] = b'X';
        assert!(RecoveryRecord::decode(&bad).is_none());
    }

}
