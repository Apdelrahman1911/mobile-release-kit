//! Closed removal progress/comparison DATA, not an installer state, filesystem
//! observer, live gate, authenticated package or permission to mutate/reinstall.
//! A previous record never certifies its writer's future close or outer exit.
//! Native callers retain all source/control/roster originals and their own EX.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{macos_install_maintenance::{CheckData, MaintenanceTargetData},
    macos_install_transaction::INVOCATION_LIMIT, protocol::strict_json};

pub const RECORD_LIMIT: usize = 16 * 1024;
const KIND: &str = "mrk-macos-removal-progress-v1";
const KEYS: [&str; 14] = ["schemaVersion", "kind", "target", "sourceCommit",
    "removalDescriptorSha256", "installedProducerSha256", "installedInventorySha256",
    "installationStateSha256", "payloadRosterSha256", "requestId", "rootNonce",
    "previousAttempt", "prefix", "firstFailure"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordDataError { Limit, Shape, Binding, Transition, ReusedIdentity }
type Result<T> = std::result::Result<T, RecordDataError>;
fn require(value: bool, error: RecordDataError) -> Result<()> {
    if value { Ok(()) } else { Err(error) }
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

/// Independent source-selected comparison inputs, NOT signature/custody proof.
/// The state/roster hashes cover the protected prior state and complete planned
/// current/retained payload census; no names or missing files are discovered here.
#[derive(Clone, Copy)]
pub struct RemovalBindingData<'a> {
    pub target: MaintenanceTargetData,
    pub source_commit: &'a str,
    pub removal_descriptor_sha256: &'a str,
    pub installed_producer_sha256: &'a str,
    pub installed_inventory_sha256: &'a str,
    pub installation_state_sha256: &'a str,
    pub payload_roster_sha256: &'a str,
}
impl RemovalBindingData<'_> {
    fn valid(self) -> bool {
        hex(self.source_commit, 40) && [self.removal_descriptor_sha256,
            self.installed_producer_sha256, self.installed_inventory_sha256,
            self.installation_state_sha256, self.payload_roster_sha256].iter().all(|s| hex(s, 64))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrefixData { AdmissionRecorded, AppWithdrawn, PayloadRosterRemoval, PayloadAbsentObserved }
impl PrefixData {
    fn next(self, next: Self) -> bool {
        matches!((self, next), (Self::AdmissionRecorded, Self::AppWithdrawn)
            | (Self::AppWithdrawn, Self::PayloadRosterRemoval)
            | (Self::PayloadRosterRemoval, Self::PayloadAbsentObserved))
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FailureKindData { OriginalFailed, OriginalUnknown, PostMismatch, Deadline, Persistence, CloseUnknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirstFailureData { pub phase: PrefixData, pub kind: FailureKindData }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviousAttempt { request_id: String, root_nonce: String, record_sha256: String }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordWire {
    schema_version: u32, kind: String, target: String, source_commit: String,
    removal_descriptor_sha256: String, installed_producer_sha256: String,
    installed_inventory_sha256: String, installation_state_sha256: String, payload_roster_sha256: String,
    request_id: String, root_nonce: String, previous_attempt: Option<PreviousAttempt>,
    prefix: PrefixData, first_failure: Option<FirstFailureData>,
}

/// Private validated fields; no Deserialize/Clone or native action conversion.
/// The original bytes are retained so a historical link hashes exactly the
/// admitted record, not a reserialization that silently changes its identity.
#[derive(Debug)]
pub struct RemovalRecordData { wire: RecordWire, bytes: Vec<u8>, sha256: String, target: MaintenanceTargetData }
impl RemovalRecordData {
    pub fn parse_data(bytes: &[u8], expected: RemovalBindingData<'_>) -> Result<Self> {
        Self::parse_record_data(bytes, Some(expected))
    }
    /// Closed historical comparison DATA only: this does not select an expected
    /// source or grant signature, current-original, resume or reinstall authority.
    pub fn parse_shape_data(bytes: &[u8]) -> Result<Self> {
        Self::parse_record_data(bytes, None)
    }
    fn parse_record_data(bytes: &[u8], expected: Option<RemovalBindingData<'_>>) -> Result<Self> {
        require(!bytes.is_empty() && bytes.len() <= RECORD_LIMIT, RecordDataError::Limit)?;
        // Preserve the original expected-binding check before parsing/copying,
        // and its precedence over previous-identity and phase refusals below.
        if let Some(expected) = expected { require(expected.valid(), RecordDataError::Binding)?; }
        let value = strict_json(bytes).map_err(|_| RecordDataError::Shape)?;
        let fields = value.as_object().ok_or(RecordDataError::Shape)?;
        // Option-valued fields are mandatory too; serde alone accepts omission.
        require(fields.len() == KEYS.len() && KEYS.iter().all(|k| fields.contains_key(*k)), RecordDataError::Shape)?;
        // Derived struct visitors also accept positional arrays. These closed
        // optional records are explicitly null or objects, never sequences.
        require(["previousAttempt", "firstFailure"].iter().all(|key|
            fields.get(*key).is_some_and(|v| v.is_null() || v.is_object())), RecordDataError::Shape)?;
        let wire: RecordWire = serde_json::from_value(value).map_err(|_| RecordDataError::Shape)?;
        let target = if wire.target == MaintenanceTargetData::Arm64.target() { MaintenanceTargetData::Arm64 }
            else if wire.target == MaintenanceTargetData::Intel.target() { MaintenanceTargetData::Intel }
            else { return Err(RecordDataError::Binding); };
        require(wire.schema_version == 1 && wire.kind == KIND && hex(&wire.source_commit, 40)
            && [&wire.removal_descriptor_sha256, &wire.installed_producer_sha256,
                &wire.installed_inventory_sha256, &wire.installation_state_sha256,
                &wire.payload_roster_sha256].iter().all(|s| hex(s, 64))
            && hex(&wire.request_id, 32) && hex(&wire.root_nonce, 32), RecordDataError::Binding)?;
        if let Some(expected) = expected {
            require(target == expected.target && wire.source_commit == expected.source_commit
                && wire.removal_descriptor_sha256 == expected.removal_descriptor_sha256
                && wire.installed_producer_sha256 == expected.installed_producer_sha256
                && wire.installed_inventory_sha256 == expected.installed_inventory_sha256
                && wire.installation_state_sha256 == expected.installation_state_sha256
                && wire.payload_roster_sha256 == expected.payload_roster_sha256, RecordDataError::Binding)?;
        }
        if let Some(previous) = &wire.previous_attempt {
            require(hex(&previous.request_id, 32) && hex(&previous.root_nonce, 32)
                && hex(&previous.record_sha256, 64), RecordDataError::Binding)?;
            require(previous.request_id != wire.request_id && previous.root_nonce != wire.root_nonce,
                RecordDataError::ReusedIdentity)?;
        }
        // No forward DATA transition follows a latched failure. Consequently
        // its recorded phase is the last prefix, never a future effect claim.
        require(wire.first_failure.is_none_or(|f| f.phase == wire.prefix), RecordDataError::Transition)?;
        Ok(Self { wire, bytes: bytes.to_vec(), sha256: format!("{:x}", Sha256::digest(bytes)), target })
    }
    fn from_wire(wire: RecordWire, expected: RemovalBindingData<'_>) -> Result<Self> {
        let mut bytes = serde_json::to_vec(&wire).map_err(|_| RecordDataError::Shape)?;
        bytes.push(b'\n');
        Self::parse_data(&bytes, expected)
    }
    /// Comparison encoding only. Actual original admission and publication are
    /// future caller obligations, not effects carried out by this constructor.
    pub fn admission_data(request_id: &str, root_nonce: &str, expected: RemovalBindingData<'_>) -> Result<Self> {
        // Public caller strings are checked before any owned copies/encoding.
        require(expected.valid() && hex(request_id, 32) && hex(root_nonce, 32), RecordDataError::Binding)?;
        Self::from_wire(RecordWire { schema_version: 1, kind: KIND.into(), target: expected.target.target().into(),
            source_commit: expected.source_commit.into(), removal_descriptor_sha256: expected.removal_descriptor_sha256.into(),
            installed_producer_sha256: expected.installed_producer_sha256.into(),
            installed_inventory_sha256: expected.installed_inventory_sha256.into(),
            installation_state_sha256: expected.installation_state_sha256.into(), payload_roster_sha256: expected.payload_roster_sha256.into(),
            request_id: request_id.into(), root_nonce: root_nonce.into(), previous_attempt: None,
            prefix: PrefixData::AdmissionRecorded, first_failure: None }, expected)
    }
    /// Borrowed, validated comparison fields; not an independently selected
    /// expected binding. Callers still authenticate their own current originals.
    pub fn binding_data(&self) -> RemovalBindingData<'_> {
        RemovalBindingData { target: self.target, source_commit: &self.wire.source_commit,
            removal_descriptor_sha256: &self.wire.removal_descriptor_sha256,
            installed_producer_sha256: &self.wire.installed_producer_sha256,
            installed_inventory_sha256: &self.wire.installed_inventory_sha256,
            installation_state_sha256: &self.wire.installation_state_sha256,
            payload_roster_sha256: &self.wire.payload_roster_sha256 }
    }
    /// Retained owned storage only, including spare capacities, not caller input,
    /// parser/encoder temporaries or allocator overhead. The owner quotes those
    /// separately before parsing; no allocation or re-encoding is done here.
    pub fn owned_bytes_data(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(self.bytes.capacity())?
            .checked_add(self.sha256.capacity())?;
        for value in [&self.wire.kind, &self.wire.target, &self.wire.source_commit,
            &self.wire.removal_descriptor_sha256, &self.wire.installed_producer_sha256,
            &self.wire.installed_inventory_sha256, &self.wire.installation_state_sha256,
            &self.wire.payload_roster_sha256, &self.wire.request_id, &self.wire.root_nonce] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        if let Some(previous) = &self.wire.previous_attempt {
            for value in [&previous.request_id, &previous.root_nonce, &previous.record_sha256] {
                bytes = bytes.checked_add(value.capacity())?;
            }
        }
        Some(bytes)
    }
    pub fn bytes_data(&self) -> &[u8] { &self.bytes }
    pub fn digest_data(&self) -> &str { &self.sha256 }
    pub fn request_id_data(&self) -> &str { &self.wire.request_id }
    pub fn root_nonce_data(&self) -> &str { &self.wire.root_nonce }
    pub fn prefix_data(&self) -> PrefixData { self.wire.prefix }
    pub fn first_failure_data(&self) -> Option<FirstFailureData> { self.wire.first_failure }
    pub fn previous_attempt_data(&self) -> Option<(&str, &str, &str)> {
        self.wire.previous_attempt.as_ref().map(|p| (p.request_id.as_str(), p.root_nonce.as_str(), p.record_sha256.as_str()))
    }
    /// Caller records an actually returned effect before a later POST/clock/
    /// persistence veto. This method does not observe that return or write it.
    pub fn next_prefix_data(&self, next: PrefixData, expected: RemovalBindingData<'_>) -> Result<Self> {
        require(self.wire.first_failure.is_none() && self.wire.prefix.next(next), RecordDataError::Transition)?;
        let mut wire = self.wire.clone(); wire.prefix = next;
        Self::from_wire(wire, expected)
    }
    pub fn first_failure_latched_data(&self, kind: FailureKindData, expected: RemovalBindingData<'_>) -> Result<Self> {
        if self.wire.first_failure.is_some() { return Self::parse_data(&self.bytes, expected); }
        let mut wire = self.wire.clone(); wire.first_failure = Some(FirstFailureData { phase: wire.prefix, kind });
        Self::from_wire(wire, expected)
    }
    /// `existing_attempt_count` INCLUDES the predecessor and all retained
    /// attempts, before this new record. 63 may make64; 64 must never make65.
    /// Count is supplied DATA, not a directory/history observer or pruning grant.
    /// This creates fresh admission only; it does NOT inherit an old prefix or
    /// clear the predecessor's failure. Classify PRIOR record + fresh observation.
    pub fn new_attempt_data(&self, request_id: &str, root_nonce: &str, existing_attempt_count: usize,
        expected: RemovalBindingData<'_>) -> Result<Self> {
        require(existing_attempt_count > 0 && existing_attempt_count < INVOCATION_LIMIT, RecordDataError::Limit)?;
        // Recheck the entire previous binding against this independent selection.
        Self::parse_data(&self.bytes, expected)?;
        let mut fresh = Self::admission_data(request_id, root_nonce, expected)?.wire;
        fresh.previous_attempt = Some(PreviousAttempt { request_id: self.wire.request_id.clone(),
            root_nonce: self.wire.root_nonce.clone(), record_sha256: self.sha256.clone() });
        Self::from_wire(fresh, expected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSlotsData { OldOnly, NewOnly, Both, Neither, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadPresenceData { AllPresentMatching, PartialInRosterMatching, AllAbsent, Unknown }
/// All fields are present comparison DATA from a future native observer. A
/// Matches label is not actual EX or signature authority. Namespace/roster
/// comparisons must cover every current/retained planned entry and control;
/// unknown/foreign names are never ignored and no old inode grants custody.
#[derive(Clone, Copy)]
pub struct FreshObservationData<'a> {
    pub request_id: &'a str, pub root_nonce: &'a str, pub prior_record_sha256: &'a str,
    pub source_purpose: CheckData, pub exclusive_original: CheckData,
    pub protected_controls: CheckData, pub remaining_roster: CheckData, pub complete_namespace: CheckData,
    pub app_slots: AppSlotsData, pub payload: PayloadPresenceData,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassificationData {
    Unobserved, Indeterminate, Mismatch, Incomplete,
    FreshAppCoordinationRequired, WithdrawalObservedAfterAdmission, RemainingPayloadObserved,
    PayloadAbsenceObservedAfterInterruptedRemoval, PayloadAbsenceReobserved,
}
fn checks(values: &[CheckData]) -> std::result::Result<(), ClassificationData> {
    for value in values {
        match value {
            CheckData::Matches => (), CheckData::Unobserved => return Err(ClassificationData::Unobserved),
            CheckData::Unknown => return Err(ClassificationData::Indeterminate),
            CheckData::Differs => return Err(ClassificationData::Mismatch),
        }
    }
    Ok(())
}
/// Historical failure deliberately remains in `prior`; a current observation
/// does not rewrite it or certify old unlink/close/outer-exit outcomes.
pub fn classify_data(prior: &RemovalRecordData, current: FreshObservationData<'_>) -> ClassificationData {
    use {AppSlotsData as A, ClassificationData as C, PayloadPresenceData as P, PrefixData as S};
    if !hex(current.request_id, 32) || !hex(current.root_nonce, 32)
        || current.request_id == prior.request_id_data() || current.root_nonce == prior.root_nonce_data()
        || current.prior_record_sha256 != prior.digest_data() { return C::Mismatch; }
    if let Err(value) = checks(&[current.source_purpose, current.exclusive_original, current.protected_controls,
        current.remaining_roster, current.complete_namespace]) { return value; }
    if current.app_slots == A::Unknown || current.payload == P::Unknown { return C::Indeterminate; }
    match (prior.prefix_data(), current.app_slots, current.payload) {
        (S::AdmissionRecorded, A::OldOnly, P::AllPresentMatching) => C::FreshAppCoordinationRequired,
        (S::AdmissionRecorded, A::NewOnly, P::AllPresentMatching) => C::WithdrawalObservedAfterAdmission,
        (S::AppWithdrawn, A::NewOnly, P::AllPresentMatching)
        | (S::PayloadRosterRemoval, A::NewOnly, P::AllPresentMatching | P::PartialInRosterMatching) => C::RemainingPayloadObserved,
        (S::PayloadRosterRemoval, A::Neither, P::AllAbsent) => C::PayloadAbsenceObservedAfterInterruptedRemoval,
        (S::PayloadAbsentObserved, A::Neither, P::AllAbsent) => C::PayloadAbsenceReobserved,
        (_, A::Both, _) | (S::AppWithdrawn | S::PayloadRosterRemoval | S::PayloadAbsentObserved, A::OldOnly, _)
        | (S::PayloadAbsentObserved, _, P::AllPresentMatching | P::PartialInRosterMatching) => C::Mismatch,
        _ => C::Incomplete,
    }
}
/// Closed linked-history comparison only, never source/EX or deletion authority.
/// `chain` is the complete unique tip-to-genesis chain. The native caller must
/// authenticate its actual raw originals and complete namespace independently,
/// and quote all retained records/reference storage before reading them.
/// A future writer still links chain[0], never the ancestor used for comparison.
/// Read-only classification permits64; new_attempt_data still forbids making65.
/// No allocation, parsing, IO, historical failure rewrite or capability escapes.
pub fn classify_linked_data(chain: &[&RemovalRecordData], expected: RemovalBindingData<'_>,
    current: FreshObservationData<'_>) -> Result<ClassificationData> {
    use {AppSlotsData as A, ClassificationData as C, PayloadPresenceData as P, PrefixData as S};
    require(!chain.is_empty() && chain.len() <= INVOCATION_LIMIT, RecordDataError::Limit)?;
    require(expected.valid(), RecordDataError::Binding)?;
    // Validate the ENTIRE chain before returning even a direct tip result. A
    // successful tip cannot conceal an unrelated, broken or truncated tail.
    for (index, record) in chain.iter().enumerate() {
        let binding = record.binding_data();
        require(binding.target == expected.target && binding.source_commit == expected.source_commit
            && binding.removal_descriptor_sha256 == expected.removal_descriptor_sha256
            && binding.installed_producer_sha256 == expected.installed_producer_sha256
            && binding.installed_inventory_sha256 == expected.installed_inventory_sha256
            && binding.installation_state_sha256 == expected.installation_state_sha256
            && binding.payload_roster_sha256 == expected.payload_roster_sha256, RecordDataError::Binding)?;
        require(chain[..index].iter().all(|earlier|
            earlier.request_id_data() != record.request_id_data()
                && earlier.root_nonce_data() != record.root_nonce_data()), RecordDataError::ReusedIdentity)?;
    }
    for pair in chain.windows(2) {
        require(pair[0].previous_attempt_data() == Some((pair[1].request_id_data(),
            pair[1].root_nonce_data(), pair[1].digest_data())), RecordDataError::Binding)?;
    }
    require(chain[chain.len()-1].previous_attempt_data().is_none(), RecordDataError::Shape)?;
    if !hex(current.request_id,32) || !hex(current.root_nonce,32)
        || current.prior_record_sha256 != chain[0].digest_data()
        || chain.iter().any(|record| current.request_id == record.request_id_data()
            || current.root_nonce == record.root_nonce_data()) { return Ok(C::Mismatch); }
    let direct = classify_data(chain[0], current);
    if direct != C::Incomplete
        || !matches!(chain[0].prefix_data(), S::AdmissionRecorded | S::AppWithdrawn)
        || !matches!((current.app_slots,current.payload),
            (A::NewOnly,P::PartialInRosterMatching) | (A::Neither,P::AllAbsent)) { return Ok(direct); }
    for prior in &chain[1..] {
        if matches!(prior.prefix_data(), S::AdmissionRecorded | S::AppWithdrawn) { continue; }
        // This digest view is internal and only follows fully checked raw links.
        // All fresh observations/checks/IDs stay identical. The FIRST meaningful
        // phase is terminal even if it rejects; never search for older success.
        let observation = FreshObservationData { prior_record_sha256: prior.digest_data(), ..current };
        return Ok(classify_data(prior, observation));
    }
    Ok(C::Incomplete)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReinstallClassificationData { Unobserved, Indeterminate, Mismatch, RemovalIncomplete, NewInstallAfterRemovalObservation }
/// This descriptive result is never RestoreFixedApp or earlier-removal success.
/// A genuine new Install owner must authenticate its own current package/source
/// and EX, reobserve all controls/absence, and enforce its release policy.
/// Archived app DIRECTORY must remain until the final payload disappearance;
/// a different native ordering requires an explicitly reviewed table extension.
pub fn classify_reinstall_data(prior: &RemovalRecordData, current: FreshObservationData<'_>) -> ReinstallClassificationData {
    use {ClassificationData as C, ReinstallClassificationData as R};
    match classify_data(prior, current) {
        C::PayloadAbsenceObservedAfterInterruptedRemoval | C::PayloadAbsenceReobserved => R::NewInstallAfterRemovalObservation,
        C::Unobserved => R::Unobserved, C::Indeterminate => R::Indeterminate, C::Mismatch => R::Mismatch,
        _ => R::RemovalIncomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn expected() -> RemovalBindingData<'static> {
        RemovalBindingData { target: MaintenanceTargetData::Arm64, source_commit: "1111111111111111111111111111111111111111",
            removal_descriptor_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            installed_producer_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
            installed_inventory_sha256: "4444444444444444444444444444444444444444444444444444444444444444",
            installation_state_sha256: "5555555555555555555555555555555555555555555555555555555555555555",
            payload_roster_sha256: "6666666666666666666666666666666666666666666666666666666666666666" }
    }
    const OLD_REQUEST: &str = "11111111111111111111111111111111";
    const OLD_NONCE: &str = "22222222222222222222222222222222";
    const NEW_REQUEST: &str = "33333333333333333333333333333333";
    const NEW_NONCE: &str = "44444444444444444444444444444444";
    fn begin() -> RemovalRecordData { RemovalRecordData::admission_data(OLD_REQUEST, OLD_NONCE, expected()).unwrap() }
    fn at(prefix: PrefixData) -> RemovalRecordData {
        let mut record = begin();
        for next in [PrefixData::AppWithdrawn, PrefixData::PayloadRosterRemoval, PrefixData::PayloadAbsentObserved] {
            if record.prefix_data() == prefix { break; }
            record = record.next_prefix_data(next, expected()).unwrap();
        }
        record
    }
    fn parse(value: Value) -> Result<RemovalRecordData> {
        RemovalRecordData::parse_data(&serde_json::to_vec(&value).unwrap(), expected())
    }
    fn fresh<'a>(record: &'a RemovalRecordData, app_slots: AppSlotsData, payload: PayloadPresenceData) -> FreshObservationData<'a> {
        FreshObservationData { request_id: NEW_REQUEST, root_nonce: NEW_NONCE, prior_record_sha256: record.digest_data(),
            source_purpose: CheckData::Matches, exclusive_original: CheckData::Matches, protected_controls: CheckData::Matches,
            remaining_roster: CheckData::Matches, complete_namespace: CheckData::Matches, app_slots, payload }
    }
    #[test]
    fn removal_record_closed_schema_and_bindings_are_data_only() {
        let original = begin();
        let base: Value = serde_json::from_slice(original.bytes_data()).unwrap();
        assert_eq!(RemovalRecordData::parse_data(original.bytes_data(), expected()).unwrap().digest_data(), original.digest_data());
        for key in KEYS {
            let mut value = base.clone(); value.as_object_mut().unwrap().remove(key);
            assert_eq!(parse(value).unwrap_err(), RecordDataError::Shape, "missing {key}");
        }
        let mut extra = base.clone(); extra["available"] = json!(true);
        assert_eq!(parse(extra).unwrap_err(), RecordDataError::Shape);
        for (key, value) in [("schemaVersion", json!(true)), ("prefix", json!(1)), ("firstFailure", json!([])),
            ("previousAttempt", json!([])), ("rootNonce", Value::Null)] {
            let mut changed = base.clone(); changed[key] = value;
            assert_eq!(parse(changed).unwrap_err(), RecordDataError::Shape, "type {key}");
        }
        for key in ["target", "sourceCommit", "removalDescriptorSha256", "installedProducerSha256",
            "installedInventorySha256", "installationStateSha256", "payloadRosterSha256", "requestId", "rootNonce"] {
            let mut changed = base.clone(); changed[key] = json!("0".repeat(if key.ends_with("Sha256") {64} else {32}));
            assert_eq!(parse(changed).unwrap_err(), RecordDataError::Binding, "binding {key}");
        }
        let mut kind = base.clone(); kind["kind"] = json!("mrk-macos-maintenance-state-v2");
        assert_eq!(parse(kind).unwrap_err(), RecordDataError::Binding);
        let mut nested = base.clone(); nested["firstFailure"] = json!({"phase":"admission-recorded","kind":"original-unknown","closed":true});
        assert_eq!(parse(nested).unwrap_err(), RecordDataError::Shape);
        let text = String::from_utf8(original.bytes_data().to_vec()).unwrap();
        let duplicate = text.replacen('{', "{\"schemaVersion\":1,", 1);
        assert_eq!(RemovalRecordData::parse_data(duplicate.as_bytes(), expected()).unwrap_err(), RecordDataError::Shape);
        let nonfinite = text.replacen("\"schemaVersion\":1", "\"schemaVersion\":NaN", 1);
        assert_eq!(RemovalRecordData::parse_data(nonfinite.as_bytes(), expected()).unwrap_err(), RecordDataError::Shape);
        let mut bound = original.bytes_data().to_vec(); bound.resize(RECORD_LIMIT, b' ');
        let full = RemovalRecordData::parse_data(&bound, expected()).unwrap();
        assert_eq!(full.bytes_data().len(), RECORD_LIMIT);
        assert_ne!(full.digest_data(), original.digest_data()); // original bytes, not canonical echo
        bound.push(b' ');
        assert_eq!(RemovalRecordData::parse_data(&bound, expected()).unwrap_err(), RecordDataError::Limit);
        assert_eq!(RemovalRecordData::parse_data(&[], expected()).unwrap_err(), RecordDataError::Limit);
        let mut other = expected(); other.target = MaintenanceTargetData::Intel;
        assert_eq!(RemovalRecordData::parse_data(original.bytes_data(), other).unwrap_err(), RecordDataError::Binding);
        // The public constructor must refuse before copying unbounded input.
        let oversized = "1".repeat(RECORD_LIMIT + 1);
        let zero = "0".repeat(32);
        for (request, nonce) in [(&oversized[..], OLD_NONCE), (OLD_REQUEST, &oversized[..]),
            (&zero[..], OLD_NONCE), (OLD_REQUEST, &zero[..])] {
            assert_eq!(RemovalRecordData::admission_data(request, nonce, expected()).unwrap_err(), RecordDataError::Binding);
        }
        let invalid_source = RemovalBindingData { source_commit: &oversized, ..expected() };
        let invalid_roster = RemovalBindingData { payload_roster_sha256: &oversized, ..expected() };
        for invalid in [invalid_source, invalid_roster] {
            assert_eq!(RemovalRecordData::admission_data(OLD_REQUEST, OLD_NONCE, invalid).unwrap_err(), RecordDataError::Binding);
        }
        // Shape-only history parsing uses the same closed grammar, but a valid
        // different source/target is comparison DATA rather than expected truth.
        let mut independent = base.clone();
        independent["target"] = json!(MaintenanceTargetData::Intel.target());
        independent["sourceCommit"] = json!("7".repeat(40));
        let raw = serde_json::to_vec_pretty(&independent).unwrap();
        let shape = RemovalRecordData::parse_shape_data(&raw).unwrap();
        let binding = shape.binding_data();
        assert_eq!(binding.target, MaintenanceTargetData::Intel);
        assert_eq!(binding.source_commit, "7".repeat(40));
        assert!(std::ptr::eq(binding.source_commit, shape.wire.source_commit.as_str()));
        assert_eq!(shape.bytes_data(), raw);
        assert_eq!(shape.digest_data(), format!("{:x}", Sha256::digest(&raw)));
        assert_eq!(RemovalRecordData::parse_data(&raw, expected()).unwrap_err(), RecordDataError::Binding);
        assert_eq!(RemovalRecordData::parse_data(&raw, binding).unwrap().bytes_data(), raw);
        for key in KEYS {
            let mut changed = base.clone(); changed.as_object_mut().unwrap().remove(key);
            assert_eq!(RemovalRecordData::parse_shape_data(&serde_json::to_vec(&changed).unwrap()).unwrap_err(),
                RecordDataError::Shape, "shape missing {key}");
        }
        let mut invalid = Vec::new();
        let mut changed = base.clone(); changed["extra"] = json!(true); invalid.push((changed, RecordDataError::Shape));
        for (key, value) in [("schemaVersion", json!(2)), ("kind", json!("other")), ("target", json!("other")),
            ("sourceCommit", json!("f".repeat(39))), ("prefix", json!("future")),
            ("firstFailure", json!({"phase":"payload-absent-observed","kind":"deadline"})),
            ("previousAttempt", json!({"requestId":NEW_REQUEST,"rootNonce":NEW_NONCE})),
            ("firstFailure", json!({"phase":"admission-recorded","kind":"deadline","extra":true}))] {
            let error = match key { "prefix" | "previousAttempt" => RecordDataError::Shape,
                "firstFailure" if value.get("extra").is_some() => RecordDataError::Shape,
                "firstFailure" => RecordDataError::Transition, _ => RecordDataError::Binding };
            let mut changed = base.clone(); changed[key] = value; invalid.push((changed, error));
        }
        for key in ["sourceCommit", "removalDescriptorSha256", "installedProducerSha256", "installedInventorySha256",
            "installationStateSha256", "payloadRosterSha256", "requestId", "rootNonce"] {
            let width = if key == "sourceCommit" {40} else if key.ends_with("Sha256") {64} else {32};
            for value in ["0".repeat(width), "A".repeat(width), "f".repeat(width + 1)] {
                let mut changed = base.clone(); changed[key] = json!(value); invalid.push((changed, RecordDataError::Binding));
            }
            let mut changed = base.clone(); changed[key] = json!(1); invalid.push((changed, RecordDataError::Shape));
        }
        // Nonempty positional arrays can satisfy serde's derived struct
        // visitor, but are not objects in this fixed wire schema.
        for (key, value) in [("previousAttempt", json!([NEW_REQUEST, NEW_NONCE, expected().payload_roster_sha256])),
            ("firstFailure", json!(["admission-recorded", "deadline"]))] {
            let mut changed = base.clone(); changed[key] = value; invalid.push((changed, RecordDataError::Shape));
        }
        for (changed, error) in invalid {
            let raw = serde_json::to_vec(&changed).unwrap();
            assert_eq!(RemovalRecordData::parse_shape_data(&raw).unwrap_err(), error);
            assert_eq!(RemovalRecordData::parse_data(&raw, expected()).unwrap_err(), error);
        }
        for raw in [duplicate.as_bytes(), nonfinite.as_bytes()] {
            assert_eq!(RemovalRecordData::parse_shape_data(raw).unwrap_err(), RecordDataError::Shape);
        }
        assert_eq!(RemovalRecordData::parse_shape_data(&[]).unwrap_err(), RecordDataError::Limit);
        assert_eq!(RemovalRecordData::parse_shape_data(&bound).unwrap_err(), RecordDataError::Limit);
        let shape_full = RemovalRecordData::parse_shape_data(full.bytes_data()).unwrap();
        assert_eq!(shape_full.bytes_data(), full.bytes_data());
        assert_eq!(shape_full.digest_data(), full.digest_data());
        // All seven independent tuple fields still compare, even though each
        // substituted value is a valid shape-only historical field.
        for index in 0..7 {
            let mut expected = expected();
            match index { 0 => expected.target = MaintenanceTargetData::Intel,
                1 => expected.source_commit = "7777777777777777777777777777777777777777",
                2 => expected.removal_descriptor_sha256 = expected.payload_roster_sha256,
                3 => expected.installed_producer_sha256 = expected.payload_roster_sha256,
                4 => expected.installed_inventory_sha256 = expected.payload_roster_sha256,
                5 => expected.installation_state_sha256 = expected.payload_roster_sha256,
                _ => expected.payload_roster_sha256 = expected.installed_producer_sha256 }
            assert_eq!(RemovalRecordData::parse_data(original.bytes_data(), expected).unwrap_err(), RecordDataError::Binding);
        }
        assert_eq!(RemovalRecordData::parse_data(b"{", invalid_source).unwrap_err(), RecordDataError::Binding);
        assert_eq!(RemovalRecordData::parse_data(&[], invalid_source).unwrap_err(), RecordDataError::Limit);
        // Count actual capacity, not byte lengths; grow each retained backing
        // in turn without changing its validated bytes or borrowing authority.
        let mut capacity_record = RemovalRecordData::parse_shape_data(original.bytes_data()).unwrap();
        let initial = capacity_record.owned_bytes_data().unwrap();
        let old = capacity_record.bytes.capacity(); capacity_record.bytes.reserve(old + 1);
        assert_eq!(capacity_record.owned_bytes_data().unwrap(), initial + capacity_record.bytes.capacity() - old);
        macro_rules! spare {
            ($field:expr) => {{
                let total = capacity_record.owned_bytes_data().unwrap();
                let old = $field.capacity(); $field.reserve(old + 1);
                assert_eq!(capacity_record.owned_bytes_data().unwrap(), total + $field.capacity() - old);
            }};
        }
        spare!(capacity_record.sha256); spare!(capacity_record.wire.kind); spare!(capacity_record.wire.target);
        spare!(capacity_record.wire.source_commit); spare!(capacity_record.wire.removal_descriptor_sha256);
        spare!(capacity_record.wire.installed_producer_sha256); spare!(capacity_record.wire.installed_inventory_sha256);
        spare!(capacity_record.wire.installation_state_sha256); spare!(capacity_record.wire.payload_roster_sha256);
        spare!(capacity_record.wire.request_id); spare!(capacity_record.wire.root_nonce);
        assert_eq!(capacity_record.bytes_data(), original.bytes_data());
        assert_eq!(capacity_record.digest_data(), original.digest_data());
        let w = &original.wire;
        assert_eq!(original.owned_bytes_data(), Some(std::mem::size_of::<RemovalRecordData>() + original.bytes.capacity()
            + original.sha256.capacity() + w.kind.capacity() + w.target.capacity() + w.source_commit.capacity()
            + w.removal_descriptor_sha256.capacity() + w.installed_producer_sha256.capacity()
            + w.installed_inventory_sha256.capacity() + w.installation_state_sha256.capacity()
            + w.payload_roster_sha256.capacity() + w.request_id.capacity() + w.root_nonce.capacity()));
    }
    #[test]
    fn removal_prefix_failure_and_new_attempt_never_rewrite_history() {
        use PrefixData as P;
        let prefixes = [P::AdmissionRecorded, P::AppWithdrawn, P::PayloadRosterRemoval, P::PayloadAbsentObserved];
        for (index, prefix) in prefixes.iter().enumerate() {
            let record = at(*prefix);
            for (next_index, next) in prefixes.iter().enumerate() {
                assert_eq!(record.next_prefix_data(*next, expected()).is_ok(), next_index == index + 1);
            }
            let failed = record.first_failure_latched_data(FailureKindData::OriginalUnknown, expected()).unwrap();
            let later = failed.first_failure_latched_data(FailureKindData::Persistence, expected()).unwrap();
            assert_eq!(later.bytes_data(), failed.bytes_data());
            assert_eq!(later.first_failure_data(), Some(FirstFailureData { phase: *prefix, kind: FailureKindData::OriginalUnknown }));
            for next in prefixes { assert_eq!(failed.next_prefix_data(next, expected()).unwrap_err(), RecordDataError::Transition); }
            let fresh = failed.new_attempt_data(NEW_REQUEST, NEW_NONCE, INVOCATION_LIMIT - 1, expected()).unwrap();
            assert_eq!(fresh.prefix_data(), P::AdmissionRecorded);
            assert_eq!(fresh.first_failure_data(), None);
            assert_eq!(fresh.previous_attempt_data(), Some((OLD_REQUEST, OLD_NONCE, failed.digest_data())));
            assert_eq!(failed.first_failure_data().unwrap().kind, FailureKindData::OriginalUnknown);
            for count in [0, INVOCATION_LIMIT, usize::MAX] {
                assert_eq!(failed.new_attempt_data(NEW_REQUEST, NEW_NONCE, count, expected()).unwrap_err(), RecordDataError::Limit);
            }
            for (request, nonce) in [(OLD_REQUEST, NEW_NONCE), (NEW_REQUEST, OLD_NONCE)] {
                assert_eq!(failed.new_attempt_data(request, nonce, 1, expected()).unwrap_err(), RecordDataError::ReusedIdentity);
            }
            let mut mismatch = expected(); mismatch.installed_inventory_sha256 = expected().payload_roster_sha256;
            assert_eq!(failed.new_attempt_data(NEW_REQUEST, NEW_NONCE, 1, mismatch).unwrap_err(), RecordDataError::Binding);
        }
        // Actual returned-prefix DATA precedes a later veto, never the reverse.
        let returned = begin().next_prefix_data(P::AppWithdrawn, expected()).unwrap();
        let late = returned.first_failure_latched_data(FailureKindData::PostMismatch, expected()).unwrap();
        assert_eq!(late.prefix_data(), P::AppWithdrawn);
        let mut future: Value = serde_json::from_slice(begin().bytes_data()).unwrap();
        future["firstFailure"] = json!({"phase":"payload-absent-observed","kind":"deadline"});
        assert_eq!(parse(future).unwrap_err(), RecordDataError::Transition);
        // A shape-only tip preserves the actual original digest, including
        // whitespace, and new_attempt still requires the independently bound
        // ORIGINAL genesis payload commitment rather than a new envelope hash.
        let mut raw = late.bytes_data().to_vec(); raw.extend_from_slice(b"  ");
        let prior = RemovalRecordData::parse_shape_data(&raw).unwrap();
        let mut child = prior.new_attempt_data(NEW_REQUEST, NEW_NONCE, 1, expected()).unwrap();
        assert_ne!(prior.digest_data(), late.digest_data());
        assert_eq!(child.previous_attempt_data(), Some((OLD_REQUEST, OLD_NONCE, prior.digest_data())));
        assert_eq!(child.binding_data().payload_roster_sha256, prior.binding_data().payload_roster_sha256);
        assert_eq!(child.first_failure_data(), None);
        assert_eq!(prior.first_failure_data(), late.first_failure_data());
        let shape_child = RemovalRecordData::parse_shape_data(child.bytes_data()).unwrap();
        assert_eq!(shape_child.previous_attempt_data(), child.previous_attempt_data());
        let mut new_envelope = expected(); new_envelope.payload_roster_sha256 = prior.digest_data();
        assert_eq!(prior.new_attempt_data(NEW_REQUEST, NEW_NONCE, 1, new_envelope).unwrap_err(), RecordDataError::Binding);
        let prior_capacity = child.wire.previous_attempt.as_ref().unwrap();
        let expected_size = std::mem::size_of::<RemovalRecordData>() + child.bytes.capacity() + child.sha256.capacity()
            + [&child.wire.kind, &child.wire.target, &child.wire.source_commit, &child.wire.removal_descriptor_sha256,
                &child.wire.installed_producer_sha256, &child.wire.installed_inventory_sha256,
                &child.wire.installation_state_sha256, &child.wire.payload_roster_sha256,
                &child.wire.request_id, &child.wire.root_nonce, &prior_capacity.request_id,
                &prior_capacity.root_nonce, &prior_capacity.record_sha256].iter().map(|s| s.capacity()).sum::<usize>();
        assert_eq!(child.owned_bytes_data(), Some(expected_size));
        for index in 0..3 {
            let before = child.owned_bytes_data().unwrap();
            let previous = child.wire.previous_attempt.as_mut().unwrap();
            let value = match index { 0 => &mut previous.request_id, 1 => &mut previous.root_nonce, _ => &mut previous.record_sha256 };
            let capacity = value.capacity(); value.reserve(capacity + 1); let delta = value.capacity() - capacity;
            assert_eq!(child.owned_bytes_data().unwrap(), before + delta);
        }
        let base: Value = serde_json::from_slice(child.bytes_data()).unwrap();
        for key in ["requestId", "rootNonce", "recordSha256"] {
            for value in [Value::Null, json!("0".repeat(if key == "recordSha256" {64} else {32})), json!("A")] {
                let error = if value.is_null() { RecordDataError::Shape } else { RecordDataError::Binding };
                let mut changed = base.clone(); changed["previousAttempt"][key] = value;
                assert_eq!(RemovalRecordData::parse_shape_data(&serde_json::to_vec(&changed).unwrap()).unwrap_err(), error);
            }
        }
        for (key, value) in [("requestId", NEW_REQUEST), ("rootNonce", NEW_NONCE)] {
            let mut reused = base.clone(); reused["previousAttempt"][key] = json!(value);
            let raw = serde_json::to_vec(&reused).unwrap();
            assert_eq!(RemovalRecordData::parse_shape_data(&raw).unwrap_err(), RecordDataError::ReusedIdentity);
            assert_eq!(RemovalRecordData::parse_data(&raw, expected()).unwrap_err(), RecordDataError::ReusedIdentity);
            let mut wrong = expected(); wrong.target = MaintenanceTargetData::Intel;
            assert_eq!(RemovalRecordData::parse_data(&raw, wrong).unwrap_err(), RecordDataError::Binding);
        }
        let raw = String::from_utf8(child.bytes_data().to_vec()).unwrap()
            .replacen("\"previousAttempt\":{", "\"previousAttempt\":{\"requestId\":\"duplicate\",", 1);
        assert_eq!(RemovalRecordData::parse_shape_data(raw.as_bytes()).unwrap_err(), RecordDataError::Shape);
    }
    #[test]
    fn fresh_removal_and_reinstall_table_never_upgrades_old_failure() {
        use {AppSlotsData as A, ClassificationData as C, PayloadPresenceData as P, PrefixData as S, ReinstallClassificationData as R};
        let cases = [
            (S::AdmissionRecorded,A::OldOnly,P::AllPresentMatching,C::FreshAppCoordinationRequired),
            (S::AdmissionRecorded,A::NewOnly,P::AllPresentMatching,C::WithdrawalObservedAfterAdmission),
            (S::AppWithdrawn,A::NewOnly,P::AllPresentMatching,C::RemainingPayloadObserved),
            (S::PayloadRosterRemoval,A::NewOnly,P::AllPresentMatching,C::RemainingPayloadObserved),
            (S::PayloadRosterRemoval,A::NewOnly,P::PartialInRosterMatching,C::RemainingPayloadObserved),
            (S::PayloadRosterRemoval,A::Neither,P::AllAbsent,C::PayloadAbsenceObservedAfterInterruptedRemoval),
            (S::PayloadAbsentObserved,A::Neither,P::AllAbsent,C::PayloadAbsenceReobserved),
            (S::AdmissionRecorded,A::Neither,P::AllAbsent,C::Incomplete),
            (S::AdmissionRecorded,A::NewOnly,P::PartialInRosterMatching,C::Incomplete),
            (S::AppWithdrawn,A::NewOnly,P::PartialInRosterMatching,C::Incomplete),
            (S::AppWithdrawn,A::OldOnly,P::AllPresentMatching,C::Mismatch),
            (S::PayloadAbsentObserved,A::NewOnly,P::AllPresentMatching,C::Mismatch),
            (S::PayloadRosterRemoval,A::Neither,P::PartialInRosterMatching,C::Incomplete),
        ];
        for (prefix, slots, payload, want) in cases {
            let prior = at(prefix).first_failure_latched_data(FailureKindData::CloseUnknown, expected()).unwrap();
            let before = prior.bytes_data().to_vec();
            let observation = fresh(&prior, slots, payload);
            assert_eq!(classify_data(&prior, observation), want);
            let reinstall = classify_reinstall_data(&prior, observation);
            assert_eq!(reinstall == R::NewInstallAfterRemovalObservation,
                matches!(want, C::PayloadAbsenceObservedAfterInterruptedRemoval | C::PayloadAbsenceReobserved));
            assert_eq!(prior.bytes_data(), before);
            assert_eq!(prior.first_failure_data().unwrap().kind, FailureKindData::CloseUnknown);
        }
        for prefix in [S::AdmissionRecorded,S::AppWithdrawn,S::PayloadRosterRemoval,S::PayloadAbsentObserved] {
            let prior = at(prefix);
            for payload in [P::AllPresentMatching,P::PartialInRosterMatching,P::AllAbsent] {
                assert_eq!(classify_data(&prior, fresh(&prior,A::Both,payload)), C::Mismatch);
            }
        }
        let prior = at(S::PayloadRosterRemoval);
        let original = fresh(&prior,A::Neither,P::AllAbsent);
        for index in 0..5 {
            for (check,want) in [(CheckData::Unknown,C::Indeterminate),(CheckData::Unobserved,C::Unobserved),(CheckData::Differs,C::Mismatch)] {
                let mut current = original;
                match index { 0=>current.source_purpose=check,1=>current.exclusive_original=check,
                    2=>current.protected_controls=check,3=>current.remaining_roster=check,_=>current.complete_namespace=check }
                assert_eq!(classify_data(&prior,current),want);
                assert_ne!(classify_reinstall_data(&prior,current),R::NewInstallAfterRemovalObservation);
            }
        }
        let mut current=original; current.request_id=OLD_REQUEST; assert_eq!(classify_data(&prior,current),C::Mismatch);
        current=original; current.root_nonce=OLD_NONCE; assert_eq!(classify_data(&prior,current),C::Mismatch);
        current=original; current.prior_record_sha256=expected().payload_roster_sha256;
        assert_eq!(classify_data(&prior,current),C::Mismatch);
        current=original; current.app_slots=A::Unknown; assert_eq!(classify_data(&prior,current),C::Indeterminate);
        current=original; current.payload=P::Unknown; assert_eq!(classify_data(&prior,current),C::Indeterminate);
        // Real new-attempt encodings reset to Admission. A crash after that
        // write (or AppWithdrawn) must preserve the exact linked predecessor,
        // not invent an old close/result or rebind the genesis commitment.
        fn linked_child(prior: &RemovalRecordData, index: usize, prefix: PrefixData) -> RemovalRecordData {
            let mut record = prior.new_attempt_data(&format!("{:032x}",index+256),
                &format!("{:032x}",index+512),index,expected()).unwrap();
            for next in [PrefixData::AppWithdrawn,PrefixData::PayloadRosterRemoval,PrefixData::PayloadAbsentObserved] {
                if record.prefix_data() == prefix { break; }
                record = record.next_prefix_data(next,expected()).unwrap();
            }
            record
        }
        for (prefix,slots,payload,want) in [
            (S::PayloadRosterRemoval,A::NewOnly,P::PartialInRosterMatching,C::RemainingPayloadObserved),
            (S::PayloadRosterRemoval,A::Neither,P::AllAbsent,C::PayloadAbsenceObservedAfterInterruptedRemoval),
            (S::PayloadAbsentObserved,A::Neither,P::AllAbsent,C::PayloadAbsenceReobserved)] {
            let old = at(prefix).first_failure_latched_data(FailureKindData::CloseUnknown,expected()).unwrap();
            let admission = linked_child(&old,1,S::AdmissionRecorded);
            let withdrawn = linked_child(&admission,2,S::AppWithdrawn)
                .first_failure_latched_data(FailureKindData::Persistence,expected()).unwrap();
            let tip = linked_child(&withdrawn,3,S::AdmissionRecorded);
            let chain = [&tip,&withdrawn,&admission,&old];
            let original: Vec<_> = chain.iter().map(|r| (r.bytes_data().to_vec(),r.first_failure_data())).collect();
            let current = fresh(&tip,slots,payload);
            assert_eq!(classify_data(&tip,current),C::Incomplete);
            assert_eq!(classify_linked_data(&chain,expected(),current).unwrap(),want);
            assert_eq!(classify_linked_data(&chain[1..],expected(),fresh(&withdrawn,slots,payload)).unwrap(),want);
            assert_eq!(tip.previous_attempt_data().unwrap().2,withdrawn.digest_data());
            for (record,(bytes,failure)) in chain.iter().zip(&original) {
                assert_eq!(record.bytes_data(),bytes);assert_eq!(record.first_failure_data(),*failure);
            }
            for index in 0..5 {
                for (check,want) in [(CheckData::Unknown,C::Indeterminate),
                    (CheckData::Unobserved,C::Unobserved),(CheckData::Differs,C::Mismatch)] {
                    let mut changed=current;
                    match index {0=>changed.source_purpose=check,1=>changed.exclusive_original=check,
                        2=>changed.protected_controls=check,3=>changed.remaining_roster=check,_=>changed.complete_namespace=check}
                    assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),want);
                }
            }
            let mut changed=current;changed.app_slots=A::Both;
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Mismatch);
            changed=current;changed.payload=P::Unknown;
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Indeterminate);
            changed=current;changed.prior_record_sha256=old.digest_data();
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Mismatch);
            changed=current;changed.request_id=old.request_id_data();
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Mismatch);
            changed=current;changed.root_nonce=withdrawn.root_nonce_data();
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Mismatch);
            changed=current;changed.request_id="0";
            assert_eq!(classify_linked_data(&chain,expected(),changed).unwrap(),C::Mismatch);
            let mut wrong=expected();wrong.target=MaintenanceTargetData::Intel;
            assert_eq!(classify_linked_data(&chain,wrong,current),Err(RecordDataError::Binding));
            wrong=expected();wrong.payload_roster_sha256=old.digest_data();
            assert_eq!(classify_linked_data(&chain,wrong,current),Err(RecordDataError::Binding));
            assert_eq!(classify_linked_data(&chain[..3],expected(),current),Err(RecordDataError::Shape));
            assert_eq!(classify_linked_data(&[&tip,&admission,&withdrawn,&old],expected(),current),Err(RecordDataError::Binding));
            assert_eq!(classify_linked_data(&[&tip,&withdrawn,&tip,&old],expected(),current),Err(RecordDataError::ReusedIdentity));
            // Same parsed fields, different exact original bytes: raw link fails.
            let mut whitespace=old.bytes_data().to_vec();whitespace.push(b' ');
            let changed_old=RemovalRecordData::parse_shape_data(&whitespace).unwrap();
            assert_eq!(classify_linked_data(&[&tip,&withdrawn,&admission,&changed_old],expected(),current),Err(RecordDataError::Binding));
            let mut foreign:Value=serde_json::from_slice(old.bytes_data()).unwrap();
            foreign["installedInventorySha256"]=json!("9".repeat(64));
            let foreign=RemovalRecordData::parse_shape_data(&serde_json::to_vec(&foreign).unwrap()).unwrap();
            assert_eq!(classify_linked_data(&[&tip,&withdrawn,&admission,&foreign],expected(),current),Err(RecordDataError::Binding));
            let unrelated=linked_child(&old,4,S::AdmissionRecorded);
            assert_eq!(classify_linked_data(&[&tip,&withdrawn,&admission,&old,&unrelated],expected(),current),Err(RecordDataError::Binding));
            assert_eq!(classify_linked_data(&[],expected(),current),Err(RecordDataError::Limit));
        }
        // Do not skip a first meaningful terminal refusal to find an older
        // deletion phase that would otherwise accept this partial namespace.
        let old=at(S::PayloadRosterRemoval);
        let terminal=linked_child(&old,1,S::PayloadAbsentObserved);
        let tip=linked_child(&terminal,2,S::AdmissionRecorded);
        let observation=fresh(&tip,A::NewOnly,P::PartialInRosterMatching);
        assert_eq!(classify_linked_data(&[&tip,&terminal,&old],expected(),observation).unwrap(),C::Mismatch);
        let first=begin();let entry=linked_child(&first,1,S::AppWithdrawn);
        let observation=fresh(&entry,A::Neither,P::AllAbsent);
        assert_eq!(classify_linked_data(&[&entry,&first],expected(),observation).unwrap(),C::Incomplete);
        assert_eq!(classify_linked_data(&[&first],expected(),fresh(&first,A::NewOnly,P::PartialInRosterMatching)).unwrap(),C::Incomplete);
        // Classification64 is read-only, not permission to create a65th attempt.
        let mut records=vec![at(S::PayloadRosterRemoval)];
        for index in 1..INVOCATION_LIMIT {
            records.push(linked_child(records.last().unwrap(),index,
                if index%2==0 {S::AppWithdrawn}else{S::AdmissionRecorded}));
        }
        let refs:Vec<_>=records.iter().rev().collect();let tip=refs[0];
        let observation=fresh(tip,A::NewOnly,P::PartialInRosterMatching);
        assert_eq!(classify_linked_data(&refs,expected(),observation).unwrap(),C::RemainingPayloadObserved);
        assert_eq!(tip.new_attempt_data(NEW_REQUEST,NEW_NONCE,INVOCATION_LIMIT,expected()).unwrap_err(),RecordDataError::Limit);
        let mut too_many=refs.clone();too_many.push(tip);
        assert_eq!(classify_linked_data(&too_many,expected(),observation),Err(RecordDataError::Limit));
        // Direct classification remains exact, but a direct success never hides
        // an invalid entire chain. No modification of the ordinary global table.
        for (prefix,slots,payload,want) in cases {
            let prior=at(prefix).first_failure_latched_data(FailureKindData::OriginalUnknown,expected()).unwrap();
            assert_eq!(classify_linked_data(&[&prior],expected(),fresh(&prior,slots,payload)).unwrap(),want);
        }
        let unrelated=linked_child(&old,1,S::AdmissionRecorded);
        assert_eq!(classify_linked_data(&[&old,&unrelated],expected(),fresh(&old,A::NewOnly,P::PartialInRosterMatching)),
            Err(RecordDataError::Binding));
    }
}
