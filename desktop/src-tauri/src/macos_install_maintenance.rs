//! Bounded maintenance preparation DATA, not a filesystem reader or capability.
//! Expected releases come from the release producer, never from the installation
//! being classified. Supplied check labels cannot establish signature trust,
//! current invocation, native finality, live-use exclusion or permission to act.
//! No production caller/Installer branch is enabled by this module.
#![forbid(unsafe_code)]

use serde::{de::DeserializeOwned, Deserialize};
use crate::{macos_install_paths as paths, protocol::strict_json};

pub const INPUT_LIMIT: usize = 16 * 1024;
pub const PREDECESSOR_LIMIT: usize = 8;
const PROFILE: &str = "fixed-macos26-arm64-maintenance-v2";
// These are the published engineering-v1 identities, not the next release.
const LEGACY_RELEASE: &str = "macos26-arm64-project-draft-01";
const ENTRY_ENGINEERING_RELEASE: &str = "macos26-arm64-entry-m2a-01";
const LEGACY_VERSION: &str = "0.1.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError { Limit, Shape, Binding, ReusedIdentity, Legacy }
type Result<T> = std::result::Result<T, DataError>;
fn require(ok: bool, why: DataError) -> Result<()> { if ok { Ok(()) } else { Err(why) } }
fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn version(value: &str) -> Option<[u32; 3]> {
    if value.len() > 32 { return None; }
    let mut parts = value.split('.'); let mut result = [0; 3];
    for item in &mut result {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit())
            || part.len() > 1 && part.starts_with('0') { return None; }
        *item = part.parse().ok()?;
    }
    parts.next().is_none().then_some(result)
}
fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty() && bytes.len() <= INPUT_LIMIT, DataError::Limit)?;
    serde_json::from_value(strict_json(bytes).map_err(|_| DataError::Shape)?)
        .map_err(|_| DataError::Shape)
}

/// Detached producer DATA. packageSha256 is the completed package's digest;
/// never embed that digest in the package whose bytes it hashes. Release/source
/// selection remains build-bound. This parser neither reads nor selects code.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseData {
    profile: String, package_identifier: String, bundle_identifier: String,
    package_version: String, release: String, source_commit: String,
    protocol_sha256: String, runtime_manifest_sha256: String, inventory_sha256: String,
    signing_policy_sha256: String, package_sha256: String,
}
impl ReleaseData {
    fn validate(&self) -> Result<()> {
        require(self.profile == PROFILE && self.package_identifier == paths::PACKAGE_ID
            && self.bundle_identifier == paths::BUNDLE_ID, DataError::Binding)?;
        require(self.release != LEGACY_RELEASE && self.release != ENTRY_ENGINEERING_RELEASE
            && self.package_version != LEGACY_VERSION, DataError::Legacy)?;
        require(version(&self.package_version).is_some() && self.release.len() <= 128
            && self.release.starts_with("macos26-arm64-") && self.release.len() > "macos26-arm64-".len()
            && self.release.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
            && self.release.as_bytes().last().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && hex(&self.source_commit, 40)
            && [&self.protocol_sha256, &self.runtime_manifest_sha256, &self.inventory_sha256,
                &self.signing_policy_sha256, &self.package_sha256].iter().all(|s| hex(s, 64)), DataError::Binding)
    }
    fn reuses_identity(&self, other: &Self) -> bool {
        self.release == other.release || self.package_version == other.package_version
            || self.package_sha256 == other.package_sha256
    }
}

/// An explicit finite allow-list, not a destination-derived upgrade policy.
#[derive(Debug)]
pub struct ReleaseSetData {
    current: ReleaseData, accepted_predecessors: Vec<ReleaseData>,
}
// The validated wrapper does not implement Deserialize: callers cannot bypass
// parse_data's size/identity/predecessor checks through serde_json::from_value.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSetWireData {
    schema_version: u32, current: ReleaseData, accepted_predecessors: Vec<ReleaseData>,
}
impl ReleaseSetData {
    pub fn parse_data(bytes: &[u8]) -> Result<Self> {
        let value: ReleaseSetWireData = parse(bytes)?;
        require(value.schema_version == 2, DataError::Binding)?;
        require(value.accepted_predecessors.len() <= PREDECESSOR_LIMIT, DataError::Limit)?;
        value.current.validate()?;
        for (i, predecessor) in value.accepted_predecessors.iter().enumerate() {
            predecessor.validate()?;
            require(!predecessor.reuses_identity(&value.current)
                && !value.accepted_predecessors[..i].iter().any(|old| predecessor.reuses_identity(old)),
                DataError::ReusedIdentity)?;
            require(version(&predecessor.package_version) < version(&value.current.package_version), DataError::Binding)?;
        }
        Ok(Self { current: value.current, accepted_predecessors: value.accepted_predecessors })
    }
    pub fn current_data(&self) -> &ReleaseData { &self.current }
    pub fn predecessor_data(&self) -> &[ReleaseData] { &self.accepted_predecessors }
    fn tuple_class(&self, value: &ReleaseData) -> ClassificationData {
        if value == &self.current { ClassificationData::ExactCurrentTuple }
        else if self.accepted_predecessors.contains(value) { ClassificationData::AcceptedPredecessorTuple }
        else if value.reuses_identity(&self.current)
            || self.accepted_predecessors.iter().any(|old| value.reuses_identity(old)) { ClassificationData::ReusedIdentity }
        else { ClassificationData::UnsupportedTuple }
    }
}

/// Returned-comparison labels supplied by a future original observer. No bool
/// or label constructed here is an observation or an authenticated receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckData { Unobserved, Matches, Differs, Unknown }
#[derive(Clone, Copy)]
pub struct ObjectChecksData {
    pub full_inventory: CheckData,
    pub signing_policy: CheckData,
    pub record_binding: CheckData,
}
#[derive(Clone, Copy)]
pub enum ObjectData<'a> {
    Unobserved, Absent, Unrelated, LegacyV1, Partial, Unknown,
    Present { release: &'a ReleaseData, checks: ObjectChecksData },
}
pub struct ObservationData<'a> {
    pub protected_ancestry: CheckData,
    /// Independently supplied operation-state correspondence; never infer this
    /// from inventory-recorded, a matching record, or an old result file.
    pub prior_operation: CheckData,
    pub app: ObjectData<'a>,
    pub runtime: ObjectData<'a>,
}
/// Descriptive DATA only. Deliberately has no action, available, success,
/// installed or can-maintain field and is not an IPC/serialized capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassificationData {
    Unobserved, Indeterminate, Mismatch, Occupied, LegacyUnsupported, Incomplete,
    Contradictory, ReusedIdentity, UnsupportedTuple, FixedNamesAbsent,
    ExactCurrentTuple, AcceptedPredecessorTuple, AppMissingCurrentRuntime,
}
fn check_data(value: CheckData) -> std::result::Result<(), ClassificationData> {
    match value {
        CheckData::Matches => Ok(()), CheckData::Unobserved => Err(ClassificationData::Unobserved),
        CheckData::Differs => Err(ClassificationData::Mismatch), CheckData::Unknown => Err(ClassificationData::Indeterminate),
    }
}
fn object_data(value: ObjectData<'_>) -> std::result::Result<(), ClassificationData> {
    match value {
        ObjectData::Unobserved => Err(ClassificationData::Unobserved),
        ObjectData::Unrelated => Err(ClassificationData::Occupied),
        ObjectData::LegacyV1 => Err(ClassificationData::LegacyUnsupported),
        ObjectData::Partial => Err(ClassificationData::Incomplete),
        ObjectData::Unknown => Err(ClassificationData::Indeterminate),
        ObjectData::Absent => Ok(()),
        ObjectData::Present { release, checks } => {
            if let Err(why) = release.validate() {
                return Err(if why == DataError::Legacy { ClassificationData::LegacyUnsupported }
                    else { ClassificationData::UnsupportedTuple });
            }
            check_data(checks.full_inventory)?; check_data(checks.signing_policy)?;
            check_data(checks.record_binding)
        }
    }
}
pub fn classify_data(expected: &ReleaseSetData, supplied: ObservationData<'_>) -> ClassificationData {
    for check in [supplied.protected_ancestry, supplied.prior_operation] {
        if let Err(why) = check_data(check) { return why; }
    }
    for object in [supplied.app, supplied.runtime] {
        if let Err(why) = object_data(object) { return why; }
    }
    match (supplied.app, supplied.runtime) {
        // Absence alone does not say "uninstalled", "fresh install allowed" or
        // settle any current/prior maintenance invocation.
        (ObjectData::Absent, ObjectData::Absent) => ClassificationData::FixedNamesAbsent,
        (ObjectData::Present { release: app, .. }, ObjectData::Present { release: runtime, .. }) => {
            if app != runtime {
                if expected.tuple_class(app) == ClassificationData::ReusedIdentity
                    || expected.tuple_class(runtime) == ClassificationData::ReusedIdentity {
                    ClassificationData::ReusedIdentity
                } else { ClassificationData::Contradictory }
            } else { expected.tuple_class(app) }
        }
        (ObjectData::Absent, ObjectData::Present { release, .. }) => match expected.tuple_class(release) {
            ClassificationData::ExactCurrentTuple => ClassificationData::AppMissingCurrentRuntime,
            ClassificationData::ReusedIdentity => ClassificationData::ReusedIdentity,
            _ => ClassificationData::UnsupportedTuple,
        },
        _ => ClassificationData::Incomplete,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionData { FreshInstall, SamePackageNoop, RestoreFixedApp, Update, Uninstall }
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum ReleaseReferenceData {
    Absent {},
    Release { #[serde(rename = "packageSha256")] package_sha256: String },
}
impl ReleaseReferenceData {
    fn digest(&self) -> Option<&str> {
        match self { Self::Absent {} => None, Self::Release { package_sha256 } => Some(package_sha256) }
    }
}
/// The binding portion of a future result, not its outcome or result channel.
/// Caller must independently select the actual current invocation and original
/// package/source/old/new observations. No RNG, path, read, status or replay
/// registry is provided; matching this DATA never establishes native finality.
#[derive(Debug, PartialEq, Eq)]
pub struct InvocationBindingData(InvocationWireData);
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvocationWireData {
    schema_version: u32, invocation: String, action: ActionData,
    package_sha256: String, source_commit: String,
    previous: ReleaseReferenceData, next: ReleaseReferenceData,
}
impl InvocationBindingData {
    pub fn parse_data(bytes: &[u8]) -> Result<Self> {
        let value: InvocationWireData = parse(bytes)?;
        require(value.schema_version == 2 && hex(&value.invocation, 32)
            && hex(&value.package_sha256, 64) && hex(&value.source_commit, 40), DataError::Binding)?;
        let old = value.previous.digest(); let new = value.next.digest();
        require([old, new].into_iter().flatten().all(|s| hex(s, 64)), DataError::Binding)?;
        let shape = match value.action {
            ActionData::FreshInstall => old.is_none() && new.is_some(),
            ActionData::SamePackageNoop | ActionData::RestoreFixedApp => old.is_some() && old == new,
            ActionData::Update => old.is_some() && new.is_some() && old != new,
            ActionData::Uninstall => old.is_some() && new.is_none(),
        };
        require(shape && (value.action == ActionData::Uninstall || new == Some(value.package_sha256.as_str())), DataError::Binding)?;
        Ok(Self(value))
    }
    /// `current` must not be obtained from the returned result or "latest" file.
    /// Equality is only binding correspondence, not single-use/currentness proof.
    pub fn matches_current_data(&self, current: &Self) -> bool { self == current }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    // Deliberately inert tuple DATA, not signed packages, descriptors or receipts.
    fn release(n: u32) -> Value { json!({
        "profile": PROFILE, "packageIdentifier": paths::PACKAGE_ID, "bundleIdentifier": paths::BUNDLE_ID,
        "packageVersion": format!("0.{n}.0"), "release": format!("macos26-arm64-data-{n}"),
        "sourceCommit": format!("{n:040x}"), "protocolSha256": "a".repeat(64),
        "runtimeManifestSha256": format!("{n:064x}"), "inventorySha256": format!("{:064x}", n + 20),
        "signingPolicySha256": "b".repeat(64), "packageSha256": format!("{:064x}", n + 40),
    }) }
    fn plan() -> Value { json!({"schemaVersion": 2, "current": release(3), "acceptedPredecessors": [release(2)]}) }
    fn bytes(value: &Value) -> Vec<u8> { serde_json::to_vec(value).unwrap() }
    fn parsed() -> ReleaseSetData { ReleaseSetData::parse_data(&bytes(&plan())).unwrap() }
    fn matching() -> ObjectChecksData { ObjectChecksData { full_inventory: CheckData::Matches,
        signing_policy: CheckData::Matches, record_binding: CheckData::Matches } }
    fn present(release: &ReleaseData) -> ObjectData<'_> { ObjectData::Present { release, checks: matching() } }
    fn observed<'a>(app: ObjectData<'a>, runtime: ObjectData<'a>) -> ObservationData<'a> {
        ObservationData { protected_ancestry: CheckData::Matches, prior_operation: CheckData::Matches, app, runtime }
    }
    #[test]
    fn release_data_is_closed_bounded_and_not_legacy() {
        assert_eq!(parsed().predecessor_data().len(), 1);
        for mutate in ["extra", "missing", "legacy-schema", "nested-extra", "legacy-release", "entry-engineering-release", "legacy-version", "foreign-profile"] {
            let mut value = plan();
            match mutate {
                "extra" => value["installed"] = json!(true),
                "missing" => { value.as_object_mut().unwrap().remove("acceptedPredecessors"); },
                "legacy-schema" => value["schemaVersion"] = json!(1),
                "nested-extra" => value["current"]["authenticated"] = json!(true),
                "legacy-release" => value["current"]["release"] = json!(LEGACY_RELEASE),
                "entry-engineering-release" => value["current"]["release"] = json!(ENTRY_ENGINEERING_RELEASE),
                "legacy-version" => value["current"]["packageVersion"] = json!(LEGACY_VERSION),
                _ => value["current"]["profile"] = json!("fixed-windows"),
            }
            assert!(ReleaseSetData::parse_data(&bytes(&value)).is_err(), "{mutate}");
        }
        let duplicate = String::from_utf8(bytes(&plan())).unwrap().replacen('{', "{\"schemaVersion\":2,", 1);
        assert!(ReleaseSetData::parse_data(duplicate.as_bytes()).is_err());
        assert!(ReleaseSetData::parse_data(b"{\"schemaVersion\":NaN}").is_err());
        assert!(ReleaseSetData::parse_data(&vec![b' '; INPUT_LIMIT + 1]).is_err());
        let mut many = plan(); many["acceptedPredecessors"] = json!(vec![release(2); PREDECESSOR_LIMIT + 1]);
        assert!(ReleaseSetData::parse_data(&bytes(&many)).is_err());
    }
    #[test]
    fn release_ids_versions_and_complete_package_bytes_cannot_be_reused() {
        for field in ["release", "packageVersion", "packageSha256"] {
            let mut value = plan(); value["acceptedPredecessors"][0][field] = value["current"][field].clone();
            assert!(matches!(ReleaseSetData::parse_data(&bytes(&value)), Err(DataError::ReusedIdentity)));
        }
        let mut duplicate = plan(); duplicate["acceptedPredecessors"] = json!([release(2), release(2)]);
        assert!(ReleaseSetData::parse_data(&bytes(&duplicate)).is_err());
        let mut newer = plan(); newer["acceptedPredecessors"] = json!([release(4)]);
        assert!(ReleaseSetData::parse_data(&bytes(&newer)).is_err());
        let mut numeric = plan(); numeric["acceptedPredecessors"][0]["packageVersion"] = json!("0.10.0");
        assert!(ReleaseSetData::parse_data(&bytes(&numeric)).is_err());
        for invalid in ["../macos26-arm64-data", "macos26-arm64-", "macos26-arm64-data/other", "macos26-arm64-data."] {
            let mut value = plan(); value["current"]["release"] = json!(invalid);
            assert!(ReleaseSetData::parse_data(&bytes(&value)).is_err());
        }
        for invalid in ["01.2.0", "1.2", "1.2.3.4", "1.2.-1", "4294967296.1.0"] {
            let mut value = plan(); value["current"]["packageVersion"] = json!(invalid);
            assert!(ReleaseSetData::parse_data(&bytes(&value)).is_err());
        }
        for field in ["sourceCommit", "protocolSha256", "runtimeManifestSha256", "inventorySha256", "signingPolicySha256", "packageSha256"] {
            for invalid in ["".to_owned(), "0".repeat(if field == "sourceCommit" { 40 } else { 64 }), "G".repeat(64)] {
                let mut value = plan(); value["current"][field] = json!(invalid);
                assert!(ReleaseSetData::parse_data(&bytes(&value)).is_err(), "{field}");
            }
        }
    }
    #[test]
    fn classifier_requires_the_entire_explicit_current_or_predecessor_tuple() {
        let plan = parsed(); let current = plan.current_data(); let old = &plan.predecessor_data()[0];
        assert_eq!(classify_data(&plan, observed(ObjectData::Absent, ObjectData::Absent)), ClassificationData::FixedNamesAbsent);
        assert_eq!(classify_data(&plan, observed(present(current), present(current))), ClassificationData::ExactCurrentTuple);
        assert_eq!(classify_data(&plan, observed(present(old), present(old))), ClassificationData::AcceptedPredecessorTuple);
        assert_eq!(classify_data(&plan, observed(ObjectData::Absent, present(current))), ClassificationData::AppMissingCurrentRuntime);
        assert_eq!(classify_data(&plan, observed(ObjectData::Absent, present(old))), ClassificationData::UnsupportedTuple);
        assert_eq!(classify_data(&plan, observed(present(current), ObjectData::Absent)), ClassificationData::Incomplete);
        assert_eq!(classify_data(&plan, observed(present(old), present(current))), ClassificationData::Contradictory);
        let unrelated: ReleaseData = serde_json::from_value(release(4)).unwrap();
        assert_eq!(classify_data(&plan, observed(present(&unrelated), present(&unrelated))), ClassificationData::UnsupportedTuple);
    }
    #[test]
    fn changed_bytes_or_signing_policy_never_become_same_package_data() {
        let plan = parsed();
        for field in ["sourceCommit", "protocolSha256", "runtimeManifestSha256", "inventorySha256", "signingPolicySha256", "packageSha256"] {
            let mut value = release(3); value[field] = json!("c".repeat(if field == "sourceCommit" { 40 } else { 64 }));
            let changed: ReleaseData = serde_json::from_value(value).unwrap();
            assert_eq!(classify_data(&plan, observed(present(&changed), present(&changed))), ClassificationData::ReusedIdentity, "{field}");
            assert_eq!(classify_data(&plan, observed(present(plan.current_data()), present(&changed))), ClassificationData::ReusedIdentity);
        }
    }
    #[test]
    fn missing_proof_partial_unknown_occupants_and_legacy_are_not_positive() {
        let plan = parsed(); let current = plan.current_data();
        for (check, expected) in [(CheckData::Unobserved, ClassificationData::Unobserved),
            (CheckData::Differs, ClassificationData::Mismatch), (CheckData::Unknown, ClassificationData::Indeterminate)] {
            let mut value = observed(present(current), present(current)); value.protected_ancestry = check;
            assert_eq!(classify_data(&plan, value), expected);
            let mut value = observed(present(current), present(current)); value.prior_operation = check;
            assert_eq!(classify_data(&plan, value), expected);
            for field in 0..3 {
                let mut checks = matching();
                match field { 0 => checks.full_inventory = check, 1 => checks.signing_policy = check, _ => checks.record_binding = check }
                assert_eq!(classify_data(&plan, observed(ObjectData::Present { release: current, checks }, present(current))), expected);
            }
        }
        for (object, expected) in [(ObjectData::Unobserved, ClassificationData::Unobserved),
            (ObjectData::Unknown, ClassificationData::Indeterminate), (ObjectData::Unrelated, ClassificationData::Occupied),
            (ObjectData::LegacyV1, ClassificationData::LegacyUnsupported), (ObjectData::Partial, ClassificationData::Incomplete)] {
            assert_eq!(classify_data(&plan, observed(object, present(current))), expected);
            assert_eq!(classify_data(&plan, observed(present(current), object)), expected);
        }
    }
    fn invocation() -> Value { json!({"schemaVersion": 2, "invocation": "1".repeat(32), "action": "update",
        "packageSha256": "2".repeat(64), "sourceCommit": "3".repeat(40),
        "previous": {"state": "release", "packageSha256": "4".repeat(64)},
        "next": {"state": "release", "packageSha256": "2".repeat(64)}}) }
    #[test]
    fn invocation_binding_rejects_stale_wrong_action_package_source_or_tuple_data() {
        let current = InvocationBindingData::parse_data(&bytes(&invocation())).unwrap();
        assert!(InvocationBindingData::parse_data(&bytes(&invocation())).unwrap().matches_current_data(&current));
        for field in ["invocation", "packageSha256", "sourceCommit", "previous", "next", "action"] {
            let mut value = invocation();
            match field {
                "previous" => value[field]["packageSha256"] = json!("5".repeat(64)),
                "next" => { value[field]["packageSha256"] = json!("5".repeat(64)); value["packageSha256"] = json!("5".repeat(64)); },
                "action" => { value[field] = json!("fresh-install"); value["previous"] = json!({"state": "absent"}); },
                "packageSha256" => value[field] = json!("5".repeat(64)),
                _ => value[field] = json!("5".repeat(if field == "invocation" { 32 } else { 40 })),
            }
            if let Ok(other) = InvocationBindingData::parse_data(&bytes(&value)) { assert!(!other.matches_current_data(&current), "{field}"); }
        }
    }
    #[test]
    fn invocation_shape_is_closed_and_cannot_adopt_legacy_or_invent_missing_fields() {
        for action in ["fresh-install", "same-package-noop", "restore-fixed-app", "update", "uninstall"] {
            let mut value = invocation(); value["action"] = json!(action);
            match action {
                "fresh-install" => value["previous"] = json!({"state": "absent"}),
                "same-package-noop" | "restore-fixed-app" => value["previous"] = value["next"].clone(),
                "uninstall" => value["next"] = json!({"state": "absent"}), _ => {},
            }
            assert!(InvocationBindingData::parse_data(&bytes(&value)).is_ok(), "{action}");
        }
        for field in ["schemaVersion", "invocation", "action", "packageSha256", "sourceCommit", "previous", "next"] {
            let mut value = invocation(); value.as_object_mut().unwrap().remove(field);
            assert!(InvocationBindingData::parse_data(&bytes(&value)).is_err(), "{field}");
        }
        for mutate in ["v1", "success", "nested-extra", "absent-extra", "next-absent-extra", "zero-id", "same-byte-update", "wrong-noop", "old-absent-uninstall"] {
            let mut value = invocation();
            match mutate {
                "v1" => value["schemaVersion"] = json!(1), "success" => value["installed"] = json!(true),
                "nested-extra" => value["previous"]["authenticated"] = json!(true),
                "absent-extra" => { value["action"] = json!("fresh-install"); value["previous"]["state"] = json!("absent"); },
                "next-absent-extra" => { value["action"] = json!("uninstall"); value["next"]["state"] = json!("absent"); },
                "zero-id" => value["invocation"] = json!("0".repeat(32)),
                "same-byte-update" => value["previous"] = value["next"].clone(),
                "wrong-noop" => value["action"] = json!("same-package-noop"),
                _ => { value["action"] = json!("uninstall"); value["previous"] = json!({"state": "absent"}); value["next"] = json!({"state": "absent"}); },
            }
            assert!(InvocationBindingData::parse_data(&bytes(&value)).is_err(), "{mutate}");
        }
    }
}
