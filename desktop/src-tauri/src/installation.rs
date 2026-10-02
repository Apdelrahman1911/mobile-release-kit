//! Installation location DATA and one fixed Finder request. No maintenance,
//! runtime selection, package execution, filesystem mutation or signing claim.
use serde::Serialize;
use serde_json::Value;
use crate::error::BridgeError;

pub(crate) const NORMAL_MAC_PROFILE: bool = cfg!(all(
    target_os = "macos", target_arch = "aarch64",
    feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer")
));

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub layout: &'static str,
    pub expected_location: &'static str,
    pub runtime_release: &'static str,
    pub install_mode: &'static str,
    pub maintenance: &'static str,
    pub reveal_available: bool,
    pub assurance: &'static str,
}
pub(crate) fn reveal_profile_available(runtime_profile: bool) -> bool {
    NORMAL_MAC_PROFILE && runtime_profile
}
pub(crate) fn description(reveal_available: bool) -> Option<Description> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    if NORMAL_MAC_PROFILE {
        return Some(Description {
            layout: "fixed-macos", expected_location: crate::macos_install_paths::APP,
            runtime_release: crate::macos_install_paths::RELEASE,
            install_mode: "fresh-only", maintenance: "unavailable",
            reveal_available, assurance: "profile-description-only",
        });
    }
    let _ = reveal_available;
    None
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealRequestSent {
    pub state: &'static str,
    pub finder_visibility: &'static str,
}
pub(crate) fn request_sent() -> RevealRequestSent {
    RevealRequestSent { state: "request-sent", finder_visibility: "unconfirmed" }
}
pub(crate) fn reveal_request(value: &Value) -> Result<(), BridgeError> {
    if value.as_object().is_some_and(|body| body.is_empty()) { Ok(()) }
    else { Err(BridgeError::invalid()) }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("installation_reveal_unavailable", "Show in Finder requires the normal installed macOS application profile.")
}
pub(crate) fn unconfirmed() -> BridgeError {
    BridgeError::new("installation_reveal_unconfirmed", "The Finder request could not be confirmed. No automatic retry was started.")
}


#[cfg(test)]
pub(crate) fn assert_installation_description_contract() {
    use serde_json::json;
    assert!(!reveal_profile_available(false));
    assert_eq!(reveal_profile_available(true), NORMAL_MAC_PROFILE);
    for available in [false, true] {
        let value = serde_json::to_value(description(available)).unwrap();
        if NORMAL_MAC_PROFILE {
            assert_eq!(value["layout"], "fixed-macos");
            assert_eq!(value["installMode"], "fresh-only");
            assert_eq!(value["maintenance"], "unavailable");
            assert_eq!(value["assurance"], "profile-description-only");
            assert_eq!(value["revealAvailable"], available);
            assert!(value.get("installed").is_none() && value.get("verified").is_none());
        } else { assert!(value.is_null()); }
    }
    assert_eq!(serde_json::to_value(request_sent()).unwrap(),
        json!({"state":"request-sent","finderVisibility":"unconfirmed"}));
}

#[cfg(test)]
pub(crate) fn assert_installation_reveal_request_contract() {
    use serde_json::json;
    assert!(reveal_request(&json!({})).is_ok());
    for value in [Value::Null, json!([]), json!(""), json!(false), json!(0),
        json!({"path":"/private/other.app"}), json!({"url":"file:///elsewhere"}),
        json!({"command":"open"}), json!({"profile":"macos"}), json!({"args":{}})] {
        assert_eq!(reveal_request(&value).unwrap_err().code, "invalid_request");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn installation_description_never_grants_maintenance_or_verification() { super::assert_installation_description_contract(); }
    #[test]
    fn installation_reveal_accepts_only_an_empty_object() { super::assert_installation_reveal_request_contract(); }
}

// Explicit read-only observation. These closed DATA types never select a
// runtime, prove historical Installer finality or grant maintenance authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckPhase { NotChecked, Checking, Stopping, Observed, Refused, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckReason {
    None, UnavailableProfile, Busy, DocumentUnavailable, WrongLocation, Missing,
    Incomplete, RecordMismatch, PayloadMismatch, Protection, Bounds, Native,
    Cancelled, Deadline, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckSettlement { NotStarted, Pending, Known, Unknown, LateKnown }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Matching {
    pub(crate) files: u32, pub(crate) bytes: u64,
    assurance: &'static str, maintenance: &'static str,
}
impl Matching {
    pub(crate) fn checked(files: usize, bytes: u64) -> Option<Self> {
        (files > 0 && files <= crate::macos_install_record::FILE_LIMIT
            && bytes <= crate::macos_install_record::PAYLOAD_LIMIT).then_some(Self {
                files: u32::try_from(files).ok()?, bytes,
                assurance: "read-only-correspondence", maintenance: "unavailable",
            })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckStatus {
    pub(crate) schema_version: u8, pub(crate) status_revision: u32,
    pub(crate) available: bool, pub(crate) can_start: bool,
    pub(crate) operation_id: Option<u32>, pub(crate) phase: CheckPhase,
    pub(crate) reason: CheckReason, pub(crate) settlement: CheckSettlement,
    pub(crate) assessment: Option<Matching>,
}
impl CheckStatus {
    pub(crate) fn initial(revision: u32, available: bool, can_start: bool) -> Self {
        Self { schema_version: 1, status_revision: revision, available,
            can_start: available && can_start, operation_id: None, phase: CheckPhase::NotChecked,
            reason: if available { CheckReason::None } else { CheckReason::UnavailableProfile },
            settlement: CheckSettlement::NotStarted, assessment: None }
    }
    pub(crate) fn invalidate(&mut self, reason: CheckReason) {
        self.can_start = false; self.assessment = None;
        if self.operation_id.is_some() {
            self.phase = CheckPhase::Unknown; self.reason = reason;
            // Previously known cleanup is not forgotten, but never republished
            // as successful work after the document's original authority died.
            self.settlement = if matches!(self.settlement, CheckSettlement::Known | CheckSettlement::LateKnown) {
                CheckSettlement::LateKnown
            } else { CheckSettlement::Unknown };
        } else { self.reason = reason; }
    }
}
pub(crate) fn inspect_profile_available(runtime_profile: bool) -> bool {
    fn hex(value: Option<&str>, length: usize) -> bool {
        value.is_some_and(|v| v.len() == length && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    }
    NORMAL_MAC_PROFILE && runtime_profile
        && hex(option_env!("MRK_MACOS_INSTALL_SOURCE_COMMIT"), 40)
        && hex(option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"), 64)
        && option_env!("MRK_BUNDLED_PROTOCOL_SHA256") == Some(crate::macos_install_paths::PROTOCOL_SHA)
}
pub(crate) fn inspect_request(value: &Value) -> Result<(), BridgeError> { reveal_request(value) }
pub(crate) fn cancel_inspection_request(value: &Value) -> Result<u32, BridgeError> {
    let body = value.as_object().filter(|body| body.len() == 1 && body.contains_key("operationId")).ok_or_else(BridgeError::invalid)?;
    body.get("operationId").and_then(Value::as_u64).and_then(|id| u32::try_from(id).ok()).filter(|id| *id > 0)
        .ok_or_else(BridgeError::invalid)
}
pub(crate) fn inspection_unavailable() -> BridgeError {
    BridgeError::new("installation_check_unavailable",
        "Installation checking requires the normal installed macOS app and its explicit package source bindings.")
}
pub(crate) fn inspection_busy() -> BridgeError {
    BridgeError::new("installation_check_busy", "Finish or cancel the original native operation before checking this installation.")
}

#[cfg(test)]
pub(crate) fn assert_installation_inspection_wire_contract() {
    use serde_json::json;
    assert!(inspect_request(&json!({})).is_ok());
    for value in [Value::Null, json!([]), json!({"path":"/elsewhere"}), json!({"operationId":1})] {
        assert!(inspect_request(&value).is_err());
    }
    assert_eq!(cancel_inspection_request(&json!({"operationId":1})).unwrap(), 1);
    assert_eq!(cancel_inspection_request(&json!({"operationId":u32::MAX})).unwrap(), u32::MAX);
    for value in [Value::Null, json!({}), json!({"operationId":0}), json!({"operationId":-1}),
        json!({"operationId":1.5}), json!({"operationId":u64::from(u32::MAX)+1}),
        json!({"operationId":"1"}), json!({"operationId":1,"path":"/elsewhere"})] {
        assert!(cancel_inspection_request(&value).is_err());
    }
    let mut status = CheckStatus::initial(7, true, true);
    assert!(status.assessment.is_none() && status.operation_id.is_none());
    assert!(Matching::checked(0, 0).is_none());
    assert!(Matching::checked(crate::macos_install_record::FILE_LIMIT + 1, 0).is_none());
    assert!(Matching::checked(1, crate::macos_install_record::PAYLOAD_LIMIT + 1).is_none());
    status.operation_id = Some(1); status.phase = CheckPhase::Observed;
    status.settlement = CheckSettlement::Known; status.assessment = Matching::checked(1, 7);
    let value = serde_json::to_value(status).unwrap();
    assert_eq!(value["assessment"]["assurance"], "read-only-correspondence");
    assert_eq!(value["assessment"]["maintenance"], "unavailable");
    assert!(value.get("installed").is_none() && value.get("verified").is_none());
    status.invalidate(CheckReason::DocumentUnavailable);
    assert_eq!(status.phase, CheckPhase::Unknown);
    assert_eq!(status.settlement, CheckSettlement::LateKnown);
    assert!(status.assessment.is_none() && !status.can_start);
}

#[cfg(test)]
#[test]
fn installation_inspection_rejects_paths_and_ambiguous_results() { assert_installation_inspection_wire_contract(); }
