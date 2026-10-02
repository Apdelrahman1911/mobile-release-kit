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
