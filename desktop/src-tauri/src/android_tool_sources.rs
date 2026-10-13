//! Native-folder selection DATA for Android registration. A picked folder is not
//! a supplier inventory, executable tool approval, protected copy or build lease.
use serde::{Deserialize, Serialize};
use crate::{android_build_protocol::Availability, error::BridgeError, protocol::{strict_json, valid_id}};
pub(crate) const EVENT: &str = "android-tool-sources-state-changed";
pub(crate) const REQUEST_LIMIT: usize = 1024;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role { Jdk, Sdk, Gradle }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Idle, Picking, Checking, Selected, Refused, Cancelled, Stopping, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, NotInspected, Cancelled, SourceRefused, SourceChanged, TimedOut,
    ContextChanged, DocumentLost, Shutdown, CleanupUnknown }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Selection { pub(crate) role: Role, pub(crate) display_name: String }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) operation_id: u32, pub(crate) source_generation: u32, pub(crate) role: Role }
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) source_generation: u32,
    pub(crate) project_id: Option<String>, pub(crate) availability: Availability, pub(crate) phase: Phase,
    pub(crate) reason: Reason, pub(crate) operation: Option<Operation>, pub(crate) selections: Vec<Selection>,
    pub(crate) inspection: &'static str, pub(crate) protected_copy: &'static str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Choose {
    pub(crate) schema_version: u32, pub(crate) source_generation: u32,
    pub(crate) project_id: String, pub(crate) role: Role,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel {
    pub(crate) schema_version: u32, pub(crate) source_generation: u32, pub(crate) operation_id: u32,
}
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("android_sources_invalid", "The request does not identify the original Android tool selection.")
}
// Refine only the effective Document/publisher gate before the existing owner
// snapshots its capability/revision. A selector cannot promote any denial, and
// returned Status DATA is never patched into a new capability afterwards.
pub(crate) fn status_availability(gate: Availability, source_selection_available: bool) -> Availability {
    match (gate, source_selection_available) {
        (Availability::Available, false) => Availability::RuntimeUnqualified,
        _ => gate,
    }
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_sources_unavailable", "Android tool folder selection is unavailable in this document and desktop profile.")
}
pub(crate) fn parse_empty(raw: &[u8]) -> Result<(), BridgeError> {
    if raw.len() > REQUEST_LIMIT { return Err(invalid()); }
    let item = strict_json(raw).map_err(|_| invalid())?;
    if item.as_object().is_some_and(|o| o.len() == 1 && o.get("schemaVersion").and_then(serde_json::Value::as_u64) == Some(1)) { Ok(()) }
    else { Err(invalid()) }
}
impl Choose {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        if raw.len() > REQUEST_LIMIT { return Err(invalid()); }
        let item: Self = serde_json::from_value(strict_json(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
        if item.schema_version != 1 || item.source_generation == u32::MAX || !valid_id(&item.project_id) { return Err(invalid()); }
        Ok(item)
    }
}
impl Cancel {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        if raw.len() > REQUEST_LIMIT { return Err(invalid()); }
        let item: Self = serde_json::from_value(strict_json(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
        if item.schema_version != 1 || item.source_generation == 0 || item.source_generation == u32::MAX
            || item.operation_id == 0 || item.operation_id == u32::MAX { return Err(invalid()); }
        Ok(item)
    }
}
pub(crate) fn reason(reason: crate::asset_commands::Reason) -> Reason {
    use crate::asset_commands::Reason as A;
    match reason {
        A::None => Reason::None, A::UserCancelled => Reason::Cancelled,
        A::SourceChanged => Reason::SourceChanged, A::ContextStale => Reason::ContextChanged,
        A::Deadline | A::ReviewExpired => Reason::TimedOut, A::DocumentLost => Reason::DocumentLost,
        A::Shutdown => Reason::Shutdown, A::CleanupUnknown => Reason::CleanupUnknown, _ => Reason::SourceRefused,
    }
}
pub(crate) fn display_name(path: &std::path::Path) -> String {
    let value = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    if value.is_empty() || value.len() > 128 || value.chars().any(|c| c.is_control() || matches!(c, '/' | '\\')
        || ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)) {
        "Selected folder".into()
    } else { value.to_owned() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_accepts_only_closed_roles_and_comparison_not_paths_or_account_authority() {
        let good = serde_json::json!({"schemaVersion":1,"sourceGeneration":0,"projectId":"project-a","role":"jdk"});
        assert!(Choose::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (field, value) in [("path",serde_json::json!("/private/user/jdk")), ("uid",serde_json::json!(501)),
            ("qualified",serde_json::json!(true)), ("role",serde_json::json!("shell")), ("sourceGeneration",serde_json::json!(u32::MAX))] {
            let mut bad=good.clone(); bad[field]=value; assert!(Choose::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(parse_empty(br#"{"schemaVersion":1,"schemaVersion":1}"#).is_err());
        assert!(Cancel::parse(br#"{"schemaVersion":1,"sourceGeneration":0,"operationId":1}"#).is_err());
    }
    #[test]
    fn status_selector_only_demotes_available_with_an_unqualified_source_picker() {
        use Availability::*;
        // Independent 8 x 2 oracle: all seven existing denials survive BOTH
        // selector values. The one available/unqualified cell alone changes.
        let cases = [
            (Available, RuntimeUnqualified, Available),
            (Busy, Busy, Busy),
            (Shutdown, Shutdown, Shutdown),
            (CleanupUnknown, CleanupUnknown, CleanupUnknown),
            (DocumentLost, DocumentLost, DocumentLost),
            (UnsupportedPlatform, UnsupportedPlatform, UnsupportedPlatform),
            (RuntimeUnqualified, RuntimeUnqualified, RuntimeUnqualified),
            (ToolchainUnqualified, ToolchainUnqualified, ToolchainUnqualified),
        ];
        for (gate, unqualified, qualified) in cases {
            assert_eq!(status_availability(gate, false), unqualified);
            assert_eq!(status_availability(gate, true), qualified);
        }
    }
    #[test]
    fn display_data_never_contains_parent_path_or_control_direction_text() {
        assert_eq!(display_name(std::path::Path::new("/private/account/jdk-17.jdk")), "jdk-17.jdk");
        assert_eq!(display_name(std::path::Path::new("/private/account/bad\nname")), "Selected folder");
        assert_eq!(display_name(std::path::Path::new("/private/account/\u{202e}txt")), "Selected folder");
    }
}
