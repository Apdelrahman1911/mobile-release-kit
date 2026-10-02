//! Protected Android catalog comparison DATA. These records never grant runtime,
//! filesystem, tool qualification or a renderer-selected root/account capability.
use serde::{Deserialize, Serialize};
use crate::{android_build_protocol::{Availability, MacToolchainSelection},
    error::BridgeError, protocol::strict_json};

pub(crate) const EVENT: &str = "android-toolchain-catalog-state-changed";
pub(crate) const ENTRY_LIMIT: usize = 16;
pub(crate) const REQUEST_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 32 * 1024;
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Versions {
    pub(crate) jdk_vendor: String, pub(crate) jdk_version: String,
    pub(crate) gradle_version: String, pub(crate) agp_version: String,
    pub(crate) sdk_platform: String, pub(crate) sdk_build_tools_version: String,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) selection: MacToolchainSelection,
    pub(crate) versions: Versions,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Idle, Reading, Stopping, Ready, Refused, Cancelled, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, NotInspected, Cancelled, TimedOut, DocumentLost, Shutdown,
    CatalogChanged, CatalogUnavailable, CleanupUnknown }
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32,
    pub(crate) catalog_generation: u32, pub(crate) operation_id: Option<String>,
    pub(crate) availability: Availability, pub(crate) phase: Phase,
    pub(crate) reason: Reason, pub(crate) entries: Vec<Entry>,
    pub(crate) selected: Option<MacToolchainSelection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Select {
    pub(crate) schema_version: u32, pub(crate) catalog_generation: u32,
    pub(crate) instance: String, pub(crate) record_sha256: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel {
    pub(crate) schema_version: u32, pub(crate) catalog_generation: u32,
    pub(crate) operation_id: String,
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("android_catalog_invalid", "This request does not identify the current protected Android tool catalog.")
}
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_catalog_unavailable", "Protected Android tool copies cannot be read in the current original document and host.")
}
pub(crate) fn parse_empty(value: &[u8]) -> Result<(), BridgeError> {
    if value.len() > REQUEST_LIMIT { return Err(invalid()); }
    let object = strict_json(value).map_err(|_| invalid())?;
    if object.as_object().is_some_and(|o| o.len() == 1 && o.get("schemaVersion").and_then(serde_json::Value::as_u64) == Some(1)) {
        Ok(())
    } else { Err(invalid()) }
}
impl Select {
    pub(crate) fn parse(value: &[u8]) -> Result<Self, BridgeError> {
        if value.len() > REQUEST_LIMIT { return Err(invalid()); }
        let item: Self = serde_json::from_value(strict_json(value).map_err(|_| invalid())?).map_err(|_| invalid())?;
        if item.schema_version != 1 || item.catalog_generation == 0 || item.catalog_generation == u32::MAX
            || !lower_hex(&item.instance, 32) || !lower_hex(&item.record_sha256, 64) { return Err(invalid()); }
        Ok(item)
    }
    pub(crate) fn matches(&self, entry: &Entry) -> bool {
        self.schema_version == 1 && self.catalog_generation == entry.selection.catalog_generation
            && self.instance == entry.selection.instance && self.record_sha256 == entry.selection.record_sha256
    }
}
impl Cancel {
    pub(crate) fn parse(value: &[u8]) -> Result<Self, BridgeError> {
        if value.len() > REQUEST_LIMIT { return Err(invalid()); }
        let item: Self = serde_json::from_value(strict_json(value).map_err(|_| invalid())?).map_err(|_| invalid())?;
        if item.schema_version != 1 || item.catalog_generation == 0 || item.catalog_generation == u32::MAX
            || !lower_hex(&item.operation_id, 32) { return Err(invalid()); }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn catalog_selection_has_no_renderer_path_account_or_qualification_authority_data() {
        let good = serde_json::json!({"schemaVersion":1,"catalogGeneration":2,"instance":"ab".repeat(16),"recordSha256":"cd".repeat(32)});
        assert!(Select::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (field, value) in [("root",serde_json::json!("/tmp/tools")),("ownerUid",serde_json::json!(501)),
            ("qualified",serde_json::json!(true)),("catalogGeneration",serde_json::json!(0))] {
            let mut changed=good.clone(); changed[field]=value;
            assert!(Select::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        assert!(parse_empty(br#"{"schemaVersion":1}"#).is_ok());
        assert!(parse_empty(br#"{"schemaVersion":1,"schemaVersion":1}"#).is_err());
        assert!(parse_empty(br#"{"schemaVersion":1,"path":"/tmp/tools"}"#).is_err());
    }
    #[test]
    fn catalog_selection_has_no_renderer_path_account_or_qualification_authority() { catalog_selection_has_no_renderer_path_account_or_qualification_authority_data(); }

}

// Explicit harness=false DATA bridge; ordinary libtest wrappers use these same
// inert bodies. No native custody, task, Prepare/Start or qualification is granted.
#[cfg(test)]
pub(crate) fn assert_catalog_data_contract() {
    tests::catalog_selection_has_no_renderer_path_account_or_qualification_authority_data();
}
