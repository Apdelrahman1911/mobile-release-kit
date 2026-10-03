//! Protected Android catalog comparison DATA. These records never grant runtime,
//! filesystem, tool qualification or a renderer-selected root/account capability.
use serde::{Deserialize, Serialize};
use crate::{android_build_protocol::{Availability, MacToolchainSelection},
    error::BridgeError, protocol::strict_json};

pub(crate) const EVENT: &str = "android-toolchain-catalog-state-changed";
pub(crate) const ENTRY_LIMIT: usize = 32;
pub(crate) const REQUEST_LIMIT: usize = 1024;
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Versions {
    pub(crate) jdk_vendor: String, pub(crate) jdk_version: String,
    pub(crate) gradle_version: String, pub(crate) agp_version: String,
    pub(crate) sdk_platform: String, pub(crate) sdk_build_tools_version: String,
}
impl Versions {
    fn valid(&self)->bool{
        [&self.jdk_vendor,&self.jdk_version,&self.gradle_version,&self.agp_version,
            &self.sdk_platform,&self.sdk_build_tools_version].iter().all(|s|
                !s.is_empty() && s.len()<=128 && s.bytes().all(|b|
                    b.is_ascii_alphanumeric() || b" ._+()-".contains(&b)))
    }
}
/// Existing low-level reader DATA, NOT a public catalog row or selection grant.
/// M2's owner publishes only Row after its genuine original final join.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) selection: MacToolchainSelection,
    pub(crate) versions: Versions,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Comparison {
    pub(crate) catalog_generation:u32,pub(crate) instance:String,
    pub(crate) record_sha256:String,pub(crate) inventory_sha256:String,pub(crate) os_provider_sha256:String,
}
impl Comparison {
    pub(crate) fn of(selected:&MacToolchainSelection)->Self{
        Self{catalog_generation:selected.catalog_generation,instance:selected.instance.clone(),
            record_sha256:selected.record_sha256.clone(),inventory_sha256:selected.inventory_sha256.clone(),
            os_provider_sha256:selected.os_provider_sha256.clone()}
    }
    fn valid(&self,generation:u32,instance:&str)->bool{
        generation>0 && generation<u32::MAX && self.catalog_generation==generation
            && self.instance==instance && lower_hex(&self.instance,32)
            && [&self.record_sha256,&self.inventory_sha256,&self.os_provider_sha256]
                .iter().all(|h|lower_hex(h,64))
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RowStatus { Busy, Interrupted, Refused, RecoveryRequired, VerifiedThisSession }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Row {
    pub(crate) instance:String,
    // Scan UNION only: bit1 destination, bit2 lease, bit4 private intent-root.
    // This is NOT intent Presence's destination/stage/quarantine mask.
    pub(crate) occupants:u8,pub(crate) status:RowStatus,
    pub(crate) versions:Option<Versions>,pub(crate) recovery:Option<Comparison>,
    // Present only for an actually finalized full Recover. Native retains and
    // compares the original complete selection; caller requests accept no UID.
    pub(crate) selection:Option<MacToolchainSelection>,
}
impl Row {
    pub(crate) fn valid(&self,generation:u32)->bool{
        if !lower_hex(&self.instance,32) || !(1..=7).contains(&self.occupants){return false;}
        match self.status {
            RowStatus::Busy|RowStatus::Interrupted|RowStatus::Refused =>
                self.versions.is_none() && self.recovery.is_none() && self.selection.is_none(),
            RowStatus::RecoveryRequired =>
                self.versions.as_ref().is_some_and(Versions::valid) && self.selection.is_none()
                    && self.recovery.as_ref().is_some_and(|v|v.valid(generation,&self.instance)),
            RowStatus::VerifiedThisSession =>
                self.versions.as_ref().is_some_and(Versions::valid) && self.recovery.is_none()
                    && self.selection.as_ref().is_some_and(|v|v.valid()
                        && v.catalog_generation==generation && v.instance==self.instance),
        }
    }
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
    pub(crate) reason: Reason, pub(crate) entries: Vec<Row>,
    pub(crate) selected: Option<MacToolchainSelection>,
}
/// Same bounded comparison shape, but two distinct native commands. Recover
/// accepts only recovery rows; Choose accepts only finalized verified rows.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Compare {
    pub(crate) schema_version: u32, pub(crate) catalog_generation: u32,
    pub(crate) instance: String, pub(crate) record_sha256: String,
    pub(crate) inventory_sha256:String,pub(crate) os_provider_sha256:String,
}
pub(crate) type Select=Compare;
pub(crate) type Recover=Compare;
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
impl Compare {
    pub(crate) fn parse(value: &[u8]) -> Result<Self, BridgeError> {
        if value.len() > REQUEST_LIMIT { return Err(invalid()); }
        let item: Self = serde_json::from_value(strict_json(value).map_err(|_| invalid())?).map_err(|_| invalid())?;
        if item.schema_version != 1 || item.catalog_generation == 0 || item.catalog_generation == u32::MAX
            || !lower_hex(&item.instance, 32)
            || [&item.record_sha256,&item.inventory_sha256,&item.os_provider_sha256].iter().any(|h|!lower_hex(h,64)) {return Err(invalid());}
        Ok(item)
    }
    fn matches_comparison(&self,value:&Comparison)->bool{
        self.schema_version==1 && self.catalog_generation==value.catalog_generation && self.instance==value.instance
            && self.record_sha256==value.record_sha256 && self.inventory_sha256==value.inventory_sha256
            && self.os_provider_sha256==value.os_provider_sha256
    }
    pub(crate) fn matches_selection(&self,value:&MacToolchainSelection)->bool{
        value.valid() && self.schema_version==1 && self.catalog_generation==value.catalog_generation && self.instance==value.instance
            && self.record_sha256==value.record_sha256 && self.inventory_sha256==value.inventory_sha256
            && self.os_provider_sha256==value.os_provider_sha256
    }
    pub(crate) fn matches(&self,entry:&Row)->bool{
        entry.status==RowStatus::VerifiedThisSession && entry.valid(self.catalog_generation)
            && entry.selection.as_ref().is_some_and(|v|self.matches_selection(v))
    }
    pub(crate) fn matches_recovery(&self,entry:&Row)->bool{
        entry.status==RowStatus::RecoveryRequired && entry.valid(self.catalog_generation)
            && entry.recovery.as_ref().is_some_and(|v|self.matches_comparison(v))
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
        let good=serde_json::json!({"schemaVersion":1,"catalogGeneration":2,"instance":"ab".repeat(16),
            "recordSha256":"cd".repeat(32),"inventorySha256":"ef".repeat(32),"osProviderSha256":"12".repeat(32)});
        let input=Select::parse(&serde_json::to_vec(&good).unwrap()).unwrap();
        for (field,value) in [("root",serde_json::json!("/tmp/tools")),("ownerUid",serde_json::json!(501)),
            ("qualified",serde_json::json!(true)),("catalogGeneration",serde_json::json!(0))] {
            let mut changed=good.clone();changed[field]=value;
            assert!(Select::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
            assert!(Recover::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let selected=MacToolchainSelection{catalog_generation:2,instance:"ab".repeat(16),owner_uid:501,
            record_sha256:"cd".repeat(32),inventory_sha256:"ef".repeat(32),os_provider_sha256:"12".repeat(32)};
        let versions=Versions{jdk_vendor:"Example".into(),jdk_version:"21".into(),gradle_version:"8.13".into(),
            agp_version:"8.9.2".into(),sdk_platform:"35".into(),sdk_build_tools_version:"35.0.0".into()};
        let mut row=Row{instance:selected.instance.clone(),occupants:7,status:RowStatus::RecoveryRequired,
            versions:Some(versions),recovery:Some(Comparison::of(&selected)),selection:None};
        assert!(row.valid(2) && input.matches_recovery(&row) && !input.matches(&row));
        // Metadata refresh has no selection fallback, even with exact hashes.
        row.status=RowStatus::VerifiedThisSession;row.recovery=None;row.selection=Some(selected);
        assert!(row.valid(2) && input.matches(&row) && !input.matches_recovery(&row));
        row.selection.as_mut().unwrap().inventory_sha256="00".repeat(32);assert!(!input.matches(&row));
        assert!(parse_empty(br#"{"schemaVersion":1}"#).is_ok());
        assert!(parse_empty(br#"{"schemaVersion":1,"schemaVersion":1}"#).is_err());
        assert!(parse_empty(br#"{"schemaVersion":1,"path":"/tmp/tools"}"#).is_err());
        assert_eq!(ENTRY_LIMIT,32);
    }
    #[test]
    fn catalog_selection_has_no_renderer_path_account_or_qualification_authority() { catalog_selection_has_no_renderer_path_account_or_qualification_authority_data(); }
}

// Explicit harness=false DATA bridge; no native custody or qualification.
#[cfg(test)]
pub(crate) fn assert_catalog_data_contract() {
    tests::catalog_selection_has_no_renderer_path_account_or_qualification_authority_data();
}
