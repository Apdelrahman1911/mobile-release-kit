//! Small renderer arguments; no bytes, absolute paths or native identity hints.
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use crate::{edit_protocol::token, error::BridgeError, github_workflow_edit_protocol::value_bounds,
    metadata_images_edit_protocol::{Context, PrepareMetadataImagesEdit, MAX_FILES, SMALL_REQUEST_LIMIT},
    metadata_text_edit_protocol::Platform, protocol::valid_id};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectionStart { pub project_id: String, pub platform: Platform, pub locale: String, pub asset_type: String }
impl SelectionStart { pub(crate) fn context(&self) -> Context {
    Context { platform: self.platform, locale: self.locale.clone(), asset_type: self.asset_type.clone() }
} }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectionCancel { pub operation_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open { pub project_id: String, pub selection_token: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryOpen { pub project_id: String }

// Negative facts for this invocation only. Call these exclusively before its
// original selection/registry claim (and before any matching token retirement).
// They never establish that another owner is idle or resources are settled.
pub(crate) fn selection_not_admitted(mut error: BridgeError) -> BridgeError {
    error.code = "metadata_images_selection_not_admitted".into(); error.retryable = false; error
}
pub(crate) fn import_not_matched(mut error: BridgeError) -> BridgeError {
    error.code = "metadata_images_import_not_matched".into(); error.retryable = false; error
}
pub(crate) fn recovery_not_admitted(mut error: BridgeError) -> BridgeError {
    error.code = "metadata_images_recovery_not_admitted".into(); error.retryable = false; error
}

fn decode<T: DeserializeOwned>(body: &Value, limit: usize) -> Result<T, BridgeError> {
    if !body.is_object() { return Err(BridgeError::invalid()); }
    value_bounds(body, 16, limit)?;
    T::deserialize(body).map_err(|_| BridgeError::invalid())
}
pub(crate) fn choose(body: &Value) -> Result<SelectionStart, BridgeError> {
    let value: SelectionStart = decode(body, 1024)?;
    if !valid_id(&value.project_id) || !value.context().valid() { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn selection_cancel(body: &Value) -> Result<SelectionCancel, BridgeError> {
    let value: SelectionCancel = decode(body, 128)?;
    if !token(&value.operation_id) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn open(body: &Value) -> Result<Open, BridgeError> {
    let value: Open = decode(body, 256)?;
    if !valid_id(&value.project_id) || !token(&value.selection_token) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn recovery_open(body: &Value) -> Result<RecoveryOpen, BridgeError> {
    let value: RecoveryOpen = decode(body, 128)?;
    if !valid_id(&value.project_id) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn prepare(body: &Value) -> Result<PrepareMetadataImagesEdit, BridgeError> {
    let value: PrepareMetadataImagesEdit = decode(body, SMALL_REQUEST_LIMIT)?;
    let mut ids = std::collections::BTreeSet::new();
    if !token(&value.session_id) || !token(&value.revision) || value.draft_revision == u32::MAX || value.baseline_generation == u32::MAX
        || !value.expected_baseline.valid() || value.choices.len() > MAX_FILES
        || !value.choices.iter().all(|choice| token(&choice.item_id) && ids.insert(&choice.item_id)) { return Err(BridgeError::invalid()); }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn picker_and_import_renderer_arguments_cannot_supply_paths_or_bodies() {
        let value = json!({"projectId":"project-1","platform":"ios","locale":"en-US","assetType":"APP_IPHONE_67"});
        assert!(choose(&value).is_ok());
        for key in ["root", "images", "base64", "registeredIdentity", "filename", "source", "force"] {
            let mut bad = value.clone(); bad[key] = Value::Null; assert!(choose(&bad).is_err());
        }
        let value = json!({"projectId":"project-1","selectionToken":"a".repeat(32)});
        assert!(open(&value).is_ok());
        for key in ["platform", "locale", "assetType", "paths", "images", "expectedBaseline"] {
            let mut bad = value.clone(); bad[key] = Value::Null; assert!(open(&bad).is_err());
        }
        assert!(selection_cancel(&json!({"operationId":1})).is_err());
        assert!(selection_cancel(&json!({"operationId":"A".repeat(32)})).is_err());
        assert!(recovery_open(&json!({"projectId":"project-1","transactionId":"a".repeat(32)})).is_err());
    }
    #[test]
    fn original_baseline_choices_and_counters_are_bounded_without_adding_authority() {
        let value = json!({"sessionId":"a".repeat(32),"revision":"b".repeat(32),"draftRevision":1,"baselineGeneration":0,
            "expectedBaseline":{"config":{"byteLength":2,"sha256":"c".repeat(64)},"ignore":{"byteLength":0,"sha256":"d".repeat(64)},"inventorySha256":"e".repeat(64)},
            "choices":[{"itemId":"f".repeat(32),"replaceExisting":false}]});
        assert!(prepare(&value).is_ok());
        let mut recovery = value.clone(); recovery["choices"] = json!([]); assert!(prepare(&recovery).is_ok());
        let mut duplicate = value.clone(); duplicate["choices"] = json!([value["choices"][0],value["choices"][0]]); assert!(prepare(&duplicate).is_err());
        for key in ["draftRevision", "baselineGeneration"] { for number in [json!(true),json!(-1),json!(u32::MAX),json!(1.0)] {
            let mut bad = value.clone(); bad[key] = number; assert!(prepare(&bad).is_err());
        } }
        let mut body = value; body["choices"][0]["replaceExisting"] = json!(1); assert!(prepare(&body).is_err());
    }
}
