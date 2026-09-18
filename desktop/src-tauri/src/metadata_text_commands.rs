//! Fixed metadata-text command arguments. Roots and destination names never
//! enter through renderer DATA; all selected fields form one closed roster.
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use crate::{edit_protocol::{token, REQUEST_LIMIT}, error::BridgeError,
    github_workflow_edit_protocol::value_bounds,
    metadata_text_edit_protocol::{fields_valid, locale_bounded, Context, Platform, PrepareMetadataTextEdit, TextField}};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open { pub project_id: String, pub platform: Platform, pub locale: String }
impl Open { pub(crate) fn context(&self) -> Context { Context { platform: self.platform, locale: self.locale.clone() } } }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Validate { pub platform: Platform, pub fields: Vec<TextField> }

fn decode<T: DeserializeOwned>(body: &Value, limit: usize) -> Result<T, BridgeError> {
    if !body.is_object() { return Err(BridgeError::invalid()); }
    value_bounds(body, 16, limit)?;
    T::deserialize(body).map_err(|_| BridgeError::invalid())
}
pub(crate) fn open(body: &Value) -> Result<Open, BridgeError> {
    let value: Open = decode(body, 512)?;
    if !crate::protocol::valid_id(&value.project_id) || !locale_bounded(&value.locale) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn validate(body: &Value) -> Result<Validate, BridgeError> {
    let value: Validate = decode(body, REQUEST_LIMIT)?;
    if !fields_valid(&value.fields, value.platform) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn prepare(body: &Value) -> Result<PrepareMetadataTextEdit, BridgeError> {
    let value: PrepareMetadataTextEdit = decode(body, REQUEST_LIMIT)?;
    if !token(&value.session_id) || !token(&value.revision) || value.draft_revision == u32::MAX || value.baseline_generation == u32::MAX
        || !value.expected_baseline.platform().is_some_and(|platform| fields_valid(&value.fields, platform)) { return Err(BridgeError::invalid()); }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const REVISION: &str = "fedcba9876543210fedcba9876543210";
    fn fields() -> Value { json!([{"id":"title.txt","text":"Title"},{"id":"short_description.txt","text":"Short"},{"id":"full_description.txt","text":"Full"}]) }
    fn baseline() -> Value { json!({"config":{"byteLength":2,"sha256":"a".repeat(64)},"fields":[{"id":"title.txt","state":"absent"},{"id":"short_description.txt","state":"absent"},{"id":"full_description.txt","state":"absent"}]}) }
    #[test]
    fn public_commands_have_no_path_identity_retarget_or_core_policy_surface() {
        let selected = json!({"projectId":"project-1","platform":"android","locale":"en-US"});
        assert!(open(&selected).is_ok());
        for key in ["root","registeredIdentity","metadataRoot","configPath","filename","force"] {
            let mut bad = selected.clone(); bad[key] = Value::Null; assert!(open(&bad).is_err());
        }
        let request = json!({"platform":"android","fields":fields()});
        assert!(validate(&request).is_ok());
        let mut empty = request.clone(); empty["fields"][0]["text"] = json!("");
        assert!(validate(&empty).is_ok()); // Invalid Store text still reaches pure core feedback.
        let mut too_large = request.clone(); too_large["fields"][0]["text"] = json!("a".repeat(32 * 1024 + 1));
        assert!(validate(&too_large).is_err());
        let mut bad = request; bad["fields"][0]["path"] = json!("other.txt"); assert!(validate(&bad).is_err());
    }
    #[test]
    fn prepare_requires_complete_baseline_order_and_bounded_original_correlations() {
        let body = json!({"sessionId":SESSION,"revision":REVISION,"expectedBaseline":baseline(),"fields":fields(),"draftRevision":1,"baselineGeneration":0});
        assert!(prepare(&body).is_ok());
        for key in ["root","platform","locale","metadataRoot","planToken","configDraft"] {
            let mut bad = body.clone(); bad[key] = Value::Null; assert!(prepare(&bad).is_err());
        }
        for key in ["draftRevision","baselineGeneration"] { for value in [json!(true),json!(-1),json!(1.0),json!(u32::MAX),json!(u64::from(u32::MAX)+1)] {
            let mut bad = body.clone(); bad[key] = value; assert!(prepare(&bad).is_err());
        } }
        let mut bad = body.clone(); bad["fields"].as_array_mut().unwrap().swap(0,1); assert!(prepare(&bad).is_err());
        let mut bad = body.clone(); bad["expectedBaseline"]["fields"][0]["byteLength"] = json!(0); assert!(prepare(&bad).is_err());
        let mut bad = body; bad["expectedBaseline"]["config"]["byteLength"] = json!(0); assert!(prepare(&bad).is_err());
    }
}
