//! Raw UTF-8 JSON only. A permissively decoded renderer object cannot prove
//! absence of duplicate keys. Values are correlation DATA, never writer roots.
use serde::{de::DeserializeOwned, Deserialize};
use crate::{edit_protocol::token, error::BridgeError, protocol::strict_json,
    required_notes_edit_protocol::{Baseline, Binding, Context, REQUEST_LIMIT, validate_text_bounded}};

fn decode<T: DeserializeOwned>(raw: &[u8], limit: usize) -> Result<T, BridgeError> {
    if raw.is_empty() || raw.len() > limit { return Err(BridgeError::invalid()); }
    let value = strict_json(raw).map_err(|_| BridgeError::invalid())?;
    if !value.is_object() { return Err(BridgeError::invalid()); }
    T::deserialize(&value).map_err(|_| BridgeError::invalid())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub(crate) fn capabilities(raw: &[u8]) -> Result<(), BridgeError> { let _: Empty = decode(raw, 128)?; Ok(()) }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observe { pub(crate) project_id: String, pub(crate) window_generation: String, pub(crate) context: Context }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Validate { pub(crate) context: Context, pub(crate) text: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Import { pub(crate) request_id: u32, pub(crate) project_id: String, pub(crate) window_generation: String, pub(crate) context: Context }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) request_id: u32, pub(crate) project_id: String, pub(crate) window_generation: String,
    pub(crate) context: Context, pub(crate) draft_revision: u32, pub(crate) expected_baseline: Baseline, pub(crate) text: String,
}
impl Prepare { pub(crate) fn binding(&self) -> Binding {
    Binding { request_id: self.request_id, window_generation: self.window_generation.clone(), context: self.context.clone(), draft_revision: self.draft_revision }
} }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Apply { pub(crate) request_id: u32, pub(crate) window_generation: String, pub(crate) session_id: String, pub(crate) plan_token: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Close { pub(crate) request_id: u32, pub(crate) window_generation: String, pub(crate) session_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status { pub(crate) request_id: u32, pub(crate) window_generation: String }

fn selected(project: &str, window: &str, context: &Context) -> bool { crate::protocol::valid_id(project) && token(window) && context.valid() }
pub(crate) fn observe(raw: &[u8]) -> Result<Observe, BridgeError> {
    let value: Observe = decode(raw, 2048)?;
    if !selected(&value.project_id, &value.window_generation, &value.context) { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn validate(raw: &[u8]) -> Result<Validate, BridgeError> {
    let value: Validate = decode(raw, REQUEST_LIMIT)?;
    // Invalid provider text, including a 65537-scalar draft, still reaches core
    // feedback. Prepare/import have their smaller per-kind storage boundaries.
    if !value.context.valid() || !validate_text_bounded(&value.text) { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn import(raw: &[u8]) -> Result<Import, BridgeError> {
    let value: Import = decode(raw, 2048)?;
    if value.request_id == u32::MAX || !selected(&value.project_id, &value.window_generation, &value.context) { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn prepare(raw: &[u8]) -> Result<Prepare, BridgeError> {
    let value: Prepare = decode(raw, REQUEST_LIMIT)?;
    if !value.binding().valid() || !selected(&value.project_id, &value.window_generation, &value.context)
        || !value.expected_baseline.valid_for(&value.context) || value.text.len() > value.context.kind().byte_limit() { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn apply(raw: &[u8]) -> Result<Apply, BridgeError> {
    let value: Apply = decode(raw, 2048)?;
    if value.request_id == u32::MAX || !token(&value.window_generation) || !token(&value.session_id) || !token(&value.plan_token) { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn close(raw: &[u8]) -> Result<Close, BridgeError> {
    let value: Close = decode(raw, 2048)?;
    if value.request_id == u32::MAX || !token(&value.window_generation) || !token(&value.session_id) { return Err(BridgeError::invalid()); } Ok(value)
}
pub(crate) fn status(raw: &[u8]) -> Result<Status, BridgeError> {
    let value: Status = decode(raw, 1024)?;
    if value.request_id == u32::MAX || !token(&value.window_generation) { return Err(BridgeError::invalid()); } Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    #[test]
    fn raw_note_commands_reject_duplicate_or_extra_authority_and_scalar_counter_coercion() {
        assert!(capabilities(b"{}").is_ok()); assert!(capabilities(b"{\"root\":null}").is_err());
        assert!(validate(br#"{"context":{"kind":"ios-app-review"},"text":"","text":"other"}"#).is_err());
        assert!(validate(br#"{"context":{"kind":"android-build","locale":"en-US","locale":"fr-FR"},"text":"public"}"#).is_err());
        assert!(validate(br#"{"context":{"kind":"ios-app-review","locale":null},"text":"public"}"#).is_err());
        assert!(validate(br#"{"context":{"kind":"ios-app-review"},"text":"\ud800"}"#).is_err());
        let original = json!({"requestId":1,"windowGeneration":TOKEN,"projectId":"project-1","context":{"kind":"android-build","locale":"en-US"}});
        assert!(import(&serde_json::to_vec(&original).unwrap()).is_ok());
        for key in ["root","path","filename","savedBuild","registeredIdentity","force"] {
            let mut bad=original.clone(); bad[key]=json!(null); assert!(import(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        for id in [json!(true),json!(-1),json!(1.0),json!(u32::MAX)] {
            let mut bad=original.clone(); bad["requestId"]=id; assert!(import(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    #[test]
    fn validate_admits_meaningful_oversize_feedback_but_never_silently_truncates() {
        for text in ["".to_owned(), "😀".repeat(65537), "x".repeat(2001)] {
            let request=json!({"context":{"kind":"android-build","locale":"en-US"},"text":text});
            assert!(validate(&serde_json::to_vec(&request).unwrap()).is_ok());
        }
        let request=json!({"context":{"kind":"ios-app-review"},"text":"x".repeat(65538)});
        assert!(validate(&serde_json::to_vec(&request).unwrap()).is_err());
        assert!(status(&serde_json::to_vec(&json!({"requestId":1,"windowGeneration":TOKEN,"sessionId":TOKEN})).unwrap()).is_err());
    }
}
