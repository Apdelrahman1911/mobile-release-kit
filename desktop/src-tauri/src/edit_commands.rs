//! Closed renderer arguments for the finite configuration owner. These types
//! carry intent/correlation only; the original owner holds filesystem authority.
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use crate::{edit_protocol::{bounded, token, PrepareConfigEdit, REQUEST_LIMIT}, error::BridgeError, protocol::check_value};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open { pub project_id: String }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Apply { pub session_id: String, pub plan_token: String }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Close { pub session_id: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {}

fn decode<T: DeserializeOwned>(body: &Value, limit: usize) -> Result<T, BridgeError> {
    if !body.is_object() { return Err(BridgeError::invalid()); }
    check_value(body)?;
    bounded(body, limit)?;
    // Deserialize directly from the bounded borrowed JSON; do not clone an
    // unchecked renderer object or select parameters piecemeal through Tauri.
    T::deserialize(body).map_err(|_| BridgeError::invalid())
}

pub(crate) fn open(body: &Value) -> Result<Open, BridgeError> {
    let value: Open = decode(body, 256)?;
    if !crate::protocol::valid_id(&value.project_id) { return Err(BridgeError::invalid()); }
    Ok(value)
}

pub(crate) fn prepare(body: &Value) -> Result<PrepareConfigEdit, BridgeError> {
    let value: PrepareConfigEdit = decode(body, REQUEST_LIMIT)?;
    if !token(&value.session_id) || !token(&value.revision)
        || !(value.expected_base.is_null() || value.expected_base.is_object()) || !value.draft.is_object() {
        return Err(BridgeError::invalid());
    }
    bounded(&value.expected_base, 512 * 1024)?;
    bounded(&value.draft, 512 * 1024)?;
    Ok(value)
}

pub(crate) fn workflow_prepare(body: &Value) -> Result<crate::github_workflow_edit_protocol::PrepareWorkflowEdit, BridgeError> {
    use crate::github_workflow_edit_protocol::{PrepareWorkflowEdit, value_bounds};
    let value: PrepareWorkflowEdit = decode(body, REQUEST_LIMIT)?;
    if !token(&value.session_id) || !token(&value.revision) || !value.draft.is_object()
        || value.tooling_repository.len() > 140 || value.tooling_sha.len() > 40
        || value.draft_revision == u32::MAX || value.baseline_generation == u32::MAX { return Err(BridgeError::invalid()); }
    value_bounds(&value.draft, 28, 512 * 1024)?;
    Ok(value)
}

pub(crate) fn apply(body: &Value) -> Result<Apply, BridgeError> {
    let value: Apply = decode(body, 256)?;
    if !token(&value.session_id) || !token(&value.plan_token) { return Err(BridgeError::invalid()); }
    Ok(value)
}

pub(crate) fn close(body: &Value) -> Result<Close, BridgeError> {
    let value: Close = decode(body, 128)?;
    if !token(&value.session_id) { return Err(BridgeError::invalid()); }
    Ok(value)
}

pub(crate) fn status(body: &Value) -> Result<Status, BridgeError> { decode(body, 2) }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const REVISION: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn complete_command_objects_refuse_extra_authority() {
        assert!(open(&json!({"projectId": "project-1"})).is_ok());
        assert!(open(&json!({"projectId": "project-1", "root": "/tmp/other"})).is_err());
        assert!(apply(&json!({"sessionId": SESSION, "planToken": REVISION})).is_ok());
        assert!(apply(&json!({"sessionId": SESSION, "planToken": REVISION, "draft": {}})).is_err());
        assert!(close(&json!({"sessionId": SESSION})).is_ok());
        assert!(close(&json!({"sessionId": SESSION, "force": true})).is_err());
        assert!(status(&json!({})).is_ok());
        assert!(status(&json!({"windowGeneration": SESSION})).is_err());
        assert!(status(&Value::Null).is_err());
    }

    #[test]
    fn prepare_keeps_explicit_base_and_bounded_integer_correlations() {
        let mut body = json!({"sessionId": SESSION, "revision": REVISION, "expectedBase": null,
            "draft": {}, "draftRevision": u32::MAX, "baselineGeneration": 0});
        assert!(prepare(&body).is_ok());
        body["draftRevision"] = json!(u64::from(u32::MAX) + 1);
        assert!(prepare(&body).is_err());
        body["draftRevision"] = json!(1.0);
        assert!(prepare(&body).is_err());
        body["draftRevision"] = json!(1);
        body.as_object_mut().map(|object| object.remove("expectedBase"));
        assert!(prepare(&body).is_err());
    }

    #[test]
    fn tokens_and_payloads_are_checked_before_owner_admission() {
        assert!(apply(&json!({"sessionId": SESSION.to_uppercase(), "planToken": REVISION})).is_err());
        assert!(close(&json!({"sessionId": "project-1"})).is_err());
        assert!(open(&json!({"projectId": "project-1/../../elsewhere"})).is_err());
        let body = json!({"sessionId": SESSION, "revision": REVISION, "expectedBase": null,
            "draft": {"large": "a".repeat(512 * 1024)}, "draftRevision": 1, "baselineGeneration": 0});
        assert!(prepare(&body).is_err());
    }

    #[test]
    fn workflow_prepare_has_only_draft_pin_and_local_correlation_fields() {
        let body = json!({"sessionId":SESSION,"revision":REVISION,"draft":{},"toolingRepository":"example/toolkit",
            "toolingSha":"a".repeat(40),"draftRevision":1,"baselineGeneration":0});
        assert!(workflow_prepare(&body).is_ok());
        assert!(prepare(&body).is_err());
        for key in ["expectedBase","suppliedSnapshot","root","registeredIdentity","path","content","force","credentials"] {
            let mut bad = body.clone(); bad[key] = Value::Null; assert!(workflow_prepare(&bad).is_err());
        }
        for key in ["draftRevision","baselineGeneration"] {
            for value in [json!(true),json!(-1),json!(1.0),json!(u32::MAX),json!(u64::from(u32::MAX)+1)] {
                let mut bad = body.clone(); bad[key] = value; assert!(workflow_prepare(&bad).is_err());
            }
        }
        let mut bad = body.clone(); bad["draft"] = json!({"wide":vec![Value::Null;7998]});
        assert!(workflow_prepare(&bad).is_err());
        let mut bad = body; bad["toolingRepository"] = json!("é".repeat(71));
        assert!(workflow_prepare(&bad).is_err());
    }
}
