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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfigurationRecoveryOpen { pub project_id: String, pub intent: crate::edit_protocol::RecoveryIntent }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfigurationRecoveryApply {
    pub session_id: String, pub plan_token: String, pub intent: crate::edit_protocol::RecoveryIntent,
}
pub(crate) enum ConfigurationOpen { Edit(Open), Recover(ConfigurationRecoveryOpen) }
pub(crate) enum ConfigurationPrepare { Edit(PrepareConfigEdit), Recover(crate::edit_protocol::PrepareConfigurationRecovery) }
pub(crate) enum ConfigurationApply { Edit(Apply), Recover(ConfigurationRecoveryApply) }
pub(crate) fn configuration_open(body: &Value) -> Result<ConfigurationOpen, BridgeError> {
    if body.get("intent").is_some() {
        let value: ConfigurationRecoveryOpen = decode(body, 256)?;
        if !crate::protocol::valid_id(&value.project_id) { return Err(BridgeError::invalid()); }
        Ok(ConfigurationOpen::Recover(value))
    } else { open(body).map(ConfigurationOpen::Edit) }
}
pub(crate) fn configuration_prepare(body: &Value) -> Result<ConfigurationPrepare, BridgeError> {
    if body.get("intent").is_some() {
        let value: crate::edit_protocol::PrepareConfigurationRecovery = decode(body, 256)?;
        if !token(&value.session_id) || !token(&value.revision) { return Err(BridgeError::invalid()); }
        Ok(ConfigurationPrepare::Recover(value))
    } else { prepare(body).map(ConfigurationPrepare::Edit) }
}
pub(crate) fn configuration_apply(body: &Value) -> Result<ConfigurationApply, BridgeError> {
    if body.get("intent").is_some() {
        let value: ConfigurationRecoveryApply = decode(body, 256)?;
        if !token(&value.session_id) || !token(&value.plan_token) { return Err(BridgeError::invalid()); }
        Ok(ConfigurationApply::Recover(value))
    } else { apply(body).map(ConfigurationApply::Edit) }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkflowRecoveryOpen {
    pub project_id: String,
    pub intent: crate::github_workflow_edit_protocol::RecoveryIntent,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkflowRecoveryApply {
    pub session_id: String, pub plan_token: String,
    pub intent: crate::github_workflow_edit_protocol::RecoveryIntent,
}
pub(crate) enum WorkflowOpen { Edit(Open), Recover(WorkflowRecoveryOpen) }
impl WorkflowOpen {
    pub(crate) fn project_id(&self) -> &str { match self { Self::Edit(a) => &a.project_id, Self::Recover(a) => &a.project_id } }
}
pub(crate) enum WorkflowPrepare {
    Edit(crate::github_workflow_edit_protocol::PrepareWorkflowEdit),
    Recover(crate::github_workflow_edit_protocol::PrepareWorkflowRecovery),
}
pub(crate) enum WorkflowApply { Edit(Apply), Recover(WorkflowRecoveryApply) }
impl WorkflowApply {
    pub(crate) fn session_id(&self) -> &str { match self { Self::Edit(a) => &a.session_id, Self::Recover(a) => &a.session_id } }
    pub(crate) fn plan_token(&self) -> &str { match self { Self::Edit(a) => &a.plan_token, Self::Recover(a) => &a.plan_token } }
}
pub(crate) fn workflow_open(body: &Value) -> Result<WorkflowOpen, BridgeError> {
    if body.get("intent").is_some() {
        let value: WorkflowRecoveryOpen = decode(body, 256)?;
        if !crate::protocol::valid_id(&value.project_id) { return Err(BridgeError::invalid()); }
        Ok(WorkflowOpen::Recover(value))
    } else { open(body).map(WorkflowOpen::Edit) }
}
pub(crate) fn workflow_prepare_request(body: &Value) -> Result<WorkflowPrepare, BridgeError> {
    if body.get("intent").is_some() {
        let value: crate::github_workflow_edit_protocol::PrepareWorkflowRecovery = decode(body, 256)?;
        if !token(&value.session_id) || !token(&value.revision) { return Err(BridgeError::invalid()); }
        Ok(WorkflowPrepare::Recover(value))
    } else { workflow_prepare(body).map(WorkflowPrepare::Edit) }
}
pub(crate) fn workflow_apply(body: &Value) -> Result<WorkflowApply, BridgeError> {
    if body.get("intent").is_some() {
        let value: WorkflowRecoveryApply = decode(body, 256)?;
        if !token(&value.session_id) || !token(&value.plan_token) { return Err(BridgeError::invalid()); }
        Ok(WorkflowApply::Recover(value))
    } else { apply(body).map(WorkflowApply::Edit) }
}


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

    #[test]
    fn configuration_recovery_commands_are_closed_and_preserve_normal_save() {
        let open_body=json!({"projectId":"project-1","intent":"recover"});
        let prepare_body=json!({"sessionId":SESSION,"revision":REVISION,"intent":"recover"});
        let apply_body=json!({"sessionId":SESSION,"planToken":REVISION,"intent":"recover"});
        assert!(matches!(configuration_open(&open_body),Ok(ConfigurationOpen::Recover(_))));
        assert!(matches!(configuration_prepare(&prepare_body),Ok(ConfigurationPrepare::Recover(_))));
        assert!(matches!(configuration_apply(&apply_body),Ok(ConfigurationApply::Recover(_))));
        assert!(open(&open_body).is_err());assert!(prepare(&prepare_body).is_err());assert!(apply(&apply_body).is_err());
        assert!(matches!(configuration_open(&json!({"projectId":"project-1"})),Ok(ConfigurationOpen::Edit(_))));
        assert!(matches!(configuration_prepare(&json!({"sessionId":SESSION,"revision":REVISION,"expectedBase":null,
            "draft":{},"draftRevision":u32::MAX,"baselineGeneration":0})),Ok(ConfigurationPrepare::Edit(_))));
        assert!(matches!(configuration_apply(&json!({"sessionId":SESSION,"planToken":REVISION})),Ok(ConfigurationApply::Edit(_))));
        for value in [Value::Null,json!(false),json!("edit"),json!("Recover"),json!(["recover"])] {
            let mut open=open_body.clone();open["intent"]=value.clone();assert!(configuration_open(&open).is_err());
            let mut prepare=prepare_body.clone();prepare["intent"]=value.clone();assert!(configuration_prepare(&prepare).is_err());
            let mut apply=apply_body.clone();apply["intent"]=value;assert!(configuration_apply(&apply).is_err());
        }
        for key in ["root","registeredIdentity","files","force","draft","expectedBase","draftRevision","baselineGeneration"] {
            let mut open=open_body.clone();open[key]=Value::Null;assert!(configuration_open(&open).is_err());
            let mut prepare=prepare_body.clone();prepare[key]=Value::Null;assert!(configuration_prepare(&prepare).is_err());
            let mut apply=apply_body.clone();apply[key]=Value::Null;assert!(configuration_apply(&apply).is_err());
        }
        assert!(configuration_prepare(&json!({"sessionId":SESSION,"revision":REVISION})).is_err());
        assert!(configuration_apply(&json!({"sessionId":SESSION,"planToken":"not-a-token","intent":"recover"})).is_err());
        assert!(close(&json!({"sessionId":SESSION,"intent":"recover"})).is_err());
        assert!(status(&json!({"intent":"recover"})).is_err());
    }

    #[test]
    fn workflow_recovery_commands_are_disjoint_closed_intent_not_new_ipc() {
        assert!(matches!(workflow_open(&json!({"projectId":"project-1","intent":"recover"})),Ok(WorkflowOpen::Recover(_))));
        assert!(matches!(workflow_open(&json!({"projectId":"project-1"})),Ok(WorkflowOpen::Edit(_))));
        assert!(matches!(workflow_prepare_request(&json!({"sessionId":SESSION,"revision":REVISION,"intent":"recover"})),Ok(WorkflowPrepare::Recover(_))));
        assert!(matches!(workflow_apply(&json!({"sessionId":SESSION,"planToken":REVISION,"intent":"recover"})),Ok(WorkflowApply::Recover(_))));
        for intent in [json!("edit"),json!("rollback"),json!("Recover"),json!(false),Value::Null] {
            assert!(workflow_open(&json!({"projectId":"project-1","intent":intent.clone()})).is_err());
            assert!(workflow_prepare_request(&json!({"sessionId":SESSION,"revision":REVISION,"intent":intent.clone()})).is_err());
            assert!(workflow_apply(&json!({"sessionId":SESSION,"planToken":REVISION,"intent":intent})).is_err());
        }
        for key in ["draft","toolingRepository","toolingSha","draftRevision","baselineGeneration","path","files","force"] {
            let mut body = json!({"sessionId":SESSION,"revision":REVISION,"intent":"recover"}); body[key] = Value::Null;
            assert!(workflow_prepare_request(&body).is_err());
        }
        assert!(open(&json!({"projectId":"project-1","intent":"recover"})).is_err());
        assert!(apply(&json!({"sessionId":SESSION,"planToken":REVISION,"intent":"recover"})).is_err());
    }
}

pub(crate) fn initialization_open(body: &Value) -> Result<crate::project_initialization_edit_protocol::Open, BridgeError> {
    let value: crate::project_initialization_edit_protocol::Open = decode(body, REQUEST_LIMIT)?;
    if !value.valid() { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn initialization_prepare(body: &Value) -> Result<crate::project_initialization_edit_protocol::Prepare, BridgeError> {
    let value: crate::project_initialization_edit_protocol::Prepare = decode(body, 256)?;
    if !token(&value.session_id) || !token(&value.revision) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn initialization_apply(body: &Value) -> Result<crate::project_initialization_edit_protocol::Apply, BridgeError> {
    let value: crate::project_initialization_edit_protocol::Apply = decode(body, 256)?;
    if !token(&value.session_id) || !token(&value.plan_token) { return Err(BridgeError::invalid()); }
    Ok(value)
}
