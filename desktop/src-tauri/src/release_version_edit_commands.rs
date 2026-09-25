//! Closed renderer DATA: no root, source, key or policy override.
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use crate::{edit_protocol::token, error::BridgeError, github_workflow_edit_protocol::value_bounds,
    release_version_edit_protocol::{PrepareReleaseVersionEdit, REQUEST_LIMIT}};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Open { pub project_id: String }
fn decode<T: DeserializeOwned>(body: &Value, limit: usize) -> Result<T, BridgeError> {
    if !body.is_object() { return Err(BridgeError::invalid()); }
    value_bounds(body, 16, limit)?;
    T::deserialize(body).map_err(|_| BridgeError::invalid())
}
pub(crate) fn open(body: &Value) -> Result<Open, BridgeError> {
    let value: Open = decode(body, 512)?;
    if !crate::protocol::valid_id(&value.project_id) { return Err(BridgeError::invalid()); }
    Ok(value)
}
pub(crate) fn prepare(body: &Value) -> Result<PrepareReleaseVersionEdit, BridgeError> {
    let value: PrepareReleaseVersionEdit = decode(body, REQUEST_LIMIT)?;
    if !token(&value.session_id) || !token(&value.revision) || value.draft_revision == u32::MAX || value.baseline_generation == u32::MAX
        || !value.expected_baseline.valid() || value.intent != value.expected_baseline.saved_version.intent() || !value.values.proposed() {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn prepare_body() -> Value {
        json!({"sessionId":"a".repeat(32),"revision":"b".repeat(32),
            "expectedBaseline":{"savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"savedVersion":{"state":"absent"}},
            "intent":"create","values":{"name":"1.2","build":"7"},"draftRevision":0,"baselineGeneration":0})
    }
    #[test]
    fn renderer_open_is_registered_id_only_never_a_root_source_or_platform_override() {
        assert!(open(&json!({"projectId":"inert_project-1"})).is_ok());
        for extra in ["root","source","nameKey","buildKey","iosEnabled","draft","registeredIdentity"] {
            let mut bad = json!({"projectId":"p"}); bad[extra] = json!("not-authority"); assert!(open(&bad).is_err());
        }
        for id in ["", "../p", "p\n", "p\r"] { assert!(open(&json!({"projectId":id})).is_err()); }
        assert!(open(&json!({"projectId":"x".repeat(65)})).is_err());
        assert!(open(&Value::Null).is_err());
    }
    #[test]
    fn prepare_counters_baseline_intent_and_bounded_values_remain_exact_and_closed() {
        let body = prepare_body(); assert!(prepare(&body).is_ok());
        for (pointer,value) in [("/draftRevision",json!(u32::MAX)), ("/baselineGeneration",json!(-1)),
            ("/draftRevision",json!(1.5)), ("/intent",json!("edit")), ("/values/build",json!(7)),
            ("/values/build",json!("07\n")), ("/values/name",json!("x".repeat(65))),
            ("/expectedBaseline/savedConfig/bytes",json!(0)),
            ("/expectedBaseline/savedVersion",json!({"state":"absent","bytes":0}))] {
            let mut bad = body.clone(); *bad.pointer_mut(pointer).unwrap() = value; assert!(prepare(&bad).is_err());
        }
        let mut extra = body.clone(); extra["source"] = json!("override"); assert!(prepare(&extra).is_err());
        let mut policy_invalid = body; policy_invalid["values"] = json!({"name":"bad","build":"0"});
        assert!(prepare(&policy_invalid).is_ok()); // Bounded strings only; shared core validates policy.
    }
}
