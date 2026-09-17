//! Closed passive GitHub proposal input. Caller-supplied digests are assertions,
//! never observed repository state, file revisions, or permission to apply.
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{edit_protocol::bounded, error::BridgeError, protocol::{check_value, REQUEST_LIMIT}};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum WorkflowId { Preflight, Candidate, ExternalTesting, ProductionSubmit }

#[derive(Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
enum WorkflowAssertion {
    Absent { id: WorkflowId },
    Present {
        id: WorkflowId,
        #[serde(rename = "byteLength")]
        byte_length: u64,
        sha256: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuppliedSnapshot { workflows: Vec<WorkflowAssertion> }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Proposal {
    draft: Value,
    tooling_repository: String,
    tooling_sha: String,
    supplied_snapshot: Option<SuppliedSnapshot>,
}

impl Proposal {
    pub(crate) fn into_params(self) -> Result<Value, BridgeError> {
        serde_json::to_value(self).map_err(|_| BridgeError::invalid())
    }
}

pub(crate) fn proposal(body: &Value) -> Result<Proposal, BridgeError> {
    let object = body.as_object().ok_or_else(BridgeError::invalid)?;
    // Option<T> alone would accept an omitted snapshot. The wire contract
    // requires the caller to state null explicitly, not infer an empty tree.
    if object.len() != 4 || !["draft", "toolingRepository", "toolingSha", "suppliedSnapshot"]
        .iter().all(|key| object.contains_key(*key)) { return Err(BridgeError::invalid()); }
    check_value(body)?;
    bounded(body, REQUEST_LIMIT - 1)?;
    let value = Proposal::deserialize(body).map_err(|_| BridgeError::invalid())?;
    if !value.draft.is_object() || value.tooling_repository.len() > 140 || value.tooling_sha.len() > 40 {
        return Err(BridgeError::invalid());
    }
    bounded(&value.draft, 512 * 1024)?;
    if let Some(snapshot) = &value.supplied_snapshot {
        if snapshot.workflows.len() > 4 { return Err(BridgeError::invalid()); }
        let mut ids = BTreeSet::new();
        for assertion in &snapshot.workflows {
            let id = match assertion {
                WorkflowAssertion::Absent { id } => id,
                WorkflowAssertion::Present { id, byte_length, sha256 } => {
                    if *byte_length > 1024 * 1024 || sha256.len() != 64
                        || !sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
                        return Err(BridgeError::invalid());
                    }
                    id
                }
            };
            if !ids.insert(*id) { return Err(BridgeError::invalid()); }
        }
    }
    // Core owns configuration and tooling-pin policy. This adapter only admits
    // bounded wire shapes; it neither renders templates nor validates a ref.
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Value {
        json!({"draft": {}, "toolingRepository": "example/toolkit", "toolingSha": "A".repeat(40), "suppliedSnapshot": null})
    }

    #[test]
    fn explicit_null_roundtrips_without_granting_repository_authority() {
        let body = request();
        assert_eq!(proposal(&body).and_then(Proposal::into_params).ok(), Some(body.clone()));
        for key in ["draft", "toolingRepository", "toolingSha", "suppliedSnapshot"] {
            let mut incomplete = body.clone();
            incomplete.as_object_mut().unwrap().remove(key);
            assert!(proposal(&incomplete).is_err());
        }
        for key in ["root", "revision", "token", "force", "apply"] {
            let mut extra = body.clone(); extra[key] = json!("untrusted");
            assert!(proposal(&extra).is_err());
        }
    }

    #[test]
    fn supplied_assertions_are_closed_bounded_and_unambiguous() {
        let mut body = request();
        body["suppliedSnapshot"] = json!({"workflows": [
            {"id": "candidate", "state": "absent"},
            {"id": "production-submit", "state": "present", "byteLength": 0, "sha256": "0".repeat(64)}
        ]});
        assert_eq!(proposal(&body).and_then(Proposal::into_params).ok(), Some(body.clone()));
        for record in [
            json!({"id": "candidate", "state": "absent", "path": "unrelated.yml"}),
            json!({"id": "unknown", "state": "absent"}),
            json!({"id": "candidate", "state": "present", "byteLength": true, "sha256": "0".repeat(64)}),
            json!({"id": "candidate", "state": "present", "byteLength": 1.0, "sha256": "0".repeat(64)}),
            json!({"id": "candidate", "state": "present", "byteLength": 1_048_577, "sha256": "0".repeat(64)}),
            json!({"id": "candidate", "state": "present", "byteLength": 1, "sha256": "A".repeat(64)}),
        ] {
            body["suppliedSnapshot"] = json!({"workflows": [record]});
            assert!(proposal(&body).is_err());
        }
        body["suppliedSnapshot"] = json!({"workflows": [
            {"id": "candidate", "state": "absent"}, {"id": "candidate", "state": "absent"}
        ]});
        assert!(proposal(&body).is_err());
        body["suppliedSnapshot"] = json!({"workflows": [], "observed": true});
        assert!(proposal(&body).is_err());
    }

    #[test]
    fn draft_bounds_precede_core_policy_without_rust_template_generation() {
        let mut body = request();
        // Invalid core policy still belongs to the core, not a second validator.
        body["toolingRepository"] = json!("not-a-coordinate");
        assert!(proposal(&body).is_ok());
        body["draft"] = json!({"oversized": "x".repeat(512 * 1024)});
        assert!(proposal(&body).is_err());
        body["draft"] = json!([]);
        assert!(proposal(&body).is_err());
        body["draft"] = json!({});
        body["toolingRepository"] = json!("x".repeat(141));
        assert!(proposal(&body).is_err());
    }
}
