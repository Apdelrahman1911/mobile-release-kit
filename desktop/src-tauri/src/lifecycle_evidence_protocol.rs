//! Fixed saved-document projection. No authenticated history or recovery power.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{asset_source::RegisteredRoot, candidate_evidence_protocol::{self as candidate, Assurance, DocumentState, Outcome, Runs, Summary, Phase, OperationKind, Problem}, error::BridgeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Candidate, ExternalTesting, ProductionSubmit }
impl Stage {
    pub(crate) fn paths(self) -> &'static [&'static str] {
        // The selected JSON projection of the existing final workflow layout,
        // in layout order. No recursive discovery or document-supplied path.
        match self {
            Self::Candidate => &["candidate-receipt.json", "candidate-manifest.json", "operation/candidate-operation-intent.json"],
            Self::ExternalTesting => &["external-testing-receipt.json", "operation/external-testing-operation-intent.json",
                "operation/candidate/candidate-receipt.json", "operation/candidate/candidate-manifest.json", "operation/candidate/operation/candidate-operation-intent.json"],
            Self::ProductionSubmit => &["production-submit-receipt.json", "operation/production-submit-operation-intent.json",
                "operation/candidate/candidate-receipt.json", "operation/candidate/candidate-manifest.json", "operation/candidate/operation/candidate-operation-intent.json",
                "operation/external/external-testing-receipt.json", "operation/external/operation/external-testing-operation-intent.json",
                "operation/external/operation/candidate/candidate-receipt.json", "operation/external/operation/candidate/candidate-manifest.json",
                "operation/external/operation/candidate/operation/candidate-operation-intent.json"],
        }
    }
    fn history(self) -> &'static [Self] {
        match self { Self::Candidate => &[Self::Candidate], Self::ExternalTesting => &[Self::Candidate, Self::ExternalTesting],
            Self::ProductionSubmit => &[Self::Candidate, Self::ExternalTesting, Self::ProductionSubmit] }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Choose { pub(crate) stage: Stage }
pub(crate) fn choose_request(value: &Value) -> Result<Choose, BridgeError> {
    crate::github_workflow_edit_protocol::value_bounds(value, 2, 256).map_err(|_| candidate::invalid())?;
    if !value.is_object() { return Err(candidate::invalid()); }
    Choose::deserialize(value).map_err(|_| candidate::invalid())
}
// The route fixes the lifecycle purpose. Observe/STOP cannot change a stage;
// only a fresh native choice can produce a differently staged selection ID.
pub(crate) use candidate::{empty_request, observe_request, cancel_request, Observe, Cancel};
pub(crate) fn params(root: &RegisteredRoot, stage: Stage) -> Result<Value, BridgeError> {
    let mut value = candidate::params(root)?;
    value["stage"] = serde_json::to_value(stage).map_err(|_| candidate::invalid())?;
    Ok(value)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document { path: String, state: DocumentState }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RecordedOutcome { Mutated, Reconciled, AlreadyPresent, OperatorAuthorizedReconciliation, OperatorAuthorizedRetry, OperatorAuthorizedCreateRetry }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    stage: Stage, recorded_outcome: RecordedOutcome, recorded_readback: String, recorded_runs: Runs,
    receipt_sha256: String, intent_sha256: String, previous_receipt_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Guidance { code: String, message: String }
// Presentation contract, not a second policy evaluator. Only the core selects
// a code after validating its complete chain with the existing provenance rules.
const GUIDANCE: [(&str, &str); 8] = [
    ("evidence-invalid", "Some saved documents are invalid. Recovery is undetermined; no retry or release is approved."),
    ("evidence-incomplete", "Expected saved documents are missing. This does not prove that no Store operation occurred. Recovery is undetermined."),
    ("evidence-inconsistent", "The saved documents disagree. Keep the original evidence; this inspection cannot approve recovery or a retry."),
    ("candidate-only", "Only candidate evidence was supplied. Later stages and recovery remain undetermined; these saved documents do not approve another operation."),
    ("ios-external-not-available", "iOS production requires an external receipt whose readback.state is available-to-testers; start a NEW external-testing dispatch after Beta Review approval using the original candidate, without recovery_run_id. Rerunning the old dispatch preserves its immutable pending receipt."),
    ("android-external-observation-only", "Android production requires an external receipt produced by a confirmed promotion; an observation-only already-present receipt is not authorization"),
    ("recorded-external-gate", "The saved external receipt satisfies the recorded external-to-production predicate only. Workflow authenticity, current configuration and live Store state are unverified; no release or retry is approved."),
    ("production-recorded", "A production receipt is recorded in this local chain. It is not a live Store observation or proof of publication, and does not approve replay or recovery."),
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    schema_version: u8, pub(crate) stage: Stage, outcome: Outcome, documents: Vec<Document>, summary: Option<Summary>,
    history: Vec<History>, guidance: Guidance, assurance: Assurance,
}
impl Observation {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !self.assurance.valid()
            || !self.documents.iter().map(|d| d.path.as_str()).eq(self.stage.paths().iter().copied())
            || !GUIDANCE.contains(&(self.guidance.code.as_str(), self.guidance.message.as_str())) { return false; }
        let invalid = self.documents.iter().any(|d| d.state == DocumentState::Invalid);
        let missing = self.documents.iter().any(|d| d.state == DocumentState::Missing);
        if self.outcome != Outcome::Consistent {
            return self.summary.is_none() && self.history.is_empty() && match self.outcome {
                Outcome::Invalid => invalid && self.guidance.code == "evidence-invalid",
                Outcome::Incomplete => !invalid && missing && self.guidance.code == "evidence-incomplete",
                Outcome::Inconsistent => !invalid && !missing && self.guidance.code == "evidence-inconsistent",
                Outcome::Consistent => false,
            };
        }
        let Some(summary) = &self.summary else { return false; };
        if invalid || missing || !summary.valid() || !self.history.iter().map(|row| row.stage).eq(self.stage.history().iter().copied()) { return false; }
        let mut previous = None;
        for row in &self.history {
            if !candidate::display_text(&row.recorded_readback, 64, 256) || !row.recorded_runs.valid()
                || !candidate::hex(&row.receipt_sha256, 64) || !candidate::hex(&row.intent_sha256, 64)
                || row.previous_receipt_sha256.as_deref() != previous { return false; }
            previous = Some(row.receipt_sha256.as_str());
        }
        let first = &self.history[0];
        // Runs are deliberately separate manifest/receipt declarations. Do not
        // invent equality between their recorded execution/production roles.
        if !summary.candidate_history_matches(&first.receipt_sha256, &first.intent_sha256) { return false; }
        match self.stage {
            Stage::Candidate => self.guidance.code == "candidate-only",
            Stage::ProductionSubmit => self.guidance.code == "production-recorded",
            Stage::ExternalTesting => self.guidance.code == "recorded-external-gate"
                || self.guidance.code == "ios-external-not-available" && summary.platform() == "ios"
                || self.guidance.code == "android-external-observation-only" && summary.platform() == "android",
        }
    }
}
pub(crate) fn result(value: Value, stage: Stage) -> Result<Observation, BridgeError> {
    candidate::bounds(&value)?;
    let result = Observation::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    // Reject positional objects, omitted nullable keys and every normalization.
    if result.stage != stage || !result.valid() || serde_json::to_value(&result).map_err(|_| BridgeError::protocol())? != value { return Err(BridgeError::protocol()); }
    Ok(result)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Selection { pub(crate) selection_id: String, pub(crate) display_name: String, pub(crate) stage: Stage }
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) operation_id: String, pub(crate) kind: OperationKind, pub(crate) selection_id: Option<String>, pub(crate) stage: Stage }
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u8, pub(crate) revision: String, pub(crate) availability: &'static str,
    pub(crate) phase: Phase, pub(crate) selection: Option<Selection>, pub(crate) operation: Option<Operation>,
    pub(crate) result: Option<Observation>, pub(crate) problem: Option<Problem>,
}
impl Status {
    pub(crate) fn unavailable(revision: u64) -> Self {
        Self { schema_version: 1, revision: revision.to_string(), availability: "unavailable", phase: Phase::Idle,
            selection: None, operation: None, result: None, problem: Some(Problem::Unavailable) }
    }
    pub(crate) fn checked(self) -> Result<Self, BridgeError> {
        if !self.valid() { return Err(BridgeError::protocol()); }
        candidate::bounds(&serde_json::to_value(&self).map_err(|_| BridgeError::protocol())?)?;
        Ok(self)
    }
    fn valid(&self) -> bool {
        if self.schema_version != 1 || !candidate::decimal(&self.revision, false, 20) || self.revision.parse::<u64>().is_err() { return false; }
        if self.selection.as_ref().is_some_and(|s| !candidate::selection_id(&s.selection_id)
            || !candidate::display_text(&s.display_name, 128, 512) || s.display_name.contains(['/', '\\'])) { return false; }
        if self.operation.as_ref().is_some_and(|op| candidate::operation_id(&op.operation_id).is_none()
            || match op.kind { OperationKind::Choose => op.selection_id.is_some(), OperationKind::Observe => !op.selection_id.as_deref().is_some_and(candidate::selection_id) }
            || self.selection.as_ref().is_some_and(|s| s.stage != op.stage)) { return false; }
        if self.availability == "unavailable" {
            return self.phase == Phase::Idle && self.selection.is_none() && self.operation.is_none()
                && self.result.is_none() && self.problem == Some(Problem::Unavailable);
        }
        if self.availability != "available" || (self.phase == Phase::Unknown) != (self.problem == Some(Problem::CleanupUnknown)) { return false; }
        if self.phase == Phase::Observed {
            if !self.result.as_ref().is_some_and(|r| r.valid() && self.selection.as_ref().is_some_and(|s| s.stage == r.stage)) { return false; }
        } else if self.result.is_some() { return false; }
        match self.phase {
            Phase::Idle => self.selection.is_none() && self.operation.is_none() && self.problem.is_none(),
            Phase::Choosing => self.selection.is_none() && self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Choose),
            Phase::Selected => self.selection.is_some() && self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Choose),
            Phase::Observing | Phase::Observed => self.problem.is_none() && self.operation.as_ref().is_some_and(|op| op.kind == OperationKind::Observe
                && self.selection.as_ref().is_some_and(|s| op.selection_id.as_deref() == Some(s.selection_id.as_str()))),
            Phase::Stopping => self.problem.is_some() && self.operation.is_some(),
            Phase::Cancelled => self.problem == Some(Problem::Cancelled) && self.operation.is_some(),
            Phase::Refused => self.problem.is_some(),
            Phase::Unknown => self.problem == Some(Problem::CleanupUnknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixtures() -> Value { serde_json::from_str(include_str!("../../tests/fixtures/lifecycle-evidence.json")).unwrap() }
    #[test]
    fn shared_core_fixtures_are_exact_documents_only_projections() {
        let fixtures = fixtures(); let rows = fixtures.as_object().unwrap(); assert_eq!(rows.len(), 13);
        for (name, value) in rows {
            let stage = Stage::deserialize(&value["stage"]).unwrap();
            assert_eq!(serde_json::to_value(result(value.clone(), stage).unwrap()).unwrap(), *value, "{name}");
        }
    }
    #[test]
    fn commands_cannot_supply_a_path_reclassify_a_selection_or_cancel_without_original_id() {
        for stage in ["candidate", "external-testing", "production-submit"] { assert!(choose_request(&json!({"stage":stage})).is_ok()); }
        for value in [json!({}), json!(["candidate"]), json!({"stage":"production"}), json!({"stage":"candidate","root":"private"})] { assert!(choose_request(&value).is_err()); }
        assert!(observe_request(&json!({"selectionId":"evidence-local"})).is_ok());
        assert!(observe_request(&json!({"selectionId":"evidence-local","stage":"production-submit"})).is_err());
        assert!(cancel_request(&json!({"operationId":"12","selectionId":null})).is_ok());
        assert!(cancel_request(&json!({"operationId":"12"})).is_err());
        assert!(cancel_request(&json!({"selectionId":"evidence-local"})).is_err());
        assert!(cancel_request(&json!({"operationId":"12","selectionId":null,"stage":"candidate"})).is_err());
    }
    #[test]
    fn stage_paths_purpose_and_assurances_are_closed() {
        let original = fixtures()["androidProduction"].clone();
        assert!(result(original.clone(), Stage::Candidate).is_err());
        let legacy: Value = serde_json::from_str(include_str!("../../tests/fixtures/candidate-evidence.json")).unwrap();
        assert!(result(legacy["androidConsistent"].clone(), Stage::Candidate).is_err());
        for flag in ["artifactBytesVerified", "workflowAuthenticated", "storeStateObserved", "comparedWithSourceProject", "releaseReady", "recoveryAuthorized"] {
            let mut value = original.clone(); value["assurance"][flag] = json!(true); assert!(result(value, Stage::ProductionSubmit).is_err());
        }
        for path in ["../candidate-manifest.json", "candidate-manifest.json", "https://private.invalid/proof"] {
            let mut value = original.clone(); value["documents"][0]["path"] = json!(path); assert!(result(value, Stage::ProductionSubmit).is_err());
        }
        let mut value = original.clone(); value["documents"].as_array_mut().unwrap().swap(0, 1); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original.clone(); value["guidance"]["message"] = json!("PRIVATE_CANARY"); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original; value["guidance"]["code"] = json!("release-ready"); assert!(result(value, Stage::ProductionSubmit).is_err());
    }
    #[test]
    fn history_digest_joins_order_nullable_fields_and_large_decimals_are_lossless() {
        let original = fixtures()["androidProduction"].clone();
        for field in ["previousReceiptSha256", "intentSha256", "receiptSha256"] {
            let mut value = original.clone(); value["history"][0][field] = json!("f".repeat(64)); assert!(result(value, Stage::ProductionSubmit).is_err());
        }
        let mut value = original.clone(); value["history"][1]["previousReceiptSha256"] = json!("f".repeat(64)); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original.clone(); value["history"].as_array_mut().unwrap().swap(0, 1); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original.clone(); value["history"][0].as_object_mut().unwrap().remove("previousReceiptSha256"); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original.clone(); value["history"][0]["recordedRuns"]["executedBy"]["runId"] = json!(9007199254740993u64); assert!(result(value, Stage::ProductionSubmit).is_err());
        let mut value = original; value["history"][0]["recordedRuns"]["executedBy"] = json!(["12","1"]); assert!(result(value, Stage::ProductionSubmit).is_err());
        let value = fixtures()["iosRecordedRetry"].clone();
        assert_ne!(value["summary"]["recordedRuns"], value["history"][0]["recordedRuns"]);
        assert_eq!(serde_json::to_value(result(value.clone(), Stage::Candidate).unwrap()).unwrap(), value);
    }
    #[test]
    fn failed_observations_have_no_history_or_summary_and_bounded_output() {
        for name in ["missingExternal", "invalidExternal", "inconsistentProduction"] {
            let original = fixtures()[name].clone(); let stage = Stage::deserialize(&original["stage"]).unwrap();
            let mut value = original.clone(); value["history"] = fixtures()["androidCandidate"]["history"].clone(); assert!(result(value, stage).is_err());
            let mut value = original.clone(); value["summary"] = fixtures()["androidCandidate"]["summary"].clone(); assert!(result(value, stage).is_err());
        }
        let mut value = fixtures()["androidCandidate"].clone(); value["history"][0]["recordedReadback"] = json!("x".repeat(65)); assert!(result(value, Stage::Candidate).is_err());
        let mut value = fixtures()["androidCandidate"].clone(); value["private"] = json!(vec![0;2049]); assert!(result(value, Stage::Candidate).is_err());
    }
    #[test]
    fn status_joins_selection_operation_and_result_stage_and_keeps_unknown_sticky_data() {
        let observation = result(fixtures()["androidCandidate"].clone(), Stage::Candidate).unwrap();
        let selected = Selection { selection_id: "evidence-local".into(), display_name: "Final evidence".into(), stage: Stage::Candidate };
        let op = Operation { operation_id: "12".into(), kind: OperationKind::Observe, selection_id: Some(selected.selection_id.clone()), stage: Stage::Candidate };
        let status = Status { schema_version:1, revision:"9007199254740993".into(), availability:"available", phase:Phase::Observed,
            selection:Some(selected), operation:Some(op), result:Some(observation), problem:None };
        assert!(status.clone().checked().is_ok());
        let mut bad = status.clone(); bad.operation.as_mut().unwrap().stage = Stage::ExternalTesting; assert!(bad.checked().is_err());
        let mut bad = status.clone(); bad.selection.as_mut().unwrap().stage = Stage::ProductionSubmit; assert!(bad.checked().is_err());
        let mut unknown = status; unknown.phase = Phase::Unknown; unknown.problem = Some(Problem::CleanupUnknown); assert!(unknown.clone().checked().is_err());
        unknown.result = None; assert!(unknown.clone().checked().is_ok()); unknown.problem = Some(Problem::Cancelled); assert!(unknown.checked().is_err());
        assert!(Status::unavailable(u64::MAX).checked().is_ok());
    }
}
