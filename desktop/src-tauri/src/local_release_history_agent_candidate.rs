//! Private-field comparison projection only; never opens or updates a journal.
use super::CandidateInputs;
use crate::agent_candidate_build::{Candidate, ANDROID_PRIMARY_BYTES};

impl CandidateInputs {
    pub(crate) fn agent_candidate(&self, operation: &str, head_sequence: u32) -> Option<Candidate> {
        if !self.valid(operation) {
            return None;
        }
        let result = Candidate {
            operation_id: self.operation_id.clone(),
            head_sequence,
            candidate_sha256: self.candidate_sha256.clone(),
            source_commit: self.source_commit.clone(),
            source_tree: self.source_tree.clone(),
            primary_bytes: self.files[0].bytes,
            primary_sha256: self.files[0].sha256.clone(),
        };
        result.valid(ANDROID_PRIMARY_BYTES).then_some(result)
    }
}
