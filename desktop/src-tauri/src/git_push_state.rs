//! Schema8 DATA within the original GitOperations row, not another journal.
//! A decoded row cannot recover an old send permit, original Connection, or
//! native join. Candidate/unknown remains a fence even after a matching GET.
use crate::{error::BridgeError, git_local_protocol as local, git_push_protocol as push};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalData {
    pub(crate) effect_phase: push::Effect,
    pub(crate) retained_paths: Vec<String>,
    pub(crate) transmission: local::push_worker::Returned,
}
impl FinalData {
    pub(crate) fn valid(&self, intent: Option<&push::Intent>) -> bool {
        self.effect_phase == push::Effect::RemoteReturned
            && self.retained_paths.len() <= 1
            && self.retained_paths.iter().all(|v| push::retained_path(v))
            && intent.is_some_and(|i| self.transmission.valid(i))
    }
    pub(crate) fn successful(&self, intent: Option<&push::Intent>) -> bool {
        self.valid(intent) && self.retained_paths.is_empty()
    }
    /// Comparison invoked by the real parent's joined arm; this is not that
    /// join witness and cannot call the final CAS by itself.
    pub(crate) fn from_returned(
        request: &local::Request,
        candidate: &local::Candidate,
        terminal: &local::Terminal,
        returned: &local::push_worker::Returned,
    ) -> Result<Self, BridgeError> {
        let local::Action::Push(action) = &request.action else {
            return Err(BridgeError::protocol());
        };
        let intent = candidate
            .intent
            .push_details()
            .ok_or_else(BridgeError::protocol)?;
        let result: push::Mutation =
            serde_json::from_value(terminal.result.clone()).map_err(|_| BridgeError::protocol())?;
        if request.phase != local::Phase::Apply
            || terminal.phase != local::Phase::Apply
            || terminal.action != local::Kind::Push
            || terminal.status != crate::git_read_protocol::Outcome::Ok
            || !terminal.child_declared_settled()
            || terminal.push_transmission.as_ref() != Some(returned)
            || !returned.valid(intent)
            || !result.valid(action, &request.id)
            || result.intent.as_ref() != Some(intent)
            || !request
                .binding
                .as_ref()
                .is_some_and(|b| candidate.intent.matches(&b.review))
            || request.native.is_none()
            || request.initialization.is_some()
            || request.fetch_target.is_some()
            || result.effect_phase != push::Effect::RemoteReturned
        {
            return Err(BridgeError::protocol());
        }
        let value = Self {
            effect_phase: result.effect_phase,
            retained_paths: result.retained_paths,
            transmission: returned.clone(),
        };
        if !value.valid(Some(intent)) {
            return Err(BridgeError::protocol());
        }
        Ok(value)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    pub(crate) reviewed: push::Review,
    pub(crate) candidate: Option<push::Intent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_state: Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(review: &push::Review) -> Self {
        Self {
            reviewed: review.clone(),
            candidate: None,
            final_state: None,
        }
    }
    pub(crate) fn valid(
        &self,
        revision: &str,
        head: Option<&str>,
        reference: Option<&str>,
        index: &str,
        review_digest: &str,
    ) -> bool {
        self.reviewed.valid()
            && self.reviewed.expected_revision == revision
            && Some(self.reviewed.head.as_str()) == head
            && Some(self.reviewed.branch.as_str()) == reference
            && self.reviewed.expected_index == index
            && self.reviewed.review_digest == review_digest
            && self
                .candidate
                .as_ref()
                .is_none_or(|i| i.matches(&self.reviewed))
            && self
                .final_state
                .as_ref()
                .is_none_or(|d| d.valid(self.candidate.as_ref()))
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        self.reviewed == other.reviewed
    }
    pub(crate) fn accepts(&self, intent: &push::Intent) -> bool {
        self.candidate.is_none() && self.final_state.is_none() && intent.matches(&self.reviewed)
    }
}
