//! Fetch DATA in schema6 of the SAME GitOperations row. Only original
//! GitLocalNativeJoined can supply final data to the existing final CAS.
//! These values cannot grant a request, adopt a pack, repair or retry anything.
use crate::{error::BridgeError, git_fetch_protocol as fetch, git_local_protocol as local};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalData {
    pub(crate) effect_phase: fetch::Effect,
    pub(crate) retained_paths: Vec<String>,
}
impl FinalData {
    pub(crate) fn valid(&self, intent: Option<&fetch::Intent>) -> bool {
        self.retained_paths.len() <= 5
            && self.retained_paths.windows(2).all(|p| p[0] < p[1])
            && self
                .retained_paths
                .iter()
                .all(|p| fetch::retained_path(p, intent))
            && (self.effect_phase == fetch::Effect::NotPublished
                || intent.is_some_and(fetch::Intent::valid))
    }
    pub(crate) fn successful(&self, intent: Option<&fetch::Intent>) -> bool {
        self.valid(intent)
            && self.effect_phase == fetch::Effect::RefPublished
            && self.retained_paths.is_empty()
    }
    /// This does not create the joined witness. Its only caller is the SAME
    /// original Supervisor after its positive publication and all prior joins.
    pub(crate) fn from_returned(
        request: &local::Request,
        candidate: &local::Candidate,
        terminal: &local::Terminal,
        returned: &local::fetch_worker::Returned,
    ) -> Result<Self, BridgeError> {
        let local::Action::Fetch(action) = &request.action else {
            return Err(BridgeError::protocol());
        };
        let intent = candidate
            .intent
            .fetch_details()
            .ok_or_else(BridgeError::protocol)?;
        let result: fetch::Mutation =
            serde_json::from_value(terminal.result.clone()).map_err(|_| BridgeError::protocol())?;
        if terminal.phase != local::Phase::Apply
            || terminal.action != local::Kind::Fetch
            || terminal.status != crate::git_read_protocol::Outcome::Ok
            || !terminal.child_declared_settled()
            || terminal.fetch_publication.as_ref() != Some(returned)
            || !request
                .native
                .as_ref()
                .is_some_and(|n| returned.valid(intent, n))
            || !result.valid(action, &request.id)
            || result.intent.as_ref() != Some(intent)
            || !request
                .binding
                .as_ref()
                .is_some_and(|b| candidate.intent.matches(&b.review))
            || result.effect_phase != returned.phase
        {
            return Err(BridgeError::protocol());
        }
        let value = Self {
            effect_phase: result.effect_phase,
            retained_paths: result.retained_paths,
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
    // The bounded metadata review has no paths, contents, token or credential
    // reference. Storing it explains the original target even before a pack
    // exists; deserializing it is never another native review/Apply grant.
    pub(crate) reviewed: fetch::Review,
    pub(crate) candidate: Option<fetch::Intent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_state: Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(review: &fetch::Review) -> Self {
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
            && !self.reviewed.up_to_date()
            && self.reviewed.expected_revision == revision
            && self.reviewed.head.as_deref() == head
            && self.reviewed.branch.as_deref() == reference
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
    pub(crate) fn accepts(&self, intent: &fetch::Intent) -> bool {
        self.candidate.is_none() && self.final_state.is_none() && intent.matches(&self.reviewed)
    }
}
