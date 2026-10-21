//! A closed facet of the original Connection/Activity, not another read owner.
use super::*;
use crate::{service_github_action_protocol as wire, service_github_action_requests as rows};
use std::sync::Weak;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Capture {
    request: p::Request,
    generation: u32,
    root: RegisteredRoot,
    credential_end: Instant,
}
pub(super) struct Permission {
    scope: Weak<rows::NativeScope>,
    capture: Capture,
    stamp: SavedEditStamp,
}
impl Permission {
    pub(super) fn heap(&self) -> Option<usize> {
        self.capture
            .request
            .heap()?
            .checked_add(self.capture.root.path.capacity())
    }
}
impl State {
    pub(super) fn revoke_agent(&mut self) {
        if let Some(permission) = self.agent_permission.take() {
            if let Some(scope) = permission.scope.upgrade() {
                scope.unused_closed();
            }
        }
    }
}
impl ConnectionState {
    pub(super) fn activity_write_review(&self) -> bool {
        self.preflight.consent.is_some()
            || self.release.consent.is_some()
            || self.setup.consent.is_some()
            || self.publication.activity_review_conflict()
            || self.repository_create.activity_review_conflict()
            || self.pull_request.activity_review_conflict()
            || self.actions_retry.activity_review_conflict()
            || self.play_cleanup.activity_review_conflict()
    }
    pub(crate) fn github_activity_agent_review(
        &self,
        selected: &wire::Selection,
        generation: u32,
        root: &RegisteredRoot,
        binding: &str,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<action_delegation::Review, BridgeError> {
        let wire::Selection::ActivityOverview(value) = selected else {
            return Err(refused(p::Reason::InvalidInput));
        };
        if !value.valid()
            || self.activity_write_review()
            || self.native_work_pending()
            || self.unknown
            || self.exhausted
            || self.activity.exhausted
            || self.activity.agent_permission.is_some()
            || !self.activity.view.available
            || self.activity.view.reason != p::Reason::None
            || value.expected_revision != self.activity.view.revision
            || value.expected_connection_revision != self.status.revision
        {
            return Err(refused(p::Reason::Busy));
        }
        let session = self
            .private
            .as_ref()
            .filter(|s| {
                s.id == value.session_id
                    && s.generation == generation
                    && s.retirement.is_none()
                    && s.token.is_some()
                    && now < s.clock.end
            })
            .ok_or_else(|| refused(p::Reason::NotConnected))?;
        let account = self
            .status
            .account
            .value
            .as_ref()
            .filter(|a| {
                self.status.account.state == FactState::Observed
                    && session.account_pin.as_ref() == Some(&a.id)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let repo = self
            .status
            .repository
            .value
            .as_ref()
            .filter(|r| {
                self.status.repository.state == FactState::Observed
                    && session.repository_pin.as_ref() == Some(&r.id)
                    && session.repository.eq_ignore_ascii_case(&r.full_name)
            })
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        let request = p::Request {
            target: p::Target {
                project_binding: binding.into(),
                repository: session.repository.clone(),
                account_id: account.id.clone(),
                repository_id: repo.id.clone(),
            },
            selection: p::Selection::Overview { branch: None },
        };
        if !request.valid() {
            return Err(refused(p::Reason::InvalidInput));
        }
        let data = wire::Review::ActivityOverview(wire::activity::Reference {
            session_id: value.session_id.clone(),
            expected_revision: value.expected_revision,
            expected_connection_revision: value.expected_connection_revision,
            account_id: account.id.clone(),
            repository_id: repo.id.clone(),
        });
        if !data.valid() {
            return Err(BridgeError::protocol());
        }
        Ok(action_delegation::Review {
            identity: self.activity.agent_identity.clone(),
            stamp: edit.stamp()?,
            end: now
                .checked_add(Duration::from_millis(wire::INTENT_MS))
                .ok_or_else(BridgeError::protocol)?
                .min(session.clock.end),
            data,
            activity: Some(Capture {
                request,
                generation,
                root: root.clone(),
                credential_end: session.clock.end,
            }),
        })
    }
    pub(crate) fn github_activity_agent_allow(
        &mut self,
        review: action_delegation::Review,
        scope: &Arc<rows::NativeScope>,
    ) -> Result<(), BridgeError> {
        if self.activity.agent_permission.is_some()
            || self.activity_write_review()
            || self.native_work_pending()
            || !Arc::ptr_eq(&review.identity, &self.activity.agent_identity)
            || scope.review != review.data
            || !Arc::ptr_eq(&scope.identity, &review.identity)
            || scope.current(false).is_err()
        {
            return Err(refused(p::Reason::Busy));
        }
        let capture = review.activity.ok_or_else(BridgeError::invalid)?;
        self.activity.agent_permission = Some(Permission {
            scope: Arc::downgrade(scope),
            capture,
            stamp: review.stamp,
        });
        Ok(())
    }
    pub(crate) fn github_activity_agent_revoke(&mut self, scope: &Arc<rows::NativeScope>) {
        if self
            .activity
            .agent_permission
            .as_ref()
            .and_then(|p| p.scope.upgrade())
            .is_some_and(|s| Arc::ptr_eq(&s, scope))
        {
            self.activity.revoke_agent();
        }
        // An entered original stays on its Active/ticket; its first READ/STOP
        // timestamp is sampled by the same Supervisor, never a replacement read.
    }
    pub(crate) fn github_activity_agent_current(
        &self,
        entry: &Arc<rows::Entry>,
        args: &p::ReadArgs,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
    ) -> Result<(), BridgeError> {
        entry
            .current(false)
            .map_err(crate::asset_session::application_service::public_error)?;
        let scope = entry.scope();
        let wire::Review::ActivityOverview(reference) = &scope.review else {
            return Err(BridgeError::invalid());
        };
        let permission = self
            .activity
            .agent_permission
            .as_ref()
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if !Arc::ptr_eq(&scope.identity, &self.activity.agent_identity)
            || permission
                .scope
                .upgrade()
                .is_none_or(|s| !Arc::ptr_eq(&s, scope))
            || generation != permission.capture.generation
            || root != &permission.capture.root
            || !edit.matches(&permission.stamp)
            || args.session_id != reference.session_id
            || args.project_id != scope.runtime_id
            || args.expected_revision != reference.expected_revision
            || args.expected_connection_revision != reference.expected_connection_revision
            || args.selection != (p::Selection::Overview { branch: None })
            || self.activity_write_review()
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        Ok(())
    }
    pub(super) fn activity_agent_take(
        &mut self,
        entry: &Arc<rows::Entry>,
        request: &p::Request,
        generation: u32,
        root: &RegisteredRoot,
    ) -> Result<(), BridgeError> {
        let permission = self
            .activity
            .agent_permission
            .as_ref()
            .ok_or_else(|| refused(p::Reason::TargetChanged))?;
        if &permission.capture.request != request
            || generation != permission.capture.generation
            || root != &permission.capture.root
            || permission
                .scope
                .upgrade()
                .is_none_or(|s| !Arc::ptr_eq(&s, entry.scope()))
            || self.activity_write_review()
        {
            return Err(refused(p::Reason::TargetChanged));
        }
        // All actual pre-entry cuts have returned. Consume only this permission;
        // it can never authorize a second read even if admission is later lost.
        self.activity.agent_permission.take();
        Ok(())
    }
}
pub(super) fn accepted(
    entry: &Option<Arc<rows::Entry>>,
    id: &str,
    reason: p::Reason,
    observation: Option<&p::Observation>,
) {
    let Some(entry) = entry else { return };
    let mapped = match reason {
        p::Reason::None => wire::Reason::None,
        p::Reason::Cancelled => wire::Reason::UserCancelled,
        p::Reason::Expired => wire::Reason::Expired,
        p::Reason::TargetChanged | p::Reason::SelectionChanged => wire::Reason::ContextChanged,
        p::Reason::Busy => wire::Reason::Busy,
        p::Reason::RuntimeUnavailable | p::Reason::Unqualified => wire::Reason::Unavailable,
        p::Reason::CleanupUnknown => wire::Reason::CleanupUnknown,
        _ => wire::Reason::NativeRefused,
    };
    if mapped == wire::Reason::CleanupUnknown {
        entry.unknown(mapped);
    } else {
        entry.activity_returned(
            id,
            mapped,
            if mapped == wire::Reason::None {
                observation.and_then(|o| wire::activity::Snapshot::from_observation(o).ok())
            } else {
                None
            },
        );
    }
}

// Native-only borrowed projection. The standalone CLI wire/Entry needs no
// Connection protocol or transport module.
use crate::{github_activity_protocol as native, service_protocol::Error};
use wire::activity::{
    decimal, Conclusion, Coverage, Pull, PullState, Run, RunState, Section, SectionReason,
    SectionState, ROWS,
};
impl wire::activity::Snapshot {
    /// The original Connection calls this only after protocol and final control
    /// acceptance. Recheck the borrowed native data; never copy its Value tree.
    pub(crate) fn from_observation(o: &native::Observation) -> Result<Self, Error> {
        let fail = || Error::InvalidRequest;
        if o.selection != (native::Selection::Overview { branch: None })
            || !native::data_valid(
                &o.data,
                &native::Request {
                    target: o.target.clone(),
                    selection: o.selection.clone(),
                },
            )
        {
            return Err(fail());
        }
        fn section<T>(
            v: &serde_json::Value,
            project: impl Fn(&serde_json::Value) -> Option<T>,
        ) -> Option<Section<T>> {
            let source = v["rows"].as_array()?;
            if source.len() > ROWS {
                return None;
            }
            let mut rows = Vec::with_capacity(source.len());
            for r in source {
                rows.push(project(r)?);
            }
            Some(Section {
                state: SectionState::from_str(v["state"].as_str()?)?,
                reason: SectionReason::from_str(v["reason"].as_str()?)?,
                coverage: Coverage::from_str(v["coverage"].as_str()?)?,
                total: if v["total"].is_null() {
                    None
                } else {
                    Some(u32::try_from(v["total"].as_u64()?).ok()?)
                },
                rows,
            })
        }
        let s = Self {
            account_id: decimal(&o.target.account_id, false).ok_or_else(fail)?,
            repository_id: decimal(&o.target.repository_id, false).ok_or_else(fail)?,
            observed_at: o.observed_at.clone(),
            pull_requests: section(&o.data["pullRequests"], |r| {
                Some(Pull {
                    number: decimal(r["number"].as_str()?, false)?,
                    state: PullState::from_str(r["state"].as_str()?)?,
                    draft: r["draft"].as_bool()?,
                })
            })
            .ok_or_else(fail)?,
            workflow_runs: section(&o.data["workflowRuns"], |r| {
                Some(Run {
                    id: decimal(r["id"].as_str()?, false)?,
                    attempt: u16::try_from(r["attempt"].as_u64()?).ok()?,
                    status: RunState::from_str(r["status"].as_str()?)?,
                    conclusion: if r["conclusion"].is_null() {
                        None
                    } else {
                        Some(Conclusion::from_str(r["conclusion"].as_str()?)?)
                    },
                })
            })
            .ok_or_else(fail)?,
        };
        if !s.valid() {
            return Err(fail());
        }
        Ok(s)
    }
}

#[cfg(test)]
#[path = "service_github_activity_native_tests.rs"]
mod tests;
