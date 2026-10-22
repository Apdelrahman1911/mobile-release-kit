//! Private inputs for the three ORIGINAL owners, not another executor. The
//! captured PR text is one immutable Arc; service/CLI rows contain only hashes.
use super::*;
use crate::{asset_source::RegisteredRoot, edit_owner::SavedEditGuard,
    github_repository_create_protocol as repository, github_pull_request_protocol as pr,
    github_actions_retry_protocol as retry};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub(crate) use super::dispatch::{Producer, Records, producer_ready, hash};
pub(crate) const INPUT_BACKING: usize = 8192;
pub(crate) const MAIN_RAW_LIMIT: usize = 16 * 1024 + 512;
pub(crate) const ROOT_BACKING: usize = super::dispatch::ROOT_BACKING;
pub(crate) const CONTEXT_BACKING: usize = 768;

pub(crate) fn shared<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Arc<T>, D::Error> {
    T::deserialize(d).map(Arc::new)
}
pub(crate) fn pr_input<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<pr::PrepareArgs>, D::Error> {
    let mut a = pr::PrepareArgs::deserialize(d)?;
    if !a.valid() { return Err(serde::de::Error::custom("PR input")); }
    // One bounded normalization, not another JSON tree/parser. String capacities
    // cannot be inferred from valid lengths. Drop still zeroizes the same Draft.
    fn compact(s: &mut String) { *s = std::mem::take(s).into_boxed_str().into_string(); }
    compact(&mut a.session_id);
    compact(&mut a.draft.base); compact(&mut a.draft.head);
    compact(&mut a.draft.title); compact(&mut a.draft.body);
    Ok(Arc::new(a))
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Input {
    RepositoryPrepare(Arc<repository::PrepareArgs>),
    RepositoryPending(Arc<repository::PendingArgs>),
    RepositoryReconcile(Arc<repository::ReconcileArgs>),
    PrPrepare(Arc<pr::PrepareArgs>),
    PrPending(Arc<pr::PendingArgs>),
    PrReconcile(Arc<pr::ReconcileArgs>),
    FailedJobsPrepare(Arc<retry::PrepareArgs>),
    FailedJobsPending(Arc<retry::PendingArgs>),
    FailedJobsReconcile(Arc<retry::ReconcileArgs>),
}
// No Serialize/Debug implementation for Arc<Draft> or token-bearing state.
// The borrowed tag is exactly the closed MAIN selection, hashed by a fixed sink.
impl Serialize for Input {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        enum Ref<'a> {
            RepositoryPrepare(&'a repository::PrepareArgs), RepositoryPending(&'a repository::PendingArgs),
            RepositoryReconcile(&'a repository::ReconcileArgs), PrPrepare(&'a pr::PrepareArgs),
            PrPending(&'a pr::PendingArgs), PrReconcile(&'a pr::ReconcileArgs),
            FailedJobsPrepare(&'a retry::PrepareArgs), FailedJobsPending(&'a retry::PendingArgs),
            FailedJobsReconcile(&'a retry::ReconcileArgs),
        }
        match self {
            Self::RepositoryPrepare(v) => Ref::RepositoryPrepare(v).serialize(s),
            Self::RepositoryPending(v) => Ref::RepositoryPending(v).serialize(s),
            Self::RepositoryReconcile(v) => Ref::RepositoryReconcile(v).serialize(s),
            Self::PrPrepare(v) => Ref::PrPrepare(v).serialize(s), Self::PrPending(v) => Ref::PrPending(v).serialize(s),
            Self::PrReconcile(v) => Ref::PrReconcile(v).serialize(s),
            Self::FailedJobsPrepare(v) => Ref::FailedJobsPrepare(v).serialize(s),
            Self::FailedJobsPending(v) => Ref::FailedJobsPending(v).serialize(s),
            Self::FailedJobsReconcile(v) => Ref::FailedJobsReconcile(v).serialize(s),
        }
    }
}
impl Input {
    pub(crate) fn kind(&self) -> p::Kind {
        match self {
            Self::RepositoryPrepare(_) => p::Kind::RepositoryPrepare, Self::RepositoryPending(_) => p::Kind::RepositoryPending,
            Self::RepositoryReconcile(_) => p::Kind::RepositoryReconcile, Self::PrPrepare(_) => p::Kind::PrPrepare,
            Self::PrPending(_) => p::Kind::PrPending, Self::PrReconcile(_) => p::Kind::PrReconcile,
            Self::FailedJobsPrepare(_) => p::Kind::FailedJobsPrepare, Self::FailedJobsPending(_) => p::Kind::FailedJobsPending,
            Self::FailedJobsReconcile(_) => p::Kind::FailedJobsReconcile,
        }
    }
    pub(crate) fn session(&self) -> &str {
        match self {
            Self::RepositoryPrepare(v) => &v.session_id, Self::RepositoryPending(v) => &v.session_id,
            Self::RepositoryReconcile(v) => &v.session_id, Self::PrPrepare(v) => &v.session_id,
            Self::PrPending(v) => &v.session_id, Self::PrReconcile(v) => &v.session_id,
            Self::FailedJobsPrepare(v) => &v.session_id, Self::FailedJobsPending(v) => &v.session_id,
            Self::FailedJobsReconcile(v) => &v.session_id,
        }
    }
    pub(crate) fn revision(&self) -> u32 {
        match self {
            Self::RepositoryPrepare(v) => v.expected_revision, Self::RepositoryPending(v) => v.expected_revision,
            Self::RepositoryReconcile(v) => v.expected_revision, Self::PrPrepare(v) => v.expected_revision,
            Self::PrPending(v) => v.expected_revision, Self::PrReconcile(v) => v.expected_revision,
            Self::FailedJobsPrepare(v) => v.expected_revision, Self::FailedJobsPending(v) => v.expected_revision,
            Self::FailedJobsReconcile(v) => v.expected_revision,
        }
    }
    pub(crate) fn connection_revision(&self) -> Option<u32> {
        match self {
            Self::RepositoryPrepare(v) => Some(v.expected_connection_revision), Self::RepositoryPending(v) => Some(v.expected_connection_revision),
            Self::PrPrepare(v) => Some(v.expected_connection_revision), Self::PrPending(v) => Some(v.expected_connection_revision),
            Self::FailedJobsPrepare(v) => Some(v.expected_connection_revision), Self::FailedJobsPending(v) => Some(v.expected_connection_revision),
            _ => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        let scalar = match self {
            Self::RepositoryPrepare(v) => v.valid(), Self::RepositoryPending(v) => v.valid(), Self::RepositoryReconcile(v) => v.valid(),
            Self::PrPrepare(v) => v.valid(), Self::PrPending(v) => v.valid(), Self::PrReconcile(v) => v.valid(),
            Self::FailedJobsPrepare(v) => v.valid(), Self::FailedJobsPending(v) => v.valid(), Self::FailedJobsReconcile(v) => v.valid(),
        };
        if !scalar { return false; }
        use crate::service_metadata_text_protocol::bounded;
        match self {
            Self::RepositoryPrepare(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::RepositoryPending(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::RepositoryReconcile(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::PrPrepare(v) => bounded(v.as_ref(),16*1024).is_ok(),
            Self::PrPending(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::PrReconcile(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::FailedJobsPrepare(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::FailedJobsPending(v) => bounded(v.as_ref(),1024).is_ok(),
            Self::FailedJobsReconcile(v) => bounded(v.as_ref(),1024).is_ok(),
        }
    }
    /// Includes the SINGLE real Arc allocation and its typed payload. Captures
    /// and caller clones share this allocation; State.heap charges it once.
    pub(crate) fn heap(&self) -> Option<usize> {
        use std::mem::size_of_val;
        let (session, cell, extra) = match self {
            Self::RepositoryPrepare(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), 0),
            Self::RepositoryPending(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), 0),
            Self::RepositoryReconcile(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), v.marker.capacity()),
            Self::PrPrepare(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), v.draft.heap()?),
            Self::PrPending(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), 0),
            Self::PrReconcile(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), v.marker.capacity()),
            Self::FailedJobsPrepare(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), v.run_id.capacity()),
            Self::FailedJobsPending(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), 0),
            Self::FailedJobsReconcile(v) => (v.session_id.capacity(), size_of_val(v.as_ref()), v.marker.capacity()),
        };
        session.checked_add(cell)?.checked_add(extra)?.checked_add(2 * std::mem::size_of::<usize>())
    }
    pub(crate) fn retained_fits(&self) -> bool { self.valid() && self.heap().is_some_and(|n| n <= INPUT_BACKING) }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RepositoryPrepare(a), Self::RepositoryPrepare(b)) => Arc::ptr_eq(a,b),
            (Self::RepositoryPending(a), Self::RepositoryPending(b)) => Arc::ptr_eq(a,b),
            (Self::RepositoryReconcile(a), Self::RepositoryReconcile(b)) => Arc::ptr_eq(a,b),
            (Self::PrPrepare(a), Self::PrPrepare(b)) => Arc::ptr_eq(a,b),
            (Self::PrPending(a), Self::PrPending(b)) => Arc::ptr_eq(a,b),
            (Self::PrReconcile(a), Self::PrReconcile(b)) => Arc::ptr_eq(a,b),
            (Self::FailedJobsPrepare(a), Self::FailedJobsPrepare(b)) => Arc::ptr_eq(a,b),
            (Self::FailedJobsPending(a), Self::FailedJobsPending(b)) => Arc::ptr_eq(a,b),
            (Self::FailedJobsReconcile(a), Self::FailedJobsReconcile(b)) => Arc::ptr_eq(a,b),
            _ => false,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Capture {
    pub(crate) input: Input,
    pub(crate) generation: u32,
    pub(crate) root: RegisteredRoot,
    pub(crate) credential_end: Instant,
    pub(crate) account: String,
    pub(crate) account_login: String,
    pub(crate) repository: Option<String>,
    pub(crate) coordinate: String,
    pub(crate) binding: String,
    pub(crate) retry_head: Option<String>,
}
impl Capture {
    pub(crate) fn retained_fits(&self) -> bool {
        self.root.path.capacity() <= ROOT_BACKING && self.input.retained_fits()
            && self.context_heap().is_some_and(|n| n <= CONTEXT_BACKING)
    }
    fn context_heap(&self) -> Option<usize> {
        [self.account.capacity(), self.account_login.capacity(), self.repository.as_ref().map_or(0,String::capacity),
            self.coordinate.capacity(), self.binding.capacity(), self.retry_head.as_ref().map_or(0,String::capacity)]
            .into_iter().try_fold(0usize, |n,v| n.checked_add(v))
    }
    pub(crate) fn heap(&self) -> Option<usize> { self.input.heap()?.checked_add(self.context_heap()?)?.checked_add(self.root.path.capacity()) }
    pub(crate) fn same(&self, other: &Self) -> bool { self.input.same_original(&other.input) && self == other }
}
pub(crate) struct Permission {
    pub(crate) scope: Weak<r::NativeScope>,
    pub(crate) capture: Capture,
    pub(crate) stamp: SavedEditStamp,
    pub(crate) claimed: bool,
}
impl Permission {
    pub(crate) fn heap(&self) -> Option<usize> { self.capture.heap() }
    pub(crate) fn close(self) { if let Some(s) = self.scope.upgrade() { s.unused_closed(); } }
}
impl ConnectionState {
    pub(crate) fn operation_capture(&self, input: Input, generation: u32, root: &RegisteredRoot,
        binding: &str, now: Instant) -> Result<Capture, BridgeError> {
        if !input.retained_fits() || self.unknown || self.exhausted || self.native_work_pending()
            || self.cooldown_blocked || self.cooldown.is_some_and(|v| now < v) { return Err(BridgeError::invalid()); }
        let private = self.private.as_ref().filter(|v| v.id == input.session() && v.generation == generation
            && v.retirement.is_none() && v.token.is_some() && now < v.clock.end).ok_or_else(BridgeError::invalid)?;
        if input.connection_revision().is_some_and(|n| n != self.status.revision)
            || !self.status.session.as_ref().is_some_and(|s| s.state == SessionState::Connected) { return Err(BridgeError::invalid()); }
        let account = self.status.account.value.as_ref().filter(|v| self.status.account.state == FactState::Observed
            && private.account_pin.as_ref() == Some(&v.id)).ok_or_else(BridgeError::invalid)?;
        let repository = if matches!(input, Input::RepositoryPrepare(_) | Input::RepositoryPending(_) | Input::RepositoryReconcile(_)) {
            // The same /user-only original path. Missing repository metadata is
            // neither a reason to disable review nor evidence of remote absence.
            None
        } else {
            Some(self.status.repository.value.as_ref().filter(|v| self.status.repository.state == FactState::Observed
                && private.repository_pin.as_ref() == Some(&v.id)
                && private.repository.eq_ignore_ascii_case(&v.full_name)).ok_or_else(BridgeError::invalid)?.id.clone())
        };
        let retry_head = if let Input::FailedJobsPrepare(a) = &input {
            let scope = retry::Scope { project_binding: binding.into(), repository: private.repository.clone(),
                account_id: account.id.clone(), repository_id: repository.clone().ok_or_else(BridgeError::invalid)? };
            Some(self.activity.actions_retry_head(a.activity_revision, &a.session_id, &private.project_id,
                &scope, &a.run_id, a.attempt).ok_or_else(BridgeError::invalid)?.to_owned())
        } else { None };
        let capture = Capture { input, generation, root: root.clone(), credential_end: private.clock.end,
            account: account.id.clone(), account_login: account.login.clone(), repository,
            coordinate: private.repository.clone(), binding: binding.into(), retry_head };
        if !capture.retained_fits() { return Err(BridgeError::invalid()); }
        Ok(capture)
    }
}

impl ConnectionState {
    pub(crate) fn operation_permission_retained(&self)->bool {
        self.repository_create_operation_permission_retained() || self.pull_request_operation_permission_retained()
            || self.actions_retry_operation_permission_retained()
    }
}

#[cfg(test)]
#[path="github_operation_delegation_tests.rs"]
pub(crate) mod tests;
