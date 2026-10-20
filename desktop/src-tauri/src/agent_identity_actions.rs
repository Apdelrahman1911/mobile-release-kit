//! One-use delegation of an ALREADY OPENED identity proposal. This is a child
//! of the existing 32-entry inbox, not an executor, a new queue or a write grant
//! derived from read access. Only original EditOwner hooks publish observations.
use super::*;
use crate::service_protocol::{OperationState, Settlement};

pub const CONSENT: &str = "agent-exact-opened-identity-edit-v1";
pub const REPORT_LIMIT: usize = 64 * 1024;
// Compact paths (65 * <=512), IDs once per review, 32 retained entries plus
// sixteen IPC/GUI/native comparison copies and allocation slack. Charged through
// the SAME inbox census, not a new quota or a claim about process RSS.
pub(crate) const DOCUMENT_BACKING: usize = (LIMIT + 16) * REPORT_LIMIT;
const IDLE: u8 = 0;
const QUEUE: u8 = 1;
const ADMIT: u8 = 2;
const SENT: u8 = 3;
const DENIED: u8 = 4;
const DOUBT: u8 = 5;

// Explicit null is valid, but serde must still reject an absent field. The
// parent helper is intentionally String-only for Selection.project.
fn required_nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub operation_id: Id,
    pub owner_generation: Id,
    pub revision: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Start {
    pub origin: Query,
    pub original: Original,
    pub plan_token: Id,
    pub reviewed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    NotRequested,
    Queued,
    Admitting,
    Submitted,
    Refused,
    Unconfirmed,
}
fn step(value: u8) -> Step {
    match value {
        IDLE => Step::NotRequested,
        QUEUE => Step::Queued,
        ADMIT => Step::Admitting,
        SENT => Step::Submitted,
        DENIED => Step::Refused,
        _ => Step::Unconfirmed,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    NotStarted,
    Unchanged,
    Committed,
    RolledBack,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Journal {
    NotCreated,
    Clean,
    RecoveryRequired,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    SavedIdentity,
    AndroidApplicationId,
    IosBundleId,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub role: Role,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub plan_token: Id,
    pub before_identity: String,
    pub after_identity: String,
    pub changes: Vec<Location>,
    pub unchanged: bool,
    pub new_application_warning: bool,
    pub build_verification_required: bool,
    pub retain_version_reservations: bool,
}
impl Review {
    pub(crate) fn valid(&self, change: &Change) -> bool {
        let mut before = change.clone();
        before.desired_identity = self.before_identity.clone();
        before.validate().is_ok()
            && self.after_identity == change.desired_identity
            && self.build_verification_required
            && self.retain_version_reservations
            && self.unchanged == (self.before_identity == self.after_identity)
            && self.new_application_warning == !self.unchanged
            && (self.unchanged && self.changes.is_empty()
                || !self.unchanged
                    && change.identity_intent == IdentityIntent::NewApplication
                    && (2..=65).contains(&self.changes.len())
                    && self
                        .changes
                        .iter()
                        .filter(|r| r.role == Role::SavedIdentity)
                        .count()
                        == 1)
            && self.changes.iter().enumerate().all(|(i, r)| {
                !self.changes[..i].iter().any(|before| {
                    before.path == r.path && before.line == r.line && before.column == r.column
                })
            })
            && self.changes.iter().all(|r| {
                r.line > 0
                    && r.line <= 2 * 1024 * 1024
                    && r.column > 0
                    && r.column <= 2 * 1024 * 1024
                    && relative_path(&r.path)
                    && (r.role == Role::SavedIdentity) == (r.path == "release/mobile-release.json")
                    && match change.selection.platform {
                        Platform::Android => r.role != Role::IosBundleId,
                        Platform::Ios => r.role != Role::AndroidApplicationId,
                    }
            })
    }
}
fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').count() <= 16
        && path.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.+ @()-".contains(&c))
                && ![
                    ".git",
                    ".gradle",
                    ".idea",
                    ".mobile-release",
                    "build",
                    "deriveddata",
                    "pods",
                    "node_modules",
                    "private",
                    "secrets",
                    "credentials",
                    "xcuserdata",
                ]
                .contains(&p.to_ascii_lowercase().as_str())
                && ![".mobile-release-", ".private-", ".codex-private-"]
                    .iter()
                    .any(|s| p.to_ascii_lowercase().starts_with(s))
        })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub status_revision: u32,
    pub state: OperationState,
    pub settlement: Settlement,
    pub apply_submitted: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub review: Option<Review>,
    #[serde(deserialize_with = "required_nullable")]
    pub effect: Option<Effect>,
    #[serde(deserialize_with = "required_nullable")]
    pub journal: Option<Journal>,
}
impl Observation {
    fn valid(&self, change: &Change, original: &Original) -> bool {
        self.status_revision > 0
            && self.effect.is_some() == self.journal.is_some()
            && self
                .review
                .as_ref()
                .is_none_or(|r| r.valid(change) && r.plan_token != original.revision)
            && (!self.apply_submitted
                || self.review.is_some()
                || self.state == OperationState::Unknown)
            && (self.state == OperationState::Unknown
                || self.effect != Some(Effect::Unknown) && self.journal != Some(Journal::Unknown))
            && (self.settlement != Settlement::Settled
                || self.journal != Some(Journal::RecoveryRequired)
                || self.state == OperationState::RecoveryRequired)
            && match (self.state, self.settlement) {
                (OperationState::Unknown, Settlement::Unknown) => true,
                (
                    OperationState::Running | OperationState::CancellationRequested,
                    Settlement::Pending,
                ) => true,
                (OperationState::Prepared, Settlement::Pending) => {
                    self.review.is_some() && !self.apply_submitted
                }
                (OperationState::Succeeded, Settlement::Settled) => {
                    self.apply_submitted
                        && (self.effect == Some(Effect::Committed)
                            && self.journal == Some(Journal::Clean)
                            || self.effect == Some(Effect::Unchanged)
                                && matches!(
                                    self.journal,
                                    Some(Journal::Clean | Journal::NotCreated)
                                ))
                }
                (OperationState::RecoveryRequired, Settlement::Settled) => {
                    self.journal == Some(Journal::RecoveryRequired)
                }
                (OperationState::Failed | OperationState::Cancelled, Settlement::Settled) => true,
                _ => false,
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub origin: Query,
    pub change: Change,
    pub original: Original,
    pub prepare: Step,
    pub start: Step,
    pub permission_live: bool,
    pub remaining_ms: u64,
    pub cancel_requested: bool,
    pub unconfirmed: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub observation: Option<Observation>,
    pub do_not_replay: bool,
    pub history_must_be_queried: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        self.change.validate()?;
        if !self.do_not_replay
            || !self.history_must_be_queried
            || self.remaining_ms > LIFETIME.as_millis() as u64
            || !self.permission_live && self.remaining_ms != 0
            || self.permission_live
                && (self.cancel_requested || self.unconfirmed || self.start == Step::Submitted)
            || self.permission_live && matches!(self.prepare, Step::Refused | Step::Unconfirmed)
            || self.permission_live && matches!(self.start, Step::Refused | Step::Unconfirmed)
            || (self.prepare == Step::Unconfirmed || self.start == Step::Unconfirmed)
                && !self.unconfirmed
            || self
                .observation
                .as_ref()
                .is_some_and(|o| !o.valid(&self.change, &self.original))
            || self.observation.as_ref().is_some_and(|o| {
                o.apply_submitted && !matches!(self.start, Step::Submitted | Step::Unconfirmed)
                    || o.review.is_some()
                        && !matches!(self.prepare, Step::Submitted | Step::Unconfirmed)
            })
            || serde_json::to_vec(self)
                .map_err(|_| Error::InvalidRequest)?
                .len()
                > REPORT_LIMIT
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

pub(crate) struct Action {
    original: Original,
    expires: Instant,
    prepare: AtomicU8,
    start: AtomicU8,
    cancelled: OnceLock<Instant>,
    unconfirmed: AtomicBool,
    // This is ONLY the original boolean STOP sender; it retains no Session.
    stop: tokio::sync::watch::Sender<bool>,
    observed: Mutex<Option<Observation>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Prepare,
    Start,
}
impl Action {
    fn slot(&self, kind: Kind) -> &AtomicU8 {
        match kind {
            Kind::Prepare => &self.prepare,
            Kind::Start => &self.start,
        }
    }
    fn live(&self, now: Instant) -> bool {
        now < self.expires
            && self.cancelled.get().is_none()
            && !*self.stop.borrow()
            && !self.unconfirmed.load(Ordering::Acquire)
    }
    pub(crate) fn cancel(&self, at: Instant) {
        let _ = self.cancelled.set(at);
        self.stop.send_replace(true);
    }
    fn doubt(&self) {
        self.unconfirmed.store(true, Ordering::Release);
        self.cancel(Instant::now());
    }
    pub(crate) fn cancellation_at(&self, now: Instant) -> Option<(Instant, bool)> {
        let expiry = (now >= self.expires && self.start.load(Ordering::Acquire) != SENT)
            .then_some((self.expires, true));
        self.cancelled
            .get()
            .map(|at| (*at, false))
            .into_iter()
            .chain(expiry)
            .min_by_key(|(at, _)| *at)
    }
    pub(crate) fn original(&self) -> &Original {
        &self.original
    }
    pub(crate) fn retained_plan(&self) -> Result<Id, Error> {
        self.observed
            .lock()
            .map_err(|_| {
                self.doubt();
                Error::StateUnknown
            })?
            .as_ref()
            .and_then(|o| o.review.as_ref())
            .map(|r| r.plan_token.clone())
            .ok_or(Error::Conflict)
    }
}
impl Entry {
    pub(crate) fn actions(&self) -> Option<&Action> {
        self.actions.get()
    }
    /// Exact intent only. Unlike global proposal revocation, this must not
    /// revoke the shared lease or Stop a later intent using that lease.
    pub(crate) fn cancel_action(&self, at: Instant) {
        let _ = self.action_cancelled.set(at);
        if let Some(a) = self.actions() {
            a.cancel(*self.action_cancelled.get().unwrap());
        }
    }
    pub(crate) fn action_unconfirmed(&self) {
        if let Some(a) = self.actions() {
            a.doubt();
        }
    }
    pub(crate) fn action_occupies(&self) -> bool {
        self.actions().is_some_and(|a| {
            a.observed.lock().map_or(true, |o| {
                o.as_ref()
                    .is_none_or(|o| o.settlement != Settlement::Settled)
            })
        })
    }
    /// The native child calls this only while retaining the original Registry
    /// and genuine Document/root proof, after its off-lock service comparison.
    pub(crate) fn allow_actions(
        &self,
        original: Original,
        native_end: Instant,
        stop: tokio::sync::watch::Sender<bool>,
    ) -> Result<(), Error> {
        let now = Instant::now();
        if !self.review_live(now)
            || self.action_cancelled.get().is_some()
            || !self.bound_to(
                original.operation_id.as_str(),
                original.owner_generation.as_str(),
            )
            || native_end <= now
            || *stop.borrow()
        {
            return Err(Error::AccessDenied);
        }
        let expires = native_end
            .min(self.approval.get().ok_or(Error::AccessDenied)?.expires)
            .min(now.checked_add(LIFETIME).ok_or(Error::StateUnknown)?);
        self.actions
            .set(Action {
                original,
                expires,
                prepare: AtomicU8::new(IDLE),
                start: AtomicU8::new(IDLE),
                cancelled: OnceLock::new(),
                unconfirmed: AtomicBool::new(false),
                stop,
                observed: Mutex::new(None),
            })
            .map_err(|_| Error::Conflict)?;
        // Cancellation can arrive through the original IPC while the native
        // Allow holds Doc/Edit. Retain its first instant; never renew/rearm.
        if let Some(at) = self.action_cancelled.get() {
            self.actions().unwrap().cancel(*at);
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub(crate) fn action_status(&self) -> Result<Status, Error> {
        let a = self.actions().ok_or(Error::AccessDenied)?;
        let now = Instant::now();
        let observation = a
            .observed
            .lock()
            .map_err(|_| {
                a.doubt();
                Error::StateUnknown
            })?
            .clone();
        let prepare = step(a.prepare.load(Ordering::Acquire));
        let start = step(a.start.load(Ordering::Acquire));
        let cancel_requested = self.action_cancelled.get().is_some() || a.cancelled.get().is_some();
        let unconfirmed = a.unconfirmed.load(Ordering::Acquire)
            || prepare == Step::Unconfirmed
            || start == Step::Unconfirmed;
        let live = !cancel_requested
            && !unconfirmed
            && !matches!(prepare, Step::Refused | Step::Unconfirmed)
            && !matches!(start, Step::Submitted | Step::Refused | Step::Unconfirmed)
            && observation
                .as_ref()
                .is_none_or(|o| o.settlement == Settlement::Pending)
            && self.review_live(now)
            && a.live(now);
        let result = Status {
            origin: Query {
                service_instance: self.input.service_instance.clone(),
                project_id: self.input.project_id.clone(),
                intent_id: self.input.intent_id.clone(),
            },
            change: self.input.change.clone(),
            original: a.original.clone(),
            prepare,
            start,
            permission_live: live,
            remaining_ms: if live {
                a.expires.saturating_duration_since(now).as_millis() as u64
            } else {
                0
            },
            cancel_requested,
            unconfirmed,
            observation,
            do_not_replay: true,
            history_must_be_queried: true,
        };
        result.validate()?;
        Ok(result)
    }
    fn queue_action(&self, kind: Kind, input: Option<&Start>) -> Result<(), Error> {
        let a = self.actions().ok_or(Error::AccessDenied)?;
        if (kind == Kind::Start) != input.is_some() {
            return Err(Error::InvalidRequest);
        }
        if let Some(input) = input {
            if !input.reviewed || input.original != a.original {
                return Err(Error::Conflict);
            }
            let observed = a.observed.lock().map_err(|_| {
                a.doubt();
                Error::StateUnknown
            })?;
            if observed
                .as_ref()
                .and_then(|o| o.review.as_ref())
                .is_none_or(|r| r.plan_token != input.plan_token)
            {
                return Err(Error::Conflict);
            }
        }
        // Repeated exact requests are observation only, including failed or
        // unknown admission. A fresh connection cannot renew either slot.
        let slot = a.slot(kind);
        if slot.load(Ordering::Acquire) != IDLE {
            return Ok(());
        }
        let now = Instant::now();
        if !self.review_live(now) || self.action_cancelled.get().is_some() || !a.live(now) {
            return Err(Error::Expired);
        }
        if kind == Kind::Start {
            let observed = a.observed.lock().map_err(|_| {
                a.doubt();
                Error::StateUnknown
            })?;
            if a.prepare.load(Ordering::Acquire) != SENT
                || observed.as_ref().is_none_or(|o| {
                    o.state != OperationState::Prepared
                        || o.settlement != Settlement::Pending
                        || o.apply_submitted
                })
            {
                return Err(Error::Conflict);
            }
        }
        let _ = slot.compare_exchange(IDLE, QUEUE, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }
    pub(crate) fn action_admitting(&self, kind: Kind) -> bool {
        let now = Instant::now();
        self.review_live(now)
            && self.action_cancelled.get().is_none()
            && self
                .actions()
                .is_some_and(|a| a.live(now) && a.slot(kind).load(Ordering::Acquire) == ADMIT)
    }
    /// Called ONLY at the existing Registry claim, before the original send.
    pub(crate) fn consume_action(&self, kind: Kind) -> Result<(), Error> {
        if !self.action_admitting(kind) {
            return Err(Error::AccessDenied);
        }
        self.actions()
            .unwrap()
            .slot(kind)
            .compare_exchange(ADMIT, SENT, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Error::Conflict)
    }
    /// DATA from original changed/observe_final hooks. Never a public status
    /// parse or a lost Weak interpreted as completion. Unknown is absorbing.
    pub(crate) fn observe_action(&self, value: Observation) -> Result<(), Error> {
        let Some(a) = self.actions() else {
            return Ok(());
        };
        if !value.valid(&self.input.change, &a.original)
            || value.apply_submitted && !matches!(a.start.load(Ordering::Acquire), SENT | DOUBT)
            || value.review.is_some() && !matches!(a.prepare.load(Ordering::Acquire), SENT | DOUBT)
        {
            a.doubt();
            return Err(Error::StateUnknown);
        }
        let mut observed = a.observed.lock().map_err(|_| {
            a.doubt();
            Error::StateUnknown
        })?;
        if let Some(old) = observed.as_ref() {
            if old == &value {
                return Ok(());
            }
            if value.status_revision <= old.status_revision
                || old.settlement == Settlement::Unknown && value.settlement != Settlement::Unknown
                || old.settlement == Settlement::Settled
                || old
                    .review
                    .as_ref()
                    .is_some_and(|r| value.review.as_ref() != Some(r))
                || old.apply_submitted && !value.apply_submitted
            {
                a.doubt();
                return Err(Error::StateUnknown);
            }
        }
        *observed = Some(value);
        Ok(())
    }
}
pub(crate) struct Claim {
    entry: Arc<Entry>,
    kind: Kind,
    returned: bool,
}
impl Claim {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }
    pub(crate) fn returned(mut self, success: bool) {
        self.returned = true;
        let a = self.entry.actions().unwrap();
        let slot = a.slot(self.kind);
        if success && slot.load(Ordering::Acquire) == SENT {
            return;
        }
        if !success
            && slot
                .compare_exchange(ADMIT, DENIED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            a.cancel(Instant::now()); // Refused action is not native settlement.
        } else {
            slot.store(DOUBT, Ordering::Release);
            a.doubt();
        }
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if !self.returned {
            let a = self.entry.actions().unwrap();
            a.slot(self.kind).store(DOUBT, Ordering::Release);
            a.doubt();
        }
    }
}
impl Inbox {
    fn action_entry(&self, query: &Query) -> Result<Arc<Entry>, Error> {
        if query.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let entry = self.entry(&query.intent_id)?;
        if entry.input.project_id != query.project_id {
            return Err(Error::Conflict);
        }
        Ok(entry)
    }
    pub(crate) fn identity_action(
        &self,
        query: &Query,
        kind: Option<Kind>,
        start: Option<&Start>,
        cancel: bool,
    ) -> Result<Status, Error> {
        let entry = self.action_entry(query)?;
        if let Some(kind) = kind {
            {
                let book = self.lock()?;
                self.live(&book)?;
            }
            entry.queue_action(kind, start)?;
        }
        if cancel {
            entry.cancel_action(Instant::now());
        }
        entry.action_status()
    }
    pub(crate) fn claim_identity_action(&self) -> Result<Option<Claim>, Error> {
        let book = self.lock()?;
        self.live(&book)?;
        for entry in &book.entries {
            let Some(a) = entry.actions() else { continue };
            for kind in [Kind::Prepare, Kind::Start] {
                if a.slot(kind)
                    .compare_exchange(QUEUE, ADMIT, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(Some(Claim {
                        entry: entry.clone(),
                        kind,
                        returned: false,
                    }));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
#[path = "agent_identity_actions_tests.rs"]
mod tests;
