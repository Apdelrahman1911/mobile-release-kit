//! Bounded, in-memory identity *requests*, not a second edit owner or writer.
//! This module also supplies the CLI's closed DATA types; it deliberately has
//! no Desktop, native-root, engine, filesystem, subprocess or renderer import.
use crate::service_protocol::{Error, Id};
use serde::{Deserialize, Serialize};
use std::{
    path::{Component, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};

#[path = "agent_identity_actions.rs"]
pub(crate) mod actions;

pub(crate) const LIMIT: usize = 32;
pub(crate) const LIFETIME: Duration = Duration::from_secs(15 * 60);
const QUEUED: u8 = 0;
const CLAIMING: u8 = 1;
const BOUND: u8 = 2;
const DECLINED: u8 = 3;
const EXPIRED: u8 = 4;
const REFUSED: u8 = 5;
const UNCONFIRMED: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityIntent {
    Preserve,
    NewApplication,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub platform: Platform,
    pub target: String,
    #[serde(deserialize_with = "required_option")]
    pub project: Option<String>,
}
fn required_option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub selection: Selection,
    pub desired_identity: String,
    pub identity_intent: IdentityIntent,
}
impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentityChange(..)")
    }
}
impl Change {
    pub fn validate(&self) -> Result<(), Error> {
        let target = &self.selection.target;
        if target.is_empty()
            || target.len() > 255
            || !target
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_. :()-".contains(&c))
        {
            return Err(Error::InvalidRequest);
        }
        let safe_path = |s: &str| {
            !s.is_empty()
                && s.len() <= 512
                && s.split('/').count() <= 16
                && s.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .bytes()
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
                        .contains(&part.to_ascii_lowercase().as_str())
                        && ![".mobile-release-", ".private-", ".codex-private-"]
                            .iter()
                            .any(|prefix| part.to_ascii_lowercase().starts_with(prefix))
                })
        };
        let selected = match self.selection.platform {
            Platform::Android => {
                self.selection.project.is_none()
                    && (target == ":"
                        || target.starts_with(':')
                            && target[1..].split(':').all(|part| {
                                !part.is_empty()
                                    && part
                                        .bytes()
                                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                            })
                            && safe_path(&format!(
                                "{}/build.gradle.kts",
                                target[1..].replace(':', "/")
                            )))
            }
            Platform::Ios => self
                .selection
                .project
                .as_deref()
                .is_some_and(|project| safe_path(project) && project.ends_with(".xcodeproj")),
        };
        let identity = &self.desired_identity;
        if !selected
            || identity.len() > 255
            || identity.split('.').count() < 2
            || !identity.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && part.bytes().all(|c| {
                        c.is_ascii_alphanumeric()
                            || c == match self.selection.platform {
                                Platform::Android => b'_',
                                Platform::Ios => b'-',
                            }
                    })
            })
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Submit {
    pub service_instance: Id,
    pub intent_id: Id,
    pub project_id: Id,
    pub expected_observation_revision: u64,
    pub change: Change,
}
impl Submit {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0 {
            return Err(Error::InvalidRequest);
        }
        self.change.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub service_instance: Id,
    pub project_id: Id,
    pub intent_id: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentState {
    Queued,
    DesktopReview,
    OriginalSidAvailable,
    Declined,
    Expired,
    RefusedBeforeClaim,
    AdmissionUnconfirmed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentStatus {
    pub service_instance: Id,
    pub project_id: Id,
    pub intent_id: Id,
    pub state: IntentState,
    pub operation_id: Option<Id>,
    /// A liveness observation only. Neither true nor false settles native work.
    pub original_link_retained: bool,
    /// The separate operation query may be absent/failed. This is never an ACK
    /// from the durable history publisher or a promise that it was enrolled.
    pub history_must_be_queried: bool,
}
impl IntentStatus {
    pub fn validate(&self) -> Result<(), Error> {
        if self.history_must_be_queried != self.operation_id.is_some()
            || self.state == IntentState::OriginalSidAvailable && self.operation_id.is_none()
            || self.original_link_retained && self.operation_id.is_none()
            || !matches!(
                self.state,
                IntentState::OriginalSidAvailable | IntentState::AdmissionUnconfirmed
            ) && self.operation_id.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

/// Native comparison facts, NOT a root lease; constructed/rechecked by the
/// original Document. There is intentionally no serde or public constructor.
pub(crate) struct NativeScope {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration: u32,
    pub(crate) input_revision: u64,
    pub(crate) document: Weak<()>,
}
impl NativeScope {
    fn valid(&self) -> bool {
        !self.runtime_id.is_empty()
            && self.runtime_id.len() <= 64
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && self.root.is_absolute()
            && self.root.to_str().is_some_and(|s| {
                s.len() <= 4096
                    && !s.contains('\0')
                    && !s.contains("//")
                    && !s.split('/').any(|p| p == "." || p == "..")
            })
            && self
                .root
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && self.inode != 0
            && self.registration != 0
            && self.document.strong_count() != 0
    }
}
/// From the original authenticated IPC admission, never request JSON. Fresh
/// connection IDs are recorded as origin DATA, not reused as write permits.
pub(crate) struct Origin {
    pub(crate) instance: Id,
    pub(crate) client: Id,
    pub(crate) session: Id,
}
/// Original service's checked saved-state comparison, obtained OFF Doc/Edit
/// locks. The real registered root is independently rechecked at GUI admission.
pub(crate) struct SavedPoint {
    pub(crate) project_id: Id,
    pub(crate) runtime_id: String,
    pub(crate) root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) revision: u64,
    pub(crate) fresh: bool,
}
impl SavedPoint {
    pub(crate) fn matches(&self, scope: &NativeScope) -> bool {
        self.project_id == scope.project_id
            && self.runtime_id == scope.runtime_id
            && self.root == scope.root
            && self.device == scope.device
            && self.inode == scope.inode
            && self.revision != 0
            && self.fresh
    }
}
struct Lease {
    scope: Arc<NativeScope>,
    expires: Instant,
    revoked: AtomicBool,
    failed: Arc<AtomicBool>,
}
impl Lease {
    fn live(&self, now: Instant) -> bool {
        now < self.expires
            && !self.failed.load(Ordering::Acquire)
            && !self.revoked.load(Ordering::Acquire)
            && self.scope.document.strong_count() != 0
    }
}
struct Original {
    operation_id: Id,
    generation: Id,
    retained: Weak<()>,
}
struct Approval {
    expires: Instant,
}
pub(crate) struct Entry {
    input: Submit,
    origin: Origin,
    lease: Arc<Lease>,
    phase: AtomicU8,
    claimed: AtomicBool,
    approval: OnceLock<Approval>,
    original: OnceLock<Original>,
    actions: OnceLock<actions::Action>,
    action_cancelled: OnceLock<Instant>,
}
impl Entry {
    pub(crate) fn input(&self) -> &Submit {
        &self.input
    }
    pub(crate) fn scope(&self) -> &NativeScope {
        &self.lease.scope
    }
    pub(crate) fn admission_live(&self, now: Instant) -> bool {
        self.phase.load(Ordering::Acquire) == CLAIMING
            && self.lease.live(now)
            && self
                .approval
                .get()
                .is_some_and(|approval| now < approval.expires)
    }
    pub(crate) fn original_claim_entered(&self) {
        self.claimed.store(true, Ordering::Release);
    }
    /// Only the fixed original EditOwner claim hook calls this. The hook's
    /// first claimed flag precedes fallible ID/link checks, so an error cannot
    /// later be reclassified as a negative admission receipt.
    pub(crate) fn bind_original(
        &self,
        operation_id: Id,
        generation: Id,
        retained: Weak<()>,
    ) -> Result<(), Error> {
        if !self.claimed.load(Ordering::Acquire)
            || self.phase.load(Ordering::Acquire) != CLAIMING
            || retained.strong_count() == 0
            || self
                .original
                .set(Original {
                    operation_id,
                    generation,
                    retained,
                })
                .is_err()
        {
            self.unconfirmed();
            return Err(Error::StateUnknown);
        }
        self.phase.store(BOUND, Ordering::Release);
        Ok(())
    }
    pub(crate) fn bound_to(&self, operation: &str, generation: &str) -> bool {
        self.original.get().is_some_and(|original| {
            original.operation_id.as_str() == operation
                && original.generation.as_str() == generation
        }) && self.phase.load(Ordering::Acquire) == BOUND
    }
    pub(crate) fn review_live(&self, now: Instant) -> bool {
        self.phase.load(Ordering::Acquire) == BOUND
            && !self.lease.failed.load(Ordering::Acquire)
            && !self.lease.revoked.load(Ordering::Acquire)
            && self.scope().document.strong_count() != 0
            && self
                .approval
                .get()
                .is_some_and(|approval| now < approval.expires)
    }
    pub(crate) fn unconfirmed(&self) {
        self.phase.store(UNCONFIRMED, Ordering::Release);
    }
    pub(crate) fn revoke(&self) {
        self.cancel_action(Instant::now());
        self.lease.revoked.store(true, Ordering::Release);
    }
    fn expire_pending(&self, now: Instant) {
        if !self.lease.live(now) {
            let _ =
                self.phase
                    .compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire);
        }
    }
    fn occupies(&self, now: Instant) -> bool {
        self.expire_pending(now);
        matches!(
            self.phase.load(Ordering::Acquire),
            QUEUED | CLAIMING | UNCONFIRMED
        ) || self.action_occupies()
    }
    pub(crate) fn status(&self) -> IntentStatus {
        self.expire_pending(Instant::now());
        let mut state = match self.phase.load(Ordering::Acquire) {
            QUEUED => IntentState::Queued,
            CLAIMING => IntentState::DesktopReview,
            BOUND => IntentState::OriginalSidAvailable,
            DECLINED => IntentState::Declined,
            EXPIRED => IntentState::Expired,
            REFUSED => IntentState::RefusedBeforeClaim,
            _ => IntentState::AdmissionUnconfirmed,
        };
        let original = self.original.get();
        // The once-only link is written before the BOUND release. A reader
        // which sampled CLAIMING immediately before that write still reports
        // the actual link, not an inconsistent preclaim state with a SID.
        if original.is_some() && state != IntentState::AdmissionUnconfirmed {
            state = IntentState::OriginalSidAvailable;
        }
        IntentStatus {
            service_instance: self.input.service_instance.clone(),
            project_id: self.input.project_id.clone(),
            intent_id: self.input.intent_id.clone(),
            state,
            operation_id: original.map(|original| original.operation_id.clone()),
            original_link_retained: original
                .is_some_and(|original| original.retained.strong_count() != 0),
            history_must_be_queried: original.is_some(),
        }
    }
}

/// Retained before entering the original Open. Drop/unreturned is not proof of
/// no admission. Only the returned preclaim branch can record that refusal.
pub(crate) struct ClaimAttempt {
    entry: Arc<Entry>,
    returned: bool,
}
impl ClaimAttempt {
    pub(crate) fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
    pub(crate) fn returned(mut self, ok: bool) -> Result<(), Error> {
        self.returned = true;
        if !ok && !self.entry.claimed.load(Ordering::Acquire) {
            self.entry.phase.store(REFUSED, Ordering::Release);
            return Ok(());
        }
        if self.entry.phase.load(Ordering::Acquire) != BOUND || self.entry.original.get().is_none()
        {
            self.entry.unconfirmed();
            return Err(Error::StateUnknown);
        }
        Ok(())
    }
}
impl Drop for ClaimAttempt {
    fn drop(&mut self) {
        if !self.returned {
            self.entry.unconfirmed();
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaseStatus {
    pub(crate) enabled: bool,
    pub(crate) remaining_ms: u64,
    pub(crate) project_id: Option<Id>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuiProposal {
    pub(crate) request: Submit,
    pub(crate) runtime_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuiStatus {
    pub(crate) lease: LeaseStatus,
    pub(crate) pending: Option<GuiProposal>,
    pub(crate) requests: Vec<IntentStatus>,
}
struct Book {
    lease: Option<Arc<Lease>>,
    entries: Vec<Arc<Entry>>,
    closed: bool,
}
pub(crate) struct Inbox {
    instance: Id,
    book: Mutex<Book>,
    failed: Arc<AtomicBool>,
}
impl Inbox {
    pub(crate) fn new(instance: Id) -> Self {
        Self {
            instance,
            book: Mutex::new(Book {
                lease: None,
                entries: Vec::with_capacity(LIMIT),
                closed: false,
            }),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Book>, Error> {
        self.book.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            Error::StateUnknown
        })
    }
    fn live(&self, book: &Book) -> Result<(), Error> {
        if self.failed.load(Ordering::Acquire) {
            Err(Error::StateUnknown)
        } else if book.closed {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) fn allow(&self, scope: NativeScope) -> Result<LeaseStatus, Error> {
        if !scope.valid() {
            return Err(Error::InvalidRequest);
        }
        let now = Instant::now();
        let lease = Arc::new(Lease {
            scope: Arc::new(scope),
            expires: now.checked_add(LIFETIME).ok_or(Error::StateUnknown)?,
            revoked: AtomicBool::new(false),
            failed: self.failed.clone(),
        });
        let mut book = self.lock()?;
        self.live(&book)?;
        // The Document independently proves idle before this operation. Old
        // pending data is retired; it never migrates into a fresh grant.
        if let Some(old) = book.lease.replace(lease) {
            old.revoked.store(true, Ordering::Release);
        }
        for entry in &book.entries {
            entry.expire_pending(now);
        }
        Ok(lease_view(&book, now))
    }
    pub(crate) fn revoke(&self) -> Result<(), Error> {
        let book = self.lock()?;
        if let Some(lease) = &book.lease {
            lease.revoked.store(true, Ordering::Release);
        }
        for entry in &book.entries {
            entry.revoke();
            entry.expire_pending(Instant::now());
        }
        Ok(())
    }
    pub(crate) fn close(&self) {
        // Cleanup-only poison handling: never restore admission or clear it.
        let mut book = match self.book.lock() {
            Ok(book) => book,
            Err(poisoned) => {
                self.failed.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        book.closed = true;
        if let Some(lease) = &book.lease {
            lease.revoked.store(true, Ordering::Release);
        }
        for entry in &book.entries {
            entry.revoke();
        }
    }
    pub(crate) fn submit(
        &self,
        origin: Origin,
        input: Submit,
        point: &SavedPoint,
    ) -> Result<IntentStatus, Error> {
        input.validate()?;
        if input.service_instance != self.instance || origin.instance != self.instance {
            return Err(Error::Conflict);
        }
        let mut book = self.lock()?;
        self.live(&book)?;
        if let Some(entry) = book
            .entries
            .iter()
            .find(|entry| entry.input.intent_id == input.intent_id)
        {
            // A new connection can observe an identical intent, never acquire
            // its original client identity, renew approval or cause dispatch.
            return if entry.input == input {
                Ok(entry.status())
            } else {
                Err(Error::Conflict)
            };
        }
        let now = Instant::now();
        let lease = book
            .lease
            .as_ref()
            .filter(|lease| lease.live(now))
            .ok_or(Error::AccessDenied)?
            .clone();
        if input.project_id != lease.scope.project_id
            || !point.matches(&lease.scope)
            || input.expected_observation_revision != point.revision
        {
            return Err(Error::Conflict);
        }
        if book.entries.len() >= LIMIT || book.entries.iter().any(|entry| entry.occupies(now)) {
            return Err(Error::Busy);
        }
        let entry = Arc::new(Entry {
            input,
            origin,
            lease,
            phase: AtomicU8::new(QUEUED),
            claimed: AtomicBool::new(false),
            approval: OnceLock::new(),
            original: OnceLock::new(),
            actions: OnceLock::new(),
            action_cancelled: OnceLock::new(),
        });
        let status = entry.status();
        book.entries.push(entry);
        Ok(status)
    }
    pub(crate) fn query(&self, query: &Query) -> Result<IntentStatus, Error> {
        if query.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let book = self.lock()?;
        // Status and original cancellation remain useful after consent ends.
        book.entries
            .iter()
            .find(|entry| {
                entry.input.intent_id == query.intent_id
                    && entry.input.project_id == query.project_id
            })
            .map(|entry| entry.status())
            .ok_or(Error::Conflict)
    }
    pub(crate) fn entry(&self, id: &Id) -> Result<Arc<Entry>, Error> {
        self.lock()?
            .entries
            .iter()
            .find(|entry| &entry.input.intent_id == id)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn begin_review(&self, entry: &Arc<Entry>) -> Result<ClaimAttempt, Error> {
        let book = self.lock()?;
        self.live(&book)?;
        if !book
            .entries
            .iter()
            .any(|candidate| Arc::ptr_eq(candidate, entry))
        {
            return Err(Error::AccessDenied);
        }
        let now = Instant::now();
        let expires = now.checked_add(LIFETIME).ok_or(Error::StateUnknown)?;
        entry.expire_pending(now);
        if !entry.lease.live(now)
            || entry
                .phase
                .compare_exchange(QUEUED, CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(Error::AccessDenied);
        }
        if entry.approval.set(Approval { expires }).is_err() {
            entry.unconfirmed();
            return Err(Error::StateUnknown);
        }
        Ok(ClaimAttempt {
            entry: entry.clone(),
            returned: false,
        })
    }
    pub(crate) fn decline(&self, id: &Id) -> Result<(), Error> {
        let entry = self.entry(id)?;
        entry
            .phase
            .compare_exchange(QUEUED, DECLINED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Error::Conflict)
    }
    pub(crate) fn gui_status(&self) -> Result<GuiStatus, Error> {
        let book = self.lock()?;
        let now = Instant::now();
        let requests = book.entries.iter().map(|entry| entry.status()).collect();
        let pending = book
            .entries
            .iter()
            .find(|entry| entry.phase.load(Ordering::Acquire) == QUEUED)
            .map(|entry| GuiProposal {
                request: entry.input.clone(),
                runtime_id: entry.scope().runtime_id.clone(),
            });
        Ok(GuiStatus {
            lease: lease_view(&book, now),
            pending,
            requests,
        })
    }
}
fn lease_view(book: &Book, now: Instant) -> LeaseStatus {
    match book
        .lease
        .as_ref()
        .filter(|lease| !book.closed && lease.live(now))
    {
        Some(lease) => LeaseStatus {
            enabled: true,
            remaining_ms: lease.expires.saturating_duration_since(now).as_millis() as u64,
            project_id: Some(lease.scope.project_id.clone()),
        },
        None => LeaseStatus {
            enabled: false,
            remaining_ms: 0,
            project_id: None,
        },
    }
}
/// Fixed worst-case census, charged once per original Document. Includes all
/// 32 non-evicted request payloads/root facts, eight original IPC workers with
/// bounded decoded copies, GUI snapshot/link transients and allocation slack.
/// Root input itself is native-only; no request can enlarge the fixed roster.
pub(crate) const fn document_backing_bytes() -> usize {
    (LIMIT + 16) * (4096 + 4096 + 2048) + actions::DOCUMENT_BACKING
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    fn input(n: u32) -> Submit {
        Submit {
            service_instance: id(1),
            intent_id: id(n),
            project_id: id(2),
            expected_observation_revision: 3,
            change: Change {
                selection: Selection {
                    platform: Platform::Android,
                    target: ":app".into(),
                    project: None,
                },
                desired_identity: "com.example.app".into(),
                identity_intent: IdentityIntent::NewApplication,
            },
        }
    }
    fn origin(n: u32) -> Origin {
        Origin {
            instance: id(1),
            client: id(n),
            session: id(n + 1),
        }
    }
    fn scope(document: &Arc<()>) -> NativeScope {
        NativeScope {
            project_id: id(2),
            runtime_id: "project-1".into(),
            root: "/inert/identity-fixture".into(),
            device: 7,
            inode: 8,
            registration: 9,
            input_revision: 10,
            document: Arc::downgrade(document),
        }
    }
    fn point() -> SavedPoint {
        SavedPoint {
            project_id: id(2),
            runtime_id: "project-1".into(),
            root: "/inert/identity-fixture".into(),
            device: 7,
            inode: 8,
            revision: 3,
            fresh: true,
        }
    }
    fn ready() -> (Inbox, Arc<()>) {
        let document = Arc::new(());
        let inbox = Inbox::new(id(1));
        inbox.allow(scope(&document)).unwrap();
        (inbox, document)
    }
    #[test]
    fn read_connection_alone_has_no_request_permission() {
        let inbox = Inbox::new(id(1));
        assert_eq!(
            inbox.submit(origin(30), input(4), &point()).err(),
            Some(Error::AccessDenied)
        );
        assert!(inbox.gui_status().unwrap().pending.is_none());
    }
    #[test]
    fn closed_identity_data_never_adopts_paths_credentials_or_continuity() {
        let good = serde_json::to_value(&input(4).change).unwrap();
        assert!(serde_json::from_value::<Change>(good.clone())
            .unwrap()
            .validate()
            .is_ok());
        for key in [
            "root",
            "credentials",
            "continuity",
            "window",
            "command",
            "force",
            "draft",
        ] {
            let mut bad = good.clone();
            bad[key] = serde_json::Value::Null;
            assert!(serde_json::from_value::<Change>(bad).is_err());
        }
        let mut bad = input(4).change;
        bad.selection.project = Some("../Other.xcodeproj".into());
        assert!(bad.validate().is_err());
        let duplicate = r#"{"selection":{"platform":"android","target":":app","project":null},"desiredIdentity":"com.example.a","desiredIdentity":"com.example.b","identityIntent":"new-application"}"#;
        assert!(serde_json::from_str::<Change>(duplicate).is_err());
    }
    #[test]
    fn fresh_connection_retry_only_observes_original_intent() {
        let (inbox, _document) = ready();
        let first = inbox.submit(origin(30), input(4), &point()).unwrap();
        let second = inbox.submit(origin(40), input(4), &point()).unwrap();
        assert!(first == second);
        let entry = inbox.entry(&id(4)).unwrap();
        assert!(entry.origin.client == id(30) && entry.origin.session == id(31));
        let mut changed = input(4);
        changed.change.desired_identity = "com.example.other".into();
        assert_eq!(
            inbox.submit(origin(40), changed, &point()).err(),
            Some(Error::Conflict)
        );
        assert_eq!(
            inbox.submit(origin(40), input(5), &point()).err(),
            Some(Error::Busy)
        );
    }
    #[test]
    fn stale_observation_alias_or_instance_never_queues() {
        let (inbox, _document) = ready();
        let mut bad = point();
        bad.runtime_id = "project-2".into();
        assert_eq!(
            inbox.submit(origin(30), input(4), &bad).err(),
            Some(Error::Conflict)
        );
        bad = point();
        bad.inode += 1;
        assert_eq!(
            inbox.submit(origin(30), input(4), &bad).err(),
            Some(Error::Conflict)
        );
        bad = point();
        bad.revision += 1;
        assert_eq!(
            inbox.submit(origin(30), input(4), &bad).err(),
            Some(Error::Conflict)
        );
        let mut request = input(4);
        request.service_instance = id(8);
        assert_eq!(
            inbox.submit(origin(30), request, &point()).err(),
            Some(Error::Conflict)
        );
    }
    #[test]
    fn approval_is_one_use_and_never_an_operation_receipt() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let entry = inbox.entry(&id(4)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        assert!(matches!(entry.status().state, IntentState::DesktopReview));
        assert!(entry.status().operation_id.is_none());
        assert!(inbox.begin_review(&entry).is_err());
        claim.returned(false).unwrap();
        assert!(matches!(
            entry.status().state,
            IntentState::RefusedBeforeClaim
        ));
        assert!(matches!(
            inbox.submit(origin(40), input(4), &point()).unwrap().state,
            IntentState::RefusedBeforeClaim
        ));
    }
    #[test]
    fn postclaim_and_unreturned_failures_cannot_become_not_started() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let entry = inbox.entry(&id(4)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        entry.original_claim_entered();
        assert_eq!(claim.returned(false).err(), Some(Error::StateUnknown));
        assert!(matches!(
            entry.status().state,
            IntentState::AdmissionUnconfirmed
        ));
        assert_eq!(
            inbox.submit(origin(40), input(5), &point()).err(),
            Some(Error::Busy)
        );
        let (other, _doc) = ready();
        other.submit(origin(30), input(4), &point()).unwrap();
        let entry = other.entry(&id(4)).unwrap();
        drop(other.begin_review(&entry).unwrap());
        assert!(matches!(
            entry.status().state,
            IntentState::AdmissionUnconfirmed
        ));
    }
    #[test]
    fn original_handoff_releases_only_proposal_slot_and_never_finality() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let entry = inbox.entry(&id(4)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        let retained = Arc::new(());
        entry.original_claim_entered();
        entry
            .bind_original(id(50), id(51), Arc::downgrade(&retained))
            .unwrap();
        claim.returned(true).unwrap();
        assert!(entry.bound_to(id(50).as_str(), id(51).as_str()));
        assert!(entry.status().original_link_retained);
        inbox.submit(origin(40), input(5), &point()).unwrap();
        drop(retained);
        let status = entry.status();
        assert!(!status.original_link_retained);
        assert!(matches!(status.state, IntentState::OriginalSidAvailable));
        assert!(status.operation_id == Some(id(50)));
        assert!(status.validate().is_ok());
    }
    #[test]
    fn revoke_and_expiry_never_renew_or_hide_original_link() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let entry = inbox.entry(&id(4)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        let retained = Arc::new(());
        entry.original_claim_entered();
        entry
            .bind_original(id(50), id(51), Arc::downgrade(&retained))
            .unwrap();
        claim.returned(true).unwrap();
        assert!(entry.review_live(Instant::now()));
        assert!(!entry.review_live(Instant::now() + LIFETIME));
        inbox.revoke().unwrap();
        assert!(!entry.review_live(Instant::now()));
        assert!(
            inbox
                .query(&Query {
                    service_instance: id(1),
                    project_id: id(2),
                    intent_id: id(4)
                })
                .unwrap()
                .operation_id
                == Some(id(50))
        );
        assert!(matches!(
            inbox.submit(origin(40), input(4), &point()).unwrap().state,
            IntentState::OriginalSidAvailable
        ));
        assert_eq!(
            inbox.submit(origin(40), input(5), &point()).err(),
            Some(Error::AccessDenied)
        );
    }
    #[test]
    fn complete_ledger_never_evicts_old_request_ids() {
        let (inbox, _document) = ready();
        for n in 100..100 + LIMIT as u32 {
            inbox.submit(origin(30), input(n), &point()).unwrap();
            inbox.decline(&id(n)).unwrap();
        }
        assert_eq!(
            inbox.submit(origin(40), input(200), &point()).err(),
            Some(Error::Busy)
        );
        assert!(matches!(
            inbox
                .submit(origin(40), input(100), &point())
                .unwrap()
                .state,
            IntentState::Declined
        ));
        assert!(document_backing_bytes() < 4 * 1024 * 1024);
    }
    #[test]
    fn restart_does_not_restore_or_replay_an_intent() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        inbox.close();
        assert_eq!(
            inbox.submit(origin(40), input(4), &point()).err(),
            Some(Error::Unavailable)
        );
        let fresh = Inbox::new(id(99));
        assert_eq!(
            fresh
                .query(&Query {
                    service_instance: id(1),
                    project_id: id(2),
                    intent_id: id(4)
                })
                .err(),
            Some(Error::Conflict)
        );
        assert_eq!(
            fresh.submit(origin(40), input(4), &point()).err(),
            Some(Error::Conflict)
        );
    }
    #[test]
    fn poisoned_inbox_permanently_fences_original_review_without_reverse_lock() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let entry = inbox.entry(&id(4)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        let retained = Arc::new(());
        entry.original_claim_entered();
        entry
            .bind_original(id(50), id(51), Arc::downgrade(&retained))
            .unwrap();
        claim.returned(true).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = inbox.book.lock().unwrap();
            panic!("inert inbox poison fixture");
        }));
        assert!(panic.is_err());
        assert_eq!(inbox.revoke().err(), Some(Error::StateUnknown));
        // The native all-path Prepare/Apply check reads only this atomic fence,
        // even though the original poisoned inbox lock cannot be reacquired.
        assert!(!entry.review_live(Instant::now()));
        inbox.close();
        assert!(entry.status().operation_id == Some(id(50)));
    }
    #[test]
    fn stale_saved_point_can_observe_same_request_but_never_enqueue_new_work() {
        let (inbox, _document) = ready();
        inbox.submit(origin(30), input(4), &point()).unwrap();
        let mut stale = point();
        stale.fresh = false;
        assert!(inbox.submit(origin(40), input(4), &stale).is_ok());
        assert_eq!(
            inbox.submit(origin(40), input(5), &stale).err(),
            Some(Error::Conflict)
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn original_ipc_requires_separate_lease_and_reconnect_never_dispatches_an_edit() {
        use crate::{
            application_service::{
                tests::{passive, register_fixture},
                ApplicationService,
            },
            application_state_store::{Fixture, PrivateStateDirectory},
            installed_cli_ipc as ipc, service_protocol as p,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let f = Fixture::short();
            let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (project, root) =
                register_fixture(&service, &f.app, "proposal-project", "project-1");
            let observation = service
                .publish_passive_snapshot("project-1", &passive(&root, &"1".repeat(64)))
                .unwrap();
            service
                .allow_agent_read(vec![project.clone()], Duration::from_secs(30))
                .unwrap();
            let mut host = ipc::start(service.clone()).await.unwrap();
            let mut proposal = input(4);
            proposal.service_instance = service.instance().clone();
            proposal.project_id = project.clone();
            proposal.expected_observation_revision = observation.observation.unwrap().revision;
            let request = |input: Submit| p::Request {
                version: p::VERSION,
                request_id: Id::random().unwrap(),
                request: p::RequestBody::IdentitySubmit(input),
            };
            let denied = ipc::request(&f.app, &request(proposal.clone()))
                .await
                .unwrap();
            assert_eq!(denied.response, p::ResponseBody::Error(Error::AccessDenied));
            // TEST DATA permission for the actual IPC/inbox, never a forged
            // Document/Window, native root acquisition, GUI claim or Session.
            let document = Arc::new(());
            let point = service.identity_request_point("project-1").unwrap();
            service
                .identity_requests()
                .allow(NativeScope {
                    project_id: project.clone(),
                    runtime_id: "project-1".into(),
                    root,
                    device: point.device,
                    inode: point.inode,
                    registration: 1,
                    input_revision: 0,
                    document: Arc::downgrade(&document),
                })
                .unwrap();
            let first = ipc::request(&f.app, &request(proposal.clone()))
                .await
                .unwrap();
            let second = ipc::request(&f.app, &request(proposal.clone()))
                .await
                .unwrap();
            assert_ne!(first.client_id, second.client_id);
            assert_eq!(first.response, second.response);
            let p::ResponseBody::IdentityIntent(status) = &first.response else {
                panic!("wrong closed response")
            };
            assert_eq!(status.state, IntentState::Queued);
            assert!(status.operation_id.is_none());
            service.invalidate_native("project-1").unwrap();
            assert_eq!(
                ipc::request(&f.app, &request(proposal.clone()))
                    .await
                    .unwrap()
                    .response,
                first.response
            );
            let mut changed = proposal.clone();
            changed.intent_id = id(5);
            assert_eq!(
                ipc::request(&f.app, &request(changed))
                    .await
                    .unwrap()
                    .response,
                p::ResponseBody::Error(Error::Conflict)
            );
            service
                .identity_requests()
                .decline(&proposal.intent_id)
                .unwrap();
            let last = ipc::request(&f.app, &request(proposal)).await.unwrap();
            assert!(matches!(
                last.response,
                p::ResponseBody::IdentityIntent(IntentStatus {
                    state: IntentState::Declined,
                    operation_id: None,
                    ..
                })
            ));
            let joined = host.shutdown().await.unwrap();
            assert!(joined.workers_joined >= 6);
            service.stop().unwrap();
            store.close().unwrap();
        });
    }
}
