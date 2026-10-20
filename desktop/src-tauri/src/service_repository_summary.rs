//! Redacted Git-observation DATA for the existing authenticated service.
//! This does not run Git, fetch refs, inspect a checkout, or grant an operation.
use crate::service_protocol::{Error, Id, PROJECT_LIMIT};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

pub(crate) const VIEW_BYTES: usize = 2048;
// At most the existing 64 registered projects: one private root comparison,
// two revision digests, and one small DATA row each. Includes BTree/string
// cells, 256KiB for the existing native validator's bounded borrowed-key sets,
// one small projection and eight typed/encoded replies. The
// original Git owner/transport retain their separate charges; not an RSS cap.
pub(crate) const DOCUMENT_BACKING: usize = PROJECT_LIMIT * (4096 + 64 + 1024) + 288 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    CapturedDesktopGitObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    HistoricalNotRevalidated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    LocalRefsNoFetch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capture {
    Unobserved,
    Observed,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Head {
    Attached,
    Detached,
    Unborn,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrackingState {
    Detached,
    NotConfigured,
    Unsupported,
    Unborn,
    Gone,
    Shallow,
    Limit,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Changes {
    pub total: u16,
    pub index: u16,
    pub worktree: u16,
    pub untracked: u16,
    pub conflicts: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tracking {
    pub state: TrackingState,
    pub ahead: Option<u16>,
    pub behind: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    /// The original native GitRead ID, not a new service operation or receipt.
    pub operation_id: String,
    pub head: Head,
    pub changes: Changes,
    pub tracking: Tracking,
    pub restriction_count: u8,
}
impl Observation {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let c = &self.changes;
        let t = &self.tracking;
        if operation_sequence(&self.operation_id).is_none()
            || c.total > 512
            || [c.index, c.worktree, c.untracked, c.conflicts]
                .iter()
                .any(|v| *v > c.total)
            || u32::from(c.untracked) + u32::from(c.conflicts) > u32::from(c.total)
            || self.restriction_count > 64
            || (self.head == Head::Detached) != (t.state == TrackingState::Detached)
            || self.head == Head::Unborn
                && !matches!(t.state, TrackingState::Unborn | TrackingState::Unsupported)
            || t.state == TrackingState::Unborn && self.head != Head::Unborn
        {
            return Err(Error::InvalidRequest);
        }
        match (t.state, t.ahead, t.behind) {
            (TrackingState::Complete, Some(a), Some(b))
                if u32::from(a) + u32::from(b) <= 10_000 =>
            {
                Ok(())
            }
            (TrackingState::Complete, _, _) => Err(Error::InvalidRequest),
            (_, None, None) => Ok(()),
            _ => Err(Error::InvalidRequest),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    pub schema_version: u32,
    pub project_id: Id,
    pub scope: Scope,
    pub freshness: Freshness,
    pub basis: Basis,
    pub capture: Capture,
    pub observation: Option<Observation>,
}
impl View {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || (self.capture == Capture::Observed) != self.observation.is_some()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(value) = &self.observation {
            value.validate()?;
        }
        Ok(())
    }
}

/// Private native-registration comparison DATA. Never a public DTO, project
/// registration API or read authority. The Host checks its original document
/// and registration before supplying it; the service matches its saved binding.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Source {
    pub(crate) runtime_id: String,
    pub(crate) canonical_root: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration_generation: u32,
}
impl Source {
    fn valid(&self) -> bool {
        !self.runtime_id.is_empty()
            && self.runtime_id.len() <= 64
            && self
                .runtime_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && self.canonical_root.starts_with('/')
            && self.canonical_root.len() <= 4096
            && !self.canonical_root.contains('\0')
            && self.inode != 0
            && self.registration_generation != 0
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Captured {
    pub(crate) observation: Observation,
    // Retained only for contradictory SAME-original detection. Neither raw
    // revision digest nor native source identity is exported to the client.
    pub(crate) observation_revision: String,
    pub(crate) reference_revision: String,
}
impl Captured {
    fn valid(&self) -> bool {
        self.observation.validate().is_ok()
            && [&self.observation_revision, &self.reference_revision]
                .iter()
                .all(|v| {
                    v.len() == 64
                        && v.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
    }
}
fn operation_sequence(id: &str) -> Option<u64> {
    let digits = id.strip_prefix("git-read-")?;
    let value = digits.parse::<u64>().ok()?;
    // Existing Supervisor IDs use this exact canonical increasing counter.
    // It orders DATA from those originals; it never establishes their finality.
    (digits == value.to_string()).then_some(value)
}
struct Row {
    source: Source,
    sequence: u64,
    value: Option<Captured>,
    binding_changed: bool,
}
#[derive(Default)]
struct Book {
    rows: BTreeMap<String, Row>,
    retired: bool,
}
/// ONE bounded volatile projection, shared by the existing Host/Service.
/// No native owner, callback, task, file, timer, durable namespace or writer.
#[derive(Default)]
pub(crate) struct ObservationSlot {
    book: Mutex<Book>,
}
impl ObservationSlot {
    pub(crate) fn publish(&self, source: Source, value: Captured) {
        if !value.valid() {
            self.retire();
            return;
        }
        let id = value.observation.operation_id.clone();
        self.record(source, &id, Some(value));
    }
    pub(crate) fn unavailable(&self, source: Source, operation_id: &str) {
        self.record(source, operation_id, None);
    }
    fn record(&self, source: Source, operation_id: &str, value: Option<Captured>) {
        let Some(sequence) = operation_sequence(operation_id).filter(|_| source.valid()) else {
            self.retire();
            return;
        };
        let Ok(mut book) = self.book.lock() else {
            return;
        };
        if book.retired {
            return;
        }
        if let Some(old) = book.rows.get_mut(&source.runtime_id) {
            if old.source != source {
                old.value = None;
                old.binding_changed = true;
                return; // A rebound alias cannot inherit or repair this row.
            }
            if old.binding_changed || sequence < old.sequence {
                return;
            }
            if sequence == old.sequence {
                if old.value != value {
                    old.value = None;
                }
                return; // In particular, an unavailable original cannot revive.
            }
            old.sequence = sequence;
            old.value = value;
            return;
        }
        if book.rows.len() >= PROJECT_LIMIT {
            book.retired = true;
            return; // Never evict a known row to disguise missing history.
        }
        book.rows.insert(
            source.runtime_id.clone(),
            Row {
                source,
                sequence,
                value,
                binding_changed: false,
            },
        );
    }
    pub(crate) fn retire(&self) {
        if let Ok(mut book) = self.book.lock() {
            book.retired = true;
        }
    }
    pub(crate) fn view(
        &self,
        project_id: Id,
        runtime_id: &str,
        root: &str,
        device: u64,
        inode: u64,
    ) -> View {
        let (capture, observation) = match self.book.lock().as_deref() {
            Ok(book) if !book.retired => match book.rows.get(runtime_id) {
                None => (Capture::Unobserved, None),
                Some(row)
                    if !row.binding_changed
                        && row.source.canonical_root == root
                        && row.source.device == device
                        && row.source.inode == inode =>
                {
                    match &row.value {
                        Some(value) => (Capture::Observed, Some(value.observation.clone())),
                        None => (Capture::Unavailable, None),
                    }
                }
                Some(_) => (Capture::Unavailable, None),
            },
            _ => (Capture::Unavailable, None),
        };
        View {
            schema_version: 1,
            project_id,
            scope: Scope::CapturedDesktopGitObservation,
            freshness: Freshness::HistoricalNotRevalidated,
            basis: Basis::LocalRefsNoFetch,
            capture,
            observation,
        }
    }
}

pub(crate) fn human(view: &View) -> String {
    let mut text = String::from("Desktop Git observation; historical, not revalidated now.\nTracking uses local refs only; no fetch or remote freshness check.\n");
    let Some(value) = &view.observation else {
        text.push_str(match view.capture {
            Capture::Unobserved => "No completed Git Observe has been captured for this project in this Desktop session.\n",
            _ => "The Git observation is unavailable; a clean checkout is not inferred.\n",
        });
        text.push_str("Use Desktop to inspect Git; this command does not run an inspection.\n");
        return text;
    };
    let head = match value.head {
        Head::Attached => "attached",
        Head::Detached => "detached",
        Head::Unborn => "unborn",
    };
    let c = &value.changes;
    text.push_str(&format!("Original read: {}\nHEAD: {head}; {} recorded changed paths (index {}, worktree {}, untracked {}, conflicts {}).\n",
        value.operation_id, c.total, c.index, c.worktree, c.untracked, c.conflicts));
    match value.tracking.state {
        TrackingState::Complete => match (value.tracking.ahead, value.tracking.behind) {
            (Some(a), Some(b)) => text.push_str(&format!(
                "Local tracking comparison: ahead {a}, behind {b}.\n"
            )),
            _ => text.push_str("Local tracking comparison unavailable.\n"),
        },
        state => {
            let label = match state {
                TrackingState::Detached => "detached HEAD",
                TrackingState::NotConfigured => "not configured",
                TrackingState::Unsupported => "unsupported",
                TrackingState::Unborn => "unborn HEAD",
                TrackingState::Gone => "tracking ref missing",
                TrackingState::Shallow => "shallow history",
                TrackingState::Limit => "comparison limit reached",
                TrackingState::Complete => unreachable!(),
            };
            text.push_str(&format!(
                "Local tracking comparison: {label}; ahead/behind unavailable.\n"
            ));
        }
    }
    text.push_str(&format!(
        "Recorded restrictions: {}. This is not permission to edit, commit, build or release.\n",
        value.restriction_count
    ));
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn source() -> Source {
        Source {
            runtime_id: "project-1".into(),
            canonical_root: "/private/root-sentinel".into(),
            device: 11,
            inode: 12,
            registration_generation: 1,
        }
    }
    pub(crate) fn captured(sequence: u64) -> Captured {
        Captured {
            observation: Observation {
                operation_id: format!("git-read-{sequence}"),
                head: Head::Attached,
                changes: Changes {
                    total: 3,
                    index: 1,
                    worktree: 1,
                    untracked: 1,
                    conflicts: 0,
                },
                tracking: Tracking {
                    state: TrackingState::Complete,
                    ahead: Some(2),
                    behind: Some(3),
                },
                restriction_count: 0,
            },
            observation_revision: "a".repeat(64),
            reference_revision: "b".repeat(64),
        }
    }
    fn view(slot: &ObservationSlot, source: &Source) -> View {
        slot.view(
            Id::parse(&"1".repeat(32)).unwrap(),
            &source.runtime_id,
            &source.canonical_root,
            source.device,
            source.inode,
        )
    }
    #[test]
    fn public_view_is_bounded_codes_and_counts_not_private_root_or_revision_data() {
        let slot = ObservationSlot::default();
        let source = source();
        slot.publish(source.clone(), captured(1));
        let view = view(&slot, &source);
        view.validate().unwrap();
        let bytes = serde_json::to_vec(&view).unwrap();
        assert!(bytes.len() < VIEW_BYTES && DOCUMENT_BACKING < 1024 * 1024);
        let text = String::from_utf8(bytes).unwrap();
        for omitted in [
            "root-sentinel",
            "device",
            "inode",
            "registrationGeneration",
            "project-1",
            &"a".repeat(64),
            &"b".repeat(64),
        ] {
            assert!(!text.contains(omitted));
        }
        assert_eq!(view.freshness, Freshness::HistoricalNotRevalidated);
        assert_eq!(view.basis, Basis::LocalRefsNoFetch);
        assert!(human(&view).contains("no fetch"));
        let mut raw = serde_json::to_value(&view).unwrap();
        raw["headPath"] = serde_json::json!("sentinel");
        assert!(serde_json::from_value::<View>(raw).is_err());
    }
    #[test]
    fn root_alias_and_generation_changes_cannot_borrow_a_different_project_observation() {
        let slot = ObservationSlot::default();
        let source = source();
        slot.publish(source.clone(), captured(1));
        for field in 0..4 {
            let mut different = source.clone();
            match field {
                0 => different.runtime_id = "project-2".into(),
                1 => different.canonical_root.push_str("-other"),
                2 => different.device += 1,
                _ => different.inode += 1,
            }
            assert_ne!(view(&slot, &different).capture, Capture::Observed);
        }
        let mut rebound = source.clone();
        rebound.registration_generation += 1;
        slot.publish(rebound, captured(2));
        slot.publish(source.clone(), captured(3));
        assert_eq!(view(&slot, &source).capture, Capture::Unavailable);
    }
    #[test]
    fn same_original_conflict_is_unavailable_and_older_or_repeated_results_do_not_repair_it() {
        let slot = ObservationSlot::default();
        let source = source();
        slot.publish(source.clone(), captured(2));
        let mut changed = captured(2);
        changed.reference_revision = "c".repeat(64);
        slot.publish(source.clone(), changed);
        slot.publish(source.clone(), captured(1));
        slot.publish(source.clone(), captured(2));
        assert_eq!(view(&slot, &source).capture, Capture::Unavailable);
        slot.publish(source.clone(), captured(3));
        assert_eq!(view(&slot, &source).capture, Capture::Observed);
        slot.unavailable(source.clone(), "git-read-4");
        slot.publish(source.clone(), captured(4));
        assert_eq!(view(&slot, &source).capture, Capture::Unavailable);
    }
    #[test]
    fn native_loss_poison_and_capacity_never_become_empty_or_refreshable() {
        let slot = ObservationSlot::default();
        let source = source();
        slot.publish(source.clone(), captured(1));
        slot.retire();
        slot.publish(source.clone(), captured(2));
        assert_eq!(view(&slot, &source).capture, Capture::Unavailable);
        let restarted = ObservationSlot::default();
        assert_eq!(view(&restarted, &source).capture, Capture::Unobserved);
        for index in 0..=PROJECT_LIMIT {
            let mut row = source.clone();
            row.runtime_id = format!("project-{index}");
            row.inode += index as u64;
            restarted.publish(row, captured(index as u64));
        }
        assert_eq!(view(&restarted, &source).capture, Capture::Unavailable);
        let poisoned = ObservationSlot::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.book.lock().unwrap();
            panic!("synthetic projection lock poison");
        }));
        assert!(result.is_err());
        assert_eq!(view(&poisoned, &source).capture, Capture::Unavailable);
    }
    #[test]
    fn incompatible_counts_tracking_and_nonoriginal_ids_are_rejected() {
        for field in 0..6 {
            let mut value = captured(1).observation;
            match field {
                0 => value.changes.total = 513,
                1 => value.changes.untracked = 4,
                2 => value.tracking.ahead = None,
                3 => value.tracking.ahead = Some(10_000),
                4 => value.head = Head::Detached,
                _ => value.operation_id = "git-read-01".into(),
            }
            assert!(value.validate().is_err());
        }
        let mut value = captured(1).observation;
        value.tracking = Tracking {
            state: TrackingState::Unborn,
            ahead: None,
            behind: None,
        };
        value.head = Head::Unborn;
        assert!(value.validate().is_ok());
    }
}
