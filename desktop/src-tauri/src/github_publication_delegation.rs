//! Original five-file publication facts for the existing GitHub delegation pool.
//! This child does not own permission, a journal, transport or native operation.
//! PendingRead is created only at the parent's positively joined Pending accept
//! site; public Status/marker/hash DATA cannot construct its private identity.
use super::*;
use crate::{service_github_action_protocol as wire, service_github_action_requests as request};
use sha2::{Digest, Sha256};

const ROW_BYTES: usize = 16 * 1024;
// One row at a time: original bounded metadata, canonical DOM/encoded copy and
// fixed hash/framing. No second full 64-row roster is retained or serialized.
pub(super) const WORKING_BYTES: usize = 4 * ROW_BYTES;

fn row_bytes(row: &p::Pending) -> Result<Vec<u8>, BridgeError> {
    if !row.valid()
        || row
            .heap()
            .and_then(|v| v.checked_add(std::mem::size_of::<p::Pending>()))
            .is_none_or(|v| v > ROW_BYTES)
    {
        return Err(refused(p::Reason::ResponseLimit));
    }
    // Same ordered-key canonical JSON as Prepared::sha256. Full claimed and
    // confirmed progress is part of the record, not merely its marker/summary.
    let value = serde_json::to_value(row).map_err(|_| BridgeError::protocol())?;
    let raw = serde_json::to_vec(&value).map_err(|_| BridgeError::protocol())?;
    if raw.len() > ROW_BYTES {
        return Err(refused(p::Reason::ResponseLimit));
    }
    Ok(raw)
}
fn roster(rows: &[p::Pending]) -> Result<[u8; 32], BridgeError> {
    if rows.len() > 64 {
        return Err(refused(p::Reason::ResponseLimit));
    }
    let mut hash = Sha256::new();
    hash.update(b"mrk:original-publication-pending:1\0");
    hash.update((rows.len() as u32).to_be_bytes());
    for (index, row) in rows.iter().enumerate() {
        let target = row.summary.target();
        if rows[..index]
            .iter()
            .any(|v| v.summary.target().marker() == target.marker())
        {
            return Err(BridgeError::protocol());
        }
        let raw = row_bytes(row)?;
        hash.update((raw.len() as u32).to_be_bytes());
        hash.update(raw);
    }
    Ok(hash.finalize().into())
}

pub(super) struct PendingRead {
    pub(super) identity: Arc<()>,
    pub(super) original_id: String,
    pub(super) session_id: String,
    pub(super) project_id: String,
    pub(super) generation: u32,
    pub(super) root: RegisteredRoot,
    pub(super) stamp: SavedEditStamp,
    pub(super) end: Instant,
    pub(super) agent: Option<std::sync::Weak<request::NativeScope>>,
    producer:Option<action_delegation::dispatch::Producer>,
    rows_sha256: [u8; 32],
}
pub(super) struct SelectedRow<'a> {
    // A borrow from the same retained native view, not a reconstructed Status.
    pub(super) record: &'a p::Pending,
    pub(super) sha256: String,
}
impl PendingRead {
    /// Called only after the original Pending ticket/response/control/source
    /// joins have been accepted. Consumes the original private root/edit stamp;
    /// no boolean supplied by a renderer can mint an equivalent witness.
    pub(super) fn returned(
        active: Active,
        rows: &[p::Pending],
        settled_at: Instant,
        session_end: Instant,
        now: Instant,
    ) -> Result<Self, BridgeError> {
        if active.request.kind != p::Kind::Pending
            || active.request.target.setup().is_none()
            || !active.request.valid()
            || rows
                .iter()
                .any(|row| !row.summary.target().same_scope(&active.request.target))
            || settled_at > now
        {
            return Err(BridgeError::protocol());
        }
        let end = settled_at
            .checked_add(Duration::from_secs(120))
            .ok_or_else(BridgeError::protocol)?
            .min(session_end).min(active.agent.as_ref().map_or(session_end,|e|e.scope().read.end()));
        if now >= end {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let rows_sha256 = roster(rows)?;
        Ok(Self {
            producer:active.agent.as_ref().map(|e|action_delegation::dispatch::Producer::new(e,active.ticket.operation_id())),
            identity: Arc::new(()),
            original_id: active.ticket.operation_id().to_owned(),
            session_id: active.session_id,
            project_id: active.project_id,
            generation: active.generation,
            root: active.root,
            stamp: active.stamp,
            end,
            agent: None,
            rows_sha256,
        })
    }
    pub(super) fn binding(
        &self,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> bool {
        now < self.end && self.source(generation, root, edit)
    }
    pub(super) fn source(
        &self,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
    ) -> bool {
        generation == self.generation && root == &self.root && edit.matches(&self.stamp)
    }
    fn view(&self, view: &p::Status) -> bool {
        action_delegation::dispatch::producer_ready(&self.producer) && view.session_id.as_deref() == Some(self.session_id.as_str())
            && view.operation.as_ref().is_some_and(|op| {
                op.id == self.original_id
                    && op.kind == p::Kind::Pending
                    && op.purpose.is_none()
                    && op.phase == p::Phase::Settled
                    && op.reason == p::Reason::None
                    && op.effect == p::Effect::None
            })
            && roster(&view.pending).is_ok_and(|v| v == self.rows_sha256)
    }
    pub(super) fn select<'a>(
        &self,
        view: &'a p::Status,
        marker: &str,
    ) -> Result<SelectedRow<'a>, BridgeError> {
        if !view.available || view.reason != p::Reason::None || !self.view(view) {
            return Err(refused(p::Reason::TargetChanged));
        }
        let record = view
            .pending
            .iter()
            .find(|v| v.summary.target().marker().as_str() == marker)
            .filter(|v| !v.summary.counter())
            .ok_or_else(|| refused(p::Reason::InvalidInput))?;
        Ok(SelectedRow {
            record,
            sha256: p::digest(&row_bytes(record)?),
        })
    }
    pub(super) fn heap(&self) -> Option<usize> {
        self.original_id
            .capacity()
            .checked_add(self.session_id.capacity())?
            .checked_add(self.project_id.capacity())?
            .checked_add(self.root.path.capacity())?
            .checked_add(2 * std::mem::size_of::<usize>())? // Arc<()> allocation
            .checked_add(self.producer.as_ref().map_or(0,action_delegation::dispatch::Producer::heap))
    }
}

impl ConnectionState {
    pub(crate) fn publication_agent_review(
        &self,
        selected: &wire::Selection,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<action_delegation::Review, BridgeError> {
        if !selected.valid()
            || self.publication.active.is_some()
            || self.publication.exhausted
            || !self.publication.view.available
            || self.publication.view.reason != p::Reason::None
        {
            return Err(refused(p::Reason::ConsentExpired));
        }
        match selected {
            wire::Selection::SetupPublish(value) => {
                let consent = self
                    .publication
                    .consent
                    .as_ref()
                    .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
                if !action_delegation::dispatch::producer_ready(&consent.producer) || consent.prepared.setup().is_none()
                    || consent.agent.is_some()
                    || value.session_id != consent.session_id
                    || value.consent_id != consent.id
                    || value.expected_revision != self.publication.view.revision
                    || generation != consent.generation
                    || root != &consent.root
                    || !edit.matches(&consent.stamp)
                    || now >= consent.end
                {
                    return Err(refused(p::Reason::ConsentExpired));
                }
                action_delegation::review(
                    wire::Kind::SetupPublish,
                    &consent.session_id,
                    &consent.id,
                    value.expected_revision,
                    &consent.prepared,
                    consent.identity.clone(),
                    edit.stamp()?,
                    consent.end,
                )
            }
            wire::Selection::SetupReconcile(value) => {
                let read = self
                    .publication
                    .pending_read
                    .as_ref()
                    .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
                if read.agent.is_some()
                    || value.session_id != read.session_id
                    || value.expected_revision != self.publication.view.revision
                    || !read.binding(generation, root, edit, now)
                {
                    return Err(refused(p::Reason::ConsentExpired));
                }
                let selected = read.select(&self.publication.view, &value.marker)?;
                let data = wire::Review::SetupReconcile(wire::PendingReference {
                    session_id: read.session_id.clone(),
                    expected_revision: value.expected_revision,
                    marker: selected.record.summary.target().marker().clone(),
                    record_sha256: selected.sha256,
                });
                if !data.valid() {
                    return Err(BridgeError::protocol());
                }
                Ok(action_delegation::Review {
                    identity: read.identity.clone(),
                    stamp: edit.stamp()?,
                    end: read.end,
                    data,
                    activity: None,
                    dispatch: None,
                    enrollment: None,
                })
            }
            _ => Err(refused(p::Reason::InvalidInput)),
        }
    }
    pub(crate) fn publication_agent_allow(
        &mut self,
        review: &action_delegation::Review,
        scope: &Arc<request::NativeScope>,
    ) -> Result<(), BridgeError> {
        if scope.review != review.data {
            return Err(refused(p::Reason::ConsentExpired));
        }
        let slot = match &review.data {
            wire::Review::SetupPublish(_) => {
                let consent = self
                    .publication
                    .consent
                    .as_mut()
                    .filter(|c| {
                        c.prepared.setup().is_some() && Arc::ptr_eq(&c.identity, &review.identity)
                    })
                    .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
                &mut consent.agent
            }
            wire::Review::SetupReconcile(value) => {
                let read = self
                    .publication
                    .pending_read
                    .as_mut()
                    .filter(|v| Arc::ptr_eq(&v.identity, &review.identity))
                    .ok_or_else(|| refused(p::Reason::ConsentExpired))?;
                if read.select(&self.publication.view, &value.marker)?.sha256 != value.record_sha256
                {
                    return Err(refused(p::Reason::TargetChanged));
                }
                &mut read.agent
            }
            _ => return Err(refused(p::Reason::InvalidInput)),
        };
        if slot.is_some() {
            return Err(refused(p::Reason::ConsentExpired));
        }
        *slot = Some(Arc::downgrade(scope));
        Ok(())
    }
    pub(crate) fn publication_agent_revoke(&mut self, scope: &Arc<request::NativeScope>) {
        let same = |value: &Option<std::sync::Weak<request::NativeScope>>| {
            value
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|v| Arc::ptr_eq(&v, scope))
        };
        if self
            .publication
            .consent
            .as_ref()
            .is_some_and(|c| same(&c.agent))
            || self
                .publication
                .pending_read
                .as_ref()
                .is_some_and(|r| same(&r.agent))
        {
            let before = self.publication.view.clone();
            self.publication.revoke_consent();
            self.publication.finish(before);
        }
    }
    /// Called under the SAME Doc/Edit guards, before any counter facet or path
    /// acquisition. It compares native identities; the public hash is not a loan.
    pub(crate) fn publication_agent_current(
        &self,
        command: &p::Command,
        entry: &Arc<request::Entry>,
        generation: u32,
        root: &RegisteredRoot,
        edit: &SavedEditGuard<'_>,
        now: Instant,
    ) -> Result<(), BridgeError> {
        entry
            .current(false)
            .map_err(crate::asset_session::application_service::public_error)?;
        let scope = entry.scope();
        let good = match (command, &scope.review) {
            (p::Command::Publish(args), wire::Review::SetupPublish(value)) => {
                self.publication.consent.as_ref().is_some_and(|c| {
                    c.prepared.setup().is_some()
                        && Arc::ptr_eq(&c.identity, &scope.identity)
                        && action_delegation::origin(&c.agent, Some(entry))
                        && args.confirm
                        && args.session_id == value.session_id
                        && args.consent_id == value.consent_id
                        && args.expected_revision == value.expected_revision
                        && value.expected_revision == self.publication.view.revision
                        && c.id == value.consent_id
                        && c.session_id == value.session_id
                        && c.generation == generation
                        && &c.root == root
                        && edit.matches(&c.stamp)
                        && now < c.end
                        && action_delegation::review(
                            wire::Kind::SetupPublish,
                            &c.session_id,
                            &c.id,
                            value.expected_revision,
                            &c.prepared,
                            c.identity.clone(),
                            match edit.stamp() {
                                Ok(s) => s,
                                Err(_) => return false,
                            },
                            c.end,
                        )
                        .is_ok_and(|v| v.data == scope.review)
                })
            }
            (p::Command::Reconcile(args), wire::Review::SetupReconcile(value)) => {
                self.publication.pending_read.as_ref().is_some_and(|r| {
                    Arc::ptr_eq(&r.identity, &scope.identity)
                        && action_delegation::origin(&r.agent, Some(entry))
                        && args.session_id == value.session_id
                        && args.marker == value.marker
                        && args.expected_revision == value.expected_revision
                        && value.expected_revision == self.publication.view.revision
                        && r.session_id == value.session_id
                        && r.binding(generation, root, edit, now)
                        && r.select(&self.publication.view, &value.marker)
                            .is_ok_and(|v| v.sha256 == value.record_sha256)
                })
            }
            _ => false,
        };
        if !good {
            return Err(refused(p::Reason::ConsentExpired));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn row() -> p::Pending {
        let request = super::super::tests::request(p::Kind::Publish);
        let summary = request.prepared.unwrap().setup().unwrap().summary();
        p::Pending {
            summary: summary.into(),
            claimed: vec![
                p::Step::Tree,
                p::Step::Commit,
                p::Step::Branch,
                p::Step::Pull,
            ],
            confirmed: BTreeMap::from([
                (p::Step::Tree, "f".repeat(40)),
                (p::Step::Commit, "1".repeat(40)),
                (p::Step::Branch, "1".repeat(40)),
            ]),
        }
    }
    // Same existing in-memory Owner/edit fixture; these are comparison tests,
    // not a process receipt, IO/Host finality or a remote Pending-load proof.
    fn comparison(at: Instant) -> (PendingRead, p::Status) {
        let (mut state, _edit, _doc, _root, control) =
            super::super::tests::fixture(p::Kind::Pending, at);
        let rows = vec![row()];
        let read = PendingRead::returned(
            state.publication.active.take().unwrap(),
            &rows,
            at,
            at + Duration::from_secs(200),
            at,
        )
        .unwrap();
        state.publication.view.operation.as_mut().unwrap().phase = p::Phase::Settled;
        state.publication.view.available = true;
        state.publication.view.reason = p::Reason::None;
        state.publication.view.pending = rows;
        assert!(control.retained()); // comparison did not retire an Owner
        (read, state.publication.view)
    }
    #[test]
    fn exact_original_load_and_full_progress_are_required_not_marker_or_status_alone() {
        let (read, mut view) = comparison(Instant::now());
        let before = read.select(&view, &"c".repeat(32)).unwrap().sha256;
        assert_eq!(before, p::digest(&row_bytes(&row()).unwrap()));
        view.pending[0].confirmed.insert(p::Step::Pull, "23".into());
        assert!(read.select(&view, &"c".repeat(32)).is_err());
        assert_ne!(before, p::digest(&row_bytes(&view.pending[0]).unwrap()));
        view.pending = vec![row()];
        view.operation.as_mut().unwrap().id.push('2');
        assert!(read.select(&view, &"c".repeat(32)).is_err());
    }
    #[test]
    fn replacement_load_identity_is_distinct_even_with_equal_public_rows() {
        let at = Instant::now();
        let (first, view) = comparison(at);
        let (second, _) = comparison(at);
        assert!(!Arc::ptr_eq(&first.identity, &second.identity));
        assert_eq!(first.rows_sha256, second.rows_sha256);
        assert!(first.select(&view, &"0".repeat(32)).is_err());
        assert!(first.heap().unwrap() < WORKING_BYTES);
    }
    #[test]
    fn complete_roster_duplicate_foreign_and_nonpending_original_refuse() {
        assert!(roster(&[row(), row()]).is_err());
        assert!(roster(&vec![row(); 65]).is_err());
        let at = Instant::now();
        for kind in [p::Kind::Prepare, p::Kind::Publish, p::Kind::Reconcile] {
            let (mut state, _edit, _doc, _root, control) = super::super::tests::fixture(kind, at);
            assert!(PendingRead::returned(
                state.publication.active.take().unwrap(),
                &[row()],
                at,
                at + Duration::from_secs(200),
                at,
            )
            .is_err());
            assert!(control.retained());
        }
        let (mut state, _edit, _doc, _root, _) = super::super::tests::fixture(p::Kind::Pending, at);
        let mut foreign = row();
        if let p::Record::Setup(summary) = &mut foreign.summary {
            summary.target.repository_id = "33".into();
        }
        assert!(PendingRead::returned(
            state.publication.active.take().unwrap(),
            &[foreign],
            at,
            at + Duration::from_secs(200),
            at
        )
        .is_err());
    }
    #[test]
    fn original_native_edit_root_and_deadline_cannot_be_replaced_or_renewed() {
        let at = Instant::now();
        let (mut state, edit, doc, root, control) =
            super::super::tests::fixture(p::Kind::Pending, at);
        let read = PendingRead::returned(
            state.publication.active.take().unwrap(),
            &[row()],
            at,
            at + Duration::from_secs(25),
            at,
        )
        .unwrap();
        assert_eq!(read.end, at + Duration::from_secs(25));
        {
            let guard = edit.saved_registration_guard(&doc).unwrap();
            assert!(read.binding(2, &root, &guard, at));
            assert!(!read.binding(3, &root, &guard, at));
            let mut wrong = root.clone();
            wrong.path.push("other");
            assert!(!read.binding(2, &wrong, &guard, at));
            assert!(!read.binding(2, &root, &guard, read.end));
        }
        edit.document_lost("main");
        assert!(!read.binding(2, &root, &edit.saved_registration_guard(&doc).unwrap(), at));
        assert!(control.retained());
    }
}

#[path="github_counter_delegation.rs"]
mod counter;
