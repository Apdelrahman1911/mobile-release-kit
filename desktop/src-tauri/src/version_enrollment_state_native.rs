//! Child of the existing VersionAllocations codec/port. Same namespace, native
//! Store and CAS; no reset, new journal, allocation policy or filesystem owner.
use super::*;
use crate::{
    application_service_host::{NativeStateLease, NativeStateReady},
    supervisor::{VersionEnrollmentControl, VersionEnrollmentJoined},
    version_enrollment_protocol as p,
};
use std::{sync::Mutex, time::Instant};
use tokio::{
    sync::oneshot,
    task::{JoinError, JoinHandle},
};

// This new path does not expand the original Document's 16MiB data partition.
// The full namespace remains retained and unchanged if it exceeds this bound.
const ENROLLMENT_STATE_LIMIT: usize = 256 * 1024;

fn authority(offer: &p::Offer) -> Result<Authority> {
    need(offer.valid())?;
    decode(
        serde_json::to_value(&offer.authority)
            .map_err(|_| StateError::from(Error::InvalidRequest))?,
    )
}
fn checkpoint(value: &p::Checkpoint) -> Result<Checkpoint> {
    decode(serde_json::to_value(value).map_err(|_| StateError::from(Error::InvalidRequest))?)
}
impl VersionAllocationStatePort {
    /// The actual captured slot, not a new IO/read or a lookup by renderer ID.
    fn enrollment_previous(&self, offer: &p::Offer) -> Result<Option<p::Checkpoint>> {
        need(authority(offer)? == self.authority)?;
        let state = self.state()?;
        if let Some(enrolled) = state
            .enrollments
            .iter()
            .find(|e| e.local_project_id == self.project.project_id.as_str())
        {
            need(enrolled.authority_project_id == self.authority.project_id)?;
        }
        let row = state
            .authorities
            .iter()
            .find(|r| r.authority.project_id == self.authority.project_id);
        if let Some(row) = row {
            need(row.authority == self.authority)?;
            Ok(Some(
                serde_json::from_value(
                    serde_json::to_value(&row.checkpoint).map_err(|_| unknown())?,
                )
                .map_err(|_| unknown())?,
            ))
        } else {
            Ok(None)
        }
    }
    /// Only Custody::commit reaches this from a fresh original HTTP return.
    /// The worker proved full canonical chain + old prefix/commit ancestry;
    /// these secondary checks preserve the exact captured local rows.
    fn enroll_observed(
        &mut self,
        offer: &p::Offer,
        previous: Option<&p::Checkpoint>,
        unsupported: &mut bool,
    ) -> Result<WriteAck> {
        need(self.enrollment_previous(offer)?.as_ref() == previous)?;
        let current = checkpoint(&offer.checkpoint)?;
        need(
            current.valid()
                && previous.is_none_or(|old| {
                    current.sequence >= old.sequence
                        && (current.sequence != old.sequence
                            || current.head_sha256 == old.head_sha256)
                }),
        )?;
        let mut next = self.state()?.clone();
        if !next
            .authorities
            .iter()
            .any(|r| r.authority.project_id == self.authority.project_id)
        {
            need(previous.is_none())?;
            // Anchor the actual CURRENT reviewed checkpoint, including nonzero
            // sequence; never relabel a current commit as a genesis commit.
            next.authorities.push(AuthorityState {
                authority: self.authority.clone(),
                checkpoint: current,
                pending: None,
            });
            next.authorities
                .sort_by(|a, b| a.authority.project_id.cmp(&b.authority.project_id));
        }
        if !next
            .enrollments
            .iter()
            .any(|e| e.local_project_id == self.project.project_id.as_str())
        {
            next.enrollments.push(Enrollment {
                local_project_id: self.project.project_id.as_str().to_owned(),
                authority_project_id: self.authority.project_id.clone(),
            });
            next.enrollments
                .sort_by(|a, b| a.local_project_id.cmp(&b.local_project_id));
        }
        // An existing authority/checkpoint/pending/candidate is NOT rewritten
        // from remote data. Even already connected needs this exact-slot CAS;
        // a same-byte concurrent revision must not acknowledge a stale port.
        // The typed successor derives only from the bounded original plus
        // one authority/mapping. Check the SAME fixed limits before the sole
        // CAS; this does not truncate or reserialize old rows differently.
        {
            let bytes = next.bytes()?;
            if let Err(error) = crate::protocol::strict_version_enrollment_state_json(&bytes) {
                if error.code == "version_enrollment_state_limit" {
                    *unsupported = true;
                    return Err(Error::Unavailable.into());
                }
                return Err(Error::RecoveryRequired.into());
            }
        }
        self.store(next)
    }
}

struct Custody {
    ready: Arc<NativeStateReady>,
    offer: p::Offer,
    lease: Option<Arc<NativeStateLease>>,
    port: Option<VersionAllocationStatePort>,
    entered: bool,
    commit_entered: bool,
    unsupported: bool,
    retirement_entered: bool,
    retirement_result: Option<Result<()>>,
}
impl Custody {
    fn load(&mut self) -> Result<Option<p::Checkpoint>> {
        need(!self.entered && self.lease.is_none() && self.port.is_none())?;
        self.entered = true;
        self.lease = Some(Arc::new(self.ready.begin_use()?));
        let lease = self.lease.as_ref().ok_or_else(unknown)?;
        lease.store().check_native_use(lease.native_use())?;
        self.port = Some(VersionAllocationStatePort::new(
            lease.store().clone(),
            lease.project_binding().clone(),
            serde_json::to_value(&self.offer.authority)
                .map_err(|_| StateError::from(Error::InvalidRequest))?,
        )?);
        let port = self.port.as_mut().ok_or_else(unknown)?;
        if let Err(error) = port.load_bounded(ENROLLMENT_STATE_LIMIT) {
            // Unavailable with this retained snapshot is the named parser's
            // byte/node refusal, not a missing file or malformed JSON.
            self.unsupported = error.code == Error::Unavailable && port.snapshot.is_some();
            return Err(error);
        }
        port.enrollment_previous(&self.offer)
    }
    fn commit(&mut self, joined: &VersionEnrollmentJoined) -> Result<WriteAck> {
        need(!self.commit_entered && !self.retirement_entered)?;
        self.commit_entered = true;
        let request = joined.request();
        let reply = joined
            .outcome()
            .as_ref()
            .map_err(|_| StateError::from(Error::Conflict))?;
        need(
            request.kind == p::Kind::Confirm
                && request.review.as_ref() == Some(&self.offer)
                && reply.result.reason == p::Reason::None
                && reply.result.offer.as_ref() == Some(&self.offer)
                && reply.result.control.reason == crate::github_connection_protocol::Reason::None,
        )?;
        let lease = self.lease.as_ref().ok_or_else(unknown)?;
        lease.store().check_native_use(lease.native_use())?;
        let port = self.port.as_mut().ok_or_else(unknown)?;
        need(port.matches_native_binding(lease.store(), lease.project_binding()))?;
        port.enroll_observed(
            &self.offer,
            request.previous.as_ref(),
            &mut self.unsupported,
        )
    }
}

enum Returned {
    Loaded(Option<p::Checkpoint>),
    Committed(WriteAck),
}
struct Job {
    release: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Result<Returned>>>,
    result: Option<Result<Returned>>,
    join_error: Option<JoinError>,
}
/// Exactly load and optional one enrollment write. Installed in the original
/// Document lane BEFORE register; neither body result nor Drop frees NativeUse.
pub(crate) struct Jobs {
    custody: Arc<Mutex<Custody>>,
    control: Arc<VersionEnrollmentControl>,
    work_end: Instant,
    slots: [Option<Job>; 2],
    active: Option<usize>,
    count: usize,
    sealed: bool,
}
impl Jobs {
    pub(crate) fn new(
        ready: Arc<NativeStateReady>,
        offer: p::Offer,
        control: Arc<VersionEnrollmentControl>,
        work_end: Instant,
    ) -> Result<Self> {
        need(offer.valid() && control.current() && Instant::now() < work_end)?;
        Ok(Self {
            custody: Arc::new(Mutex::new(Custody {
                ready,
                offer,
                lease: None,
                port: None,
                entered: false,
                commit_entered: false,
                unsupported: false,
                retirement_entered: false,
                retirement_result: None,
            })),
            control,
            work_end,
            slots: [None, None],
            active: None,
            count: 0,
            sealed: false,
        })
    }
    pub(crate) fn register_load(&mut self) -> Result<()> {
        need(self.count == 0)?;
        self.register(None)
    }
    pub(crate) fn register_commit(&mut self, joined: Arc<VersionEnrollmentJoined>) -> Result<()> {
        need(
            self.count == 1
                && self.all_returned()
                && joined.matches(&self.control, joined.request()),
        )?;
        self.register(Some(joined))
    }
    fn register(&mut self, joined: Option<Arc<VersionEnrollmentJoined>>) -> Result<()> {
        need(
            !self.sealed
                && self.count < 2
                && self.active.is_none()
                && self.control.current()
                && Instant::now() < self.work_end,
        )?;
        self.sealed = true; // A failed/panicking registration cannot start another job.
        let index = self.count;
        let (release, enter) = oneshot::channel();
        self.slots[index] = Some(Job {
            release: Some(release),
            handle: None,
            result: None,
            join_error: None,
        });
        self.active = Some(index);
        self.count += 1;
        let custody = self.custody.clone();
        let control = self.control.clone();
        let end = self.work_end;
        let handle = tokio::task::spawn_blocking(move || {
            let mut failure_at = None;
            let result = (|| {
                enter
                    .blocking_recv()
                    .map_err(|_| StateError::from(Error::AccessDenied))?;
                need(control.current() && Instant::now() < end)?;
                let mut custody = custody.lock().map_err(|_| unknown())?;
                need(control.current() && Instant::now() < end)?;
                let result = match joined {
                    Some(joined) => custody.commit(&joined).map(Returned::Committed),
                    None => custody.load().map(Returned::Loaded),
                };
                // Sample at the original IO return, BEFORE releasing custody
                // or waiting for an async observer to notice the failed job.
                if result.is_err() {
                    failure_at = Some(Instant::now());
                }
                result
            })();
            // The custody guard is gone before forwarding STOP to Supervisor.
            if result.is_err() {
                control.stop_at(failure_at.unwrap_or_else(Instant::now));
            }
            result
        });
        self.slots[index].as_mut().ok_or_else(unknown)?.handle = Some(handle);
        self.sealed = false;
        Ok(())
    }
    /// Pure release only; called AFTER original same-Document rematch, with no
    /// Host/Store/custody lock held. STOP never aborts a running fsync.
    pub(crate) fn release(&mut self) -> Result<()> {
        let index = self.active.ok_or_else(unknown)?;
        if !self.control.current() || Instant::now() >= self.work_end {
            self.stop();
            return Err(Error::Expired.into());
        }
        let job = self.slots[index].as_mut().ok_or_else(unknown)?;
        let sender = job.release.take().ok_or_else(unknown)?;
        sender.send(()).map_err(|_| unknown())
    }
    pub(crate) fn stop(&mut self) {
        self.sealed = true;
        for job in self.slots.iter_mut().flatten() {
            job.release.take();
        }
    }
    pub(crate) fn join_pending(&self) -> bool {
        self.active.is_some()
    }
    pub(crate) async fn join(&mut self) -> Result<()> {
        let index = self.active.ok_or_else(unknown)?;
        let job = self.slots[index].as_mut().ok_or_else(unknown)?;
        // Borrow the SAME retained handle. A timeout never aborts/drops it or
        // retires NativeUse; STOP only contracts this original join endpoint.
        let mut stop = self.control.stop_clock();
        let returned = loop {
            let end = self
                .control
                .cleanup_end(self.work_end)
                .ok_or_else(unknown)?;
            tokio::select! {
                biased;
                returned=job.handle.as_mut().ok_or_else(unknown)?=>break (returned,end),
                changed=stop.changed()=>{if changed.is_err(){self.control.unknown();return Err(unknown());}},
                _=tokio::time::sleep_until(end.into())=>{self.control.unknown();self.sealed=true;return Err(unknown());},
            }
        };
        let (returned, end) = returned;
        match returned {
            Ok(result) => {
                job.result = Some(result);
                job.handle.take();
                self.active = None;
                if Instant::now() >= end
                    || self.control.check_cleanup(self.work_end).is_err()
                {
                    self.control.unknown();
                    self.sealed = true;
                    Err(unknown())
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                job.join_error = Some(error);
                self.sealed = true;
                self.control.unknown();
                Err(unknown())
            }
        }
    }
    pub(crate) fn previous(&self) -> Result<Option<p::Checkpoint>> {
        match self.slots[0]
            .as_ref()
            .and_then(|j| j.result.as_ref())
            .ok_or_else(unknown)?
        {
            Ok(Returned::Loaded(value)) => Ok(value.clone()),
            Err(error) => Err(*error),
            _ => Err(unknown()),
        }
    }
    pub(crate) fn state_too_large(&self) -> bool {
        self.custody.lock().is_ok_and(|c| c.unsupported)
    }
    pub(crate) fn committed(&self) -> Result<&WriteAck> {
        match self.slots[1]
            .as_ref()
            .and_then(|j| j.result.as_ref())
            .ok_or_else(unknown)?
        {
            Ok(Returned::Committed(value)) => Ok(value),
            Err(error) => Err(*error),
            _ => Err(unknown()),
        }
    }
    fn all_returned(&self) -> bool {
        self.active.is_none()
            && self
                .slots
                .iter()
                .flatten()
                .all(|j| j.handle.is_none() && j.result.is_some() && j.join_error.is_none())
    }
    /// OFF Doc/Edit/Host. Positive original HTTP observer join (or proved
    /// never-admitted) AND both actual jobs returned are necessary to retire.
    pub(crate) fn retire_original(
        &mut self,
        joined: Option<&VersionEnrollmentJoined>,
    ) -> Result<()> {
        need(
            !self.control.uncertain()
                && self.all_returned()
                && joined.map_or_else(
                    || self.control.never_admitted(),
                    |j| j.matches(&self.control, j.request()),
                ),
        )?;
        self.sealed = true;
        self.control
            .check_cleanup(self.work_end)
            .map_err(|_| unknown())?;
        let mut custody = self.custody.lock().map_err(|_| unknown())?;
        need(!custody.retirement_entered && custody.retirement_result.is_none())?;
        // Acquiring this custody mutex can itself be delayed. Check again
        // before entering the original Store mutex; do not forward failure
        // while retaining this guard.
        if self.control.uncertain()
            || self
                .control
                .cleanup_end(self.work_end)
                .is_none_or(|end| Instant::now() >= end)
        {
            drop(custody);
            self.control.unknown();
            return Err(unknown());
        }
        custody.retirement_entered = true;
        let result = custody.lease.as_ref().map_or(Ok(()), |lease| {
            lease.store().retire_native_use(lease.native_use())
        });
        let failure_at = result.as_ref().err().map(|_| Instant::now());
        // Remember the actual primitive result even when its return is late.
        // In particular, a physically retired token must never be retried.
        custody.retirement_result = Some(result);
        drop(custody);
        if let Some(at) = failure_at {
            self.control.stop_at(at);
        }
        self.control
            .check_cleanup(self.work_end)
            .map_err(|_| unknown())?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_state_store::Fixture;
    fn offer() -> p::Offer {
        p::Offer {
            authority: p::Authority {
                project_id: "a".repeat(32),
                repository: "fixture/app".into(),
                repository_id: "123".into(),
                ledger_id: "00000000-0000-4000-8000-000000000003".into(),
                genesis_sha256: "b".repeat(64),
                protected_branch: true,
            },
            checkpoint: p::Checkpoint {
                sequence: 3,
                head_sha256: "c".repeat(64),
                commit: "d".repeat(40),
            },
            blob: "e".repeat(40),
            version: p::Version {
                name: "1.2.3".into(),
                build: 7,
            },
        }
    }
    fn port(
        store: &Arc<PrivateStateDirectory>,
        local: &str,
        offer: &p::Offer,
    ) -> VersionAllocationStatePort {
        VersionAllocationStatePort::new(
            store.clone(),
            ProjectBinding {
                project_id: Id::parse(local).unwrap(),
                canonical_root: "/synthetic/project".into(),
                device: 1,
                inode: 2,
            },
            serde_json::to_value(&offer.authority).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn expired_cleanup_does_not_enter_original_token_retirement() {
        let f = Fixture::new();
        let store = PrivateStateDirectory::open(&f.app).unwrap();
        let original = store.begin_native_use().unwrap();
        let control = VersionEnrollmentControl::new();
        let now = Instant::now();
        let end = now + std::time::Duration::from_secs(60);
        control.stop_at(now.checked_sub(crate::supervisor::CLEANUP_TIME).unwrap());
        assert!(control.check_cleanup(end).is_err());
        store.check_native_use(&original).unwrap();
        assert_eq!(store.close().unwrap_err().code, Error::Busy);
        assert!(control.returned(end).is_err());
        assert!(control.pending());
        // Test-owned primitive teardown only, not an original all-jobs receipt.
        store.retire_native_use(&original).unwrap();
        store.close().unwrap();
    }
    #[test]
    fn actual_store_mutex_return_after_cutoff_keeps_retired_fact_but_no_lane_credit() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let original = Arc::new(store.begin_native_use().unwrap());
        let control = Arc::new(VersionEnrollmentControl::new());
        let end = Instant::now() + std::time::Duration::from_secs(60);
        // SAME real Book mutex, not an IO callback or a result-shaped join.
        let held = store.ipc_directory().unwrap();
        let (started, entered) = std::sync::mpsc::sync_channel(0);
        let (retirement, final_check) = std::thread::scope(|scope| {
            let store = store.clone();
            let original = original.clone();
            let worker_control = control.clone();
            let worker = scope.spawn(move || {
                worker_control.check_cleanup(end).unwrap();
                started.send(()).unwrap();
                let actual = store.retire_native_use(&original);
                // As in Custody, remember actual success BEFORE checking the
                // current endpoint after the possibly delayed Store return.
                let remembered = Some(actual);
                (remembered, worker_control.check_cleanup(end))
            });
            entered.recv().unwrap();
            control.stop_at(
                Instant::now()
                    .checked_sub(crate::supervisor::CLEANUP_TIME)
                    .unwrap(),
            );
            drop(held);
            worker.join().unwrap()
        });
        assert!(retirement.unwrap().is_ok());
        assert!(final_check.is_err());
        assert_eq!(
            store.check_native_use(&original).unwrap_err().code,
            Error::Conflict
        );
        assert!(control.uncertain());
        assert!(control.pending());
        assert!(control.returned(end).is_err());
        // Do NOT retry retirement of the physically retired original token.
        store.close().unwrap();
    }
    #[test]
    fn actual_current_checkpoint_is_stored_without_genesis_invention_and_reconnect_is_cas() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        let mut first = port(&store, &"1".repeat(32), &offer);
        first.load().unwrap();
        assert!(first.enrollment_previous(&offer).unwrap().is_none());
        assert_eq!(
            first
                .enroll_observed(&offer, None, &mut false)
                .unwrap()
                .revision,
            Revision(1)
        );
        let original = first.snapshot().unwrap().bytes.clone();
        assert_eq!(first.state().unwrap().authorities[0].checkpoint.sequence, 3);
        assert_eq!(
            first.state().unwrap().authorities[0].checkpoint.commit,
            offer.checkpoint.commit
        );
        let previous = first.enrollment_previous(&offer).unwrap();
        assert_eq!(
            first
                .enroll_observed(&offer, previous.as_ref(), &mut false)
                .unwrap()
                .revision,
            Revision(2)
        );
        assert_eq!(first.snapshot().unwrap().bytes, original);
        store.close().unwrap();
    }
    #[test]
    fn second_local_mapping_preserves_existing_checkpoint_pending_and_candidates() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        let mut first = port(&store, &"1".repeat(32), &offer);
        first.load().unwrap();
        first.enroll_observed(&offer, None, &mut false).unwrap();
        let request = json!({"projectId":offer.authority.project_id,"identityRevision":"1".repeat(64),
            "source":{"commit":"2".repeat(40),"tree":"3".repeat(40),"ref":"refs/heads/main",
                "configurationSha256":"4".repeat(64),"versionSha256":"5".repeat(64)},
            "baseVersion":{"name":"1.2.3","build":7},"platforms":["android"],
            "policy":{"schemaVersion":1,"mode":"automatic","rules":[{"ref":"refs/heads/main","increment":"build"}],
                "buildCeiling":2100000000,"storeMaxAgeSeconds":300}});
        first.select_new(request, None).unwrap();
        let request = first.selected_request().unwrap().clone();
        let old_value =
            serde_json::to_value(&first.state().unwrap().authorities[0].checkpoint).unwrap();
        let mut reservation = json!({"sequence":4,"previousSha256":offer.checkpoint.head_sha256,"request":request,
            "requestSha256":hash(b"mrk:allocation-request:1\0",&request).unwrap(),"version":{"name":"1.2.3","build":8},
            "storeObservations":[],"allocatedAt":2000});
        reservation["sha256"] =
            json!(hash(b"mrk:allocation-reservation:1\0", &reservation).unwrap());
        let pending = json!({"schemaVersion":1,"protocol":ALLOCATION_PROTOCOL,"authority":offer.authority,
            "checkpoint":old_value,"expectedBlob":offer.blob,"reservation":reservation});
        first
            .apply(Revision(2), &request, Transition::Pending(pending))
            .unwrap();
        let old = first.state().unwrap().authorities[0].checkpoint.clone();
        let pending = canonical(&first.state().unwrap().authorities[0].pending, ROW_LIMIT).unwrap();
        let candidates = canonical(&first.state().unwrap().candidates, STATE_LIMIT).unwrap();
        let mut advanced = offer.clone();
        advanced.checkpoint.sequence = 4;
        advanced.checkpoint.head_sha256 = reservation["sha256"].as_str().unwrap().into();
        advanced.checkpoint.commit = "a".repeat(40);
        let mut second = port(&store, &"2".repeat(32), &offer);
        second.load().unwrap();
        let previous = second.enrollment_previous(&advanced).unwrap();
        second
            .enroll_observed(&advanced, previous.as_ref(), &mut false)
            .unwrap();
        assert!(second.state().unwrap().authorities[0].checkpoint == old);
        assert_eq!(second.state().unwrap().enrollments.len(), 2);
        assert_eq!(
            canonical(&second.state().unwrap().candidates, STATE_LIMIT).unwrap(),
            candidates
        );
        assert_eq!(
            canonical(&second.state().unwrap().authorities[0].pending, ROW_LIMIT).unwrap(),
            pending
        );
        assert!(second.selected_request().is_err()); // Never adopt the other local candidate.
        store.close().unwrap();
    }
    #[test]
    fn stale_slot_cannot_confirm_even_identical_bytes_and_failed_port_stays_retained() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        let mut first = port(&store, &"1".repeat(32), &offer);
        first.load().unwrap();
        first.enroll_observed(&offer, None, &mut false).unwrap();
        let mut stale = port(&store, &"1".repeat(32), &offer);
        stale.load().unwrap();
        let previous = stale.enrollment_previous(&offer).unwrap();
        first
            .enroll_observed(&offer, previous.as_ref(), &mut false)
            .unwrap();
        let error = stale
            .enroll_observed(&offer, previous.as_ref(), &mut false)
            .err()
            .unwrap();
        assert_eq!(error.code, Error::Conflict);
        assert!(stale.attempted.is_some());
        assert_eq!(stale.failure(), Some(error));
        assert!(stale.load().is_err());
        assert!(stale
            .enroll_observed(&offer, previous.as_ref(), &mut false)
            .is_err());
        store.close().unwrap();
    }
    #[test]
    fn foreign_authority_and_rewound_review_do_not_write_or_rebind() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        let mut first = port(&store, &"1".repeat(32), &offer);
        first.load().unwrap();
        first.enroll_observed(&offer, None, &mut false).unwrap();
        let previous = first.enrollment_previous(&offer).unwrap();
        let bytes = first.snapshot().unwrap().bytes.clone();
        let mut wrong = offer.clone();
        wrong.authority.repository_id = "999".into();
        assert!(first
            .enroll_observed(&wrong, previous.as_ref(), &mut false)
            .is_err());
        wrong = offer.clone();
        wrong.checkpoint.sequence = 2;
        assert!(first
            .enroll_observed(&wrong, previous.as_ref(), &mut false)
            .is_err());
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().bytes,
            bytes
        );
        store.close().unwrap();
    }
    #[test]
    fn enrollment_bound_precedes_parse_and_keeps_full_state_while_ordinary_load_stays_one_mib() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        let mut state = State::empty();
        state.authorities.push(AuthorityState {
            authority: authority(&offer).unwrap(),
            checkpoint: checkpoint(&offer.checkpoint).unwrap(),
            pending: None,
        });
        let rules:Vec<_>=(0..32).map(|n|json!({"ref":format!("refs/heads/{n:02}-{}","q".repeat(185)),"increment":"build"})).collect();
        for n in 1..=40 {
            let local = format!("{n:032x}");
            state.enrollments.push(Enrollment {
                local_project_id: local.clone(),
                authority_project_id: offer.authority.project_id.clone(),
            });
            state.candidates.push(Candidate {local_project_id:local,request:Request(json!({"projectId":offer.authority.project_id,
                "candidateId":format!("{n:08x}-0000-4000-8000-000000000001"),"identityRevision":"1".repeat(64),
                "source":{"commit":"2".repeat(40),"tree":"3".repeat(40),"ref":"refs/heads/main",
                    "configurationSha256":"4".repeat(64),"versionSha256":"5".repeat(64)},
                "baseVersion":{"name":"1.2.3","build":7},"platforms":["android"],
                "policy":{"schemaVersion":1,"mode":"automatic","rules":rules,"buildCeiling":2100000000,"storeMaxAgeSeconds":300}})),reservation:None});
        }
        let bytes = state.bytes().unwrap();
        assert!(bytes.len() > ENROLLMENT_STATE_LIMIT && bytes.len() <= STATE_LIMIT);
        store
            .replace(Namespace::VersionAllocations, Revision(0), &bytes)
            .unwrap();
        let mut ordinary = port(&store, &format!("{:032x}", 1), &offer);
        ordinary.load().unwrap();
        assert_eq!(ordinary.state().unwrap().candidates.len(), 40);
        let mut bounded = port(&store, &format!("{:032x}", 1), &offer);
        assert_eq!(
            bounded
                .load_bounded(ENROLLMENT_STATE_LIMIT)
                .unwrap_err()
                .code,
            Error::Unavailable
        );
        assert!(bounded.state.is_none());
        assert_eq!(bounded.snapshot.as_ref().unwrap().bytes, bytes);
        assert!(bounded.load().is_err());
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().bytes,
            bytes
        );
        let mut unsupported = false;
        let previous = ordinary.enrollment_previous(&offer).unwrap();
        assert_eq!(
            ordinary
                .enroll_observed(&offer, previous.as_ref(), &mut unsupported)
                .err()
                .unwrap()
                .code,
            Error::Unavailable
        );
        assert!(unsupported);
        assert!(ordinary.attempted.is_none()); // No native CAS was called.
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().bytes,
            bytes
        );
        // Invalid oversized DATA reaches the same size refusal, not the JSON
        // parser's RecoveryRequired route; the full original is still retained.
        let invalid = vec![b'!'; ENROLLMENT_STATE_LIMIT + 1];
        store
            .replace(Namespace::VersionAllocations, Revision(1), &invalid)
            .unwrap();
        let mut bounded = port(&store, &format!("{:032x}", 1), &offer);
        assert_eq!(
            bounded
                .load_bounded(ENROLLMENT_STATE_LIMIT)
                .unwrap_err()
                .code,
            Error::Unavailable
        );
        assert_eq!(bounded.snapshot.as_ref().unwrap().bytes, invalid);
        store.close().unwrap();
    }
    #[test]
    fn tiny_container_complexity_is_refused_before_canonical_clones_without_reset() {
        let f = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let offer = offer();
        // Under 256KiB and the ORIGINAL 50k nodes, but deliberately not a
        // valid state. It must not allocate/canonical-clone all 16k maps.
        let tiny = json!({"schemaVersion":3,"protocol":PROTOCOL,"authorities":[],"enrollments":[],
            "candidates":vec![json!({"x":0}); 16_000]});
        let mut bytes = serde_json::to_vec(&tiny).unwrap();
        bytes.push(b'\n');
        assert!(bytes.len() < ENROLLMENT_STATE_LIMIT);
        assert!(strict_version_allocation_state_json(&bytes).is_ok());
        assert_eq!(
            crate::protocol::strict_version_enrollment_state_json(&bytes)
                .unwrap_err()
                .code,
            "version_enrollment_state_limit"
        );
        store
            .replace(Namespace::VersionAllocations, Revision(0), &bytes)
            .unwrap();
        let mut bounded = port(&store, &"1".repeat(32), &offer);
        assert_eq!(
            bounded
                .load_bounded(ENROLLMENT_STATE_LIMIT)
                .unwrap_err()
                .code,
            Error::Unavailable
        );
        assert!(bounded.state.is_none());
        assert!(bounded.attempted.is_none());
        assert_eq!(bounded.snapshot.as_ref().unwrap().bytes, bytes);
        assert!(bounded.load().is_err());
        assert_eq!(
            store.read(Namespace::VersionAllocations).unwrap().bytes,
            bytes
        );
        // A syntax error is still malformed/recovery-required, NOT reported
        // as complexity. Both refusals preserve original state and custody.
        store
            .replace(Namespace::VersionAllocations, Revision(1), b"{oops}\n")
            .unwrap();
        let mut malformed = port(&store, &"1".repeat(32), &offer);
        assert_eq!(
            malformed
                .load_bounded(ENROLLMENT_STATE_LIMIT)
                .unwrap_err()
                .code,
            Error::RecoveryRequired
        );
        assert_eq!(malformed.snapshot.as_ref().unwrap().bytes, b"{oops}\n");
        store.close().unwrap();
    }
}
