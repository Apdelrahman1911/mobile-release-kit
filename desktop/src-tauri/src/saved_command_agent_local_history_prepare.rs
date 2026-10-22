//! Genuine Local History consent/Prepared publication, separate from Start.
//! No runtime, key or journal is opened by this comparison facet.
use super::*;
use crate::{
    service_local_history_prepare_protocol as p,
    service_store_requests::history::preparation::Entry,
};
use std::sync::Weak;

pub(crate) struct Link {
    pub(crate) entry: Arc<Entry>,
    pub(crate) registration: u32,
    pub(crate) input_revision: u64,
    pub(crate) document: Weak<()>,
    pub(crate) stamp: crate::edit_owner::SavedEditStamp,
    pub(crate) consent: Weak<crate::asset_session::LocalHistoryConsent>,
    witness: Arc<()>,
}
impl Link {
    pub(super) fn stop_at(&self, now: Instant) -> Option<(Reason, Instant)> {
        self.entry
            .stop_at(now)
            .map(|(r, at)| (agent_history::native_reason(r), at))
    }
    fn matches(&self, p: &Prepared) -> bool {
        p.agent_history_preparation
            .as_ref()
            .is_some_and(|l| std::ptr::eq(l.as_ref(), self))
            && p.local_history
                .as_ref()
                .is_some_and(|c| self.consent.as_ptr() == Arc::as_ptr(c))
            && p.registration == self.registration
            && p.project.path == self.entry.scope().saved.root
            && p.projection.context.project_id() == self.entry.scope().saved.runtime_id
    }
}
pub(super) struct Commit {
    pub(super) consent: Arc<crate::asset_session::LocalHistoryConsent>,
    pub(super) link: Option<Arc<Link>>,
}
impl Commit {
    pub(super) fn admit(
        &self,
        c: &Context,
        g: u32,
        root: &RegisteredRoot,
        expires: Instant,
    ) -> Result<Instant, BridgeError> {
        let Context::LocalReleaseHistory(context) = c else {
            return Err(history_wire::invalid());
        };
        if !self.consent.bound_to(context, g, root) {
            return Err(history_wire::invalid());
        }
        if let Some(link) = &self.link {
            link.entry
                .current(Instant::now())
                .map_err(|_| history_wire::invalid())?;
            if link.registration != g
                || link.entry.scope().saved.root != root.path
                || link.entry.scope().saved.runtime_id != context.project_id
            {
                return Err(history_wire::invalid());
            }
            Ok(expires.min(link.entry.end()))
        } else {
            Ok(expires)
        }
    }
}
/// Called only AFTER the common Prepared assignment and BEFORE bump/snapshot.
/// Failure closes that installed original, never erases it as unadmitted.
pub(super) fn committed(inner: &Inner, r: &mut Registry) -> Result<(), BridgeError> {
    let Some(p) = r.prepared.as_ref() else {
        return Err(history_wire::invalid());
    };
    let Some(link) = &p.agent_history_preparation else {
        return Ok(());
    };
    let result = (|| {
        if !link.matches(p) {
            return Err(history_wire::invalid());
        }
        let revision = r
            .revision
            .checked_add(1)
            .filter(|v| *v < u32::MAX)
            .ok_or_else(history_wire::invalid)?;
        let review = agent_history::review(
            &p.projection.context,
            &p.projection.operation_id,
            &p.projection.owner_generation,
            revision,
        )?;
        link.entry
            .constructed(review, p.expires, Arc::downgrade(&link.witness))
            .map_err(|_| history_wire::invalid())
    })();
    if result.is_err() {
        link.entry.unknown(p::Reason::CleanupUnknown);
        inner.retire_prepared(r, Reason::CleanupUnknown);
    }
    result
}
pub(super) fn retired(p: &Prepared, reason: Reason) {
    if let Some(link) = &p.agent_history_preparation {
        link.entry
            .retired(agent_history::reason(reason, &link.entry.control));
    }
}
impl SavedCommandOwner {
    pub(crate) fn prepare_agent_history(
        &self,
        input: history_wire::Prepare,
        registration: u32,
        root: RegisteredRoot,
        gate: history_wire::Availability,
        consent: Arc<crate::asset_session::LocalHistoryConsent>,
        entry: Arc<Entry>,
        native: crate::application_service_host::NativeProject,
        stamp: crate::edit_owner::SavedEditStamp,
    ) -> Result<history_wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::LocalReleaseHistory)?;
        if native.runtime_id != entry.scope().saved.runtime_id
            || native.canonical_root != entry.scope().saved.root
            || (native.device, native.inode)
                != (entry.scope().saved.device, entry.scope().saved.inode)
        {
            return Err(history_wire::invalid());
        }
        // Reuse the immutable captured Entry root/runtime strings. Retain only
        // the native registration/epoch/weak identity and original edit stamp.
        let link = Arc::new(Link {
            entry,
            registration: native.registration_generation,
            input_revision: native.input_revision,
            document: Arc::downgrade(&native.document_identity),
            stamp,
            consent: Arc::downgrade(&consent),
            witness: Arc::new(()),
        });
        self.prepare_bound_preparations_history(
            Context::LocalReleaseHistory(input.context()),
            registration,
            root,
            Availability::from_history(gate),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Commit {
                consent,
                link: Some(link),
            }),
        )?
        .history()
    }
    pub(crate) fn history_preparation_link(&self) -> Option<Arc<Link>> {
        self.inner
            .lock()
            .prepared
            .as_ref()
            .and_then(|p| p.agent_history_preparation.clone())
    }
    pub(crate) fn publish_history_preparation(
        &self,
        entry: &Arc<Entry>,
    ) -> Result<Option<p::Review>, BridgeError> {
        let mut r = self.inner.lock();
        self.inner.expire_prepared(&mut r, Instant::now());
        let Some(p) = r.prepared.as_mut().filter(|p| {
            p.agent_history_preparation
                .as_ref()
                .is_some_and(|l| Arc::ptr_eq(&l.entry, entry))
        }) else {
            return Ok(None);
        };
        if !entry.ready() || p.agent_history.is_some() {
            return Ok(None);
        }
        if !p.projection.intent_usable {
            p.projection.intent_usable = true;
            self.inner.bump(&mut r);
        }
        let p = r.prepared.as_ref().ok_or_else(history_wire::invalid)?;
        agent_history::review(
            &p.projection.context,
            &p.projection.operation_id,
            &p.projection.owner_generation,
            r.revision,
        )
        .map(Some)
    }
    pub(crate) fn stop_history_preparation(
        &self,
        entry: &Arc<Entry>,
        reason: p::Reason,
        at: Instant,
    ) {
        entry.cancel(reason, at);
        if entry.handed_off() {
            return;
        }
        let mut r = self.inner.lock();
        if r.prepared.as_ref().is_some_and(|p| {
            p.agent_history_preparation
                .as_ref()
                .is_some_and(|l| Arc::ptr_eq(&l.entry, entry))
        }) {
            self.inner
                .retire_prepared(&mut r, agent_history::native_reason(reason));
        }
    }
    /// Early non-consuming check, before ordinary GUI Start's destructive
    /// stale-context tails. Public IDs cannot bypass a private delegation.
    pub(crate) fn ordinary_history_start(&self, operation: &str, generation: &str) -> bool {
        self.inner.lock().prepared.as_ref().is_some_and(|p| {
            p.projection.operation_id == operation
                && p.projection.owner_generation == generation
                && p.agent_history_preparation.is_none()
                && p.agent_history.is_none()
        })
    }
}
pub(super) fn backing_bytes() -> Option<usize> {
    // One current and one outgoing native scalar link. Root/runtime bytes are
    // already retained in the SAME Entry, not cloned into this link. Weak
    // control blocks/witness/stamp backing remain conservatively covered.
    let n = 2usize.checked_mul(std::mem::size_of::<Link>() + 512)?;
    (n <= 2048).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_protocol::Id;
    use crate::service_store_requests::{
        history::preparation::{Claim, Scope},
        Inbox,
    };
    use std::path::PathBuf;
    fn id(n: u32) -> Id {
        Id::parse(&format!("{n:032x}")).unwrap()
    }
    struct Fixture {
        owner: SavedCommandOwner,
        inbox: Inbox,
        entry: Arc<Entry>,
        consent: Arc<crate::asset_session::LocalHistoryConsent>,
        _edit: crate::edit_owner::EditOwner,
        _document: Arc<()>,
    }
    fn installed() -> (Fixture, Claim) {
        let config =
            RuntimeConfig::packaged(PathBuf::from("/never-opened-history-prepare-fixture"));
        let owner = SavedCommandOwner::new(config.clone(), SavedCommandDomain::LocalReleaseHistory);
        let edit = crate::edit_owner::EditOwner::new(config);
        let document = Arc::new(());
        let control = Arc::new(AndroidRegistrationControl::default());
        edit.bind_saved_registration(&document, control.clone());
        edit.initial_document("main").unwrap();
        let stamp = edit
            .saved_registration_guard(&document)
            .unwrap()
            .stamp()
            .unwrap();
        let root = RegisteredRoot {
            path: PathBuf::from("/never-opened-history-prepare-fixture"),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let context = history_wire::Context {
            project_id: "runtime-p1".into(),
            execution_mode: history_wire::ExecutionMode::Local,
            action: history_wire::Action::Verify,
            platform: None,
            candidate_operation_id: None,
            stage_operation_id: None,
        };
        let consent = crate::asset_session::LocalHistoryConsent::unbound_preparation_data(
            &context,
            1,
            root.clone(),
        );
        // A real allocation with no document/native identity: it can never pass
        // a producer currentness check or launch the native History runtime.
        assert!(!consent.current(&context, 1, &root));
        let read = Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                Instant::now() + Duration::from_secs(1000),
            ),
        );
        let inbox = Inbox::new(id(2));
        let request = p::Request {
            origin: p::Query {
                project_id: id(1),
                service_instance: id(2),
                request_id: id(3),
            },
            selection: p::Selection {
                kind: p::Kind::Verify,
                platform: None,
                candidate_operation_id: None,
                stage_operation_id: None,
            },
        };
        inbox
            .prepare_history(
                request.clone(),
                Scope {
                    saved: crate::agent_identity_requests::SavedPoint {
                        project_id: id(1),
                        runtime_id: context.project_id.clone(),
                        root: root.path.clone(),
                        device: 1,
                        inode: 2,
                        revision: 0,
                        fresh: false,
                    },
                    read,
                },
                Instant::now(),
            )
            .unwrap();
        let entry = inbox.history_preparation(&request.origin).unwrap();
        let claim = inbox.claim_history_preparation().unwrap().unwrap();
        let link = Arc::new(Link {
            entry: entry.clone(),
            registration: 1,
            input_revision: control.epoch().unwrap(),
            document: Arc::downgrade(&document),
            stamp,
            consent: Arc::downgrade(&consent),
            witness: Arc::new(()),
        });
        let projection = RunProjection {
            agent_build: None,
            agent_local_check: None,
            operation_id: id(10).as_str().into(),
            owner_generation: id(11).as_str().into(),
            context: Context::LocalReleaseHistory(context),
            phase: Phase::AwaitingConsent,
            intent_usable: false,
            outcome: None,
            reason: Reason::None,
            result: None,
            stage: None,
        };
        // Inert actual-object setup at the original common commit boundary.
        // No qualified Profile/Session/GO or physical finality is fabricated.
        {
            let mut r = owner.inner.lock();
            r.prepared = Some(Prepared {
                agent_history_preparation: Some(link),
                agent_history: None,
                agent_store_preparation: None,
                agent_store: None,
                store_witness: None,
                agent_build: None,
                agent_local_check: None,
                upload_key_preparation: None,
                upload_key: None,
                apple: None,
                tools: None,
                local_history: Some(consent.clone()),
                projection,
                expires: entry.end(),
                registration: 1,
                project: root,
                recovery_stamp: None,
                material: None,
                recovery: None,
                android_selection: None,
                artifact_selection: None,
                artifact_tools: None,
            });
            committed(&owner.inner, &mut r).unwrap();
            owner.inner.bump(&mut r);
        }
        (
            Fixture {
                owner,
                inbox,
                entry,
                consent,
                _edit: edit,
                _document: document,
            },
            claim,
        )
    }
    fn ready(f: &Fixture, c: Claim) -> p::Review {
        c.returned();
        f.entry
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
        f.owner
            .publish_history_preparation(&f.entry)
            .unwrap()
            .unwrap()
    }
    fn start_scope(
        f: &Fixture,
        a: &Arc<agent_history::Approval>,
    ) -> Arc<crate::service_store_requests::history::Scope> {
        use crate::service_store_requests::history as h;
        Arc::new(h::Scope {
            preparation: Some(Arc::downgrade(&f.entry)),
            project_id: id(1),
            runtime_id: "runtime-p1".into(),
            review_id: id(4),
            review: a.review().clone(),
            root: f.entry.scope().saved.root.clone(),
            device: 1,
            inode: 2,
            observation_revision: 0,
            expires: a.expires(),
            read: f.entry.scope().read.clone(),
            document: Arc::downgrade(&f._document),
            witness: a.witness(),
            control: h::Control::new(),
            retired: std::sync::atomic::AtomicBool::new(false),
            changes: tokio::sync::watch::channel(0).0,
        })
    }
    #[test]
    fn common_prepared_commit_keeps_consent_and_waits_actual_prepare_and_history_returns() {
        let (f, c) = installed();
        let original = f.entry.status().unwrap().review.unwrap();
        assert!(f.owner.history_preparation_link().is_some());
        assert!(f
            .owner
            .publish_history_preparation(&f.entry)
            .unwrap()
            .is_none());
        {
            let r = f.owner.inner.lock();
            assert!(Arc::ptr_eq(
                r.prepared.as_ref().unwrap().local_history.as_ref().unwrap(),
                &f.consent
            ));
            assert!(!r.prepared.as_ref().unwrap().projection.intent_usable);
            assert!(r.active.is_none());
        }
        c.returned();
        let history = f.entry.claim_history().unwrap().unwrap();
        assert!(f
            .owner
            .publish_history_preparation(&f.entry)
            .unwrap()
            .is_none());
        history.returned(Ok(())).unwrap();
        let live = f
            .owner
            .publish_history_preparation(&f.entry)
            .unwrap()
            .unwrap();
        assert_eq!(live.operation_id, original.operation_id);
        assert!(live.status_revision > original.status_revision);
        assert!(f
            .owner
            .history_approval(
                p::Kind::Verify,
                &live.operation_id,
                &live.owner_generation,
                live.status_revision
            )
            .is_err());
        assert!(!f
            .owner
            .ordinary_history_start(live.operation_id.as_str(), live.owner_generation.as_str()));
        assert!(f.owner.inner.lock().prepared.is_some());
        assert!(backing_bytes().is_some());
    }
    #[test]
    fn genuine_preparation_binding_handoff_uses_old_submit_and_cannot_replay_gui_or_old_cancel() {
        let (f, c) = installed();
        let live = ready(&f, c);
        let approval = f
            .owner
            .history_approval_from(
                p::Kind::Verify,
                &live.operation_id,
                &live.owner_generation,
                live.status_revision,
                Some(&f.entry),
            )
            .unwrap();
        let scope = start_scope(&f, &approval);
        f.inbox.can_allow_history_from(Some(&f.entry)).unwrap();
        let binding = f
            .owner
            .bind_history_approval(approval, scope.clone())
            .unwrap();
        assert!(f.entry.installing());
        assert!(!f
            .owner
            .ordinary_history_start(live.operation_id.as_str(), live.owner_generation.as_str()));
        f.inbox.allow_history(scope.clone(), id(5)).unwrap();
        assert!(f.entry.handed_off());
        f.inbox
            .submit_history(
                crate::service_local_history_protocol::Submit {
                    origin: p::Query {
                        project_id: id(1),
                        service_instance: id(2),
                        request_id: id(6),
                    },
                    grant_id: id(5),
                    review_id: id(4),
                },
                Instant::now(),
            )
            .unwrap();
        let caller = f.inbox.claim_local_history().unwrap().unwrap();
        binding.attach(caller.entry()).unwrap();
        f.owner
            .stop_history_preparation(&f.entry, p::Reason::UserCancelled, Instant::now());
        assert!(f.owner.inner.lock().prepared.is_some());
        assert!(scope.control.first().unwrap().is_none());
        assert!(f
            .owner
            .history_approval_from(
                p::Kind::Verify,
                &live.operation_id,
                &live.owner_generation,
                live.status_revision,
                Some(&f.entry)
            )
            .is_err());
        drop(caller);
        assert!(scope.control.first().is_err());
        assert!(f.owner.inner.lock().active.is_none());
    }
    #[test]
    fn failed_install_and_lost_prepare_return_never_reissue_or_clear_the_original() {
        for lost in [false, true] {
            let (f, c) = installed();
            if lost {
                drop(c);
                assert!(f
                    .owner
                    .publish_history_preparation(&f.entry)
                    .unwrap()
                    .is_none());
            } else {
                let live = ready(&f, c);
                let a = f
                    .owner
                    .history_approval_from(
                        p::Kind::Verify,
                        &live.operation_id,
                        &live.owner_generation,
                        live.status_revision,
                        Some(&f.entry),
                    )
                    .unwrap();
                let scope = start_scope(&f, &a);
                let binding = f.owner.bind_history_approval(a, scope).unwrap();
                // Actual ordinary stop of the installed binding, before Book
                // grant publication: the consumed handoff stays Unknown.
                f.owner
                    .stop_agent_history(&binding, p::Reason::PermissionRevoked, Instant::now());
            }
            assert_eq!(f.entry.status().unwrap().phase, p::Phase::Unknown);
            assert!(f.entry.pending());
            assert!(f.inbox.can_allow_history_from(Some(&f.entry)).is_err());
            assert!(f.inbox.claim_history_preparation().unwrap().is_none());
            assert!(f.owner.inner.lock().active.is_none());
        }
    }
}
