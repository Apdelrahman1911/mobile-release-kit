//! Original in-memory gates/latches and real target-size census. None of these
//! fixtures owns a Supervisor, native source, credential, Host job or receipt.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use super::*;
use crate::service_protocol::{Id, Settlement};

fn id(n: u64) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn root() -> asset_source::RegisteredRoot {
    asset_source::RegisteredRoot {
        path: "/never-opened-enrollment-native-data".into(),
        identity: asset_source::ProjectIdentity::Posix(
            asset_source::DirectoryIdentity::synthetic_evidence_identity(),
        ),
    }
}
fn input() -> data::Input {
    data::Input::CounterEnrollmentReview(data::ReviewSelection {
        session_id: "session-a".into(),
        expected_revision: 4,
        expected_connection_revision: 9,
    })
}
fn pins(end: Instant) -> Pins {
    Pins {
        session_id: "session-a".into(),
        project_id: "project-1".into(),
        generation: 2,
        target: p::Target {
            project_binding: "b".repeat(64),
            repository: "fixture/app".into(),
            account_id: "11".into(),
            repository_id: "22".into(),
        },
        credential_end: end,
    }
}
fn offer() -> p::Offer {
    p::Offer {
        authority: p::Authority {
            project_id: "1".repeat(32),
            repository: "fixture/app".into(),
            repository_id: "22".into(),
            ledger_id: "00000000-0000-4000-8000-000000000001".into(),
            genesis_sha256: "b".repeat(64),
            protected_branch: true,
        },
        checkpoint: p::Checkpoint {
            sequence: 2,
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
struct F {
    doc: DocumentBinding,
    inbox: rows::Inbox,
    scope: Arc<rows::NativeScope>,
    lane: Arc<Lane>,
    caller: Option<rows::Claim>,
}
impl F {
    fn new() -> Self {
        let bridge = Arc::new(DesktopBridge::new("/never-opened-enrollment-data".into()));
        let doc = DocumentBinding::new(bridge.clone());
        bridge.edits.initial_document("main").unwrap();
        let now = Instant::now();
        let end = now + Duration::from_secs(60);
        let edit = bridge
            .edits
            .saved_registration_guard(&doc.inner.session_identity)
            .unwrap();
        let capture = Capture {
            input: input(),
            root: root(),
            pins: pins(end),
            input_epoch: doc.inner.android_registration_control.epoch().unwrap(),
            stamp: Arc::new(edit.stamp().unwrap()),
            reviewed: None,
        };
        let original = Arc::new(Original {
            root: root(),
            stamp: edit.stamp().unwrap(),
            pins: pins(end),
            input_epoch: capture.input_epoch,
        });
        drop(edit);
        let scope = rows::NativeScope::new(
            id(1),
            "project-1".into(),
            root().path,
            1,
            2,
            3,
            wire::Review::CounterEnrollmentReview(data::ReviewReference {
                session_id: "session-a".into(),
                expected_revision: 4,
                expected_connection_revision: 9,
                request_sha256: "b".repeat(64),
            }),
            Arc::new(()),
            end,
            Arc::new(crate::service_version_reserve_requests::ReadPermission::new(end)),
            Arc::downgrade(&doc.inner.session_identity),
            tokio::sync::watch::channel(1).0,
        );
        let inbox = rows::Inbox::new(id(2));
        inbox.allow(scope.clone(), id(3)).unwrap();
        let query = wire::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(4),
        };
        inbox
            .submit(wire::Submit {
                origin: query.clone(),
                grant_id: id(3),
            })
            .unwrap();
        let caller = inbox
            .claim_enrollment(
                &query,
                &doc.inner.session_identity,
                "project-1",
                wire::Kind::CounterEnrollmentReview,
                None,
            )
            .unwrap();
        let control = Arc::new(VersionEnrollmentControl::new());
        control.bind_agent(&scope).unwrap();
        let lane = Arc::new(Lane {
            id: "a".repeat(32),
            agent: Some(caller.entry().clone()),
            original,
            control,
            end,
            request: Mutex::new(None),
            ticket: Mutex::new(None),
            joined: Mutex::new(None),
            host_ticket: Mutex::new(None),
            jobs: AsyncMutex::new(None),
            state_failure: Mutex::new(None),
        });
        {
            let mut state = doc.lock();
            state.version_enrollment.permission = Some(Permission {
                capture,
                scope: Arc::downgrade(&scope),
            });
            state.version_enrollment.lane = Some(lane.clone());
        }
        // Inert attachment/finality test facts, not a native admission or IO.
        caller.entry().enrollment_attached(&lane.id).unwrap();
        Self {
            doc,
            inbox,
            scope,
            lane,
            caller: Some(caller),
        }
    }
    fn entry(&self) -> &Arc<rows::Entry> {
        self.lane.agent.as_ref().unwrap()
    }
    fn native_fact(&self) {
        self.entry().go(&self.lane.id).unwrap();
        self.lane.control.returned(self.lane.end).unwrap();
        let status = p::Status {
            schema_version: 1,
            revision: 5,
            project_id: Some("project-1".into()),
            operation_id: Some(self.lane.id.clone()),
            phase: p::Phase::Reviewed,
            reason: p::Reason::None,
            review: Some(p::ReviewView {
                id: self.lane.id.clone(),
                repository: "fixture/app".into(),
                version: p::Version {
                    name: "1.2.3".into(),
                    build: 7,
                },
                reservations: 2,
            }),
        };
        {
            let mut state = self.doc.lock();
            state.version_enrollment.view = status.clone();
            state.version_enrollment.review = Some(Review {
                id: self.lane.id.clone(),
                identity: Arc::new(()),
                producer: Some(Arc::downgrade(self.entry())),
                original: self.lane.original.clone(),
                offer: offer(),
                end: self.lane.end,
            });
        }
        returned(&self.lane, &status, false);
    }
    fn caller_fact(&mut self) {
        self.caller.take().unwrap().returned(Ok(()));
    }
    fn history_fact(&self) {
        self.entry()
            .claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
    }
}

#[test]
fn foreign_gui_or_other_kind_cannot_take_the_linked_origin_before_its_old_tail() {
    let f = F::new();
    let other = F::new();
    let state = f.doc.lock();
    assert!(f
        .doc
        .enrollment_origin_allowed(&state, "project-1", None, None)
        .is_err());
    assert!(f
        .doc
        .enrollment_origin_allowed(&state, "project-1", None, Some(other.entry()))
        .is_err());
    assert!(permission_retained(&state));
    assert!(Arc::ptr_eq(
        state.version_enrollment.lane.as_ref().unwrap(),
        &f.lane
    ));
    drop(state);
    let args: crate::asset_session::agent_github_action::Allow = crate::asset_session::agent_github_action::decode(
        &serde_json::to_vec(&serde_json::json!({"selection":{"kind":"repository-create","sessionId":"session-a",
            "consentId":"b".repeat(32),"expectedRevision":1},"consentVersion":"agent-repository-create-once-v1",
            "expectedPermissionRevision":"0"})).unwrap()).unwrap();
    assert_eq!(
        f.doc
            .allow_agent_github_action(MAIN, args)
            .err()
            .unwrap()
            .code,
        "cli_access_busy"
    );
    assert!(f.doc.enrollment_entry_attached(f.entry()));
    assert!(!f.doc.enrollment_entry_attached(other.entry()));
    assert!(f.doc.lock().version_enrollment.permission.is_some());
}

#[test]
fn completed_exact_review_withdrawal_preserves_offer_but_never_uses_a_later_capture() {
    let mut f = F::new();
    f.native_fact();
    {
        let state = f.doc.lock();
        assert!(!producer_ready(
            state.version_enrollment.review.as_ref().unwrap()
        ));
    }
    f.caller_fact();
    f.history_fact();
    let (identity, original, offered) = {
        let state = f.doc.lock();
        let r = state.version_enrollment.review.as_ref().unwrap();
        assert!(producer_ready(r));
        (r.identity.clone(), r.original.clone(), r.offer.clone())
    };
    let at = Instant::now();
    f.scope.revoke(wire::Reason::PermissionRevoked, at);
    {
        let mut state = f.doc.lock();
        f.doc.enrollment_agent_revoke(&mut state, &f.scope, at);
        let r = state.version_enrollment.review.as_ref().unwrap();
        assert!(Arc::ptr_eq(&identity, &r.identity) && Arc::ptr_eq(&original, &r.original));
        assert_eq!(r.offer, offered);
        assert!(producer_ready(r));
        assert!(!permission_retained(&state));
        // A later native capture has its own exact Scope identity. Re-delivery
        // of the old withdrawal cannot clear or STOP it by kind/project alone.
        let other = F::new();
        let capture = other
            .doc
            .lock()
            .version_enrollment
            .permission
            .as_ref()
            .unwrap()
            .capture
            .clone();
        state.version_enrollment.permission = Some(Permission {
            capture,
            scope: Arc::downgrade(&other.scope),
        });
        f.doc.enrollment_agent_revoke(&mut state, &f.scope, at);
        assert!(permission_retained(&state));
        assert!(other.lane.control.current());
    }
    assert!(f.entry().positively_returned(&f.lane.id));
    assert_eq!(
        f.inbox.query(f.entry().origin(), false).unwrap().settlement,
        Settlement::Settled
    );
}

#[test]
fn missing_history_or_unknown_withdrawal_retains_the_original_and_cannot_supply_connect() {
    for unknown in [false, true] {
        let mut f = F::new();
        f.native_fact();
        f.caller_fact();
        if unknown {
            f.entry().unknown(wire::Reason::HistoryUnavailable);
        }
        let at = Instant::now();
        f.scope.revoke(wire::Reason::PermissionRevoked, at);
        let mut state = f.doc.lock();
        f.doc.enrollment_agent_revoke(&mut state, &f.scope, at);
        assert!(permission_retained(&state));
        assert!(!producer_ready(
            state.version_enrollment.review.as_ref().unwrap()
        ));
        assert!(!f.entry().enrollment_retired(&f.lane.id));
        assert!(Arc::ptr_eq(
            state.version_enrollment.lane.as_ref().unwrap(),
            &f.lane
        ));
    }
}

#[test]
fn original_quiet_read_and_late_earlier_stop_contract_same_control_without_renewal() {
    let f = F::new();
    let at = Instant::now();
    f.lane.control.agent_stop_requested(at);
    let earlier = at - Duration::from_millis(500);
    f.scope.read.revoke(earlier);
    // The same Control.current used by GO and native jobs samples the old READ
    // without a public status/relay callback or a second time owner.
    assert!(!f.lane.control.current());
    assert_eq!(
        f.lane.control.cleanup_end(f.lane.end),
        Some(earlier + Duration::from_secs(2))
    );
    sample(&f.doc, &f.lane); // outer driver forwards the same F only after guards
    assert_eq!(
        f.lane.control.cleanup_end(f.lane.end),
        Some(earlier + Duration::from_secs(2))
    );
    let renewed = crate::service_version_reserve_requests::ReadPermission::new(
        f.lane.end + Duration::from_secs(30),
    );
    assert!(renewed.stop(at).unwrap().is_none());
    assert!(!f.lane.control.current());
    let fresh = F::new();
    assert!(fresh
        .scope
        .first(true, fresh.scope.read.end())
        .unwrap()
        .is_some());
    assert!(!fresh.lane.control.current());
    assert_eq!(
        fresh.lane.control.cleanup_end(fresh.lane.end),
        Some(fresh.scope.read.end() + Duration::from_secs(2))
    );
    let overdue = F::new();
    let first = Instant::now() - Duration::from_secs(3);
    overdue.scope.read.revoke(first);
    sample(&overdue.doc, &overdue.lane);
    assert!(overdue.lane.control.uncertain() && overdue.lane.control.pending());
    assert_eq!(
        overdue.entry().status().unwrap().state,
        wire::State::Unknown
    );
    assert_eq!(
        overdue.lane.control.cleanup_end(overdue.lane.end),
        Some(first + Duration::from_secs(2))
    );
    assert!(!overdue.entry().enrollment_retired(&overdue.lane.id));
}

#[test]
fn original_native_unknown_propagates_without_waiting_for_status_or_another_settle() {
    let mut f = F::new();
    f.lane.control.unknown();
    assert!(!f.lane.control.current() && f.lane.control.uncertain());
    assert!(f.entry().claim_history().unwrap().is_none());
    assert_eq!(f.entry().status().unwrap().state, wire::State::Unknown);
    assert!(f.lane.control.returned(f.lane.end).is_err());
    f.caller_fact();
    assert!(f.entry().pending());
    assert!(!f.entry().enrollment_retired(&f.lane.id));
    assert!(f.entry().status().unwrap().result.is_none());
}

#[test]
fn native_capture_uses_real_edit_stamp_bounded_capacity_and_full_private_pins() {
    let f = F::new();
    let state = f.doc.lock();
    let original = &state
        .version_enrollment
        .permission
        .as_ref()
        .unwrap()
        .capture;
    assert!(original.retained_fits());
    let guard = f
        .doc
        .inner
        .bridge
        .edits
        .saved_registration_guard(&f.doc.inner.session_identity)
        .unwrap();
    assert!(guard.matches(&original.stamp));
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.pins.target.account_id = "12".into(),
            1 => changed.pins.target.repository_id = "23".into(),
            2 => changed.root.path.push("different"),
            3 => changed.input_epoch += 1,
            _ => changed.pins.credential_end += Duration::from_millis(1),
        }
        assert!(changed != *original);
    }
    let mut excessive = original.clone();
    excessive.root.path.reserve(4097);
    assert!(!excessive.retained_fits());
    let [allow, active] = native_phases().unwrap();
    eprintln!("counter-enrollment native DATA: allow={allow} active={active} retained={} Capture={} NativeReview={}",
        data::NATIVE_BACKING, size_of::<Capture>(), size_of::<native::Review>());
    assert!(allow <= data::NATIVE_BACKING && active <= data::NATIVE_BACKING);
    assert_eq!(native_backing(), Some(data::NATIVE_BACKING));
}

#[test]
fn enrollment_public_reason_roster_matches_original_native_codes_not_provider_messages() {
    for reason in [
        p::Reason::None,
        p::Reason::CounterMissing,
        p::Reason::ProtectionUnavailable,
        p::Reason::ProtectionUnsupported,
        p::Reason::AuthorityChanged,
        p::Reason::AuthorityRewound,
        p::Reason::LedgerInvalid,
        p::Reason::ReviewChanged,
        p::Reason::InvalidInput,
        p::Reason::Unauthorized,
        p::Reason::Forbidden,
        p::Reason::NotFoundOrInaccessible,
        p::Reason::TargetChanged,
        p::Reason::RateLimited,
        p::Reason::NetworkUnavailable,
        p::Reason::TlsFailed,
        p::Reason::ResponseInvalid,
        p::Reason::ResponseLimit,
        p::Reason::Expired,
        p::Reason::Cancelled,
        p::Reason::Busy,
        p::Reason::NotConnected,
        p::Reason::RuntimeUnavailable,
        p::Reason::CleanupUnknown,
        p::Reason::StateUnavailable,
        p::Reason::StateTooLarge,
        p::Reason::Connected,
    ] {
        let value = serde_json::to_value(reason).unwrap();
        let projected: data::OutcomeReason = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(projected).unwrap(), value);
    }
    assert!(
        serde_json::from_value::<data::OutcomeReason>(serde_json::json!(
            "arbitrary-provider-message"
        ))
        .is_err()
    );
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[test]
fn enrollment_uses_complete_actual_document_and_original_code_plus_data_admission() {
    let bridge = Arc::new(DesktopBridge::new("/never-opened-enrollment-census".into()));
    let doc = DocumentBinding::new(bridge.clone());
    bridge.edits.initial_document("main").unwrap();
    let mut state = doc.lock();
    let retained = lookup_memory::retained_document_bytes(&doc.inner, &state)
        .unwrap()
        .checked_add(installation_memory::additional_document_bytes(&doc, &state).unwrap())
        .unwrap();
    let code = crate::macos_history_inventory::CODE_CONTROL_RESERVE;
    let future = code.checked_add(p::RETAINED_LIMIT).unwrap();
    eprintln!("enrollment admission: completeDoc={retained} originalData={} newNative={} code={code} shared={SESSION_BYTES}",
        p::RETAINED_LIMIT, data::NATIVE_BACKING);
    assert_eq!(
        retained_bytes(&state),
        Some(size_of::<State>() + data::NATIVE_BACKING)
    );
    assert_eq!(
        crate::macos_history_inventory::admission_bytes(retained, future),
        Some(retained + future)
    );
    let observation = credential_format::inspect(
        credential_format::FileKind::AndroidKeystore,
        &[],
        &mut || false,
    )
    .ok()
    .expect("inert empty format DATA");
    state.records.push(Record {
        key: RecordKey {
            id: Token("inert-enrollment-capacity".into()),
            revision: 1,
        },
        payload: Arc::new(Payload {
            kind: Kind::AndroidKeystore,
            fields: None,
            material: Some(Arc::new(Material {
                origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                    Vec::with_capacity(SESSION_BYTES),
                )),
                observation,
            })),
        }),
        mutation_pending: false,
    });
    let grown = lookup_memory::retained_document_bytes(&doc.inner, &state)
        .unwrap()
        .checked_add(installation_memory::additional_document_bytes(&doc, &state).unwrap())
        .unwrap();
    assert!(grown >= retained + SESSION_BYTES);
    assert!(crate::macos_history_inventory::admission_bytes(grown, future).is_none());
    state.retiring = true;
    assert!(lookup_memory::retained_document_bytes(&doc.inner, &state).is_err());
}
