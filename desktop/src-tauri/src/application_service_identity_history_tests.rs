//! Synthetic metadata/store fixtures only. No native identity runtime, engine,
//! application edit, provider, IPC listener or actual installed qualification.
use super::*;
use crate::application_state_store::{Fixture as StateFixture, Namespace};
use std::{fs::File, os::unix::fs::MetadataExt};

struct Fixture {
    host: Arc<ApplicationHost>,
    service: Arc<ApplicationService>,
    store: Arc<PrivateStateDirectory>,
    native: NativeProject,
    root: RegisteredRoot,
    project: p::Id,
    _files: StateFixture,
}
impl Fixture {
    fn new() -> Self {
        let files = StateFixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&files.app).unwrap());
        let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
        let (project, path) = crate::application_service::tests::register_fixture(
            &service,
            &files.app,
            "synthetic-project",
            "project-1",
        );
        let held = File::open(&path).unwrap();
        let metadata = held.metadata().unwrap();
        let root = RegisteredRoot {
            path: path.clone(),
            identity: asset_source::ProjectIdentity::Posix(
                asset_source::DirectoryIdentity::vault_original(
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                ),
            ),
        };
        drop(held);
        let native = NativeProject {
            runtime_id: "project-1".into(),
            canonical_root: path,
            device: metadata.dev(),
            inode: metadata.ino(),
            registration_generation: 2,
            document_identity: Arc::new(()),
            input_revision: 7,
        };
        let host = Arc::new(ApplicationHost::new());
        {
            // Same limited lifecycle fixture as existing Host tests. These
            // seeded preference facts are NOT a SourceBook/admission witness.
            let mut control = host.lock().unwrap();
            control.service = Some(service.clone());
            control.store = Some(store.clone());
            control.phase = Phase::Listening;
            control
                .registered
                .insert(native.runtime_id.clone(), native.clone());
        }
        Self {
            host,
            service,
            store,
            native,
            root,
            project,
            _files: files,
        }
    }
    fn source<'a>(&'a self, id: &'a str) -> IdentitySource<'a> {
        IdentitySource {
            runtime_id: &self.native.runtime_id,
            root: &self.root,
            registration: self.native.registration_generation,
            document: &self.native.document_identity,
            session_id: id,
        }
    }
    fn capture(&self, id: &str) -> IdentityCapture {
        self.host.capture_identity(self.source(id), 1).unwrap()
    }
    fn stored(&self) -> serde_json::Value {
        serde_json::from_slice(&self.store.read(Namespace::Projects).unwrap().bytes).unwrap()
    }
    fn operations(&self) -> p::ResponseBody {
        self.service
            .allow_agent_read(vec![self.project.clone()], Duration::from_secs(60))
            .unwrap();
        let client = self.service.admit_client().unwrap();
        self.service
            .dispatch(
                &client,
                p::Request {
                    version: p::VERSION,
                    request_id: p::Id::random().unwrap(),
                    request: p::RequestBody::Operations(p::ProjectQuery {
                        project_id: self.project.clone(),
                    }),
                },
            )
            .response
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.service.stop().unwrap();
        self.store.close().unwrap();
        // StateFixture deletes only its newly-created synthetic directory.
    }
}

/// Hold the ACTUAL Host and Service mutexes, not a pretend write callback.
/// Release them and join both finite test threads even when the timing assertion
/// fails, so a regression reports failure instead of parking a test worker.
fn under_original_mutexes<T: Send>(f: &Fixture, body: impl FnOnce() -> T + Send) -> T {
    use std::{sync::mpsc, thread};
    thread::scope(|scope| {
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let held = scope.spawn(move || {
            let _control = f.host.control.lock().unwrap();
            crate::application_service::tests::with_state_locked(&f.service, || {
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            });
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let worker = scope.spawn(move || {
            let result = body();
            let _ = done_tx.send(());
            result
        });
        let without_io_mutexes = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let _ = release_tx.send(());
        held.join().unwrap();
        let result = worker.join().unwrap();
        assert!(
            without_io_mutexes,
            "native history waited for Host/Service IO mutexes"
        );
        result
    })
}

#[test]
fn held_original_io_mutexes_skip_capture_but_cannot_delay_a_captured_final() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    let skipped = under_original_mutexes(&f, || {
        let skipped = f
            .host
            .capture_identity(f.source("22222222222222222222222222222222"), 2)
            .is_none();
        capture.record(3, IdentityObservation::Succeeded);
        skipped
    });
    assert!(skipped);
    assert_eq!(
        f.host.history.lock().unwrap().rows.iter().flatten().count(),
        1
    );
    assert!(f.host.publish_identity_history().unwrap());
    assert_eq!(f.stored()["operations"][0]["state"], "succeeded");
    assert_eq!(f.stored()["operations"].as_array().unwrap().len(), 1);
}

#[test]
fn native_error_fences_all_reads_immediately_with_both_original_io_mutexes_held() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    f.service
        .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = f.service.admit_client().unwrap();
    // This real read result is no longer sendable after the permanent fence.
    let prior = f.service.dispatch(
        &client,
        p::Request {
            version: p::VERSION,
            request_id: p::Id::parse("33333333333333333333333333333333").unwrap(),
            request: p::RequestBody::Operations(p::ProjectQuery {
                project_id: f.project.clone(),
            }),
        },
    );
    assert!(matches!(prior.response, p::ResponseBody::Operations(_)));
    under_original_mutexes(&f, || {
        capture.unavailable();
        assert!(matches!(
            f.service.read_access_status(),
            Err(Error::StateUnknown)
        ));
        assert!(matches!(f.service.admit_client(), Err(Error::StateUnknown)));
        assert_eq!(f.service.client_current(&client), Err(Error::StateUnknown));
        assert!(matches!(
            f.service
                .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60)),
            Err(Error::StateUnknown)
        ));
        let response = f.service.dispatch(
            &client,
            p::Request {
                version: p::VERSION,
                request_id: p::Id::parse("44444444444444444444444444444444").unwrap(),
                request: p::RequestBody::Operations(p::ProjectQuery {
                    project_id: f.project.clone(),
                }),
            },
        );
        assert!(matches!(
            response.response,
            p::ResponseBody::Error(Error::StateUnknown)
        ));
    });
    assert!(f.host.lock().unwrap().fence.is_none()); // Host report is off-native only.
    assert_eq!(f.host.publish_identity_history(), Err(Error::StateUnknown));
    assert_eq!(f.host.lock().unwrap().fence, Some(Error::StateUnknown));
    f.service.revoke_agent_read().unwrap(); // Cleanup still works; it cannot clear the fence.
    assert!(matches!(
        f.service
            .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60)),
        Err(Error::StateUnknown)
    ));
    assert!(f.stored()["operations"].as_array().unwrap().is_empty());
}

#[test]
fn dormant_invalid_or_unregistered_observation_does_not_start_service_or_write() {
    let host = Arc::new(ApplicationHost::new());
    let document = Arc::new(());
    let root = RegisteredRoot {
        path: "/inert/unopened-identity-history-project".into(),
        identity: asset_source::ProjectIdentity::Posix(
            asset_source::DirectoryIdentity::synthetic_evidence_identity(),
        ),
    };
    let source = || IdentitySource {
        runtime_id: "project-1",
        root: &root,
        registration: 1,
        document: &document,
        session_id: "11111111111111111111111111111111",
    };
    assert!(host.capture_identity(source(), 1).is_none());
    assert!(!host.publish_identity_history().unwrap());
    assert!(host.lock().unwrap().service.is_none());
    assert!(host.lock().unwrap().native_location.is_none());
    let f = Fixture::new();
    let before = f.store.read(Namespace::Projects).unwrap().revision;
    for sid in [
        "00000000000000000000000000000000",
        "session-1",
        "A1111111111111111111111111111111",
    ] {
        assert!(f.host.capture_identity(f.source(sid), 1).is_none());
    }
    let mut other = f.source("11111111111111111111111111111111");
    other.runtime_id = "unregistered";
    assert!(f.host.capture_identity(other, 1).is_none());
    assert_eq!(f.store.read(Namespace::Projects).unwrap().revision, before);
    assert!(f.host.lock().unwrap().fence.is_none());
}

#[test]
fn capture_pins_original_root_document_host_and_native_id() {
    let f = Fixture::new();
    let sid = "11111111111111111111111111111111";
    let document = Arc::new(());
    let mut source = f.source(sid);
    source.document = &document;
    assert!(f.host.capture_identity(source, 1).is_none());
    let other = RegisteredRoot {
        path: f.root.path.with_file_name("other-project"),
        identity: f.root.identity.clone(),
    };
    let mut source = f.source(sid);
    source.root = &other;
    assert!(f.host.capture_identity(source, 1).is_none());
    let capture = f.capture(sid);
    assert_eq!(capture.key.operation.as_str(), sid);
    assert_eq!(capture.key.native.registration, 2);
    f.host
        .lock()
        .unwrap()
        .registered
        .get_mut("project-1")
        .unwrap()
        .inode += 1;
    capture.record(2, IdentityObservation::Prepared);
    assert!(f.host.lock().unwrap().fence.is_none());
    assert_eq!(f.host.publish_identity_history(), Err(Error::Conflict));
    assert_eq!(f.host.lock().unwrap().fence, Some(Error::Conflict));
    assert!(f.stored()["operations"].as_array().unwrap().is_empty());
}

#[test]
fn unrelated_global_roster_and_input_bumps_preserve_original_history_binding() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    {
        let mut state = f.host.lock().unwrap();
        let native = state.registered.get_mut("project-1").unwrap();
        native.registration_generation += 1;
        native.input_revision += 1;
        state.source_epoch += 1;
    }
    capture.record(2, IdentityObservation::Prepared);
    assert!(f.host.publish_identity_history().unwrap());
    assert_eq!(f.stored()["operations"][0]["state"], "prepared");
    assert_eq!(capture.key.native.registration, 2);
}

#[test]
fn real_service_row_is_redacted_and_visible_in_read_only_operation_list() {
    let f = Fixture::new();
    let sid = "11111111111111111111111111111111";
    let capture = f.capture(sid);
    assert!(f.host.publish_identity_history().unwrap());
    capture.record(2, IdentityObservation::Succeeded);
    assert!(f.host.publish_identity_history().unwrap());
    let body = f.operations();
    let p::ResponseBody::Operations(rows) = &body else {
        panic!("expected original service operation list");
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].operation_id.as_str(), sid);
    assert_eq!(rows[0].project_id, f.project);
    assert_eq!(rows[0].action, p::Action::EditProjectIdentity);
    assert_eq!(
        (rows[0].state, rows[0].settlement),
        (p::OperationState::Succeeded, p::Settlement::Settled)
    );
    let bytes = serde_json::to_string(&body).unwrap();
    assert!(!bytes.contains(f.native.canonical_root.to_str().unwrap()));
    assert!(!bytes.contains("project-1"));
    assert!(!bytes.contains("identityStatus"));
    assert!(!bytes.contains("checkout"));
    assert!(!bytes.contains("appStoreAppId"));
    assert_eq!(f.stored()["operations"][0].as_object().unwrap().len(), 7);
}

#[test]
fn final_during_original_claim_survives_ack_without_control_lock_over_io() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    assert!(f
        .host
        .flush_identity_with(|claim| {
            assert!(f.host.control.try_lock().is_ok());
            assert!(f.host.history.inbox.try_lock().is_ok());
            capture.record(2, IdentityObservation::Succeeded);
            publish_claim(claim)
        })
        .unwrap());
    assert_eq!(f.stored()["operations"][0]["state"], "running");
    assert!(f.host.publish_identity_history().unwrap());
    assert_eq!(f.stored()["operations"][0]["state"], "succeeded");
    assert!(!f.host.publish_identity_history().unwrap());
}

#[test]
fn identical_progress_has_no_repeated_durable_write_and_revisions_increase_on_change() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    f.host.publish_identity_history().unwrap();
    let first = f.store.read(Namespace::Projects).unwrap().revision;
    capture.record(2, IdentityObservation::Running);
    assert!(!f.host.publish_identity_history().unwrap());
    assert_eq!(f.store.read(Namespace::Projects).unwrap().revision, first);
    capture.record(3, IdentityObservation::Prepared);
    assert!(f.host.publish_identity_history().unwrap());
    assert!(f.store.read(Namespace::Projects).unwrap().revision.0 > first.0);
}

#[test]
fn final_record_survives_replacement_with_next_original_session() {
    let f = Fixture::new();
    let first = f.capture("11111111111111111111111111111111");
    first.record(2, IdentityObservation::Succeeded);
    let second = f.capture("22222222222222222222222222222222");
    second.record(4, IdentityObservation::Prepared);
    f.host.publish_identity_history().unwrap();
    f.host.publish_identity_history().unwrap();
    let saved = f.stored();
    let rows = saved["operations"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["state"], "succeeded");
    assert_eq!(rows[1]["state"], "prepared");
}

#[test]
fn unknown_is_absorbing_even_if_original_later_reports_settled() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    capture.record(2, IdentityObservation::Unknown);
    capture.record(3, IdentityObservation::Succeeded);
    f.host.publish_identity_history().unwrap();
    capture.record(4, IdentityObservation::Succeeded);
    assert!(!f.host.publish_identity_history().unwrap());
    assert_eq!(f.stored()["operations"][0]["state"], "unknown");
    assert_eq!(f.stored()["operations"][0]["settlement"], "unknown");
}

#[test]
fn failed_and_unreturned_claims_are_retained_never_retried() {
    for unwind in [false, true] {
        let f = Fixture::new();
        let _capture = f.capture("11111111111111111111111111111111");
        f.service
            .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60))
            .unwrap();
        if unwind {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = f.host.flush_identity_with(|_| -> Result<(), Error> {
                    panic!("synthetic publication unwind")
                });
            }))
            .is_err());
        } else {
            assert_eq!(
                f.host.flush_identity_with(|_| Err(Error::StateUnknown)),
                Err(Error::StateUnknown)
            );
        }
        let inbox = f.host.history.lock().unwrap();
        assert!(inbox.failure.is_some());
        assert!(inbox.claim.is_some());
        drop(inbox);
        assert!(matches!(
            f.service.read_access_status(),
            Err(Error::StateUnknown)
        ));
        let called = std::cell::Cell::new(false);
        assert!(f
            .host
            .flush_identity_with(|_| {
                called.set(true);
                Ok(())
            })
            .is_err());
        assert!(!called.get());
        f.host.drain_identity_history_for_exit();
        assert!(f.host.history.lock().unwrap().claim.is_some());
    }
}

#[test]
fn first_publication_cannot_rebind_an_old_same_project_pending_operation_id() {
    let f = Fixture::new();
    let sid = "11111111111111111111111111111111";
    f.service
        .publish_operation(
            "project-1",
            p::Id::parse(sid).unwrap(),
            p::Action::EditProjectIdentity,
            p::OperationState::Running,
            p::Settlement::Pending,
        )
        .unwrap();
    let old = f.stored()["operations"].clone();
    let capture = f.capture(sid);
    capture.record(2, IdentityObservation::Succeeded);
    assert_eq!(f.host.publish_identity_history(), Err(Error::Conflict));
    assert_eq!(f.stored()["operations"], old);
    assert!(f.host.history.lock().unwrap().claim.is_some());
}

#[test]
fn fixed_capacity_fences_read_observer_without_starting_or_cancelling_core_work() {
    let f = Fixture::new();
    f.service
        .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60))
        .unwrap();
    for n in 1..=SLOTS {
        assert!(f
            .host
            .capture_identity(f.source(&format!("{n:032x}")), 1)
            .is_some());
    }
    assert!(f
        .host
        .capture_identity(f.source("ffffffffffffffffffffffffffffffff"), 1)
        .is_none());
    assert!(f.host.lock().unwrap().fence.is_none());
    assert!(matches!(
        f.service.read_access_status(),
        Err(Error::StateUnknown)
    ));
    assert_eq!(f.host.publish_identity_history(), Err(Error::Busy));
    assert_eq!(f.host.lock().unwrap().fence, Some(Error::Busy));
    assert_eq!(
        f.host.history.lock().unwrap().rows.iter().flatten().count(),
        SLOTS
    );
    assert!(identity_history_document_backing_bytes() < 256 * 1024);
}

#[test]
fn revoke_never_renews_access_and_joined_relay_exit_drain_keeps_known_final() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    f.service
        .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60))
        .unwrap();
    f.host.publish_identity_history().unwrap();
    f.host.revoke().unwrap();
    f.host.retire_for_exit().unwrap();
    assert!(f
        .host
        .capture_identity(f.source("22222222222222222222222222222222"), 2)
        .is_none());
    // Synthetic ordering: existing source hook is after native finality and
    // positive original relay join. No synthetic task/receipt qualifies that.
    capture.record(3, IdentityObservation::Cancelled);
    f.host.drain_identity_history_for_exit();
    assert_eq!(f.stored()["operations"][0]["state"], "cancelled");
    assert!(!f.service.read_access_status().unwrap().enabled);
    assert!(f.host.history.lock().unwrap().closed);
    assert!(f
        .host
        .history
        .lock()
        .unwrap()
        .rows
        .iter()
        .all(Option::is_none));
}

#[test]
fn reopening_service_marks_history_stale_without_replaying_or_backfilling() {
    let f = Fixture::new();
    let capture = f.capture("11111111111111111111111111111111");
    capture.record(2, IdentityObservation::Succeeded);
    f.host.publish_identity_history().unwrap();
    f.service.stop().unwrap();
    let reopened = ApplicationService::open(f.store.clone()).unwrap();
    reopened
        .register_native("new-runtime", &f.root.path, f.native.device, f.native.inode)
        .unwrap();
    reopened
        .allow_agent_read(vec![f.project.clone()], Duration::from_secs(60))
        .unwrap();
    let client = reopened.admit_client().unwrap();
    let response = reopened.dispatch(
        &client,
        p::Request {
            version: p::VERSION,
            request_id: p::Id::random().unwrap(),
            request: p::RequestBody::Operations(p::ProjectQuery {
                project_id: f.project.clone(),
            }),
        },
    );
    let p::ResponseBody::Operations(rows) = response.response else {
        panic!("history not readable");
    };
    assert_eq!(rows.len(), 1);
    assert!(rows[0].stale);
    assert_eq!(
        rows[0].operation_id.as_str(),
        "11111111111111111111111111111111"
    );
    reopened.stop().unwrap();
}
