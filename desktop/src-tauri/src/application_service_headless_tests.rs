//! Original Host tests. Portable cases enter no native source. Mac cases use
//! actual SourceBooks + real Store/IPC and must run on supported APFS ancestry;
//! unsupported filesystems are NOT skipped or turned into passing admissions.
use super::*;
use crate::application_state_store::Fixture;
use std::mem::ManuallyDrop;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn fresh() -> Arc<ApplicationHost> {
    Arc::new(ApplicationHost::new_history(
        HistoryLease::new(Instant::now(), Duration::from_secs(60)).unwrap(),
    ))
}
#[test]
fn history_startup_deadline_and_stop_refuse_before_source_without_rearming() {
    runtime().block_on(async {
        let fixture = ManuallyDrop::new(Fixture::new());
        let project = fixture.app.parent().unwrap().join("never-opened-project");
        let started = Instant::now() - Duration::from_secs(31);
        let original = HistoryLease::new(started, Duration::from_secs(60)).unwrap();
        let host = Arc::new(ApplicationHost::new_history(original));
        assert_eq!(host.history_deadline().unwrap(), started + STARTUP_WORK);
        let same = host.clone();
        let app = fixture.app.clone();
        let root = project.clone();
        let job = tokio::spawn(async move { same.prepare_history(root, app).await });
        assert_eq!(job.await.unwrap().err(), Some(Error::Expired));
        assert_eq!(
            host.prepare_history(project.clone(), fixture.app.clone())
                .await
                .err(),
            Some(Error::AccessDenied)
        );
        assert!(host
            .originals
            .lock()
            .await
            .headless_sources
            .as_ref()
            .unwrap()
            .pre
            .not_started());
        assert!(!fixture.app.exists());
        assert!(!project.exists());
        assert!(host.shutdown().await.settled());

        let host = fresh();
        host.stop_history();
        assert_eq!(
            host.prepare_history(project, fixture.app.clone())
                .await
                .err(),
            Some(Error::AccessDenied)
        );
        assert!(host
            .originals
            .lock()
            .await
            .headless_sources
            .as_ref()
            .unwrap()
            .post
            .not_started());
        assert!(host.shutdown().await.settled());
        assert!(!fixture.app.exists());
        drop(ManuallyDrop::into_inner(fixture));
    });
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
mod macos {
    use super::*;
    use crate::application_state_store::{Namespace, PrivateStateDirectory, DIRECTORY};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn project(fixture: &Fixture) -> PathBuf {
        let root = fixture.app.parent().unwrap().join("project");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    async fn prepare(
        host: &Arc<ApplicationHost>,
        root: &Path,
        app: &Path,
    ) -> Result<HistoryTicket, Error> {
        let original = host.clone();
        let root = root.to_owned();
        let app = app.to_owned();
        // Genuine task return precedes ticket publication, just as the fixed
        // foreground entry. Never create a Doc, proof or caller-supplied stamp.
        tokio::spawn(async move { original.prepare_history(root, app).await })
            .await
            .unwrap()
    }
    fn list() -> p::Request {
        p::Request {
            version: p::VERSION,
            request_id: p::Id::random().unwrap(),
            request: p::RequestBody::Projects(p::Empty {}),
        }
    }
    #[test]
    fn history_native_original_sources_join_before_grant_and_restart_does_not_restore_it() {
        runtime().block_on(async {
            let fixture = ManuallyDrop::new(Fixture::short());
            let root = project(&fixture);
            let host = fresh();
            let ticket = prepare(&host, &root, &fixture.app).await.unwrap();
            let source_identity = ticket.original.root.identity;
            let service = host
                .originals
                .lock()
                .await
                .service
                .as_ref()
                .unwrap()
                .clone();
            assert_eq!(service.admit_client().err(), Some(Error::AccessDenied));
            {
                let originals = host.originals.lock().await;
                let sources = originals.headless_sources.as_ref().unwrap();
                assert!(sources.settled());
                assert!(sources.proof.as_ref().unwrap().identity() == source_identity);
                assert!(sources.post_proof.as_ref().unwrap().identity() == source_identity);
                host.history_source_bound(&originals).unwrap();
            }
            assert!(host.control.lock().unwrap().registered.is_empty());
            let status = host.finish_history(ticket).unwrap();
            assert!(status.enabled);
            let id = status.project_ids[0].clone();
            let client = service.admit_client().unwrap();
            let response = installed_cli_ipc::request(&fixture.app, &list())
                .await
                .unwrap();
            let p::ResponseBody::Projects(projects) = response.response else {
                panic!("not projects")
            };
            assert_eq!(projects.len(), 1);
            assert_eq!(projects[0].project_id, id);
            assert!(projects[0].observation.is_none());
            let report = host.shutdown().await;
            assert!(report.settled());
            assert!(report.workers_joined.is_some());
            assert!(!fixture.app.join(DIRECTORY).join("s").exists());
            assert!(!fixture
                .app
                .join(DIRECTORY)
                .join("agent.connection")
                .exists());
            drop(host);

            let next = fresh();
            let ticket = prepare(&next, &root, &fixture.app).await.unwrap();
            let reloaded = next
                .originals
                .lock()
                .await
                .service
                .as_ref()
                .unwrap()
                .clone();
            assert_eq!(reloaded.admit_client().err(), Some(Error::AccessDenied));
            let status = next.finish_history(ticket).unwrap();
            assert_eq!(status.project_ids, vec![id]);
            assert_eq!(
                reloaded.dispatch(&client, list()).response,
                p::ResponseBody::Error(Error::AccessDenied)
            );
            assert!(next.control.lock().unwrap().registered.is_empty());
            assert!(next.shutdown().await.settled());
            drop((next, reloaded, service));
            drop(ManuallyDrop::into_inner(fixture));
        });
    }
    #[test]
    fn history_concurrent_host_is_busy_and_cannot_take_over_or_delete_original_endpoint() {
        runtime().block_on(async {
            let fixture = ManuallyDrop::new(Fixture::short());
            let root = project(&fixture);
            let first = fresh();
            let ticket = prepare(&first, &root, &fixture.app).await.unwrap();
            first.finish_history(ticket).unwrap();
            let original_store = first.originals.lock().await.store.as_ref().unwrap().clone();
            let before = original_store.read(Namespace::Projects).unwrap();
            let descriptor =
                std::fs::symlink_metadata(fixture.app.join(DIRECTORY).join("agent.connection"))
                    .unwrap();
            // SAME actual Store/flock used by ordinary Desktop as well. Not a
            // simulated Busy, PID liveness inference or fake Document witness.
            assert_eq!(
                PrivateStateDirectory::open(&fixture.app)
                    .err()
                    .unwrap()
                    .code,
                Error::Busy
            );
            let second = fresh();
            assert_eq!(
                prepare(&second, &root, &fixture.app).await.err(),
                Some(Error::Busy)
            );
            assert!(second.originals.lock().await.store.is_none());
            assert!(second.originals.lock().await.server.is_none());
            assert_eq!(second.control.lock().unwrap().fence, Some(Error::Busy));
            assert_eq!(
                second
                    .prepare_history(root.clone(), fixture.app.clone())
                    .await
                    .err(),
                Some(Error::AccessDenied)
            );
            assert!(second.shutdown().await.settled());
            let after_descriptor =
                std::fs::symlink_metadata(fixture.app.join(DIRECTORY).join("agent.connection"))
                    .unwrap();
            assert_eq!(
                (
                    after_descriptor.dev(),
                    after_descriptor.ino(),
                    after_descriptor.len()
                ),
                (descriptor.dev(), descriptor.ino(), descriptor.len())
            );
            assert!(matches!(
                installed_cli_ipc::request(&fixture.app, &list())
                    .await
                    .unwrap()
                    .response,
                p::ResponseBody::Projects(_)
            ));
            let after = original_store.read(Namespace::Projects).unwrap();
            assert_eq!(before.revision, after.revision);
            assert_eq!(before.bytes, after.bytes);
            assert!(first.shutdown().await.settled());
            // A failed original is not reset after the winner closes.
            assert_eq!(
                second
                    .prepare_history(root.clone(), fixture.app.clone())
                    .await
                    .err(),
                Some(Error::AccessDenied)
            );
            let third = fresh();
            let ticket = prepare(&third, &root, &fixture.app).await.unwrap();
            assert!(third.finish_history(ticket).unwrap().enabled);
            assert!(third.shutdown().await.settled());
            drop((first, second, third, original_store));
            drop(ManuallyDrop::into_inner(fixture));
        });
    }
    #[test]
    fn history_stopped_joined_startup_grants_nothing_and_saved_path_cannot_adopt_replacement() {
        runtime().block_on(async {
            let fixture = ManuallyDrop::new(Fixture::short());
            let root = project(&fixture);
            let first = fresh();
            let ticket = prepare(&first, &root, &fixture.app).await.unwrap();
            first.stop_history();
            assert_eq!(
                first.finish_history(ticket).err(),
                Some(Error::AccessDenied)
            );
            assert!(first.control.lock().unwrap().registered.is_empty());
            assert!(first.shutdown().await.settled());
            // Registration exists durably, but it grants no permission over a
            // later directory at that spelling. Actual PRE/POST/native metadata
            // and original Store comparison, not the saved path, decide.
            let retained = root.with_file_name("retained-original-project");
            std::fs::rename(&root, &retained).unwrap();
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let second = fresh();
            assert_eq!(
                prepare(&second, &root, &fixture.app).await.err(),
                Some(Error::Conflict)
            );
            assert!(second.control.lock().unwrap().registered.is_empty());
            assert!(second.shutdown().await.settled());
            assert!(retained.is_dir());
            assert!(root.is_dir());
            drop((first, second));
            drop(ManuallyDrop::into_inner(fixture));
        });
    }
}
