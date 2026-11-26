//! Discovery over the SAME finite request inboxes. There
//! is no native callback, new request owner, report access, startup or writer.
use super::*;
use crate::{agent_build_requests as build, service_request_catalogue as data};

impl ApplicationService {
    pub(super) fn discover_requests(
        &self,
        client: &ClientSession,
        project: &Id,
    ) -> Result<p::ResponseBody, Error> {
        self.native_history_current()?;
        let state = self.lock()?;
        self.check(&state)?;
        let grant = live_grant(&state)?;
        if client.instance != self.instance
            || client.grant_id != grant.id
            || !grant.projects.contains(project)
        {
            return Err(Error::AccessDenied);
        }
        if !state.runtime_aliases.values().any(|id| id == project) {
            return Err(Error::Conflict);
        }
        let mut requests = Vec::with_capacity(data::DETAIL_LIMIT);
        let local = self.local_checks.entries()?;
        if local.len() > crate::agent_local_checks::LIMIT {
            return Err(Error::StateUnknown);
        }
        for entry in local
            .iter()
            .filter(|entry| &entry.input().project_id == project)
        {
            if entry.input().service_instance != self.instance {
                return Err(Error::StateUnknown);
            }
            requests.push(entry.catalogue_metadata()?);
        }
        let mut build_count = 0usize;
        for family in [build::Family::AndroidInspect, build::Family::IosArchive] {
            let entries = self.build_requests.entries(family)?;
            build_count = build_count
                .checked_add(entries.len())
                .ok_or(Error::StateUnknown)?;
            if build_count > build::LIMIT {
                return Err(Error::StateUnknown);
            }
            for entry in entries
                .iter()
                .filter(|entry| &entry.input().project_id == project)
            {
                if entry.input().service_instance != self.instance || entry.family() != family {
                    return Err(Error::StateUnknown);
                }
                requests.push(entry.catalogue_metadata()?);
            }
        }
        let mut additional_requests = Vec::with_capacity(data::ADDITIONAL_LIMIT);
        additional_requests.extend(self.git_index_requests.catalogue_requests(&self.instance, project)?);
        additional_requests.extend(self.identity_requests.catalogue_requests(&self.instance, project)?);
        additional_requests.extend(self.version_reserve_requests.catalogue_requests(&self.instance, project)?);
        additional_requests.extend(self.upload_key_requests.retained_ids(project)?.into_iter().map(|request_id| data::AdditionalRequest {family:data::AdditionalFamily::AndroidUploadKey,request_id}));
        additional_requests.extend(self.configuration_requests.catalogue(project)?);
        additional_requests.extend(self.store_requests.catalogue_requests(&self.instance, project)?);
        additional_requests.extend(self.apple_provisioning_requests.catalogue_requests(&self.instance, project)?);
        additional_requests.extend(self.github_action_requests.catalogue_requests(&self.instance,project)?);
        additional_requests.extend(self.version_edit_requests.catalogue(project)?.into_iter().map(|request_id|data::AdditionalRequest{family:data::AdditionalFamily::VersionEdit,request_id}));
        additional_requests.extend(self.play_cleanup_requests.retained_ids(&self.instance, project)?.into_iter().map(|(purpose, request_id)| data::AdditionalRequest {family:match purpose {crate::service_play_cleanup_protocol::Purpose::PlayCleanup => data::AdditionalFamily::PlayCleanup, crate::service_play_cleanup_protocol::Purpose::VersionTag => data::AdditionalFamily::VersionTag},request_id}));
        additional_requests.extend(self.tool_setup_requests.catalogue_requests(&self.instance,project)?);
        let view = data::Catalogue {
            schema_version: 2,
            scope: data::Scope::CurrentHostRetainedRequests,
            sampling: data::Sampling::PerRequestNotAtomic,
            service_instance: self.instance.clone(),
            project_id: project.clone(),
            do_not_replay: true,
            requests,
            additional_requests: Some(additional_requests),
        };
        view.validate().map_err(|_| Error::StateUnknown)?;
        self.native_history_current()?;
        // Lock custody prevents replacement, but elapsed time can still
        // expire a grant during the bounded copies. Never return that view.
        let grant = live_grant(&state)?;
        if client.instance != self.instance
            || client.grant_id != grant.id
            || !grant.projects.contains(project)
        {
            return Err(Error::AccessDenied);
        }
        // Same Service/grant guard across the complete bounded memory copy.
        // Entry/latest/publication guards never call back into Service or Doc.
        drop(state);
        Ok(p::ResponseBody::Requests(view))
    }

    pub(crate) fn requests_client_current(
        &self,
        client: &ClientSession,
        project: &Id,
    ) -> Result<(), Error> {
        // Reuse the existing project-scoped read predicate, not tool status.
        self.android_tools_client_current(client, project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_android_build as android, agent_ios_archive as ios, agent_local_checks as local,
        application_service::tests::{passive, register_fixture},
        application_state_store::Fixture,
    };
    use std::{fs::File, os::unix::fs::MetadataExt, path::PathBuf};

    // Real existing Store/Service fixtures. The scopes/links below are inert
    // DATA, not a Desktop approval, native operation, process or join receipt.
    fn setup() -> (
        Fixture,
        Arc<PrivateStateDirectory>,
        ApplicationService,
        Id,
        PathBuf,
        ClientSession,
    ) {
        let fixture = Fixture::new();
        let store = Arc::new(PrivateStateDirectory::open(&fixture.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        let (project, root) = register_fixture(&service, &fixture.app, "project", "project-1");
        service
            .publish_passive_snapshot("project-1", &passive(&root, &"a".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let client = service.admit_client().unwrap();
        (fixture, store, service, project, root, client)
    }
    fn local_scope(
        service: &ApplicationService,
        document: &Arc<()>,
        runtime: &str,
    ) -> Arc<local::NativeScope> {
        let point = service.local_check_point(runtime).unwrap();
        let (changes, _) = tokio::sync::watch::channel(0);
        Arc::new(local::NativeScope {
            project_id: point.project_id,
            runtime_id: point.runtime_id,
            root: point.root,
            device: point.device,
            inode: point.inode,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(document),
            observation_revision: point.revision,
            config: point.config.unwrap(),
            draft_revision: 1,
            baseline_generation: 1,
            changes,
        })
    }
    fn local_input(service: &ApplicationService, scope: &local::NativeScope) -> local::Submit {
        local::Submit {
            service_instance: service.instance().clone(),
            project_id: scope.project_id.clone(),
            request_id: Id::random().unwrap(),
            expected_observation_revision: scope.observation_revision,
        }
    }
    fn build_scope(
        service: &ApplicationService,
        document: &Arc<()>,
        family: build::Family,
    ) -> Arc<build::NativeScope> {
        let point = service.build_point_for_runtime("project-1").unwrap();
        let version = android::Version {
            bytes: 32,
            sha256: "b".repeat(64),
            name: "1.2.3".into(),
            build: 7,
        };
        let config = point.config.unwrap();
        let review = match family {
            build::Family::AndroidInspect => android::Review {
                mode: android::Mode::SavedAndroidBuildStructureAndVersion,
                signing: None, upload_certificate_sha256: None,
                saved_config: config,
                saved_version: version,
                tools: android::Tools {
                    instance: Id::random().unwrap(),
                    catalog_generation: 1,
                    record_sha256: "c".repeat(64),
                },
            }
            .into(),
            build::Family::IosArchive => ios::Review {
                mode: ios::Mode::SavedIosUnsignedArchive,
                signing: None,
                saved_config: config,
                saved_version: version,
            }
            .into(),
        };
        let (changes, _) = tokio::sync::watch::channel(0);
        Arc::new(build::NativeScope {
            project_id: point.project_id,
            runtime_id: point.runtime_id,
            root: point.root,
            device: point.device,
            inode: point.inode,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(document),
            observation_revision: point.revision,
            review,
            read: None,
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: 1, baseline_generation: 1 },
            changes,
        })
    }
    fn build_input(service: &ApplicationService, scope: &build::NativeScope) -> build::Prepare {
        build::Prepare {
            service_instance: service.instance().clone(),
            project_id: scope.project_id.clone(),
            request_id: Id::random().unwrap(),
            expected_observation_revision: scope.observation_revision,
        }
    }
    fn discover(
        service: &ApplicationService,
        client: &ClientSession,
        project: &Id,
    ) -> data::Catalogue {
        let response = service.dispatch(
            client,
            p::Request {
                version: p::VERSION,
                request_id: Id::random().unwrap(),
                request: p::RequestBody::Requests(p::ProjectQuery {
                    project_id: project.clone(),
                }),
            },
        );
        match response.response {
            p::ResponseBody::Requests(view) => view,
            _ => panic!("expected fixed request catalogue"),
        }
    }
    fn finish(service: &ApplicationService, store: &PrivateStateDirectory) {
        service.stop().unwrap();
        store.close().unwrap();
    }

    #[test]
    fn lost_ack_reconnect_discovers_git_identity_and_reservation_without_private_data_or_replay() {
        use crate::{agent_identity_requests as identity, service_git_protocol as git,
            service_git_requests as git_requests, service_version_reserve_protocol as version,
            service_version_reserve_requests as version_requests,
            service_play_cleanup_protocol as cleanup};
        let (_f, store, service, project, root, first) = setup();
        let document = Arc::new(());
        let review = Arc::new(());
        let point = service.identity_request_point("project-1").unwrap();
        service.identity_requests.allow(identity::NativeScope {
            project_id: project.clone(), runtime_id: "project-1".into(), root: root.clone(),
            device: point.device, inode: point.inode, registration: 1, input_revision: 1,
            document: Arc::downgrade(&document),
        }).unwrap();
        let intent = identity::Submit {
            service_instance: service.instance().clone(), project_id: project.clone(),
            intent_id: Id::random().unwrap(), expected_observation_revision: point.revision,
            change: identity::Change {
                selection: identity::Selection {platform: identity::Platform::Android, target: ":app".into(), project: None},
                desired_identity: "com.private.sentinel".into(), identity_intent: identity::IdentityIntent::NewApplication,
            },
        };
        service.submit_identity(&first, intent.clone()).unwrap(); // Deliberately discard the ACK.
        let git_scope = Arc::new(git_requests::NativeScope {
            project_id: project.clone(), runtime_id: "project-1".into(), root,
            device: point.device, inode: point.inode, registration: 1, document_revision: 1,
            input_revision: 1, read_operation_id: Some("git-read-1".into()), document: Arc::downgrade(&document),
            selection: git::Selection::new(git::Action::Stage, "d".repeat(64), vec!["private/sentinel".into()]).unwrap().into(),
            commit: None, changes: tokio::sync::watch::channel(0).0,
        });
        let git_access = service.git_index_requests.allow(git_scope).unwrap();
        let staged = git::Prepare {
            origin: git::Query {project_id: project.clone(), service_instance: service.instance().clone(), request_id: Id::random().unwrap()},
            grant_id: git_access.grant_id.unwrap(),
        };
        service.git_index_prepare(&first, staged.clone()).unwrap();
        let reserve_point = service.version_reserve_point("project-1").unwrap();
        let reserved = version::Submit {
            origin: version::Query {project_id: project.clone(), service_instance: service.instance().clone(), request_id: Id::random().unwrap()},
            grant_id: Id::random().unwrap(), review_id: Id::random().unwrap(),
        };
        service.version_reserve_requests.allow(Arc::new(version_requests::NativeScope {
            project_id: project.clone(), runtime_id: "project-1".into(), review_id: reserved.review_id.clone(),
            review_revision: 1, review_end: Instant::now() + Duration::from_secs(110), read: reserve_point.read,
            document: Arc::downgrade(&document), review: Arc::downgrade(&review), changes: tokio::sync::watch::channel(0).0,
        }), reserved.grant_id.clone()).unwrap();
        service.service_version_reserve_submit(&first, reserved.clone()).unwrap();
        let cleanup_point = service.play_cleanup_point("project-1").unwrap();
        let cleanup_input = cleanup::Submit {
            origin: cleanup::Query {purpose: cleanup::Purpose::PlayCleanup,project_id: project.clone(), service_instance: service.instance().clone(), request_id: Id::random().unwrap()},
            consent_id: Id::random().unwrap(),
        };
        let cleanup_scope = service.play_cleanup_requests.scope(
            project.clone(), "project-1".into(), cleanup_input.consent_id.clone(),
            Instant::now() + Duration::from_secs(100), cleanup_point.read,
            Arc::downgrade(&document), Arc::downgrade(&review), tokio::sync::watch::channel(0).0, 1,
        );
        service.play_cleanup_requests.allow(cleanup_scope).unwrap();
        service.service_play_cleanup_submit(&first, cleanup_input.clone()).unwrap();
        let before = store.read(Namespace::Projects).unwrap();
        let second = service.admit_client().unwrap();
        assert_ne!(first.client_id, second.client_id);
        let view = discover(&service, &second, &project);
        assert_eq!(view.schema_version, 2);
        assert!(view.requests.is_empty());
        assert_eq!(view.additional_requests.as_ref().unwrap(), &vec![
            data::AdditionalRequest {family: data::AdditionalFamily::GitIndex, request_id: staged.origin.request_id.clone()},
            data::AdditionalRequest {family: data::AdditionalFamily::Identity, request_id: intent.intent_id.clone()},
            data::AdditionalRequest {family: data::AdditionalFamily::VersionReservation, request_id: reserved.origin.request_id.clone()},
            data::AdditionalRequest {family: data::AdditionalFamily::PlayCleanup, request_id: cleanup_input.origin.request_id.clone()},
        ]);
        let encoded = serde_json::to_string(&view).unwrap();
        for private in ["sentinel", "desiredIdentity", "grantId", "reviewId", "selection", "state"] {
            assert!(!encoded.contains(private));
        }
        let p::ResponseBody::GitIndexRequest(status) = service.git_index_query(&second, &staged.origin, false).unwrap()
            else {panic!("original Git status")};
        assert_eq!(status.state, git::State::Queued);
        let p::ResponseBody::VersionReserveRequest(status) = service.service_version_reserve_query(&second, &reserved.origin, false).unwrap()
            else {panic!("original reservation status")};
        assert_eq!(status.state, version::State::Queued);
        let p::ResponseBody::PlayCleanupRequest(status) = service.service_play_cleanup_query(&second, &cleanup_input.origin, false).unwrap()
            else {panic!("original cleanup status")};
        assert_eq!(status.state, cleanup::State::Queued);
        assert!(status.do_not_replay);
        let p::ResponseBody::IdentityIntent(status) = service.query_identity(&second, &identity::Query {
            service_instance: intent.service_instance, project_id: project.clone(), intent_id: intent.intent_id,
        }).unwrap() else {panic!("original identity status")};
        assert_eq!(status.state, identity::IntentState::Queued);
        assert_eq!(discover(&service, &second, &project), view);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!((before.revision, before.bytes), (after.revision, after.bytes));
        service.revoke_agent_read().unwrap();
        assert!(matches!(service.discover_requests(&second, &project), Err(Error::AccessDenied)));
        finish(&service, &store);
    }

    #[test]
    fn read_expiring_during_original_inbox_copy_is_rechecked_before_return() {
        let (_f, store, service, project, _root, client) = setup();
        // A finite real mutex wait, not a production timing hook or fake clock.
        let expires = Instant::now() + Duration::from_millis(150);
        service.state.lock().unwrap().grant.as_mut().unwrap().expires = expires;
        let (entered, result) = std::thread::scope(|scope| {
            let (entered, worker) = service.git_index_requests.with_catalogue_book_locked(|| {
                let worker = scope.spawn(|| service.discover_requests(&client, &project));
                let until = Instant::now() + Duration::from_secs(2);
                let mut entered = false;
                while Instant::now() < until {
                    if matches!(service.state.try_lock(), Err(std::sync::TryLockError::WouldBlock)) {
                        entered = true;
                        break;
                    }
                    if worker.is_finished() { break; }
                    std::thread::sleep(Duration::from_millis(1));
                }
                std::thread::sleep(expires.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
                (entered, worker)
            }); // Release the SAME held book before joining on every path.
            (entered, worker.join())
        });
        assert!(entered);
        assert!(matches!(result, Ok(Err(Error::Expired))));
        finish(&service, &store);
    }

    #[test]
    fn unavailable_additional_inbox_is_not_successful_empty_discovery() {
        for closed in 0..4 {
            let (_f, store, service, project, _root, client) = setup();
            match closed {
                0 => service.git_index_requests.close(),
                1 => service.identity_requests.close(),
                2 => service.version_reserve_requests.close(Instant::now()),
                _ => service.play_cleanup_requests.close(Instant::now()),
            }
            assert!(matches!(service.discover_requests(&client, &project), Err(Error::Unavailable)));
            finish(&service, &store);
        }
    }

    #[test]
    fn lost_reply_reconnect_discovers_same_request_without_claim_or_write() {
        let (_f, store, service, project, _root, first) = setup();
        let document = Arc::new(());
        let scope = local_scope(&service, &document, "project-1");
        service.local_checks.allow(scope.clone()).unwrap();
        let input = local_input(&service, &scope);
        service.submit_local_check(&first, input.clone()).unwrap(); // Deliberately do not use its ACK.
        let saved = store.read(Namespace::Projects).unwrap();
        let second = service.admit_client().unwrap();
        assert_ne!(first.client_id, second.client_id);
        let view = discover(&service, &second, &project);
        assert_eq!(view.service_instance, input.service_instance);
        assert_eq!(view.requests.len(), 1);
        assert_eq!(view.requests[0].request_id, input.request_id);
        assert_eq!(
            view.requests[0].progress,
            data::Progress::LocalCheck {
                request_state: local::RequestState::Queued
            }
        );
        assert!(view.requests[0].operation.is_none());
        let query = local::Query {
            service_instance: view.service_instance,
            project_id: view.project_id,
            request_id: view.requests[0].request_id.clone(),
        };
        let p::ResponseBody::LocalCheck(status) =
            service.query_local_check(&second, &query, false).unwrap()
        else {
            panic!("same request status")
        };
        assert_eq!(status.request_state, local::RequestState::Queued);
        assert_eq!(service.local_checks.entries().unwrap().len(), 1);
        assert!(service.local_checks.access().unwrap().consumed);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!((saved.revision, saved.bytes), (after.revision, after.bytes));
        finish(&service, &store);
    }
    #[test]
    fn both_build_families_copy_original_metadata_without_start_or_review() {
        let (_f, store, service, project, _root, client) = setup();
        let document = Arc::new(());
        let android = build_scope(&service, &document, build::Family::AndroidInspect);
        service.build_requests.allow(android.clone()).unwrap();
        let old = build_input(&service, &android);
        service
            .prepare_agent_android_build(&client, old.clone())
            .unwrap();
        service
            .query_agent_android_build(&client, &old.query(), true)
            .unwrap();
        let ios = build_scope(&service, &document, build::Family::IosArchive);
        service.build_requests.allow(ios.clone()).unwrap();
        let input = build_input(&service, &ios);
        service
            .prepare_agent_ios_archive(&client, input.clone())
            .unwrap();
        let claim = service
            .build_requests
            .claim(build::Family::IosArchive)
            .unwrap()
            .unwrap();
        let operation = Id::random().unwrap();
        let generation = Id::random().unwrap();
        let link = claim
            .entry()
            .bind(
                build::Family::IosArchive,
                operation.clone(),
                generation.clone(),
                1,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        claim.returned(true);
        let before = discover(&service, &client, &project);
        assert_eq!(before.requests.len(), 2);
        let pending = &before.requests[1];
        assert_eq!(pending.request_id, input.request_id);
        assert_eq!(
            pending.progress,
            data::Progress::IosArchive {
                request_state: build::RequestState::Preparing,
                start_state: build::StartState::NotRequested
            }
        );
        assert!(pending.operation.is_none());
        assert!(!pending.history_available);
        let (_, original) = link.entry().claim_history().unwrap().unwrap();
        let returned = service.begin_operation(&ios.runtime_id, original.operation_id().clone(), p::Action::Build,
            original.state(), original.settlement());
        link.entry().history_returned(original.status_revision(), returned).unwrap();
        let view = discover(&service, &client, &project);
        assert_eq!(view.requests.len(), 2);
        assert_eq!(view.requests[0].request_id, old.request_id);
        assert_eq!(
            view.requests[0].progress,
            data::Progress::AndroidBuild {
                request_state: build::RequestState::CancelledBeforePreparation,
                start_state: build::StartState::NotRequested
            }
        );
        let row = &view.requests[1];
        assert_eq!(row.request_id, input.request_id);
        assert_eq!(
            row.progress,
            data::Progress::IosArchive {
                request_state: build::RequestState::OriginalAvailable,
                start_state: build::StartState::NotRequested
            }
        );
        let native = row.operation.as_ref().unwrap();
        assert_eq!(
            (&native.operation_id, &native.owner_generation),
            (&operation, &generation)
        );
        assert_eq!(
            (native.state, native.settlement),
            (p::OperationState::Prepared, p::Settlement::Pending)
        );
        assert!(row.history_available); // Only the SAME actual history return published it.
        let encoded = serde_json::to_string(&view).unwrap();
        for forbidden in [
            "result",
            "review",
            "savedConfig",
            "savedVersion",
            "tools",
            "recordSha256",
            "1.2.3",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert!(service
            .build_requests
            .claim(build::Family::IosArchive)
            .unwrap()
            .is_none());
        finish(&service, &store);
    }
    #[test]
    fn admission_and_native_unknown_are_not_repaired_by_discovery_or_history() {
        let (_f, store, service, project, _root, client) = setup();
        let document = Arc::new(());
        let scope = local_scope(&service, &document, "project-1");
        service.local_checks.allow(scope.clone()).unwrap();
        let input = local_input(&service, &scope);
        service.submit_local_check(&client, input).unwrap();
        let claim = service.local_checks.claim().unwrap().unwrap();
        let operation = Id::random().unwrap();
        let generation = Id::random().unwrap();
        let link = claim
            .entry()
            .bind(operation.clone(), generation.clone(), 1)
            .unwrap();
        claim.returned(false); // Original admission ACK is unknown, not a refusal.
        let before = discover(&service, &client, &project);
        assert_eq!(
            before.requests[0].progress,
            data::Progress::LocalCheck {
                request_state: local::RequestState::AdmissionUnknown
            }
        );
        link.publish(local::Operation {
            operation_id: operation.clone(),
            owner_generation: generation.clone(),
            status_revision: 2,
            state: p::OperationState::Unknown,
            settlement: p::Settlement::Unknown,
            outcome: Some(local::Outcome::Unknown),
            reason: local::Reason::CleanupUnknown,
            result: None,
        })
        .unwrap();
        let unknown = discover(&service, &client, &project);
        assert_eq!(
            unknown.requests[0].operation.as_ref().unwrap().settlement,
            p::Settlement::Unknown
        );
        assert!(!unknown.requests[0].history_available);
        link.publish(local::Operation {
            operation_id: operation,
            owner_generation: generation,
            status_revision: 3,
            state: p::OperationState::Cancelled,
            settlement: p::Settlement::Settled,
            outcome: Some(local::Outcome::Cancelled),
            reason: local::Reason::Cancelled,
            result: None,
        })
        .unwrap(); // Existing native-unknown absorption keeps the old report.
        assert_eq!(discover(&service, &client, &project), unknown);
        finish(&service, &store);
    }
    #[test]
    fn project_filter_alias_and_pre_send_revoke_do_not_leak_other_requests() {
        let (f, store, service, project, _root, _client) = setup();
        let (other, root) = register_fixture(&service, &f.app, "other", "project-2");
        service
            .publish_passive_snapshot("project-2", &passive(&root, &"d".repeat(64)))
            .unwrap();
        service
            .allow_agent_read(
                vec![project.clone(), other.clone()],
                Duration::from_secs(300),
            )
            .unwrap();
        let client = service.admit_client().unwrap();
        let document = Arc::new(());
        let scope = local_scope(&service, &document, "project-2");
        service.local_checks.allow(scope.clone()).unwrap();
        service
            .submit_local_check(&client, local_input(&service, &scope))
            .unwrap();
        let cleanup_review = Arc::new(());
        let cleanup_point = service.play_cleanup_point("project-2").unwrap();
        let cleanup_input = crate::service_play_cleanup_protocol::Submit {
            origin: crate::service_play_cleanup_protocol::Query {purpose: crate::service_play_cleanup_protocol::Purpose::PlayCleanup,
                project_id: other.clone(), service_instance: service.instance().clone(), request_id: Id::random().unwrap(),
            },
            consent_id: Id::random().unwrap(),
        };
        let cleanup_scope = service.play_cleanup_requests.scope(
            other.clone(), "project-2".into(), cleanup_input.consent_id.clone(),
            Instant::now() + Duration::from_secs(100), cleanup_point.read,
            Arc::downgrade(&document), Arc::downgrade(&cleanup_review), tokio::sync::watch::channel(0).0, 1,
        );
        service.play_cleanup_requests.allow(cleanup_scope).unwrap();
        service.service_play_cleanup_submit(&client, cleanup_input.clone()).unwrap();
        assert_eq!(discover(&service, &client, &other).additional_requests.unwrap(), vec![
            data::AdditionalRequest {family: data::AdditionalFamily::PlayCleanup, request_id: cleanup_input.origin.request_id},
        ]);
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let current = service.admit_client().unwrap();
        let filtered = discover(&service, &current, &project);
        assert!(filtered.requests.is_empty());
        assert!(filtered.additional_requests.unwrap().is_empty());
        let mut foreign = service.admit_client().unwrap();
        foreign.instance = Id::random().unwrap();
        assert!(matches!(service.discover_requests(&foreign, &project), Err(Error::AccessDenied)));
        assert_eq!(service.local_checks.entries().unwrap().len(), 1);
        assert!(matches!(
            service.discover_requests(&current, &other),
            Err(Error::AccessDenied)
        ));
        assert_eq!(
            service.requests_client_current(&client, &project),
            Err(Error::AccessDenied)
        );
        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .remove("project-1");
        assert!(matches!(
            service.discover_requests(&current, &project),
            Err(Error::Conflict)
        ));
        assert_eq!(
            service.requests_client_current(&current, &project),
            Err(Error::Conflict)
        );
        service
            .state
            .lock()
            .unwrap()
            .runtime_aliases
            .insert("project-1".into(), project.clone());
        service.revoke_agent_read().unwrap();
        assert!(matches!(
            service.discover_requests(&current, &project),
            Err(Error::AccessDenied)
        ));
        assert_eq!(
            service.requests_client_current(&current, &project),
            Err(Error::AccessDenied)
        );
        finish(&service, &store);
    }
    #[test]
    fn expired_or_failed_service_never_returns_an_empty_catalogue() {
        let (_f, store, service, project, _root, client) = setup();
        assert!(discover(&service, &client, &project).requests.is_empty());
        assert!(!service.local_checks.access().unwrap().enabled);
        assert!(
            !service
                .build_requests
                .access(build::Family::AndroidInspect)
                .unwrap()
                .enabled
        );
        service
            .state
            .lock()
            .unwrap()
            .grant
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        assert!(matches!(
            service.discover_requests(&client, &project),
            Err(Error::Expired)
        ));
        assert_eq!(
            service.requests_client_current(&client, &project),
            Err(Error::Expired)
        );
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let current = service.admit_client().unwrap();
        service.fence_native_history();
        assert!(matches!(
            service.discover_requests(&current, &project),
            Err(Error::StateUnknown)
        ));
        assert_eq!(
            service.requests_client_current(&current, &project),
            Err(Error::StateUnknown)
        );
        finish(&service, &store);
    }
    #[test]
    fn restart_clears_no_replay_catalogue_not_persisted_history_or_grants() {
        let (f, store, service, project, root, client) = setup();
        let document = Arc::new(());
        let scope = local_scope(&service, &document, "project-1");
        service.local_checks.allow(scope.clone()).unwrap();
        let input = local_input(&service, &scope);
        service.submit_local_check(&client, input.clone()).unwrap();
        let saved_operation = Id::random().unwrap();
        service
            .begin_operation(
                "project-1",
                saved_operation.clone(),
                p::Action::LocalProjectChecks,
                p::OperationState::Unknown,
                p::Settlement::Unknown,
            )
            .unwrap();
        let saved = store.read(Namespace::Projects).unwrap();
        assert_eq!(discover(&service, &client, &project).requests.len(), 1);
        finish(&service, &store);
        drop(service);
        drop(store);
        let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
        let service = ApplicationService::open(store.clone()).unwrap();
        assert_ne!(service.instance(), &input.service_instance);
        assert!(service.admit_client().is_err());
        let held = File::open(&root).unwrap();
        let native = held.metadata().unwrap();
        let current_project = service
            .register_native("project-9", &root, native.dev(), native.ino())
            .unwrap();
        nix::unistd::close(held).unwrap();
        assert_eq!(current_project.project_id, project);
        service
            .allow_agent_read(vec![project.clone()], Duration::from_secs(300))
            .unwrap();
        let current = service.admit_client().unwrap();
        let view = discover(&service, &current, &project);
        assert!(view.requests.is_empty() && view.do_not_replay);
        assert!(service
            .query_local_check(&current, &input.query(), false)
            .is_err());
        let observation = service.state.lock().unwrap().saved.operations[0].clone();
        assert_eq!(observation.operation_id, saved_operation);
        assert!(observation.stale);
        assert_eq!(observation.settlement, p::Settlement::Unknown);
        let after = store.read(Namespace::Projects).unwrap();
        assert_eq!((saved.revision, saved.bytes), (after.revision, after.bytes));
        assert!(!service.local_checks.access().unwrap().enabled);
        finish(&service, &store);
    }
}
