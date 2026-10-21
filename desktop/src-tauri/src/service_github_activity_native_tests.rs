//! Unentered Connection/Edit/Entry DATA. No token collection, source opening,
//! actual Supervisor ticket or native/provider qualification is performed.
use super::*;
use crate::github_connection_protocol::{
    Coverage, Permission as PermissionFact, Permissions, Presence, Visibility, Workflow,
    WorkflowState,
};
use crate::github_workflow_edit_protocol::WorkflowId;
use crate::{edit_owner::EditOwner, runtime::RuntimeConfig, service_protocol::Id};

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn observed<T>(value: T) -> Fact<T> {
    Fact {
        state: FactState::Observed,
        value: Some(value),
        observed_at: Some("2026-09-17T12:00:01Z".into()),
        reason: Reason::None,
    }
}
fn state(at: Instant) -> ConnectionState {
    let mut s = crate::github_connection_session::tests::fixture(at);
    // The existing Connection's DATA accept method, not a fabricated ticket.
    s.accept_final(
        Ok(GitHubReadOutcome {
            facts: GitHubReadFacts {
                schema_version: 1,
                account: observed(Account {
                    id: "11".into(),
                    login: "owner".into(),
                }),
                repository: observed(Repository {
                    id: "22".into(),
                    full_name: "owner/app".into(),
                    default_branch: "main".into(),
                    visibility: Visibility::Private,
                    archived: false,
                    permissions: Permissions {
                        pull: PermissionFact::ReportedAllowed,
                        push: PermissionFact::Unknown,
                        admin: PermissionFact::Unknown,
                    },
                }),
                automation: observed(Automation {
                    coverage: Coverage::Complete,
                    workflows: [
                        WorkflowId::Preflight,
                        WorkflowId::Candidate,
                        WorkflowId::ExternalTesting,
                        WorkflowId::ProductionSubmit,
                    ]
                    .into_iter()
                    .map(|id| Workflow {
                        id,
                        remote_id: None,
                        presence: Presence::NotListed,
                        state: WorkflowState::Unknown,
                    })
                    .collect(),
                }),
            },
            control: GitHubReadControl {
                reason: Reason::None,
                credential_expires_at: None,
                cooldown_seconds: None,
                cooldown_blocked: false,
            },
        }),
        at,
        false,
        at,
    );
    s.capability(at, Reason::None);
    assert!(!s.native_work_pending());
    // A supplied availability bit exercises the comparison, NOT profile admission.
    assert!(s.github_activity_status(true, at, Reason::None).available);
    s
}
fn root() -> RegisteredRoot {
    RegisteredRoot {
        path: "/never-opened-activity-scope".into(),
        identity: crate::asset_source::ProjectIdentity::Posix(
            crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
        ),
    }
}
fn selection(s: &ConnectionState) -> wire::Selection {
    wire::Selection::ActivityOverview(wire::activity::Selection {
        session_id: "github-session-1".into(),
        expected_revision: s.activity.view.revision,
        expected_connection_revision: s.status.revision,
    })
}
fn editor(doc: &Arc<()>, path: &str) -> EditOwner {
    let e = EditOwner::new(RuntimeConfig::packaged(path.into()));
    e.bind_saved_registration(
        doc,
        Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()),
    );
    e.initial_document("main").unwrap();
    e
}
fn scope(doc: &Arc<()>, r: &action_delegation::Review) -> Arc<rows::NativeScope> {
    rows::NativeScope::new(
        id('1'),
        "project-1".into(),
        root().path,
        1,
        2,
        1,
        r.data.clone(),
        r.identity.clone(),
        Instant::now() + Duration::from_secs(90),
        Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                Instant::now() + Duration::from_secs(100),
            ),
        ),
        Arc::downgrade(doc),
        tokio::sync::watch::channel(0).0,
    )
}

#[test]
fn activity_capture_binds_original_edit_root_connection_and_numeric_account() {
    let now = Instant::now();
    let mut state = state(now);
    let doc = Arc::new(());
    let owner = editor(&doc, "/never-opened-activity-edit-a");
    let other = editor(&doc, "/never-opened-activity-edit-b");
    let edit = owner.saved_registration_guard(&doc).unwrap();
    let foreign = other.saved_registration_guard(&doc).unwrap();
    let selected = selection(&state);
    let capture = state
        .github_activity_agent_review(&selected, 2, &root(), &"f".repeat(64), &edit, now)
        .unwrap();
    assert!(edit.matches(&capture.stamp));
    assert!(!foreign.matches(&capture.stamp));
    assert!(capture.data.prepared().is_none());
    let wire::Review::ActivityOverview(reference) = &capture.data else {
        panic!("Activity reference")
    };
    assert_eq!(
        (&reference.account_id, &reference.repository_id),
        (&"11".to_owned(), &"22".to_owned())
    );
    let held = capture.activity.as_ref().unwrap();
    assert!(held.root == root());
    assert_eq!(held.generation, 2);
    assert_eq!(
        held.request.selection,
        p::Selection::Overview { branch: None }
    );
    state.status.account.value.as_mut().unwrap().id = "12".into();
    assert!(state
        .github_activity_agent_review(&selected, 2, &root(), &"f".repeat(64), &edit, now)
        .is_err());
    assert!(!state.native_work_pending());
}

#[test]
fn activity_permission_is_one_actual_scope_not_equal_public_data_or_foreign_edit() {
    let now = Instant::now();
    let mut state = state(now);
    let doc = Arc::new(());
    let owner = editor(&doc, "/never-opened-activity-edit-c");
    let other = editor(&doc, "/never-opened-activity-edit-d");
    let edit = owner.saved_registration_guard(&doc).unwrap();
    let foreign = other.saved_registration_guard(&doc).unwrap();
    let selected = selection(&state);
    let review = state
        .github_activity_agent_review(&selected, 2, &root(), &"f".repeat(64), &edit, now)
        .unwrap();
    let actual = scope(&doc, &review);
    let equal = scope(&doc, &review);
    state.github_activity_agent_allow(review, &actual).unwrap();
    assert!(state
        .github_activity_agent_review(&selected, 2, &root(), &"f".repeat(64), &edit, now)
        .is_err());
    for original in [false, true] {
        let input_scope = if original {
            actual.clone()
        } else {
            equal.clone()
        };
        let inbox = rows::Inbox::new(id('2'));
        inbox.allow(input_scope, id('3')).unwrap();
        inbox
            .submit(wire::Submit {
                origin: wire::Query {
                    project_id: id('1'),
                    service_instance: id('2'),
                    request_id: id('4'),
                },
                grant_id: id('3'),
            })
            .unwrap();
        let call = inbox.claim().unwrap().unwrap();
        let wire::Selection::ActivityOverview(reference) = &selected else {
            panic!()
        };
        let args = p::ReadArgs {
            session_id: reference.session_id.clone(),
            project_id: "project-1".into(),
            expected_revision: reference.expected_revision,
            expected_connection_revision: reference.expected_connection_revision,
            selection: p::Selection::Overview { branch: None },
        };
        assert_eq!(
            state
                .github_activity_agent_current(call.entry(), &args, 2, &root(), &edit)
                .is_ok(),
            original
        );
        assert!(state
            .github_activity_agent_current(call.entry(), &args, 2, &root(), &foreign)
            .is_err());
        if original {
            let request = state
                .activity
                .agent_permission
                .as_ref()
                .unwrap()
                .capture
                .request
                .clone();
            let mut replaced = root();
            replaced.path.push("changed");
            assert!(state
                .activity_agent_take(call.entry(), &request, 2, &replaced)
                .is_err());
            assert!(state.activity.agent_permission.is_some());
            actual.read.revoke(now);
            assert!(state
                .github_activity_agent_current(call.entry(), &args, 2, &root(), &edit)
                .is_err());
        }
        call.returned(Err(wire::Reason::ContextChanged));
    }
    state.github_activity_agent_revoke(&actual);
    assert!(state.activity.agent_permission.is_none());
    assert!(!state.native_work_pending());
}

#[test]
fn activity_agent_does_not_discard_a_retained_gui_preflight_review() {
    let now = Instant::now();
    let mut state = state(now);
    let doc = Arc::new(());
    let owner = editor(&doc, "/never-opened-activity-edit-e");
    let edit = owner.saved_registration_guard(&doc).unwrap();
    let selected = selection(&state);
    // Presence-only private Consent DATA; no provider receipt or authorization
    // is inferred. The new path must refuse even this existing retained row.
    let prepared: crate::github_preflight_protocol::Prepared = serde_json::from_value(serde_json::json!({
        "target":{"projectBinding":"f".repeat(64),"repository":"owner/app","accountId":"11","repositoryId":"22",
            "platform":"android","branch":"main","toolingRepository":"Apdelrahman1911/mobile-release-kit","toolingSha":"a".repeat(40),"marker":"b".repeat(32)},
        "sourceSha":"c".repeat(40),"workflowId":"7","workflowPath":".github/workflows/mobile-preflight.yml",
        "callerSha256":"d".repeat(64),"observedAt":"2026-10-21T12:00:00Z","expectedRef":"refs/heads/main",
        "displayTitle":"held review","confirmation":"not an authorization fixture"})).unwrap();
    state.preflight.consent = Some(crate::github_preflight_session::Consent {
        prepared: prepared.clone(),
        end: now + Duration::from_secs(90),
        session_id: "github-session-1".into(),
        project_id: "project-1".into(),
        generation: 2,
        root: root(),
    });
    assert!(state
        .github_activity_agent_review(&selected, 2, &root(), &"f".repeat(64), &edit, now)
        .is_err());
    assert_eq!(state.preflight.consent.as_ref().unwrap().prepared, prepared);
    assert!(!state.native_work_pending());
}
