//! Document admission, empty-owner behavior and declarative command permissions.
//! No selected root, process, task, IO, GUI or native qualification.
use super::*;
use crate::android_build_protocol::{Availability, Profile};

fn empty_state() -> DocumentState {
    DocumentState {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        agent_local_check_grant: None, lifetime: DocumentLifetime::default(), revision: 0, next_operation: 0, next_context: 0,
        exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false,
        quit_pending: false, retiring: false, lock_pending: false, compatibility_picker_pending: false,
        maintenance: macos_maintenance::Closure::default(),
        saved_observation: None, saved_input: None, apple_provisioning_ready:None, git_read: None, version_allocation_source: None, version_enrollment: None, session_owner_reason: None, context: None, slot: None, records: Vec::new(), assignments: Vec::new(), quit: None,
        quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(), gh_auth: None, evidence: EvidenceRegistry::new(), images: images::Registry::new(), installation: installation::Registry::new(),
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        vault: None,
        #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        first_origin: None }
}

#[test]
fn android_pending_finished_and_unsupported_absence_do_not_poison_passive_work() {
    let mut state = empty_state();
    assert!(passive_document_gate(&state).is_ok());
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::Busy));
    assert_eq!(android_build_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
    state.lifetime.crash_hook_installed(); state.lifetime.started(true);
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::Busy));
    state.lifetime.finished(true);
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), None);
    state.lifetime.invalidate(); state.lost_observed = true;
    assert_eq!(android_build_document_gate(&state, Some(Profile::LinuxX64)), Some(Availability::DocumentLost));
    assert_eq!(android_build_document_gate(&state, None), Some(Availability::UnsupportedPlatform));
    assert!(passive_document_gate(&state).is_ok());
    state.quit_pending = true; assert!(passive_document_gate(&state).is_err());
    state.quit_pending = false; state.unknown = true; assert!(passive_document_gate(&state).is_err());
}

#[test]
fn an_empty_unqualified_android_owner_does_not_claim_resource_work() {
    // This constructor only retains RuntimeConfig DATA and empty owner books.
    let owner = crate::android_build_owner::AndroidBuildOwner::new(
        crate::runtime::RuntimeConfig::packaged("/never-opened-android-wiring-runtime".into()), None);
    let status = owner.status(Availability::Available).unwrap();
    assert_eq!(status.availability, if Profile::current().is_some() { Availability::RuntimeUnqualified } else { Availability::UnsupportedPlatform });
    assert!(status.operation.is_none() && owner.can_exit() && !owner.busy() && !owner.disabled());
    assert!(owner.ensure_idle().is_ok());
    owner.document_lost();
    let status = owner.status(Availability::DocumentLost).unwrap();
    assert_eq!(status.availability, if Profile::current().is_some() { Availability::DocumentLost } else { Availability::UnsupportedPlatform });
    assert!(status.operation.is_none() && owner.ensure_idle().is_ok());
    owner.request_shutdown();
    assert_eq!(owner.status(Availability::Shutdown).unwrap().availability, Availability::Shutdown);
    assert!(owner.can_exit() && !owner.disabled() && owner.ensure_idle().is_err());
}

#[test]
fn android_build_and_registration_commands_have_explicit_capabilities() {
    let capability: Value = serde_json::from_str(include_str!("../capabilities/main.json")).unwrap();
    let permissions = capability["permissions"].as_array().unwrap();
    for command in ["prepare_android_build", "start_android_build", "android_build_status", "cancel_android_build",
        "android_tool_registration_status", "inspect_android_tool_sources",
        "register_android_tool_sources", "cancel_android_tool_registration"] {
        let permission = format!("allow-{}", command.replace('_', "-"));
        assert_eq!(permissions.iter().filter(|value| value.as_str() == Some(permission.as_str())).count(), 1);
    }
}
