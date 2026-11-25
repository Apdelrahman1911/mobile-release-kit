pub mod protocol;
mod git_read_protocol;
mod version_enrollment_protocol;
mod version_reserve_protocol;
mod git_local_protocol;
mod git_upstream_protocol;
mod git_upstream_state;
mod git_branch_protocol;
mod git_switch_protocol;
mod git_fast_forward_protocol;
mod git_rename_protocol;
mod git_init_protocol;
mod git_fetch_protocol;
mod git_push_protocol;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod git_push_state;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod git_fetch_state;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod git_local_state;
mod service_protocol;
mod service_upload_key_protocol;
mod service_upload_key_requests;
mod service_version_edit_protocol;
mod service_version_edit_requests;
mod service_version_edit_prepare_protocol;
mod service_version_edit_prepare_requests;
mod service_configuration_protocol;
mod service_initialization_protocol;
mod service_workflow_edit_protocol;
mod service_initialization_requests;
mod service_workflow_edit_requests;
mod service_metadata_images_protocol;
mod service_metadata_images_requests;
mod service_metadata_images_prepare_protocol;
mod service_metadata_images_prepare_requests;
mod service_metadata_text_protocol;
mod service_metadata_text_requests;
mod service_configuration_requests;
#[path="service_version_reserve_protocol.rs"]
mod service_version_reserve_protocol;
#[path="service_version_reserve_review_protocol.rs"] mod service_version_reserve_review_protocol;
#[path="service_version_reserve_review_requests.rs"] mod service_version_reserve_review_requests;
#[path="service_store_protocol.rs"]
mod service_store_protocol;
#[path="service_local_history_protocol.rs"]
mod service_local_history_protocol;
#[path="service_local_history_prepare_protocol.rs"]
mod service_local_history_prepare_protocol;
#[path="service_store_prepare_protocol.rs"]
mod service_store_prepare_protocol;
#[path="service_store_inventory_protocol.rs"]
mod service_store_inventory_protocol;
mod service_tool_setup_protocol;
mod service_tool_setup_requests;
#[path="service_store_requests.rs"]
mod service_store_requests;
#[path="service_github_action_protocol.rs"]
mod service_github_action_protocol;
#[path="service_github_action_requests.rs"]
mod service_github_action_requests;
#[path="service_apple_provisioning_protocol.rs"]
mod service_apple_provisioning_protocol;
#[path="service_apple_provisioning_prepare_protocol.rs"]
mod service_apple_provisioning_prepare_protocol;
#[path="service_apple_provisioning_requests.rs"]
mod service_apple_provisioning_requests;
#[path="service_version_reserve_requests.rs"]
mod service_version_reserve_requests;
mod service_git_protocol;
mod service_git_commit_protocol;
mod service_git_repository_protocol;
mod service_git_remote_protocol;
mod service_git_requests;
mod service_setup_guidance;
mod service_android_tools;
mod service_request_catalogue;
mod service_repository_summary;
mod agent_identity_requests;
mod agent_local_checks;
mod agent_candidate_build;
mod agent_android_build;
mod agent_build_requests;
mod agent_ios_archive;
#[cfg_attr(not(any(target_os="linux",target_os="macos")),path="version_allocation_windows_data.rs")]
mod version_allocation_state_native;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), path="application_state_windows_closed.rs") ]
mod application_state_store;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), path="apple_provisioning_windows_closed.rs") ]
mod apple_provisioning_journal;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), path="application_service_windows_closed.rs") ]
mod application_service;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), path="application_service_host_windows_closed.rs") ]
mod application_service_host;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod installed_cli_ipc;
mod installed_cli;
#[cfg(any(feature = "installed-cli", test))]
mod installed_history_service;
/// Fixed same-binary foreground history entry; no owner or grant is returned.
#[cfg(feature = "installed-cli")]
pub fn run_history_service(args: impl IntoIterator<Item = std::ffi::OsString>) -> u8 {
    installed_history_service::run(args)
}
mod environment;
mod installation;
mod release_version_protocol;
mod candidate_evidence_protocol;
mod lifecycle_evidence_protocol;
mod environment_diagnostics_protocol;
mod tool_preparation;
mod tool_acquisition_protocol;
mod tool_preparation_adapters;
mod tool_preparation_protocol;
mod environment_diagnostics_owner;
mod offline_preflight_protocol;
mod local_release_history_protocol;
mod local_release_history_owner;
mod apple_provisioning_protocol;
mod local_store_preflight_protocol;
mod local_store_preflight_owner;
mod local_store_prepare_protocol;
mod local_store_execute_protocol;
mod local_store_reconcile_protocol;
mod local_store_prepare_owner;
mod local_store_execute_owner;
mod local_store_reconcile_owner;
mod artifact_inspection_protocol;
mod offline_preflight_owner;
mod android_build_protocol;
mod android_upload_key_protocol;
mod android_build_owner;
mod project_recovery_protocol;
mod project_recovery_owner;
mod ios_archive_protocol;
mod ios_archive_owner;
mod ios_toolchain;
mod android_toolchain;
mod android_toolchain_catalog;
mod android_tool_sources;
mod android_registration_protocol;
mod android_registration_app_protocol;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod android_shared_lease_macos;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
mod android_catalog_query_client;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), feature = "macos-android-registration-helper"))]
mod android_catalog_query_helper;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), feature = "macos-android-registration-helper"))]
mod android_registration_publisher;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), feature = "macos-android-registration-helper"))]
pub mod android_registration_helper;
mod android_toolchain_macos_policy;
mod android_native_macos_profile;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod android_supplier_macos_source;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod android_sdk_metadata_macos;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod android_supplier_macos;
mod saved_command_owner;
pub mod runtime;
pub(crate) mod macos_history_inventory;
// Protected original books. The retained Android launch path is wired but
// qualification-disabled; legacy inspection-only DATA remains separate.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod installed_runtime;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "installed_runtime_macos.rs"]
mod installed_runtime;
// Inspection DATA only; deliberately not the producing installed_runtime alias.
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
mod installed_runtime_windows;
#[cfg(all(feature = "ubuntu-runtime-publisher", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub mod runtime_publication;
#[cfg(all(feature = "windows-runtime-publisher", target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
pub mod runtime_publication_windows;
pub mod supervisor;
pub mod bridge;
mod document_lifetime;
#[cfg(any(test, all(feature = "desktop-shell", target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
mod windows_startup;
mod edit_commands;
mod metadata_text_commands;
mod metadata_images_commands;
mod release_version_edit_commands;
mod project_identity_commands;
mod project_identity_edit_protocol;
mod github_commands;
mod credential_assessment;
mod credential_format;
mod asset_commands;
mod asset_source;
mod asset_session;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod vault_keyring_linux;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod vault_keyring_macos;
mod vault_format;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod vault_crypto;
pub(crate) mod credential_setup;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod vault_store;
pub mod edit_protocol;
pub mod github_workflow_edit_protocol;
pub mod project_initialization_edit_protocol;
pub mod metadata_text_edit_protocol;
mod saved_text_recovery_protocol;
mod metadata_images_edit_protocol;
pub mod release_version_edit_protocol;
pub mod github_connection_protocol;
mod github_auth_capture_wire;
mod github_auth_nomination;
mod github_auth_native_owner;
mod github_auth_entry_protocol;
mod github_device_protocol;
mod github_device_native;
mod github_auth_accounts;
mod github_connection_session;
mod github_preflight_protocol;
mod github_preflight_session;
mod github_release_protocol;
mod github_release_session;
mod github_setup_protocol;
mod github_publication_protocol;
mod github_repository_create_protocol;
mod github_activity_protocol;
mod github_browser_protocol;
mod github_pull_request_protocol;
mod github_actions_retry_protocol;
mod github_play_cleanup_protocol;
mod service_play_cleanup_protocol;
mod service_play_cleanup_requests;
mod github_setup_session;
mod github_history_protocol;
mod github_history_session;
pub mod edit_owner;
#[cfg(feature = "desktop-shell")]
pub mod shell;
