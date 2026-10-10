//! Actual process main, not a libtest worker or a shipping automation switch.
#![forbid(unsafe_code)]
#[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    not(feature = "macos-android-registration-helper"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), feature = "macos-installed-observation", not(feature = "macos-installed-installer")),
        all(target_os = "windows", target_arch = "x86_64", target_env = "msvc", feature = "windows-installed-observation",
            not(feature = "windows-runtime-publisher"), not(feature = "macos-installed-installer"))))))]
compile_error!("installed-shell observation requires debug test + desktop-shell + custom-protocol on Linux x86_64 GNU, observed Mac ARM64/Intel LP64 or observed Windows x86_64 MSVC, without development-runtime, publisher or installer");
#[path = "../src/error.rs"] mod error;
#[path = "../src/protocol.rs"] mod protocol;
#[path = "../src/environment.rs"] mod environment;
#[path = "../src/installation.rs"] mod installation;
#[allow(dead_code)]
#[path = "../src/macos_build_profile.rs"] mod macos_build_profile;
#[path = "../src/macos_install_paths.rs"] mod macos_install_paths;
#[path = "../src/macos_install_record.rs"] mod macos_install_record;
#[path = "../src/macos_install_maintenance.rs"] mod macos_install_maintenance;
#[path = "../src/macos_install_transaction.rs"] mod macos_install_transaction;
#[path = "../src/macos_remove_protocol.rs"] mod macos_remove_protocol;
#[path = "../src/macos_remove_producer.rs"] mod macos_remove_producer;
#[path = "../src/macos_install_producer.rs"] mod macos_install_producer;
#[path = "../src/release_version_protocol.rs"] mod release_version_protocol;
#[path = "../src/candidate_evidence_protocol.rs"] mod candidate_evidence_protocol;
#[path = "../src/lifecycle_evidence_protocol.rs"] mod lifecycle_evidence_protocol;
#[path = "../src/environment_diagnostics_protocol.rs"] mod environment_diagnostics_protocol;
#[path = "../src/environment_diagnostics_owner.rs"] mod environment_diagnostics_owner;
#[path = "../src/offline_preflight_protocol.rs"] mod offline_preflight_protocol;
#[path = "../src/artifact_inspection_protocol.rs"] mod artifact_inspection_protocol;
#[path = "../src/offline_preflight_owner.rs"] mod offline_preflight_owner;
#[path = "../src/android_build_protocol.rs"] mod android_build_protocol;
#[path = "../src/android_build_owner.rs"] mod android_build_owner;
#[path = "../src/android_tool_sources.rs"] mod android_tool_sources;
#[path = "../src/android_registration_protocol.rs"] mod android_registration_protocol;
#[path = "../src/android_registration_app_protocol.rs"] mod android_registration_app_protocol;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "../src/android_shared_lease_macos.rs"] mod android_shared_lease_macos;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"), not(feature = "macos-android-registration-helper")))]
#[path = "../src/android_catalog_query_client.rs"] mod android_catalog_query_client;
#[path = "../src/project_recovery_protocol.rs"] mod project_recovery_protocol;
#[path = "../src/project_recovery_owner.rs"] mod project_recovery_owner;
#[path = "../src/android_toolchain.rs"] mod android_toolchain;
#[path = "../src/android_toolchain_catalog.rs"] mod android_toolchain_catalog;
#[path = "../src/android_toolchain_macos_policy.rs"] mod android_toolchain_macos_policy;
#[path = "../src/android_native_macos_profile.rs"] mod android_native_macos_profile;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/android_supplier_macos_source.rs"] mod android_supplier_macos_source;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/android_sdk_metadata_macos.rs"] mod android_sdk_metadata_macos;
#[cfg(any(test, all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/android_supplier_macos.rs"] mod android_supplier_macos;
#[path = "../src/ios_archive_protocol.rs"] mod ios_archive_protocol;
#[path = "../src/ios_archive_owner.rs"] mod ios_archive_owner;
#[path = "../src/ios_toolchain.rs"] mod ios_toolchain;
#[path = "../src/saved_command_owner.rs"] mod saved_command_owner;
#[path = "../src/runtime.rs"] mod runtime;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "../src/installed_runtime.rs"] mod installed_runtime;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "../src/installed_runtime_macos.rs"] mod installed_runtime;
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#[path = "../src/installed_runtime_windows.rs"] mod installed_runtime_windows;
#[path = "../src/supervisor.rs"] mod supervisor;
#[path = "../src/bridge.rs"] mod bridge;
#[path = "../src/document_lifetime.rs"] mod document_lifetime;
#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#[path = "../src/windows_startup.rs"] mod windows_startup;
#[path = "../src/edit_commands.rs"] mod edit_commands;
#[path = "../src/metadata_text_commands.rs"] mod metadata_text_commands;
#[path = "../src/metadata_images_commands.rs"] mod metadata_images_commands;
#[path = "../src/release_version_edit_commands.rs"] mod release_version_edit_commands;
#[path = "../src/github_commands.rs"] mod github_commands;
#[path = "../src/credential_assessment.rs"] mod credential_assessment;
#[path = "../src/credential_format.rs"] mod credential_format;
#[path = "../src/asset_commands.rs"] mod asset_commands;
#[path = "../src/asset_source.rs"] mod asset_source;
#[path = "../src/asset_session.rs"] mod asset_session;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "../src/vault_keyring_linux.rs"] mod vault_keyring_linux;
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
#[path = "../src/vault_keyring_macos.rs"] mod vault_keyring_macos;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/vault_format.rs"] mod vault_format;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/vault_crypto.rs"] mod vault_crypto;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[path = "../src/vault_store.rs"] mod vault_store;
#[path = "../src/edit_protocol.rs"] mod edit_protocol;
#[path = "../src/github_workflow_edit_protocol.rs"] mod github_workflow_edit_protocol;
#[path = "../src/project_initialization_edit_protocol.rs"] mod project_initialization_edit_protocol;
#[path = "../src/saved_text_recovery_protocol.rs"] mod saved_text_recovery_protocol;
#[path = "../src/metadata_text_edit_protocol.rs"] mod metadata_text_edit_protocol;
#[path = "../src/metadata_images_edit_protocol.rs"] mod metadata_images_edit_protocol;
#[path = "../src/release_version_edit_protocol.rs"] mod release_version_edit_protocol;
#[path = "../src/github_connection_protocol.rs"] mod github_connection_protocol;
#[path = "../src/github_connection_session.rs"] mod github_connection_session;
#[path = "../src/github_preflight_protocol.rs"] mod github_preflight_protocol;
#[path = "../src/github_preflight_session.rs"] mod github_preflight_session;
#[path = "../src/github_release_protocol.rs"] mod github_release_protocol;
#[path = "../src/github_release_session.rs"] mod github_release_session;
#[path = "../src/github_setup_protocol.rs"] mod github_setup_protocol;
#[path = "../src/github_setup_session.rs"] mod github_setup_session;
#[path = "../src/github_history_protocol.rs"] mod github_history_protocol;
#[path = "../src/github_history_session.rs"] mod github_history_session;
#[path = "../src/edit_owner.rs"] mod edit_owner;
#[path = "../src/shell.rs"] mod shell;
fn main() -> std::process::ExitCode { shell::installed_observation::main() }

#[test]
fn installation_inspection_closed_wire_contract() { installation::assert_installation_inspection_wire_contract(); }
