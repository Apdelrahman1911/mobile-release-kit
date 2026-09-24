//! Actual process main, not a libtest worker or a shipping automation switch.
#![forbid(unsafe_code)]
#[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
    not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
    any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_arch = "aarch64", feature = "macos-installed-observation", not(feature = "macos-installed-installer"))))))]
compile_error!("installed-shell observation requires debug test + desktop-shell + custom-protocol on Linux x86_64 GNU or observed Mac ARM64, without development-runtime, publisher or installer");
#[path = "../src/error.rs"] mod error;
#[path = "../src/protocol.rs"] mod protocol;
#[path = "../src/environment.rs"] mod environment;
#[path = "../src/release_version_protocol.rs"] mod release_version_protocol;
#[path = "../src/candidate_evidence_protocol.rs"] mod candidate_evidence_protocol;
#[path = "../src/environment_diagnostics_protocol.rs"] mod environment_diagnostics_protocol;
#[path = "../src/environment_diagnostics_owner.rs"] mod environment_diagnostics_owner;
#[path = "../src/offline_preflight_protocol.rs"] mod offline_preflight_protocol;
#[path = "../src/offline_preflight_owner.rs"] mod offline_preflight_owner;
#[path = "../src/android_build_protocol.rs"] mod android_build_protocol;
#[path = "../src/android_build_owner.rs"] mod android_build_owner;
#[path = "../src/android_toolchain.rs"] mod android_toolchain;
#[path = "../src/saved_command_owner.rs"] mod saved_command_owner;
#[path = "../src/runtime.rs"] mod runtime;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "../src/installed_runtime.rs"] mod installed_runtime;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "../src/installed_runtime_macos.rs"] mod installed_runtime;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "../src/macos_install_paths.rs"] mod macos_install_paths;
#[path = "../src/supervisor.rs"] mod supervisor;
#[path = "../src/bridge.rs"] mod bridge;
#[path = "../src/document_lifetime.rs"] mod document_lifetime;
#[path = "../src/edit_commands.rs"] mod edit_commands;
#[path = "../src/metadata_text_commands.rs"] mod metadata_text_commands;
#[path = "../src/github_commands.rs"] mod github_commands;
#[path = "../src/credential_assessment.rs"] mod credential_assessment;
#[path = "../src/credential_format.rs"] mod credential_format;
#[path = "../src/asset_commands.rs"] mod asset_commands;
#[path = "../src/asset_source.rs"] mod asset_source;
#[path = "../src/asset_session.rs"] mod asset_session;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[path = "../src/vault_keyring_linux.rs"] mod vault_keyring_linux;
#[path = "../src/edit_protocol.rs"] mod edit_protocol;
#[path = "../src/github_workflow_edit_protocol.rs"] mod github_workflow_edit_protocol;
#[path = "../src/metadata_text_edit_protocol.rs"] mod metadata_text_edit_protocol;
#[path = "../src/github_connection_protocol.rs"] mod github_connection_protocol;
#[path = "../src/github_connection_session.rs"] mod github_connection_session;
#[path = "../src/edit_owner.rs"] mod edit_owner;
#[path = "../src/shell.rs"] mod shell;
fn main() -> std::process::ExitCode { shell::installed_observation::main() }
