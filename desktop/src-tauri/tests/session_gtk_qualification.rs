//! Actual process main; no libtest worker and no native execution admission.
#![forbid(unsafe_code)]
#[cfg(not(all(test, debug_assertions, feature = "desktop-shell", feature = "development-runtime",
    target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
compile_error!("SG1 requires debug test + desktop-shell + development-runtime, Linux x86_64 GNU");
#[path = "../src/error.rs"] mod error;
#[path = "../src/protocol.rs"] mod protocol;
#[path = "../src/environment.rs"] mod environment;
#[path = "../src/environment_diagnostics_protocol.rs"] mod environment_diagnostics_protocol;
#[path = "../src/environment_diagnostics_owner.rs"] mod environment_diagnostics_owner;
#[path = "../src/runtime.rs"] mod runtime;
#[path = "../src/installed_runtime.rs"] mod installed_runtime;
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
#[path = "../src/edit_protocol.rs"] mod edit_protocol;
#[path = "../src/github_workflow_edit_protocol.rs"] mod github_workflow_edit_protocol;
#[path = "../src/metadata_text_edit_protocol.rs"] mod metadata_text_edit_protocol;
#[path = "../src/github_connection_protocol.rs"] mod github_connection_protocol;
#[path = "../src/github_connection_session.rs"] mod github_connection_session;
#[path = "../src/edit_owner.rs"] mod edit_owner;
#[path = "../src/shell.rs"] mod shell;
fn main() -> std::process::ExitCode { shell::qualification::main() }
