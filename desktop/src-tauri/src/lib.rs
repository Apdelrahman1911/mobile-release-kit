//! Typed desktop services. Passive queries and finite configuration transactions
//! have separate original-resource owners; neither is a generic release runner.
#[cfg(all(feature = "development-runtime", not(debug_assertions)))]
compile_error!("development-runtime is forbidden when debug assertions are disabled");

pub mod error;
pub mod protocol;
mod environment;
mod release_version_protocol;
mod candidate_evidence_protocol;
mod environment_diagnostics_protocol;
mod environment_diagnostics_owner;
pub mod runtime;
// First protected-runtime inspection backend only. It is not connected to a
// launch path and cannot construct an executable qualified-runtime capability.
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod installed_runtime;
pub mod supervisor;
pub mod bridge;
mod document_lifetime;
mod edit_commands;
mod metadata_text_commands;
mod github_commands;
mod credential_assessment;
mod credential_format;
mod asset_commands;
mod asset_source;
mod asset_session;
pub mod edit_protocol;
pub mod github_workflow_edit_protocol;
pub mod metadata_text_edit_protocol;
pub mod github_connection_protocol;
mod github_connection_session;
pub mod edit_owner;
#[cfg(feature = "desktop-shell")]
pub mod shell;
