//! Separate, transport-only installed CLI executable. This entry does not link
//! DesktopBridge, native helpers, a WebView, or the release execution owners.
#![forbid(unsafe_code)]

mod service_protocol;
#[path="service_version_reserve_protocol.rs"]
mod service_version_reserve_protocol;
#[path="service_version_reserve_requests.rs"]
mod service_version_reserve_requests;
mod service_git_protocol;
mod service_git_commit_protocol;
mod service_git_repository_protocol;
mod service_git_requests;
mod service_setup_guidance;
mod service_android_tools;
mod service_request_catalogue;
mod service_repository_summary;
mod agent_identity_requests;
mod agent_local_checks;
mod agent_android_build;
mod agent_build_requests;
mod agent_ios_archive;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod application_state_store;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod application_service;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod installed_cli_ipc;
mod installed_cli;

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(installed_cli::run(std::env::args_os().skip(1)))
}
