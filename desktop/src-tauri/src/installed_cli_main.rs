//! Same signed installed CLI. Default commands remain the closed transport
//! client. Only explicit serve-history enters the original shared Host library;
//! it never creates a WebView, document, release engine or background daemon.
#![forbid(unsafe_code)]
// Match the library's expansion budget for the shared finite capability JSON.
// This is a compiler setting, not an IPC, output, or execution-limit change.
#![recursion_limit = "256"]

mod service_protocol;
mod service_upload_key_protocol;
mod service_upload_key_requests;
mod service_configuration_protocol;
mod service_configuration_requests;
#[path="service_version_reserve_protocol.rs"]
mod service_version_reserve_protocol;
#[path="service_store_protocol.rs"]
mod service_store_protocol;
#[path="service_store_requests.rs"]
mod service_store_requests;
#[path="service_version_reserve_requests.rs"]
mod service_version_reserve_requests;
#[path="service_play_cleanup_protocol.rs"]
mod service_play_cleanup_protocol;
#[path="service_play_cleanup_requests.rs"]
mod service_play_cleanup_requests;
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
    let mut args = std::env::args_os().skip(1).peekable();
    let code = if args.peek().is_some_and(|word| word == "serve-history") {
        args.next();
        mobile_release_desktop::run_history_service(args)
    } else {
        installed_cli::run(args)
    };
    std::process::ExitCode::from(code)
}
