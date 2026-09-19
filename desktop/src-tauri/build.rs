use std::env;

fn anchor(name: &str) {
    println!("cargo:rerun-if-env-changed={name}");
    if let Ok(value) = env::var(name) {
        if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            panic!("{name} must be an explicitly reviewed lowercase SHA-256 digest");
        }
        println!("cargo:rustc-env={name}={value}");
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEVELOPMENT_RUNTIME");
    println!("cargo:rerun-if-env-changed=PROFILE");
    if env::var_os("CARGO_FEATURE_DEVELOPMENT_RUNTIME").is_some()
        && env::var("PROFILE").unwrap_or_default() != "debug" {
        panic!("development-runtime is permitted only in the debug Cargo profile");
    }
    // These are explicit packaging-plan inputs. Never hash an adjacent manifest
    // here and thereby silently promote unreviewed runtime bytes to authority.
    anchor("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256");
    anchor("MRK_BUNDLED_PROTOCOL_SHA256");
    // The two synthetic TLS manifests are explicit inputs to the SAME libtest
    // artifact. Neither is discovered or promoted to authority by this build.
    anchor("MRK_GITHUB_TLS_INPUTS_SHA256");
    anchor("MRK_GITHUB_TLS_DEADLINE_INPUTS_SHA256");
    // A closed hosted diagnostics fixture input, never runtime qualification.
    anchor("MRK_ENVIRONMENT_NATIVE_INPUTS_SHA256");
    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=MRK_COMPILED_TARGET={target}");
    #[cfg(feature = "desktop-shell")]
    {
        const COMMANDS: &[&str] = &[
            "app_info", "choose_project", "project_snapshot", "catalog",
            "environment_requirements", "release_version_observe",
            "artifact_evidence_choose", "artifact_evidence_status", "artifact_evidence_observe", "artifact_evidence_cancel",
            "start_environment_diagnostics", "environment_diagnostics_status", "cancel_environment_diagnostics",
            "prepare_offline_preflight", "start_offline_preflight", "offline_preflight_status", "cancel_offline_preflight",
            "validate_config", "suggest_config", "preview_config", "propose_github_setup",
            "open_config_edit", "prepare_config_edit", "apply_config_edit",
            "close_config_edit", "config_edit_status",
            "github_workflow_edit_open", "github_workflow_edit_prepare", "github_workflow_edit_apply",
            "github_workflow_edit_close", "github_workflow_edit_status",
            "metadata_text_observe", "metadata_text_validate", "metadata_text_edit_open", "metadata_text_edit_prepare",
            "metadata_text_edit_apply", "metadata_text_edit_close", "metadata_text_edit_status",
            "github_connection_status", "github_connection_connect_token", "github_connection_refresh", "github_connection_disconnect",
            "vault_status", "vault_open", "asset_context", "asset_choose", "credential_prepare",
            "vault_prepare_delete", "vault_commit", "vault_bind", "vault_discard", "vault_lock",
        ];
        let attributes = tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
        if let Err(error) = tauri_build::try_build(attributes) {
            panic!("Tauri context generation failed: {error}");
        }
    }
}
