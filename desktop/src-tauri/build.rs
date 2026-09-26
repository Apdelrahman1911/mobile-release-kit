use std::env;
use std::{fs, path::Path};
use sha2::{Digest, Sha256};

const ANDROID_INPUT: &str = "MRK_ANDROID_OS_CONTRACT_INPUT";
const ANDROID_SELECTORS: [&str; 3] = [
    "MRK_ANDROID_TOOL_INSTANCE", "MRK_ANDROID_TOOL_MANIFEST_SHA256", "MRK_ANDROID_OS_CONTRACT_SHA256",
];

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
fn android_input(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::{fs::{File, Metadata}, io::{self, Read}, os::unix::fs::MetadataExt, path::Component};
    use rustix::fs::{open, openat, Mode, OFlags};
    fn refused() -> io::Error { io::Error::other("Android compile input custody differs") }
    fn identity(m: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
        (m.dev(), m.ino(), m.mode(), m.uid(), m.gid(), m.nlink(), m.size(),
            m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
    }
    fn directory(m: &Metadata) -> (u64, u64, u32, u32, u32) {
        (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
    }
    if !path.is_absolute() { return Err(refused()); }
    let components: Vec<_> = path.components().collect();
    if components.len() < 3 || !matches!(components[0], Component::RootDir)
        || components[1..].iter().any(|c| !matches!(c, Component::Normal(_))) { return Err(refused()); }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut parent = File::from(open("/", flags | OFlags::DIRECTORY, Mode::empty())?);
    let mut current = std::path::PathBuf::from("/");
    let mut parents = vec![(current.clone(), directory(&parent.metadata()?))];
    for component in &components[1..components.len() - 1] {
        let Component::Normal(name) = component else { return Err(refused()); };
        let child = File::from(openat(&parent, *name, flags | OFlags::DIRECTORY, Mode::empty())?);
        current.push(name);
        let held = child.metadata()?;
        if !held.is_dir() || directory(&held) != directory(&fs::symlink_metadata(&current)?) {
            return Err(refused());
        }
        parents.push((current.clone(), directory(&held)));
        parent = child;
    }
    let Component::Normal(name) = components[components.len() - 1] else { return Err(refused()); };
    let mut input = File::from(openat(&parent, name, flags, Mode::empty())?);
    let before = input.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.size() == 0 || before.size() > 1024 * 1024
        || before.mode() & 0o7222 != 0 || identity(&before) != identity(&fs::symlink_metadata(path)?) {
        return Err(refused());
    }
    let mut raw = Vec::with_capacity(before.size() as usize);
    (&mut input).take(before.size() + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 != before.size() || identity(&input.metadata()?) != identity(&before)
        || identity(&fs::symlink_metadata(path)?) != identity(&before) { return Err(refused()); }
    for (path, original) in parents {
        if directory(&fs::symlink_metadata(path)?) != original { return Err(refused()); }
    }
    drop(input);
    if identity(&fs::symlink_metadata(path)?) != identity(&before) { return Err(refused()); }
    Ok(raw)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
fn android_input(_path: &Path) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::other("Android same-VM input requires the admitted Linux compiler host"))
}

fn android_compile_data(target: &str) {
    for name in ANDROID_SELECTORS.into_iter().chain([ANDROID_INPUT]) {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let selected: Vec<_> = ANDROID_SELECTORS.iter().map(|name| env::var_os(name)).collect();
    let input = env::var_os(ANDROID_INPUT);
    let out = std::path::PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR required"));
    let declaration = out.join("mrk-android-compile-data.rs");
    if selected.iter().all(Option::is_none) && input.is_none() {
        fs::write(declaration, "const OS_CONTRACT_BYTES: Option<&[u8]> = None;\n")
            .expect("Android absent-profile declaration write failed");
        return;
    }
    if target != "x86_64-unknown-linux-gnu" || selected.iter().any(Option::is_none) || input.is_none() {
        panic!("Android same-VM compile requires the complete explicit tuple on its one target");
    }
    let values: Vec<_> = selected.iter().map(|value| value.as_ref().and_then(|v| v.to_str())
        .expect("Android compile selector must be UTF-8")).collect();
    let instance = values[0];
    if instance.is_empty() || instance.len() > 64
        || !instance.bytes().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || !instance.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
        || !digest(values[1]) || !digest(values[2]) { panic!("Android compile selector shape differs"); }
    let path = input.as_ref().and_then(|v| v.to_str()).expect("Android input path must be UTF-8");
    if path.len() > 4096 || path.bytes().any(|c| c < 32 || c == 127) { panic!("Android input path differs"); }
    let raw = android_input(Path::new(path)).expect("Android explicit compile input refused");
    let actual: String = Sha256::digest(&raw).iter().map(|b| format!("{b:02x}")).collect();
    if actual != values[2] { panic!("Android explicit compile input does not match its admitted anchor"); }
    println!("cargo:rerun-if-changed={path}");
    fs::write(out.join("mrk-android-os-contract.json"), &raw).expect("Android bounded compile DATA write failed");
    fs::write(declaration, concat!("const OS_CONTRACT_BYTES: Option<&[u8]> = ",
        "Some(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/mrk-android-os-contract.json\")));\n"))
        .expect("Android compile DATA declaration write failed");
    for (name, value) in ANDROID_SELECTORS.iter().zip(values) { println!("cargo:rustc-env={name}={value}"); }
}

fn anchor(name: &str) {
    println!("cargo:rerun-if-env-changed={name}");
    if let Ok(value) = env::var(name) {
        if !digest(&value) {
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
    anchor("MRK_MACOS_INSTALL_INVENTORY_SHA256");
    println!("cargo:rerun-if-env-changed=MRK_MACOS_INSTALL_SOURCE_COMMIT");
    match env::var("MRK_MACOS_INSTALL_SOURCE_COMMIT") {
        Ok(value) => {
            if value.len() != 40 || !value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                panic!("MRK_MACOS_INSTALL_SOURCE_COMMIT must be an explicit lowercase source commit");
            }
            println!("cargo:rustc-env=MRK_MACOS_INSTALL_SOURCE_COMMIT={value}");
        }
        Err(_) if cfg!(feature = "macos-installed-installer") => panic!("Installer builds require the explicit source commit"),
        Err(_) => {},
    }
    if cfg!(feature = "macos-installed-installer-fixture") && cfg!(feature = "desktop-shell") {
        panic!("The fixed Installer fixture cannot be combined with the application shell");
    }
    // The two synthetic TLS manifests are explicit inputs to the SAME libtest
    // artifact. Neither is discovered or promoted to authority by this build.
    anchor("MRK_GITHUB_TLS_INPUTS_SHA256");
    anchor("MRK_GITHUB_TLS_DEADLINE_INPUTS_SHA256");
    // A closed hosted diagnostics fixture input, never runtime qualification.
    anchor("MRK_ENVIRONMENT_NATIVE_INPUTS_SHA256");
    let target = env::var("TARGET").unwrap_or_default();
    android_compile_data(&target);
    println!("cargo:rustc-env=MRK_COMPILED_TARGET={target}");
    #[cfg(feature = "desktop-shell")]
    {
        const COMMANDS: &[&str] = &[
            "app_info", "choose_project", "choose_project_path", "project_snapshot", "catalog",
            "environment_requirements", "release_version_observe",
            "artifact_evidence_choose", "artifact_evidence_status", "artifact_evidence_observe", "artifact_evidence_cancel",
            "release_evidence_choose", "release_evidence_status", "release_evidence_observe", "release_evidence_cancel",
            "start_environment_diagnostics", "environment_diagnostics_status", "cancel_environment_diagnostics",
            "prepare_offline_preflight", "start_offline_preflight", "offline_preflight_status", "cancel_offline_preflight",
            "prepare_android_build", "start_android_build", "android_build_status", "cancel_android_build",
            "validate_config", "suggest_config", "preview_config", "propose_github_setup",
            "open_config_edit", "prepare_config_edit", "apply_config_edit",
            "close_config_edit", "config_edit_status",
            "github_workflow_edit_open", "github_workflow_edit_prepare", "github_workflow_edit_apply",
            "github_workflow_edit_close", "github_workflow_edit_status",
            "metadata_text_observe", "metadata_text_validate", "metadata_text_edit_open", "metadata_text_edit_prepare",
            "metadata_text_edit_apply", "metadata_text_edit_close", "metadata_text_edit_status",
            "release_version_edit_open", "release_version_edit_prepare", "release_version_edit_apply",
            "release_version_edit_close", "release_version_edit_status",
            "github_connection_status", "github_connection_connect_token", "github_connection_refresh", "github_connection_disconnect",
            "vault_status", "vault_open", "asset_context", "asset_choose", "credential_prepare",
            "vault_prepare_delete", "vault_commit", "vault_bind", "vault_discard", "vault_lock",
        ];
        let attributes = tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
        if let Err(error) = tauri_build::try_build(attributes) {
            panic!("Tauri context generation failed: {error}");
        }
        // tauri-build 2.6.3 -> tauri-winres 0.3.6 -> embed-resource 3.0.11
        // generates OUT_DIR/resource.lib for MSVC but links only Cargo bins.
        // Reuse that same resource for the harness=false observation test.
        if target == "x86_64-pc-windows-msvc" && cfg!(feature = "windows-installed-observation") {
            let out_dir = env::var_os("OUT_DIR").expect("Windows observation resource linking requires OUT_DIR");
            let resource = std::path::PathBuf::from(out_dir).join("resource.lib");
            println!("cargo:rustc-link-arg-tests={}", resource.display());
        }
    }
}
