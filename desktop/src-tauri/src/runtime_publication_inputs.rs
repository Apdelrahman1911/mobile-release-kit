// Exact fixed anchors/resource roster shared by application and publisher DATA.
pub const CORE_VERSION: &str = "0.3.0";
pub const COMPILED_TARGET: &str = env!("MRK_COMPILED_TARGET");
pub(crate) const GITHUB_CA_LIMIT: u64 = 512 * 1024;
#[cfg(windows)]
const PYTHON_RESOURCE: &str = "python/python.exe";
#[cfg(not(windows))]
const PYTHON_RESOURCE: &str = "python/bin/python3";

// Canonical fixed inventory shared by packaging and installed-data validation.
// Presence is not runtime, TLS, XML, or native-custody qualification.
pub(crate) const REQUIRED_RUNTIME_RESOURCES: [&str; 15] = [
    "android_build_bootstrap.py", "artifact_inspection_bootstrap.py", "config_edit_bootstrap.py", "core.zip",
    "engine_bootstrap.py", "environment_bootstrap.py", "github-ca.pem",
    "github_connection_bootstrap.py", "github_preflight_bootstrap.py", "github_release_bootstrap.py", "github_setup_bootstrap.py", "ios_archive_bootstrap.py",
    "offline_preflight_bootstrap.py", "project_recovery_bootstrap.py", PYTHON_RESOURCE,
];

