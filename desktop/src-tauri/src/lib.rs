//! Typed desktop services. Passive queries and finite configuration transactions
//! have separate original-resource owners; neither is a generic release runner.
#[cfg(any(mrk_wrapping_keychain_qualification, mrk_wrapping_keychain_qualification_native))]
compile_error!("process-only wrapping qualification is forbidden in the Desktop application");
#[cfg(all(feature = "development-runtime", not(debug_assertions)))]
compile_error!("development-runtime is forbidden when debug assertions are disabled");
#[cfg(all(feature = "desktop-shell", not(feature = "development-runtime"), not(feature = "custom-protocol")))]
compile_error!("normal desktop-shell builds require custom-protocol for the embedded production frontend");

#[cfg(all(feature = "macos-installed-desktop-image", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))),
    not(feature = "desktop-shell"), not(feature = "custom-protocol"), test,
    feature = "development-runtime", feature = "ubuntu-runtime-publisher",
    feature = "windows-runtime-publisher", feature = "macos-installed-installer",
    feature = "macos-installed-installer-fixture", feature = "macos-android-registration-helper",
    feature = "macos-installed-observation", feature = "windows-installed-observation"
)))]
compile_error!("ordinary installed image requires its isolated LP64 Mac ARM64/Intel shell graph");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::DESKTOP_IMAGE_BUILD
    == cfg!(feature = "macos-installed-desktop-image"),
    "ordinary image and normal-bin/helper/observer native roles must not unify");

#[cfg(all(feature = "macos-installed-resident-image", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))), not(feature = "macos-android-registration-helper"),
    feature = "desktop-shell", feature = "custom-protocol", feature = "macos-installed-desktop-image",
    feature = "development-runtime", feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-installer-fixture",
    feature = "macos-installed-observation", feature = "windows-installed-observation", test
)))]
compile_error!("resident image requires its isolated headless LP64 Mac ARM64/Intel graph");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::RESIDENT_IMAGE_BUILD
    == cfg!(feature = "macos-installed-resident-image"));

// A selected packaging example may reach a private key; ordinary apps,
// Installers, helpers and qualification images must never feature-unify it.
#[cfg(all(feature = "macos-package-producer", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))),
    feature = "desktop-shell", feature = "custom-protocol", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-installer-fixture",
    feature = "macos-android-registration-helper", feature = "macos-installed-resident-image",
    feature = "macos-installed-desktop-image", feature = "macos-installed-observation",
    feature = "windows-installed-observation"
)))]
compile_error!("package producer requires its isolated nonshipping LP64 Mac example graph");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::PACKAGE_PRODUCER_SIGNING_BUILD
    == cfg!(feature = "macos-package-producer"),
    "package signing and ordinary app/Installer/helper native roles must not unify");

pub mod error;
pub mod protocol;
mod environment;
mod installation;
mod release_version_protocol;
mod candidate_evidence_protocol;
mod lifecycle_evidence_protocol;
mod environment_diagnostics_protocol;
mod environment_diagnostics_owner;
mod offline_preflight_protocol;
mod offline_preflight_owner;
mod android_build_protocol;
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
#[cfg(all(feature = "macos-android-registration-helper", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))), feature = "desktop-shell", feature = "custom-protocol",
    feature = "development-runtime", feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-observation", feature = "windows-installed-observation"
)))]
compile_error!("Android registration helper requires its isolated headless LP64 Mac ARM64/Intel Cargo role");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::ANDROID_REGISTRATION_HELPER_BUILD == cfg!(feature = "macos-android-registration-helper"),
    "ordinary app and separate Android helper Cargo roles must never feature-unify");
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
#[allow(dead_code)]
mod macos_build_profile;
// Pure fixed-layout DATA is also used by portable contract tests.
pub mod macos_install_paths;
pub mod macos_install_record;
pub mod macos_install_maintenance;
pub mod macos_install_transaction;
// Removal comparison DATA never relaxes installed State-v2 or grants live effects.
pub mod macos_remove_record;
// Closed removal wire DATA, not peer identity or a filesystem capability.
pub mod macos_remove_protocol;
// Producer comparison DATA alone is not signature/purpose/installation authority.
pub mod macos_install_producer;
// Separate remove-purpose DATA; no install schema or lifecycle authority.
pub mod macos_remove_producer;
// Exercise the ACTUAL build-only SOURCE parser in the existing portable DATA
// test binary, not a duplicate configuration implementation or a Mac mock.
#[cfg(test)]
#[path = "../../native/macos-installed-native/build_support/producer_selection.rs"]
mod macos_install_producer_selection_data;
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
#[cfg(all(target_os = "macos", feature = "desktop-shell", not(all(target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")))))]
compile_error!("the installed Mac desktop requires LP64 ARM64 or Intel macOS 26");
#[cfg(all(feature = "ubuntu-runtime-publisher", target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub mod runtime_publication;
#[cfg(all(feature = "windows-runtime-publisher", any(
    not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    feature = "desktop-shell", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "macos-installed-installer",
    feature = "macos-installed-observation")))]
compile_error!("windows-runtime-publisher requires the isolated Windows x64 MSVC headless producer profile");
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
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(!mrk_macos_installed_native::VAULT_HELPER_BUILD, "the app must not unify the separate vault-helper Cargo role");
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod vault_format;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod vault_crypto;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod vault_store;
pub mod edit_protocol;
pub mod github_workflow_edit_protocol;
pub mod metadata_text_edit_protocol;
mod saved_text_recovery_protocol;
mod metadata_images_edit_protocol;
pub mod release_version_edit_protocol;
pub mod github_connection_protocol;
mod github_connection_session;
mod github_preflight_protocol;
mod github_preflight_session;
mod github_release_protocol;
mod github_release_session;
pub mod edit_owner;
#[cfg(feature = "desktop-shell")]
pub mod shell;
