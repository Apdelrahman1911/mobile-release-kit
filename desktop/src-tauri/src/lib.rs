//! Typed desktop services. Passive queries and finite configuration transactions
//! have separate original-resource owners; neither is a generic release runner.
// The shipping Mac graph includes concrete, weakly linked Document/Edit/native
// owners. Allow its finite Send/Sync traversal without changing those traits.
#![recursion_limit = "256"]
// Fixed nonshipping cuts must never unify with another executable/image role.
// The ordinary Installer build selects none; no environment/argument enables one.
#[cfg(all(any(
    feature = "macos-installed-restore-app-write-fixture",
    feature = "macos-installed-restore-own-attempt-fixture",
    feature = "macos-installed-restore-stage-move-fixture"
), any(
    not(feature = "macos-installed-installer"),
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))),
    feature = "desktop-shell",
    feature = "custom-protocol",
    feature = "development-runtime",
    feature = "ubuntu-runtime-publisher",
    feature = "windows-runtime-publisher",
    feature = "macos-installed-remover",
    feature = "macos-installed-installer-fixture",
    feature = "macos-installed-app-absence-fixture",
    feature = "macos-installed-removal-abrupt-fixture",
    feature = "macos-installed-removal-observer",
    feature = "macos-installed-observation",
    feature = "windows-installed-observation",
    feature = "macos-installed-desktop-image",
    feature = "macos-installed-resident-image",
    feature = "macos-android-registration-helper",
    feature = "macos-package-producer",
    feature = "macos-remove-producer",
    feature = "macos-remove-observer-producer"
)))]
compile_error!("Restore cut fixture requires only its isolated native Installer graph");
#[cfg(any(
    all(feature = "macos-installed-restore-app-write-fixture", any(feature = "macos-installed-restore-own-attempt-fixture", feature = "macos-installed-restore-stage-move-fixture")),
    all(feature = "macos-installed-restore-own-attempt-fixture", feature = "macos-installed-restore-stage-move-fixture")
))]
compile_error!("exactly one fixed Restore cut may be compiled");
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
#[cfg(all(any(feature = "macos-package-producer", feature = "macos-remove-producer"), any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))),
    feature = "desktop-shell", feature = "custom-protocol", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-installer-fixture",
    feature = "macos-android-registration-helper", feature = "macos-installed-resident-image",
    feature = "macos-installed-desktop-image", feature = "macos-installed-observation",
    feature = "windows-installed-observation", feature = "macos-installed-remover",
    all(feature = "macos-package-producer", feature = "macos-remove-producer")
)))]
compile_error!("package producer requires its isolated nonshipping LP64 Mac example graph");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::PACKAGE_PRODUCER_SIGNING_BUILD
    == cfg!(any(feature = "macos-package-producer", feature = "macos-remove-producer")),
    "package signing and ordinary app/Installer/helper native roles must not unify");

// The readable installed coordinator is a separate one-shot privileged role.
// No shell, service/helper, observer or private-key-signing graph may unify it.
#[cfg(all(feature = "macos-installed-remover", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))),
    feature = "desktop-shell", feature = "custom-protocol", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-installer-fixture",
    feature = "macos-android-registration-helper", feature = "macos-installed-resident-image",
    feature = "macos-installed-desktop-image", feature = "macos-installed-observation",
    feature = "windows-installed-observation", feature = "macos-package-producer", feature = "macos-remove-producer"
)))]
compile_error!("installed remover requires its isolated nonsigning LP64 Mac role");

#[cfg(all(feature = "macos-android-registration-helper", any(
    not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))), feature = "desktop-shell", feature = "custom-protocol",
    feature = "development-runtime", feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher",
    feature = "macos-installed-installer", feature = "macos-installed-observation", feature = "windows-installed-observation"
)))]
compile_error!("Android registration helper requires its isolated headless LP64 Mac ARM64/Intel Cargo role");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(mrk_macos_installed_native::ANDROID_REGISTRATION_HELPER_BUILD == cfg!(feature = "macos-android-registration-helper"),
    "ordinary app and separate Android helper Cargo roles must never feature-unify");
#[cfg(all(target_os = "macos", feature = "desktop-shell", not(all(target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")))))]
compile_error!("the installed Mac desktop requires LP64 ARM64 or Intel macOS 26");
#[cfg(all(feature = "windows-runtime-publisher", any(
    not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    feature = "desktop-shell", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "macos-installed-installer",
    feature = "macos-installed-observation")))]
compile_error!("windows-runtime-publisher requires the isolated Windows x64 MSVC headless producer profile");
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
const _: () = assert!(!mrk_macos_installed_native::VAULT_HELPER_BUILD, "the app must not unify the separate vault-helper Cargo role");

// Shared unchanged DATA modules remain at the same crate paths for both graphs.
pub mod error;
mod bounded_json_seed;
#[allow(dead_code)]
mod macos_build_profile;
// Pure fixed-layout DATA is also used by portable contract tests.
pub mod macos_install_paths;
pub mod macos_install_record;
pub mod macos_existing_app_metadata;
pub mod macos_persistent_identity;
pub mod macos_store_runtime;
pub mod macos_applications_launcher;
pub mod macos_install_maintenance;
pub mod macos_install_transaction;
pub mod macos_fresh_recovery;
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

// Only standalone packaging roles select the bounded DATA closure. All application,
// helper, unsupported-target and mixed-role graphs retain their original declarations.
#[cfg(all(
    target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    any(feature = "macos-installed-installer", feature = "macos-installed-remover", feature = "macos-installed-app-absence-fixture", feature = "macos-package-producer", feature = "macos-remove-producer"),
    not(any(feature = "desktop-shell", feature = "custom-protocol", feature = "development-runtime", feature = "installed-cli", feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher", feature = "macos-xcode-setup", feature = "macos-android-registration-helper", feature = "macos-installed-resident-image", feature = "macos-installed-desktop-image", feature = "macos-installed-observation", feature = "windows-installed-observation"))
))]
include!("lib_macos_packaging.rs");
#[cfg(not(all(
    target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    any(feature = "macos-installed-installer", feature = "macos-installed-remover", feature = "macos-installed-app-absence-fixture", feature = "macos-package-producer", feature = "macos-remove-producer"),
    not(any(feature = "desktop-shell", feature = "custom-protocol", feature = "development-runtime", feature = "installed-cli", feature = "ubuntu-runtime-publisher", feature = "windows-runtime-publisher", feature = "macos-xcode-setup", feature = "macos-android-registration-helper", feature = "macos-installed-resident-image", feature = "macos-installed-desktop-image", feature = "macos-installed-observation", feature = "windows-installed-observation"))
)))]
include!("lib_application.rs");
