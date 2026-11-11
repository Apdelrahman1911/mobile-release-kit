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

