//! Four closed modes of the existing Cohort engine; no libtest/provider switch.
#[cfg(not(all(target_os = "macos", target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"), debug_assertions,
    feature = "installed-observation", mrk_wrapping_keychain_qualification,
    mrk_wrapping_keychain_qualification_native)))]
compile_error!("private helper requires the exact nonshipping native qualification handshake");
use std::sync::atomic::{AtomicBool, Ordering};
static ACTIVE: AtomicBool = AtomicBool::new(false);
// The library/observer has no definition; qualification libtest defines only refusal 0.
// This exported function reads only the one-shot state privately held by main.
#[unsafe(no_mangle)]
pub extern "C" fn mrk_wrapping_private_process_role() -> u32 {
    if ACTIVE.load(Ordering::Acquire) { 1 } else { 0 }
}
fn main() {
    let entry = std::time::Instant::now(); // Original45s includes mode parsing.
    use mrk_macos_installed_native::wrapping_keychain::private_fixture::{cohort_entry, CohortMode};
    let mut args = std::env::args_os();
    let _executable = args.next();
    let mode = match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("common") => CohortMode::Common,
        Some("stop-before-add") => CohortMode::StopBeforeAdd,
        Some("stop-before-lookup") => CohortMode::StopBeforeLookup,
        Some("creator-pair") => CohortMode::CreatorPair,
        _ => panic!("one fixed private cohort mode is required"),
    };
    assert!(args.next().is_none(), "private cohort accepts only its fixed mode");
    assert!(!ACTIVE.swap(true, Ordering::AcqRel), "private cohort is single-use");
    cohort_entry(entry, mode);
}
