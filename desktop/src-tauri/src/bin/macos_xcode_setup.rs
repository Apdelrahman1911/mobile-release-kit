//! Non-activating typecheck boundary. No argv enters provisional setup work.
//! Replace this refusal ONLY after whole original Parent/child/recovery review.
#![allow(dead_code)]
#[cfg(any(
    feature = "desktop-shell",
    feature = "macos-installed-installer",
    feature = "macos-installed-remover",
    feature = "macos-android-registration-helper",
    feature = "macos-package-producer",
    feature = "macos-remove-producer",
    feature = "macos-installed-observation",
    feature = "macos-installed-app-absence-fixture"
))]
compile_error!("setup executable requires its exclusive graph");
// Native setup implementations are feature-scoped in the existing Darwin ABI
// crate. Keep desktop unsafe_code=forbid; do not import raw FFI owners here.
fn main() {
    // No privileged operations, native calls, path input or partial success.
    std::process::exit(78);
}
