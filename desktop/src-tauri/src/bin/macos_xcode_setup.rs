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
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_apple.rs"]
mod macos_xcode_apple;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_carrier.rs"]
mod macos_xcode_carrier;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_copy.rs"]
mod macos_xcode_copy;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_parent.rs"]
mod macos_xcode_parent;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_self.rs"]
mod macos_xcode_self;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_setup.rs"]
mod macos_xcode_setup;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_source.rs"]
mod macos_xcode_source;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
#[path = "../macos_xcode_tree.rs"]
mod macos_xcode_tree;
fn main() {
    // No privileged operations, native calls, path input or partial success.
    std::process::exit(78);
}
