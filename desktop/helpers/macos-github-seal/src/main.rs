//! One request, one canonical sealed box, one process. No credential, path,
//! endpoint, algorithm, RNG or reusable-service selector is accepted.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod protocol;

#[cfg(all(target_os = "macos", target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")))]
#[allow(unsafe_code)]
mod macos;

// A non-Mac test binary may exercise only the pure framing tests. This is not
// an alternate executable helper or a crypto implementation for another OS.
#[cfg(all(not(test), not(all(target_os = "macos", target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")))))]
compile_error!("mrk-github-seal requires a reviewed 64-bit Apple Darwin target");

#[cfg(all(target_os = "macos", target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64")))]
fn main() -> std::process::ExitCode {
    // No error or secret is formatted. A nonzero original is never ciphertext
    // acceptance; the parent owns the actual exit, pipe joins and source POST.
    match macos::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(all(target_os = "macos", target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"))))]
fn main() {}
