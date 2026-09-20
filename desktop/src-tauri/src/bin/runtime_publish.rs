//! Fixed privileged package helper. It never launches the application or Python.
#![forbid(unsafe_code)]

#[cfg(any(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")),
    feature = "desktop-shell", feature = "development-runtime"))]
compile_error!("mrk-runtime-publish requires the Linux x86_64 GNU headless publisher build without development-runtime");

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu",
    not(feature = "desktop-shell"), not(feature = "development-runtime")))]
fn main() -> std::process::ExitCode {
    match mobile_release_desktop::runtime_publication::publish_fixed() {
        Ok(()) => {
            println!("Immutable runtime payload published. Product execution remains unqualified.");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Runtime publication refused: {error}. Partial or published objects were not removed; do not repair or retry automatically.");
            std::process::ExitCode::FAILURE
        }
    }
}
