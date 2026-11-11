//! Fixed privileged package helper; no application, Python or child startup.
#![forbid(unsafe_code)]

#[cfg(any(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")),
    feature = "desktop-shell", feature = "development-runtime",
    feature = "ubuntu-runtime-publisher", feature = "macos-installed-installer",
    feature = "macos-installed-observation"))]
compile_error!("mrk-windows-runtime-publish requires the isolated Windows x64 MSVC headless publisher build");

#[cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
fn main() -> std::process::ExitCode {
    // No sink lock or receipt write can turn an incomplete owner into success.
    // The original process return is observed by the privileged installer.
    match mobile_release_desktop::runtime_publication_windows::publish_fixed() {
        Ok(lines) => {
            // Bounded closed DATA from the actual settled original, not a new
            // observer. The coordinator admits it only with original exit0.
            let mut output = std::io::stdout().lock();
            if lines.len() < 4096 && std::io::Write::write_all(&mut output, lines.as_bytes()).is_ok()
                && std::io::Write::flush(&mut output).is_ok() {
                std::process::ExitCode::SUCCESS
            } else { std::process::ExitCode::FAILURE }
        },
        Err(mobile_release_desktop::runtime_publication_windows::PublicationError::OccupiedTargetSettled) =>
            std::process::ExitCode::from(2),
        Err(error) => {
            if let Some(line) = error.diagnostic_line() {
                // Closed DATA only. A failed/hung sink never supplies native finality
                // or changes the original error's exit1; no owner is queried here.
                let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
                if let Some(frame) = error.frame_diagnostic_line().or_else(|| error.admission_diagnostic_line()).or_else(|| error.copy_diagnostic_line()) {
                    if line.len() + frame.len() <= 512 {
                        let _ = std::io::Write::write_all(&mut std::io::stderr(), frame.as_bytes());
                    }
                }
            }
            std::process::ExitCode::FAILURE
        },
    }
}
