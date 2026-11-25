//! Fixed CLI presentation only. This never discovers a host or grants access.
pub(crate) const READ_UNAVAILABLE: &str = "Desktop read access is unavailable. Keep Desktop open and select a saved project. In Project settings > Advanced: CLI / AI access, choose Check access, then Allow selected project for 1 hour. For cached reads only, explicitly start mrk serve-history.";

pub(crate) fn status_text(read_only: bool, requires_running_desktop: bool) -> &'static str {
    if read_only && !requires_running_desktop {
        "Connected to foreground cached history. No fresh reads, actions or restored grants; observations remain stale.\n"
    } else {
        "Connected to Desktop. The read grant cannot execute checks; execution needs a separate one-use grant. Saved observations are not release validation.\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_guidance_names_the_explicit_ui_steps_and_cached_alternative() {
        for step in ["Keep Desktop open", "select a saved project", "Project settings",
                     "CLI / AI access", "Check access", "Allow selected project for 1 hour", "mrk serve-history"] {
            assert!(READ_UNAVAILABLE.contains(step));
        }
        assert!(READ_UNAVAILABLE.len() < 1024);
    }
    #[test]
    fn enabled_status_retains_separate_execution_permission_and_saved_data_caveat() {
        for (read_only, requires_desktop) in [(false, true), (false, false), (true, true)] {
            let status = status_text(read_only, requires_desktop);
            assert!(status.starts_with("Connected to Desktop."));
            assert!(status.contains("separate one-use grant"));
            assert!(status.contains("not release validation"));
        }
    }
    #[test]
    fn cached_status_never_becomes_fresh_access_or_a_restored_grant() {
        let status = status_text(true, false);
        assert!(status.starts_with("Connected to foreground cached history."));
        assert!(status.contains("No fresh reads, actions or restored grants"));
        assert!(status.ends_with("observations remain stale.\n"));
    }
}
