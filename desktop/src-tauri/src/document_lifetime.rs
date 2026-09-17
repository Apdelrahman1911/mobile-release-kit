//! One native window, one original document. Reload never grants a new edit
//! capability. Only the edit registry's synchronous transition grants/refuses
//! commands; these startup observations feed that same registry.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DocumentAction { None, Bind, Lost }

#[derive(Default)]
pub(crate) struct DocumentLifetime {
    navigation_seen: bool,
    started: bool,
    finished: bool,
    crash_hook_ready: bool,
    bound: bool,
    lost: bool,
}

impl DocumentLifetime {
    pub(crate) fn navigation(&mut self, trusted: bool) -> (bool, DocumentAction) {
        if !trusted || self.lost || self.navigation_seen || self.finished {
            return (false, self.invalidate());
        }
        // Platforms may report the original navigation before or after the
        // first Started callback, but never accept a second navigation.
        self.navigation_seen = true;
        (true, DocumentAction::None)
    }

    pub(crate) fn started(&mut self, trusted: bool) -> DocumentAction {
        if !trusted || self.lost || self.started || self.finished { return self.invalidate(); }
        self.started = true;
        DocumentAction::None
    }

    pub(crate) fn finished(&mut self, trusted: bool) -> DocumentAction {
        // A cached Finished from before crash observation was installed cannot
        // prove the document survived that gap. Only this live event can bind.
        if !trusted || self.lost || !self.started || self.finished || !self.crash_hook_ready || self.bound { return self.invalidate(); }
        self.finished = true;
        self.bound = true;
        DocumentAction::Bind
    }

    pub(crate) fn crash_hook_installed(&mut self) -> DocumentAction {
        if self.lost || self.crash_hook_ready { return self.invalidate(); }
        self.crash_hook_ready = true;
        DocumentAction::None
    }

    pub(crate) fn invalidate(&mut self) -> DocumentAction {
        if self.lost { return DocumentAction::None; }
        self.lost = true;
        DocumentAction::Lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_load_and_actual_hook_install_are_both_required() {
        for hook_before_start in [false, true] {
            let mut state = DocumentLifetime::default();
            if hook_before_start { assert_eq!(state.crash_hook_installed(), DocumentAction::None); }
            assert_eq!(state.navigation(true), (true, DocumentAction::None));
            assert_eq!(state.started(true), DocumentAction::None);
            if !hook_before_start { assert_eq!(state.crash_hook_installed(), DocumentAction::None); }
            assert_eq!(state.finished(true), DocumentAction::Bind);
            assert_eq!(state.navigation(true), (false, DocumentAction::Lost));
            assert_eq!(state.finished(true), DocumentAction::None);
            assert_eq!(state.crash_hook_installed(), DocumentAction::None);
        }
    }

    #[test]
    fn finished_before_actual_crash_observation_never_retroactively_binds() {
        let mut state = DocumentLifetime::default();
        state.navigation(true);
        state.started(true);
        assert_eq!(state.finished(true), DocumentAction::Lost);
        assert_eq!(state.crash_hook_installed(), DocumentAction::None);
        assert_eq!(state.finished(true), DocumentAction::None);
    }

    #[test]
    fn started_before_original_navigation_is_not_a_new_document() {
        let mut state = DocumentLifetime::default();
        assert_eq!(state.started(true), DocumentAction::None);
        assert_eq!(state.navigation(true), (true, DocumentAction::None));
        assert_eq!(state.crash_hook_installed(), DocumentAction::None);
        assert_eq!(state.finished(true), DocumentAction::Bind);
        assert_eq!(state.started(true), DocumentAction::Lost);
    }

    #[test]
    fn missing_initial_navigation_does_not_authorize_later_navigation() {
        let mut state = DocumentLifetime::default();
        assert_eq!(state.crash_hook_installed(), DocumentAction::None);
        assert_eq!(state.started(true), DocumentAction::None);
        assert_eq!(state.finished(true), DocumentAction::Bind);
        assert_eq!(state.navigation(true), (false, DocumentAction::Lost));
    }

    #[test]
    fn untrusted_repeated_or_unordered_loads_never_rearm() {
        for scenario in 0..5 {
            let mut state = DocumentLifetime::default();
            let lost = match scenario {
                0 => state.finished(true),
                1 => state.started(false),
                2 => { state.started(true); state.started(true) },
                3 => { state.navigation(true); state.navigation(true).1 },
                _ => state.navigation(false).1,
            };
            assert_eq!(lost, DocumentAction::Lost);
            assert_eq!(state.crash_hook_installed(), DocumentAction::None);
            assert_eq!(state.started(true), DocumentAction::None);
            assert_eq!(state.finished(true), DocumentAction::None);
        }
    }

    #[test]
    fn crash_or_destruction_is_absorbing_even_during_startup() {
        let mut state = DocumentLifetime::default();
        state.started(true);
        assert_eq!(state.invalidate(), DocumentAction::Lost);
        assert_eq!(state.crash_hook_installed(), DocumentAction::None);
        assert_eq!(state.finished(true), DocumentAction::None);
        assert_eq!(state.navigation(true), (false, DocumentAction::None));
    }
}
