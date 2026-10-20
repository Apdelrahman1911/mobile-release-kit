//! Fixed memory-only observer in the SAME retained Desktop relay.
//! No client/renderer command can call this producer or manufacture a root.
use super::*;
use crate::{application_service_host::NativeProject, git_read_protocol as native};

fn same_observed_context(
    value: &native::Projection,
    document_revision: u32,
    generation: u32,
) -> bool {
    document_revision != 0
        && document_revision != u32::MAX
        && value.context.revision == format!("document-{document_revision}")
        && generation != 0
        && value.context.generation == generation
}
fn capture_ready(state: &DocumentState) -> Result<bool, ()> {
    if state.lost_observed || state.unknown || state.exhausted || state.stopping {
        return Err(());
    }
    // Startup has not bound the original document yet; quit confirmation can
    // be declined, and asset retirement also brackets ordinary disposal. Skip
    // capture during those gaps without erasing already-historical facts.
    Ok(state.lifetime.original_bound() && !state.quit_pending && !state.retiring)
}
impl DocumentBinding {
    pub(crate) fn service_repository_summary_tick(&self) {
        let mut state = self.lock();
        let host = &self.inner.bridge.application_service;
        match capture_ready(&state) {
            Ok(true) => {}
            Ok(false) => return,
            Err(()) => {
                host.repository_summary_relay_lost();
                return;
            }
        }
        // The SAME owner alone can demote its ticket after original/native and
        // management joins. Never decode a child terminal as a settled read.
        git_read::reconcile(&mut state);
        let Some(entry) = &state.git_read else {
            return;
        };
        let value = match entry {
            git_read::Entry::Original { ticket, .. } => {
                if ticket.pending_phase() == native::Phase::CleanupUnknown {
                    host.repository_summary_relay_lost();
                }
                return; // No full result clone or inferred completion.
            }
            git_read::Entry::Finished(value) => value,
        };
        if value.phase == native::Phase::CleanupUnknown
            || value.outcome == Some(native::Outcome::CleanupUnknown)
        {
            host.repository_summary_relay_lost();
            return;
        }
        if value.action.kind != native::Kind::Observe {
            return;
        }
        if !same_observed_context(
            value,
            state.revision,
            self.inner.bridge.registry_generation(),
        ) {
            // Old successful facts already captured remain explicitly
            // historical; changed context cannot publish a new observation.
            return;
        }
        let id = value.context.project_id.clone();
        let result = self.inner.bridge.native_project(&id);
        let Ok((generation, root)) = self.registry_result(&mut state, result, None) else {
            host.repository_summary_relay_lost();
            return;
        };
        let Some(git_read::Entry::Finished(value)) = &state.git_read else {
            return;
        };
        if !same_observed_context(value, state.revision, generation) {
            return;
        }
        let Ok(identity) = root.identity.posix() else {
            host.repository_summary_relay_lost();
            return;
        };
        let (device, inode) = identity.service_identity();
        let Ok(input_revision) = self.inner.android_registration_control.epoch() else {
            host.repository_summary_relay_lost();
            return;
        };
        let original = NativeProject {
            runtime_id: id,
            canonical_root: root.path,
            device,
            inode,
            registration_generation: generation,
            document_identity: self.inner.session_identity.clone(),
            input_revision,
        };
        // Doc -> TRY Host -> bounded projection-cell only, no Service mutex or
        // Store IO. Holding Doc prevents a registry swap between comparisons.
        host.publish_repository_summary(&original, value);
    }
    pub(crate) fn repository_summary_relay_lost(&self) {
        self.inner
            .bridge
            .application_service
            .repository_summary_relay_lost();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_binding_and_transient_disposal_skip_without_becoming_permanent_loss() {
        // Actual Document state/lifetime transitions, DATA only. No native
        // source, main-Webview observation, project or permission is minted.
        let doc = DocumentBinding::new(Arc::new(DesktopBridge::new(
            "/inert-repository-summary-lifetime".into(),
        )));
        let mut state = doc.lock();
        assert_eq!(capture_ready(&state), Ok(false));
        assert_eq!(state.lifetime.crash_hook_installed(), DocumentAction::None);
        assert_eq!(state.lifetime.started(true), DocumentAction::None);
        assert_eq!(capture_ready(&state), Ok(false));
        assert_eq!(state.lifetime.finished(true), DocumentAction::Bind);
        assert_eq!(capture_ready(&state), Ok(true));

        state.quit_pending = true;
        assert_eq!(capture_ready(&state), Ok(false));
        state.quit_pending = false;
        assert_eq!(capture_ready(&state), Ok(true));
        state.retiring = true;
        assert_eq!(capture_ready(&state), Ok(false));
        state.retiring = false;
        assert_eq!(capture_ready(&state), Ok(true));

        // Permanent failure takes precedence even during a transient gap.
        state.quit_pending = true;
        for flag in 0..4 {
            state.lost_observed = flag == 0;
            state.unknown = flag == 1;
            state.exhausted = flag == 2;
            state.stopping = flag == 3;
            assert_eq!(capture_ready(&state), Err(()));
        }
        state.unknown = false;
        state.exhausted = false;
        state.stopping = false;
        state.quit_pending = false;
        assert_eq!(state.lifetime.invalidate(), DocumentAction::Lost);
        state.lost_observed = true; // The existing Document loss path records this.
        assert_eq!(state.lifetime.finished(true), DocumentAction::None);
        assert_eq!(capture_ready(&state), Err(()));
    }
    #[test]
    fn a_saved_projection_cannot_rematch_another_document_or_registry_revision() {
        let value = native::Projection {
            operation_id: "git-read-1".into(),
            context: native::Context {
                project_id: "project-1".into(),
                generation: 3,
                revision: "document-7".into(),
            },
            action: native::Action {
                kind: native::Kind::Observe,
                expected_revision: None,
                paths: vec![],
                staged: false,
            },
            phase: native::Phase::Settled,
            outcome: Some(native::Outcome::Ok),
            reason: None,
            result: serde_json::Value::Null,
        };
        assert!(same_observed_context(&value, 7, 3));
        for (revision, generation) in [(8, 3), (7, 4), (0, 3), (7, 0), (u32::MAX, 3)] {
            assert!(!same_observed_context(&value, revision, generation));
        }
        // This check alone intentionally does NOT validate result/finality.
        // The production caller still requires the original Finished entry.
    }
}
