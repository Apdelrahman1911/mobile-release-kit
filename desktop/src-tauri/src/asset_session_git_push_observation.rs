// Included only in the existing nonshipping installed_macos_observation child.
use crate::shell::installed_observation::git_push::{Control, Registration};
impl DocumentBinding {
    pub(crate) fn register_installed_macos_git_push(
        &self,
        registration: Registration,
    ) -> Result<(), BridgeError> {
        let state = self.lock();
        if state.next_operation != 0
            || state.next_context != 0
            || state.session
            || state.slot.is_some()
            || state.context.is_some()
            || state.vault.is_some()
            || state.quit.is_some()
            || state.lost_observed
            || state.stopping
            || state.unknown
            || self.live_session_owner_reason().is_some()
            || !self.inner.bridge.installed_project_selection_available()
            || !self.inner.bridge.supervisor.can_exit()
            || !self.inner.bridge.edits.can_exit()
        {
            return Err(BridgeError::invalid());
        }
        self.inner
            .bridge
            .supervisor
            .assert_installed_session_available(&self.inner.session_identity)?;
        let mut book = self
            .inner
            .installed_macos_session
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if book.is_some() {
            return Err(BridgeError::invalid());
        }
        let control = registration.consume(&self.inner.session_identity)?;
        self.inner
            .bridge
            .supervisor
            .bind_installed_git_push(&self.inner.session_identity, &control)?;
        *book = Some(SessionBook {
            originals: Vec::new(),
            project_fields: None,
            input_case: None,
            vault: None,
            tool_setup: None,
            git_fetch: None,
            git_upstream:None,
            git_push: Some(control),
        });
        Ok(())
    }
    pub(crate) fn installed_git_push_pending(&self, control: &Arc<Control>, id: &str) -> bool {
        let Ok(state) = self.inner.state.try_lock() else {
            return false;
        };
        let Some(git_local::Entry::Original { ticket, gate }) = &state.git_local else {
            return false;
        };
        control.bound(&self.inner.session_identity)
            && control.window(id)
            && ticket.operation_id() == id
            && gate.push_observation_matches(control)
            && matches!(
                ticket.receipt(),
                crate::supervisor::GitLocalReceipt::Pending
            )
            && !state.unknown
            && !state.stopping
    }
    pub(super) fn macos_git_push_selected(
        &self,
        state: &DocumentState,
        project: &ProjectWitness,
    ) -> bool {
        let Ok(book) = self.inner.installed_macos_session.try_lock() else {
            return false;
        };
        let Some(book) = book.as_ref() else {
            return false;
        };
        let Some(c) = &book.git_push else {
            return false;
        };
        let Some(owner) = project.owner.upgrade() else {
            return false;
        };
        c.bound(&self.inner.session_identity)
            && c.completed()
            && same_document(&self.inner, &project.document)
            && self.macos_registered(project)
            && project.root.path == c.project()
            && state.vault.is_none()
            && !git_local::pending(state)
            && !git_read::pending(state)
            && state.github.material_settled()
            && !state.github.native_work_pending()
            && book.originals.len() == 2
            && state.next_operation == 2
            && book.originals.first().is_some_and(|(o, k)| {
                Arc::ptr_eq(o, &owner) && *k == Some(Operation::ChooseProject)
            })
            && book
                .originals
                .last()
                .is_some_and(|(o, k)| o.id == 2 && k.is_none())
            && book
                .originals
                .iter()
                .all(|(o, _)| session_original_settled(&self.inner, o))
            && completed(&self.inner, &owner, NativeResponse::Accept, true, false)
                .is_some_and(|r| r.selected.as_deref() == Some(project.root.path.as_path()))
    }
}
