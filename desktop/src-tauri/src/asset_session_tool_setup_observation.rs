// Included only in the existing nonshipping installed_macos_observation child.
// This delegates ordinary actions; it cannot construct a source/native permit.
use crate::{
    android_build_protocol as build, android_tool_sources as sources,
    shell::installed_observation::tool_setup::{Control, Registration},
};

impl DocumentBinding {
    pub(crate) fn register_installed_macos_tool_setup(
        &self,
        token: Registration,
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
        let control = self
            .inner
            .bridge
            .tool_acquisition
            .bind_installed_tool_setup(&self.inner.session_identity, token)?;
        *book = Some(SessionBook {
            originals: Vec::new(),
            project_fields: None,
            input_case: None,
            vault: None,
            tool_setup: Some(control),git_fetch:None,git_push:None,git_upstream:None,
        });
        Ok(())
    }
    fn installed_tool_control(&self) -> Result<Arc<Control>, BridgeError> {
        self.inner
            .bridge
            .tool_acquisition
            .installed_tool_setup_control(&self.inner.session_identity)
            .ok_or_else(BridgeError::invalid)
    }
    pub(crate) async fn installed_tool_setup_saved(
        &self,
        project: &str,
    ) -> Result<build::Prepare, BridgeError> {
        let control = self.installed_tool_control()?;
        {
            let state = self.lock();
            let (generation, root) = self
                .inner
                .bridge
                .native_project(project)
                .map_err(|_| BridgeError::invalid())?;
            let roster = self
                .inner
                .bridge
                .native_roster()
                .map_err(|_| BridgeError::invalid())?;
            if !control.permits(&self.inner.session_identity)
                || !live(&state)
                || root.path != control.project()
                || roster.generation != generation
                || roster.roots.as_slice() != std::slice::from_ref(&root)
            {
                return Err(BridgeError::invalid());
            }
        }
        // Same real saved-read original, awaited on the existing relay. No Doc,
        // Edit, registry or Host lock crosses this IO/child/runtime operation.
        let observation = self
            .inner
            .bridge
            .observe_release_version(
                self,
                crate::release_version_protocol::Request {
                    project_id: project.to_owned(),
                },
            )
            .await?;
        if !control.permits(&self.inner.session_identity) {
            return Err(BridgeError::invalid());
        }
        let data = observation.saved_comparison();
        Ok(build::Prepare {
            project_id: project.to_owned(),
            draft_revision: 0,
            baseline_generation: 1,
            saved_config: build::Content {
                bytes: data.config_bytes,
                sha256: data.config_sha256.to_owned(),
            },
            saved_version: build::SavedVersion {
                source: data.source.to_owned(),
                bytes: data.version_bytes,
                sha256: data.version_sha256.to_owned(),
                name: data.name.to_owned(),
                build: data.build,
            },
            artifact_validation: build::ArtifactValidation {
                mode: build::ValidationMode::StructureAndVersion,
                upload_certificate_sha256: None,
            },
            signing: None,
            operation: None,
            action: None,
        })
    }
    pub(crate) fn installed_tool_setup_source(&self, id: u32, role: sources::Role) -> bool {
        let Ok(state) = self.inner.state.try_lock() else {
            return false;
        };
        let Some(slot) = &state.slot else {
            return false;
        };
        let Some(binding) = &slot.android_source else {
            return false;
        };
        let Ok(book) = self.inner.installed_macos_session.try_lock() else {
            return false;
        };
        let Some(book) = book.as_ref() else {
            return false;
        };
        let Some(control) = &book.tool_setup else {
            return false;
        };
        let Some(index) = control.case().picker(id) else {
            return false;
        };
        let Some((owner, operation)) = book.originals.iter().find(|(owner, _)| owner.id == id)
        else {
            return false;
        };
        let Ok((generation, root)) = self.inner.bridge.native_project(&binding.project_id) else {
            return false;
        };
        let Ok(roster) = self.inner.bridge.native_roster() else {
            return false;
        };
        if !control.permits(&self.inner.session_identity)
            || !live(&state)
            || crate::shell::installed_observation::tool_setup::role(index) != Some(role)
            || root.path != control.project()
            || binding.root != root
            || binding.generation != generation
            || roster.generation != generation
            || roster.roots.as_slice() != std::slice::from_ref(&root)
            || !Arc::ptr_eq(owner, &slot.owner)
            || *operation != Some(Operation::ChooseAndroidSource)
            || slot.phase != Phase::Idle
            || slot.reason != Reason::None
            || slot.settlement != Settlement::Known
            || binding.role != role
            || !session_original_settled(&self.inner, owner)
            || !owner.android_source_selected_settled()
        {
            return false;
        }
        // Both the same native callback's selected path and the fresh original
        // source close are required. This is not a supplied SourceSnapshot.
        owner.gui.installed_native_response().is_ok_and(|response| {
            response.is_some_and(|r| {
                r.operation_id == id
                    && r.response == NativeResponse::Accept
                    && r.callback_returned
                    && r.selected.as_deref() == control.target(index)
            })
        })
    }
    pub(crate) fn installed_tool_setup_sdk_location(
        &self,
        operation: &str,
        generation: &str,
    ) -> Option<std::path::PathBuf> {
        self.inner
            .bridge
            .tool_acquisition
            .installed_tool_setup_sdk_location(&self.inner.session_identity, operation, generation)
    }
    pub(super) fn macos_tool_setup_selected(
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
        let Some(control) = &book.tool_setup else {
            return false;
        };
        let Some(owner) = project.owner.upgrade() else {
            return false;
        };
        let count = control.quit_id();
        control.bound(&self.inner.session_identity)
            && control.completed()
            && state.vault.is_none()
            && same_document(&self.inner, &project.document)
            && self.macos_registered(project)
            && project.root.path == control.project()
            && book.originals.len() == count as usize
            && state.next_operation == count
            && book.originals.first().is_some_and(|(first, kind)| {
                Arc::ptr_eq(first, &owner) && *kind == Some(Operation::ChooseProject)
            })
            && book
                .originals
                .last()
                .is_some_and(|(last, kind)| last.id == count && kind.is_none())
            && book.originals[1..count as usize - 1]
                .iter()
                .all(|(_, kind)| *kind == Some(Operation::ChooseAndroidSource))
            && book.originals.iter().enumerate().all(|(i, (original, _))| {
                original.id as usize == i + 1 && session_original_settled(&self.inner, original)
            })
            && completed(&self.inner, &owner, NativeResponse::Accept, true, false)
                .is_some_and(|r| r.selected.as_deref() == Some(project.root.path.as_path()))
    }
}
