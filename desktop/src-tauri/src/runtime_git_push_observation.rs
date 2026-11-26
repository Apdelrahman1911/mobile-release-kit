//! Nonshipping profile selection from the SAME claimed observer/Document.
//! Only two compiled entry names. No path, flag, hash or response DTO admission.
use super::*;
use crate::shell::installed_observation::git_push::{Control, CONNECTION_ENTRY, REMOTE_ENTRY};
use std::sync::Arc;
impl RuntimeConfig {
    pub(crate) fn bind_git_push_observation(
        &self,
        document: &Arc<()>,
        control: &Arc<Control>,
    ) -> Result<(), BridgeError> {
        if !macos_bindings() || !control.registered(document) {
            return Err(unavailable());
        }
        self.git_push_observation
            .set(Arc::downgrade(control))
            .map_err(|_| unavailable())
    }
    pub(crate) fn push_observation(&self) -> Result<Option<Arc<Control>>, BridgeError> {
        self.git_push_observation
            .get()
            .map(|w| w.upgrade().filter(|v| v.live()).ok_or_else(unavailable))
            .transpose()
    }
}
pub(super) fn selection(
    control: &Control,
    connection: bool,
) -> Result<VerifiedRuntime, BridgeError> {
    if !macos_bindings() || !control.live() {
        return Err(unavailable());
    }
    let cwd = crate::installed_runtime::runtime_root();
    Ok(VerifiedRuntime {
        python: cwd.join("python/bin/python3"),
        bootstrap: cwd.join(if connection {
            CONNECTION_ENTRY
        } else {
            REMOTE_ENTRY
        }),
        core: cwd.join("core.zip"),
        cwd,
    })
}
pub(crate) fn helper_name(selection: &VerifiedRuntime) -> Option<&'static str> {
    (selection.bootstrap == selection.cwd.join(REMOTE_ENTRY)).then_some(REMOTE_ENTRY)
}
