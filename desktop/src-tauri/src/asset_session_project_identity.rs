//! Thin identity admission under the SAME original Document and EditOwner.
//! No process/session/filesystem owner, asynchronous handoff or Store request.
use super::*;
use crate::{
    edit_owner::RegisteredEditRoot,
    edit_protocol::EditDomain,
    project_identity_edit_protocol::{self as wire, IdentityStatus, NativeContinuity},
};

fn combine_vetoes(
    execute: Result<bool, BridgeError>,
    reconcile: Result<bool, BridgeError>,
) -> Result<NativeContinuity, BridgeError> {
    let execute = execute?;
    let reconcile = reconcile?;
    Ok(if execute || reconcile {
        NativeContinuity::Existing
    } else {
        NativeContinuity::Unknown
    })
}
pub(super) fn current_continuity(
    bridge: &DesktopBridge,
    project: &str,
    registered: &RegisteredEditRoot,
    selected: Option<wire::Platform>,
) -> Result<NativeContinuity, BridgeError> {
    let platforms = match selected {
        Some(platform) => [Some(platform), None],
        // Recovery has no renderer-selected target. Conservatively inspect both
        // native vetoes; it still can only finish its original descriptor.
        None => [Some(wire::Platform::Android), Some(wire::Platform::Ios)],
    };
    let mut existing = false;
    for platform in platforms.into_iter().flatten() {
        // Do not short-circuit a true result past another owner's error. Both
        // getters consume only already-retained original positive retirement;
        // neither status DATA nor a provider failure can manufacture absence.
        let execute = bridge.local_store_execute.known_existing_identity(
            project,
            registered.generation,
            &registered.root,
            platform,
        );
        let reconcile = bridge.local_store_reconcile.known_existing_identity(
            project,
            registered.generation,
            &registered.root,
            platform,
        );
        existing |= combine_vetoes(execute, reconcile)? == NativeContinuity::Existing;
    }
    Ok(if existing {
        NativeContinuity::Existing
    } else {
        NativeContinuity::Unknown
    })
}
impl DocumentBinding {
    pub(crate) fn open_project_identity(
        &self,
        window: &str,
        args: wire::Open,
    ) -> Result<IdentityStatus, BridgeError> {
        if !args.valid() {
            return Err(BridgeError::invalid());
        }
        // Entropy/executor acquisition is outside the document mutex. This
        // unbound ticket grants no root, continuity, execution or finality.
        let ticket = self.inner.bridge.edits.identity_open_ticket(window)?;
        let selected = args.project_id().to_owned();
        self.registered_edit_admit_published(
            EditDomain::ProjectIdentity,
            |_| Ok(selected),
            |bridge, registered, publisher| {
                let continuity =
                    current_continuity(bridge, args.project_id(), &registered, args.platform())?;
                bridge.edits.open_identity_published(
                    publisher, window, args, registered, ticket, continuity,
                )
            },
        )
    }
    pub(crate) fn prepare_project_identity(
        &self,
        window: &str,
        args: wire::Prepare,
    ) -> Result<IdentityStatus, BridgeError> {
        let session = args.session_id().to_owned();
        let result = self.registered_edit_admit_published(
            EditDomain::ProjectIdentity,
            |bridge| bridge.edits.identity_project(window, &session),
            |bridge, registered, publisher| {
                // Retained native selection, not a reinterpreted renderer or
                // serialized Status. Common prepare repeats exact session/root.
                let (project, platform) = bridge.edits.identity_context(window, &session)?;
                let continuity = current_continuity(bridge, &project, &registered, platform)?;
                bridge
                    .edits
                    .prepare_identity_published(publisher, window, args, registered, continuity)
            },
        );
        if result.is_err() {
            self.inner.bridge.edits.retire_identity_request(window);
        }
        result
    }
    pub(crate) fn apply_project_identity(
        &self,
        window: &str,
        args: wire::Apply,
    ) -> Result<IdentityStatus, BridgeError> {
        let session = args.session_id.clone();
        let result = self.registered_edit_admit_published(
            EditDomain::ProjectIdentity,
            |bridge| bridge.edits.identity_project(window, &session),
            |bridge, registered, publisher| {
                let (project, platform) = bridge.edits.identity_context(window, &session)?;
                let continuity = current_continuity(bridge, &project, &registered, platform)?;
                bridge
                    .edits
                    .apply_identity_published(publisher, window, args, registered, continuity)
            },
        );
        if result.is_err() {
            self.inner.bridge.edits.retire_identity_request(window);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_matching_fact_is_unknown_never_an_absence_or_publication_claim() {
        assert_eq!(
            combine_vetoes(Ok(false), Ok(false)).unwrap(),
            NativeContinuity::Unknown
        );
        for (execute, reconcile) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                combine_vetoes(Ok(execute), Ok(reconcile)).unwrap(),
                NativeContinuity::Existing
            );
        }
    }
    #[test]
    fn either_original_owner_error_refuses_even_if_other_owner_has_a_veto() {
        for known in [false, true] {
            assert!(combine_vetoes(Ok(known), Err(BridgeError::cleanup_unknown())).is_err());
            assert!(combine_vetoes(Err(BridgeError::cleanup_unknown()), Ok(known)).is_err());
        }
    }
}
