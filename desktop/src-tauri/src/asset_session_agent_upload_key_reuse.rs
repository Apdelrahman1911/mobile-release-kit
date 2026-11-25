//! Closed compact reply at the SAME Asset Prepared waiter. Public Access can
//! correlate this original only after all three service-return cuts; it cannot
//! create a Load, assessment, permission or Bind from status.
use super::*;

fn grant<'a>(state: &'a DocumentState, link: &Arc<requests::NativeLink>) -> Result<&'a Arc<Grant>, AssetError> {
    let g = state.agent_upload_key.grant.as_ref().ok_or_else(refused)?;
    if state.agent_upload_key.lost || !g.scope.kind.prepares()
        || state.agent_upload_key.active.as_ref().is_none_or(|l| !Arc::ptr_eq(l, link))
        || g.id != *link.entry().grant_id() || !Arc::ptr_eq(&g.scope, link.entry().scope()) {
        return Err(refused());
    }
    Ok(g)
}
pub(in crate::asset_session) fn attach_prepared(state: &DocumentState, slot: &Slot, link: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
    let g = grant(state, link)?;
    attach(state, &slot.owner, link)?;
    g.proof.attach_prepare(slot, link)
}
pub(in crate::asset_session) fn prepared_reply(document: &DocumentBinding, state: &DocumentState,
    link: &Arc<requests::NativeLink>, id: u32) -> Result<(), CommandError> {
    let g = grant(state, link)?;
    let slot = state.slot.as_ref().filter(|s| s.owner.id == id
        && s.owner.agent_upload_key.get().is_some_and(|l| Arc::ptr_eq(l, link))).ok_or_else(refused)?;
    if slot.operation != Operation::Prepare || state.unknown || state.stopping || state.lost_observed {
        return Err(refused().into());
    }
    document.service_allow_current_locked(state, &g.native, &g.edit).map_err(|_| refused())?;
    service(state).map_err(|_| refused())?.ok_or_else(refused)?.native_history_current().map_err(|_| refused())?;
    g.proof.prepared_returned(document, state, link).map_err(Into::into)
}
pub(in crate::asset_session) fn prepare_completion(document: &DocumentBinding, state: &DocumentState, slot: &Slot)
    -> Option<(p::State, p::Reason, Option<p::KeyReference>)> {
    let link = slot.owner.agent_upload_key.get()?;
    if !link.entry().scope().kind.prepares()
        || link.entry().scope().kind == p::Kind::PrepareExisting && slot.kind != Some(Kind::AndroidKeystore)
        || link.entry().scope().kind == p::Kind::CredentialAssessExisting && slot.kind.is_none_or(|k|
            !vault::upload_key_controls::delegation::credential::public_kind(k).is_some_and(|k| k.general_assessment()))
        || !slot.owner.resources_settled() || !slot.owner.coordinator.try_lock().is_ok_and(|b|
            b.receipt == JoinReceipt::Returned && b.handle.is_none())
        || !slot.owner.child.try_lock().is_ok_and(|b|
            matches!(b.receipt, JoinReceipt::Returned | JoinReceipt::New) && b.handle.is_none())
        || slot.settlement != Settlement::Known { return None; }
    if slot.phase == Phase::Preview {
        let g = grant(state, link).ok()?;
        document.service_allow_current_locked(state, &g.native, &g.edit).ok()?;
        g.proof.prepared_view(document, state, link)?;
        return Some((p::State::ReviewReady, p::Reason::None, None));
    }
    if slot.phase != Phase::Idle { return None; }
    Some(match slot.reason {
        Reason::UserCancelled | Reason::Shutdown => (p::State::Cancelled, p::Reason::PermissionRevoked, None),
        Reason::Deadline => (p::State::Cancelled, p::Reason::Expired, None),
        _ => (p::State::Refused, p::Reason::Refused, None),
    })
}

pub(super) fn access(document: &DocumentBinding, mut value: p::Access) -> p::Access {
    if !value.kind.is_some_and(p::Kind::prepares) || !value.consumed || value.enabled { return value; }
    let state = document.lock();
    let Some(link) = &state.agent_upload_key.active else { return value; };
    let Ok(g) = grant(&state, link) else { return value; };
    if value.grant_id.as_ref() != Some(&g.id) || value.request_id.as_ref() != Some(&link.entry().origin().request_id)
        || value.project_id.as_ref() != Some(&g.scope.project_id)
        || value.service_instance.as_ref() != Some(&link.entry().origin().service_instance)
        || document.service_allow_current_locked(&state, &g.native, &g.edit).is_err() { return value; }
    // Historical status alone is insufficient. The same current native stamp
    // and live Preview are rematched below. Status contains no preview token.
    if link.entry().status().is_ok_and(|s| s.state == p::State::ReviewReady
        && s.settlement == crate::service_protocol::Settlement::Settled) {
        value.prepared = g.proof.prepared_view(document, &state, link);
    }
    value
}
