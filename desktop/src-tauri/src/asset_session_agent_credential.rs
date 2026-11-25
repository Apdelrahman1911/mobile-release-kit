//! A closed proof variant in the SAME grant/relay. Old Android proof and
//! qualification are not generalized into ordinary-credential permission.
use super::*;
use vault::upload_key_controls::delegation as android;
use android::credential;
pub(super) enum Proof { Android(android::Proof), Credential(credential::Proof) }
pub(super) fn capture_qualified(document: &DocumentBinding, state: &DocumentState, selection: &p::Selection,
    context: u32, revision: u32, qualification: vault::backup_desktop::Qualification) -> Result<Proof, AssetError> {
    if selection.kind().credential() {
        credential::Proof::capture(document, state, selection, context, revision).map(Proof::Credential)
    } else {
        android::capture_qualified(document, state, selection, context, revision, qualification).map(Proof::Android)
    }
}
impl Proof {
    pub(super) fn retained_bytes(&self) -> usize { match self { Self::Android(p) => p.retained_bytes(), Self::Credential(p) => p.retained_bytes() } }
    pub(super) fn kind(&self) -> p::Kind { match self { Self::Android(p) => p.kind(), Self::Credential(p) => p.kind() } }
    pub(super) fn end(&self, at: Instant) -> Instant { match self { Self::Android(p) => p.end(at), Self::Credential(p) => p.end(at) } }
    pub(super) fn current(&self, d: &DocumentBinding, s: &DocumentState) -> Result<(), AssetError> {
        match self { Self::Android(p) => p.current(d,s), Self::Credential(p) => p.current(d,s) }
    }
    pub(super) fn attach_prepare(&self, s: &Slot, l: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        match self { Self::Android(p) => p.attach_prepare(s,l), Self::Credential(p) => p.attach_prepare(s,l) }
    }
    pub(super) fn prepared_returned(&self, d: &DocumentBinding, s: &DocumentState, l: &Arc<requests::NativeLink>) -> Result<(), AssetError> {
        match self { Self::Android(p) => p.prepared_returned(d,s,l), Self::Credential(p) => p.prepared_returned(d,s,l) }
    }
    pub(super) fn prepared_view(&self, d: &DocumentBinding, s: &DocumentState, l: &Arc<requests::NativeLink>) -> Option<p::Prepared> {
        match self { Self::Android(p) => p.prepared_view(d,s,l), Self::Credential(p) => p.prepared_view(d,s,l) }
    }
    pub(super) fn run(&self, d: &DocumentBinding, l: Arc<requests::NativeLink>, #[cfg(feature="desktop-shell")] app: tauri::AppHandle) -> Result<Option<u32>, AssetError> {
        match self { Self::Android(p) => p.run(d,l,#[cfg(feature="desktop-shell")] app), Self::Credential(p) => p.run(d,l) }
    }
}
fn current_grant<'a>(state: &'a DocumentState, slot: &Slot) -> Option<&'a Arc<Grant>> {
    let link = slot.owner.agent_upload_key.get()?;
    let grant = state.agent_upload_key.grant.as_ref()?;
    (state.agent_upload_key.active.as_ref().is_some_and(|active| Arc::ptr_eq(active,link))
        && grant.id == *link.entry().grant_id() && Arc::ptr_eq(&grant.scope,link.entry().scope())
        && grant.scope.kind == grant.proof.kind()).then_some(grant)
}
pub(super) fn completion(document: &DocumentBinding, state: &DocumentState, slot: &Slot)
    -> Option<(p::State,p::Reason,Option<p::KeyReference>)> {
    let link = slot.owner.agent_upload_key.get()?;
    if !link.entry().scope().kind.credential() { return android::completion(document,state,slot); }
    let grant = current_grant(state,slot)?;
    let Proof::Credential(proof) = &grant.proof else { return None; };
    let outcome = proof.completion(document,state,slot)?;
    // Drift cannot publish a positive attribution, but it must not hide a
    // genuinely returned, joined cancellation of this same original.
    if outcome.0.success() { document.service_allow_current_locked(state,&grant.native,&grant.edit).ok()?; }
    Some(outcome)
}
pub(super) fn import_publication(document: &DocumentBinding, state: &DocumentState, slot: &Slot,
    stamp: credential::ImportStamp) -> Result<credential::ImportStamp, Reason> {
    let grant = current_grant(state,slot).ok_or(Reason::ContextStale)?;
    let Proof::Credential(proof) = &grant.proof else { return Err(Reason::SourceRefused); };
    if grant.scope.kind != p::Kind::CredentialImportPrepared { return Err(Reason::SourceRefused); }
    document.service_allow_current_locked(state,&grant.native,&grant.edit).map_err(|_| Reason::ContextStale)?;
    proof.import_publication(document,state,slot,stamp)
}
