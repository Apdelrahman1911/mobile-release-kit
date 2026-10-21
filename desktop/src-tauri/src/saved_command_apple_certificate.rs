//! Certificate phases of the SAME AppleKeySession. Phase replies are only
//! provisional comparisons; the final volatile association is constructed
//! after the original worker/runtime/IO/driver joins, never from a JSON token.
use super::*;
use crate::{
    apple_provisioning_journal::{CertificateIssuanceIntent, CertificateJournalAck},
    credential_format::{inspect_distribution_certificate_candidate, CertificateCandidateFailure},
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

struct PublicKey {
    csr: String,
    spki: Vec<u8>,
    csr_sha256: String,
    spki_sha256: String,
    history_sha256: Option<String>,
}
struct Selected {
    id: String,
    der: Vec<u8>,
    sha256: String,
    before: u64,
    after: u64,
}
struct Batch {
    number: u32,
    seen: usize,
    ambiguous: bool,
    selected: Option<Selected>,
    ack_sha256: String,
    checked_at: u64,
}
#[derive(Default)]
struct Facts {
    key: Option<PublicKey>,
    batch: Option<Batch>,
    policy: Option<wire::CertificatePolicyInput>,
    pending: bool,
}
#[derive(Default)]
pub(super) struct State {
    facts: Mutex<Facts>,
    association: OnceLock<AppleDistributionCertificateBinding>,
}

/// No constructor, Clone, Serde or transferable trust flag. A future explicit
/// P12 operation must repeat the same fresh loan/verification in its OWN
/// original Session; an old certificate operation cannot lend this across it.
pub(crate) struct AppleDistributionCertificateBinding {
    parent: Weak<AppleKeySession>,
    original: Weak<OriginalWork>,
    loan: Weak<AppleDistributionKeyLoan>,
    request: Arc<wire::RequestBinding>,
    certificate: Selected,
    public_key_sha256: String,
}
impl AppleDistributionCertificateBinding {
    pub(crate) fn confirms_p12(
        &self,
        parent: &Arc<AppleKeySession>,
        original: &Arc<OriginalWork>,
        loan: &Arc<AppleDistributionKeyLoan>,
        request: &Arc<wire::RequestBinding>,
        leaf_sha256: &str,
        spki_sha256: &str,
    ) -> bool {
        // Comparison only; this does not admit a P12 mode, return bytes, start
        // work, or extend a clock. That separate operation remains unavailable.
        self.parent.upgrade().is_some_and(|same| Arc::ptr_eq(&same, parent))
            && self.original.upgrade().is_some_and(|same| Arc::ptr_eq(&same, original))
            && self.loan.upgrade().is_some_and(|same| Arc::ptr_eq(&same, loan))
            && Arc::ptr_eq(&self.request, request)
            && parent.same_binding(request) && parent.same_asset(original)
            && parent.worker_joined.load(Ordering::SeqCst)
            && !parent.all_jobs_joined.load(Ordering::SeqCst)
            && !parent.private_drained.load(Ordering::SeqCst)
            && !parent.clock.interrupted()
            && self.certificate.sha256 == leaf_sha256 && self.public_key_sha256 == spki_sha256
            && current_time().is_ok_and(|at| self.certificate.before <= at && at < self.certificate.after)
    }
}

pub(super) fn backing_bytes() -> Option<usize> {
    // One maintained decoder (<10MiB, sequential candidates), retained key
    // facts and two bounded identity payload/ACK representations. DER is
    // public DATA but still charged; the generic pipe buffer is separate.
    (10usize * 1024 * 1024)
        .checked_add(2 * wire::CERTIFICATE_IDENTITY_LIMIT)?
        .checked_add(2 * wire::CERTIFICATE_BATCH_DER)?
        .checked_add(16 * 1024)?
        .checked_add(std::mem::size_of::<State>())?
        .checked_add(std::mem::size_of::<AppleDistributionCertificateBinding>())
}
fn current_time() -> Result<u64, BridgeError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs()).map_err(|_| invalid())
}
fn hash(value: &str) -> Result<[u8; 32], BridgeError> {
    if value.len() != 64 { return Err(invalid()); }
    let mut result = [0; 32];
    for (out, bytes) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let part = |b: u8| match b { b'0'..=b'9' => Some(b-b'0'), b'a'..=b'f' => Some(b-b'a'+10), _ => None };
        *out = part(bytes[0]).and_then(|a| part(bytes[1]).map(|b| a * 16 + b)).ok_or_else(invalid)?;
    }
    Ok(result)
}
fn state(parent: &AppleKeySession) -> Result<&State, BridgeError> {
    parent.certificate.as_ref().ok_or_else(invalid)
}

/// One write on the original stdin task, not a new task or receipt. Keeping
/// this exact future pinned across cutoff changes avoids restarting a partial
/// ACK. A false-STOP ACK that races cancellation is never a returned reply.
/// The caller still owns the entered/unknown route and all actual IO joins.
pub(in crate::saved_command_owner) async fn write_ack<W: tokio::io::AsyncWrite + Unpin>(
    owner: &Arc<Session>, writer: &mut W, bytes: &[u8], stopped: bool,
) -> bool {
    use tokio::io::AsyncWriteExt;
    if !matches!(&owner.context, Context::AppleProvisioning(context) if context.mode.certificate() || context.mode.p12() && !stopped)
        || bytes.is_empty() || bytes.len() > wire::ACK_LIMIT { return false; }
    let mut stop = owner.stop.subscribe();
    let mut cutoff = owner.native_audit_cutoff.subscribe();
    let written = writer.write_all(bytes);
    tokio::pin!(written);
    loop {
        let wake = owner.wake.notified();
        let end = (*cutoff.borrow()).min(owner.clocks.work).min(owner.clocks.finality);
        if owner.resource_unknown.load(Ordering::SeqCst) || Instant::now() >= end
            || *stop.borrow() && !stopped { return false; }
        tokio::select! { biased;
            _ = stop.changed(), if !stopped => return false,
            changed = cutoff.changed() => { if changed.is_err() { return false; } },
            _ = wake => {},
            result = &mut written => return result.is_ok()
                && !owner.resource_unknown.load(Ordering::SeqCst)
                && (stopped || !*stop.borrow())
                && Instant::now() < (*cutoff.borrow()).min(owner.clocks.work).min(owner.clocks.finality),
            _ = tokio::time::sleep_until(end.into()) => return false,
        }
    }
}

fn originals(owner: &Arc<Session>) -> Result<(Arc<AppleKeySession>, Arc<OriginalWork>, Arc<AppleDistributionKeyLoan>, Arc<wire::RequestBinding>), BridgeError> {
    let parent = original(owner)?.clone();
    let asset = parent.original.get().and_then(Weak::upgrade).ok_or_else(invalid)?;
    let loan = parent.loan.get().and_then(Weak::upgrade).ok_or_else(invalid)?;
    let request = parent.binding.get().ok_or_else(invalid)?.clone();
    if !(parent.mode.certificate() || parent.mode.p12()) || !parent.same_asset(&asset)
        || !parent.source_returned.load(Ordering::SeqCst) || parent.clock.interrupted()
        || owner.resource_unknown.load(Ordering::SeqCst)
        || request.scope.certificate.as_ref().is_none_or(|scope| scope.source_key != loan.reference()) {
        return Err(invalid());
    }
    owner.apple.input()?.current()?;
    Ok((parent, asset, loan, request))
}

pub(in crate::saved_command_owner) fn key_ack(owner: &Arc<Session>, sequence: u32, input: wire::CertificateKeyInput) -> Result<Vec<u8>, BridgeError> {
    let (parent, asset, loan, binding) = originals(owner)?;
    if sequence != 1 || !loan.matches_public_material(&asset, input.csr.as_bytes(), &input.spki) {
        return Err(invalid());
    }
    let scope = binding.scope.certificate.as_ref().ok_or_else(invalid)?;
    // A restored NEW reference never relabels the old row. Before acknowledging
    // the key phase (and therefore before provider inventory), prove BOTH the
    // original CSR bytes and full-SPKI hash using this SAME fresh loan check.
    if !scope.prior_key_matches(parent.mode, &input.csr_sha256, &input.public_key_sha256) {
        return Err(invalid());
    }
    let history = scope.key_preparation.as_ref().filter(|history|
        history.csr_sha256 == input.csr_sha256 && history.public_key_sha256 == input.public_key_sha256)
        .map(|history| history.update_sha256.clone());
    if parent.mode == wire::Mode::CertificateCreate && history.is_none() { return Err(invalid()); }
    let bytes = wire::certificate_reply(&binding, sequence, "certificate-key", json!({
        "keySha256":input.payload_sha256,"csrSha256":input.csr_sha256,
        "publicKeySha256":input.public_key_sha256,"keySavedAckSha256":history}))?.0;
    owner.apple.input()?.current()?;
    let mut facts = state(&parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    if facts.key.is_some() { return Err(invalid()); }
    facts.key = Some(PublicKey { csr: input.csr, spki: input.spki, csr_sha256: input.csr_sha256,
        spki_sha256: input.public_key_sha256, history_sha256: history });
    Ok(bytes)
}

/// Detached history only after the original writer, worker, native jobs and
/// private source retirement. Retained public Facts alone are not a receipt.
pub(in crate::saved_command_owner) fn recovery_history(owner: &Session,
    account: &crate::apple_provisioning_journal::AccountSnapshot,
    binding: &Arc<wire::RequestBinding>) -> Option<wire::CertificateRecoveryHistory> {
    let parent = original(owner).ok()?;
    if parent.mode != wire::Mode::CertificateReview || !parent.same_binding(binding)
        || !parent.owner.upgrade().is_some_and(|same| std::ptr::eq(same.as_ref(), owner))
        || !parent.source_returned.load(Ordering::SeqCst) || !parent.worker_joined.load(Ordering::SeqCst)
        || !parent.all_jobs_joined.load(Ordering::SeqCst) || !parent.private_drained.load(Ordering::SeqCst)
        || !parent.clock.completed() || owner.resource_unknown.load(Ordering::SeqCst)
        || !owner.apple.certificate_key_returned() { return None; }
    let facts = state(parent).ok()?.facts.try_lock().ok()?;
    let key = facts.key.as_ref()?;
    wire::certificate_recovery_history(account, &binding.scope, Some((&key.csr_sha256, &key.spki_sha256))).ok()
}

pub(in crate::saved_command_owner) fn identities_ack(owner: &Arc<Session>, sequence: u32, input: wire::CertificateIdentityInput) -> Result<Vec<u8>, BridgeError> {
    let (parent, asset, loan, binding) = originals(owner)?;
    let (spki_sha256, csr, spki) = {
        let facts = state(&parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
        let key = facts.key.as_ref().ok_or_else(invalid)?;
        if input.batch != facts.batch.as_ref().map_or(1, |batch| batch.number + 1)
            || input.batch > 2 || facts.policy.is_some()
            || input.batch == 2 && (!facts.pending || parent.mode != wire::Mode::CertificateCreate) {
            return Err(invalid());
        }
        (hash(&key.spki_sha256)?, key.csr.clone(), key.spki.clone())
    };
    if !loan.matches_public_material(&asset, csr.as_bytes(), &spki) { return Err(invalid()); }
    let now = SystemTime::now();
    let checked = now.duration_since(UNIX_EPOCH).map_err(|_| invalid())?.as_secs();
    let team: [u8; 10] = binding.scope.target.team_id.as_bytes().try_into().map_err(|_| invalid())?;
    let mut selected = None;
    let mut ambiguous = false;
    let seen = input.certificates.len();
    for row in input.certificates {
        let comparison = inspect_distribution_certificate_candidate(&row.der, &team, &spki_sha256, now,
            &mut || parent.clock.interrupted() || owner.resource_unknown.load(Ordering::SeqCst));
        match comparison {
            Ok(candidate) if row.certificate_type == "DISTRIBUTION" && candidate.not_after_unix_seconds() == row.expires_at => {
                let facts = Selected { id: row.resource_id, sha256: hex(candidate.certificate_sha256()),
                    before: candidate.not_before_unix_seconds(), after: candidate.not_after_unix_seconds(), der: row.der };
                if selected.is_some() { ambiguous = true; } else { selected = Some(facts); }
            }
            Err(CertificateCandidateFailure::Interrupted) => return Err(invalid()),
            // Other-key metadata is not an absence assertion: ALL account
            // certificate rows remain in the original core reuse-first plan.
            Err(CertificateCandidateFailure::PublicKeyMismatch | CertificateCandidateFailure::NotCurrentAtComparison) => {},
            _ => ambiguous = true, // unsupported/malformed/other purpose never permits issuance.
        }
    }
    if ambiguous { selected = None; }
    let projection = selected.as_ref().map(|row| json!({"resourceId":row.id,
        "certificateSha256":row.sha256,"notBefore":row.before,"notAfter":row.after}));
    let (bytes, digest) = wire::certificate_reply(&binding, sequence, "certificate-identities", json!({
        "identitySha256":input.payload_sha256,"batch":input.batch,"seen":seen,"ambiguous":ambiguous,
        "selected":projection,"checkedAt":checked}))?;
    owner.apple.input()?.current()?;
    let mut facts = state(&parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    if input.batch != facts.batch.as_ref().map_or(1, |batch| batch.number + 1) { return Err(invalid()); }
    facts.batch = Some(Batch { number: input.batch, seen, ambiguous, selected, ack_sha256: digest, checked_at: checked });
    Ok(bytes)
}

pub(in crate::saved_command_owner) fn policy_ack(owner: &Arc<Session>, sequence: u32, input: wire::CertificatePolicyInput, digest: String) -> Result<Vec<u8>, BridgeError> {
    let (parent, asset, loan, binding) = originals(owner)?;
    let mut facts = state(&parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let key = facts.key.as_ref().ok_or_else(invalid)?;
    let batch = facts.batch.as_ref().ok_or_else(invalid)?;
    let selected = batch.selected.as_ref().ok_or_else(invalid)?;
    let at = crate::apple_provisioning_journal::profile_unix_micros(&input.checked_at).ok_or_else(invalid)? / 1_000_000;
    let now = current_time()?;
    if facts.policy.is_some() || batch.ambiguous || input.identity_ack_sha256 != batch.ack_sha256
        || input.certificate_sha256 != selected.sha256 || input.public_key_sha256 != key.spki_sha256
        || input.team_id != binding.scope.target.team_id || input.request_binding_sha256 != binding.certificate_digest()
        || at < batch.checked_at || at > now || now.saturating_sub(at) > 300
        || selected.before > at || now >= selected.after
        || !loan.matches_public_material(&asset, key.csr.as_bytes(), &key.spki) { return Err(invalid()); }
    let bytes = wire::certificate_reply(&binding, sequence, "certificate-policy", json!({
        "policySha256":digest,"certificateSha256":selected.sha256}))?.0;
    // This only acknowledges the fixed worker's provisional proof DATA. The
    // sole constructor below waits for ALL actual original producer joins.
    facts.policy = Some(input);
    Ok(bytes)
}

pub(in crate::saved_command_owner) fn current_pending(owner: &Arc<Session>, intent: &CertificateIssuanceIntent) -> Result<(), BridgeError> {
    let (parent, asset, loan, binding) = originals(owner)?;
    let facts = state(&parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    let key = facts.key.as_ref().ok_or_else(invalid)?;
    let batch = facts.batch.as_ref().ok_or_else(invalid)?;
    if parent.mode != wire::Mode::CertificateCreate || facts.policy.is_some() || batch.number != 1
        || batch.ambiguous || batch.selected.is_some() || key.history_sha256.is_none()
        || intent.context != binding.scope.provisioning || intent.source_key != loan.reference()
        || intent.csr_sha256 != key.csr_sha256 || intent.public_key_sha256 != key.spki_sha256
        || !loan.matches_public_material(&asset, key.csr.as_bytes(), &key.spki) { return Err(invalid()); }
    Ok(())
}
pub(in crate::saved_command_owner) fn pending_ack(owner: &Arc<Session>, ack: &CertificateJournalAck) -> Result<(), BridgeError> {
    current_pending(owner, ack.original.intent())?;
    if ack.row.update.sequence != 1 || ack.row.native_settlement != NativeSettlement::Pending
        || ack.row.update.receipt.is_some() { return Err(invalid()); }
    let parent = original(owner)?;
    let mut facts = state(parent)?.facts.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
    if facts.pending { return Err(invalid()); }
    facts.pending = true;
    Ok(())
}

/// Invoked only from the existing native finish path AFTER the actual original
/// worker/IO/runtime/driver joins and BEFORE Asset loan release. No DTO or ACK
/// calls it. A nonpositive/cancelled outcome simply has no association.
pub(in crate::saved_command_owner) fn producer_joined(owner: &Arc<Session>, result: Option<&wire::CertificateResult>) -> Result<(), BridgeError> {
    if !original(owner)?.mode.certificate() { return Err(invalid()); }
    positive_joined(owner,result.filter(|value|value.positive_identity()).and_then(|value|value.certificate_id.as_deref()),None)
}
/// Same sole producer; P12 supplies its own typed result, never a fabricated
/// certificate terminal or a holder transferred from an earlier operation.
pub(in crate::saved_command_owner) fn producer_joined_p12(owner:&Arc<Session>,result:Option<&wire::P12Result>)->Result<(),BridgeError> {
    if !original(owner)?.mode.p12() {return Err(invalid());}
    let positive=result.filter(|value|value.positive_identity());
    positive_joined(owner,positive.and_then(|value|value.certificate_id.as_deref()),
        positive.and_then(|value|value.certificate_sha256.as_deref().zip(value.public_key_sha256.as_deref())))
}
fn positive_joined(owner:&Arc<Session>,id:Option<&str>,hashes:Option<(&str,&str)>)->Result<(),BridgeError> {
    let parent=original(owner)?;
    if !parent.worker_joined.load(Ordering::SeqCst) {return Err(BridgeError::cleanup_unknown());}
    let Some(id)=id else{return Ok(());};
    let (_,asset,loan,binding)=originals(owner)?;
    let mut facts=state(parent)?.facts.try_lock().map_err(|_|BridgeError::cleanup_unknown())?;
    let key=facts.key.as_ref().ok_or_else(invalid)?;
    if facts.policy.is_none() || !loan.matches_public_material(&asset,key.csr.as_bytes(),&key.spki)
        || binding.scope.certificate.as_ref().is_none_or(|scope|
            !scope.prior_key_matches(parent.mode,&key.csr_sha256,&key.spki_sha256)) {return Err(invalid());}
    let spki_sha256=key.spki_sha256.clone();
    let selected=facts.batch.as_mut().and_then(|batch|batch.selected.take()).ok_or_else(invalid)?;
    if id!=selected.id || current_time()? >= selected.after
        || hashes.is_some_and(|(leaf,spki)|leaf!=selected.sha256 || spki!=spki_sha256) {return Err(invalid());}
    state(parent)?.association.set(AppleDistributionCertificateBinding {
        parent:Arc::downgrade(parent),original:Arc::downgrade(&asset),loan:Arc::downgrade(&loan),
        request:binding,certificate:selected,public_key_sha256:spki_sha256,
    }).map_err(|_|invalid())
}
pub(super) fn confirms_p12(parent:&Arc<AppleKeySession>,original:&Arc<OriginalWork>,loan:&Arc<AppleDistributionKeyLoan>,
    request:&Arc<wire::RequestBinding>,leaf:&str,spki:&str)->bool {
    parent.mode.p12() && state(parent).ok().and_then(|state|state.association.get())
        .is_some_and(|binding|binding.confirms_p12(parent,original,loan,request,leaf,spki))
}

pub(in crate::saved_command_owner) fn native_joined(owner: &Arc<Session>, native_use: Arc<NativeUse>, reservation: Arc<CertificateOriginalReservation>) -> Result<AppleCertificateNativeJoined, BridgeError> {
    let parent = original(owner)?;
    if !parent.mode.certificate() || !parent.worker_joined.load(Ordering::SeqCst)
        || owner.resource_unknown.load(Ordering::SeqCst) || parent.phase() != Some(SavePhase::ReturnedRefused)
        || reservation.intent().context != owner.apple.request_binding()?.scope.provisioning {
        return Err(BridgeError::cleanup_unknown());
    }
    Ok(AppleCertificateNativeJoined { native_use, reservation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    fn session(mode: wire::Mode) -> (SavedCommandOwner, Arc<Session>) {
        let mut data = json!({"projectId":"project-1","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":123,"sha256":"3".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":45,"sha256":"4".repeat(64),"name":"1.2.3","build":7},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,
            "executionMode":"local","platform":"ios","mode":mode,
            "reference":null,"newApplication":false,"displayName":"Synthetic"});
        if mode.certificate() {
            data["keyRecordId"] = json!("a".repeat(32));
            data["keyRecordRevision"] = json!(1);
            if mode != wire::Mode::CertificateReview {
                data["reference"] = json!({"operationId":"8".repeat(32),"ownerGeneration":"9".repeat(32)});
            }
        }
        let context = wire::prepare(&data).unwrap().context;
        let application = SavedCommandOwner::new(RuntimeConfig::packaged("/unopened-certificate-runtime".into()),
            SavedCommandDomain::AppleProvisioning);
        crate::saved_command_owner::tests::active_with_context(application, Context::AppleProvisioning(context))
    }

    // These are the real fixed write future and original Session's STOP/cutoff
    // watches, with memory IO only. No private phase, permit or native join is
    // invented; route entry and actual driver/IO finality remain separate.
    #[tokio::test]
    async fn certificate_ack_stop_before_write_refuses_false_but_audit_latches_original_cut() {
        for stopped in [false, true] {
            let (application, owner) = session(wire::Mode::CertificateCreate);
            application.inner.stop(&owner, Reason::Cancelled);
            let first = application.inner.lock().active.as_ref().unwrap().first_stop;
            let cutoff = *owner.native_audit_cutoff.borrow();
            let (mut writer, mut reader) = duplex(64);
            assert_eq!(write_ack(&owner, &mut writer, b"one-ack\n", stopped).await, stopped);
            drop(writer);
            let mut bytes = Vec::new(); reader.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes.as_slice(), if stopped { b"one-ack\n".as_slice() } else { &[] });
            assert_eq!(*owner.native_audit_cutoff.borrow(), cutoff);
            assert_eq!(application.inner.lock().active.as_ref().unwrap().first_stop, first);
            assert!(*owner.stop.borrow());
        }
    }

    #[tokio::test]
    async fn certificate_ack_stop_after_write_start_keeps_partial_unreturned() {
        let (application, owner) = session(wire::Mode::CertificateCreate);
        let (mut writer, mut reader) = duplex(4);
        let write = write_ack(&owner, &mut writer, b"never-replay-this-ack\n", false);
        let stop = async {
            let mut prefix = [0; 4]; reader.read_exact(&mut prefix).await.unwrap();
            application.inner.stop(&owner, Reason::Cancelled);
            prefix
        };
        let (returned, prefix) = tokio::join!(write, stop);
        assert!(!returned); assert_eq!(&prefix, b"neve");
        assert_eq!(application.inner.lock().active.as_ref().unwrap().projection.reason, Reason::Cancelled);
        assert!(*owner.stop.borrow());
        // The writer remains the caller's same object; this function neither
        // shuts down nor replaces it or claims the original reader joined.
    }

    #[tokio::test]
    async fn certificate_audit_partial_write_observes_shortened_cutoff_or_unknown() {
        for unknown in [false, true] {
            let (application, owner) = session(wire::Mode::CertificateCreate);
            application.inner.stop(&owner, Reason::Cancelled);
            let (mut writer, mut reader) = duplex(4);
            let write = write_ack(&owner, &mut writer, b"stopped-audit-tail\n", true);
            let narrow = async {
                let mut prefix = [0; 4]; reader.read_exact(&mut prefix).await.unwrap();
                if unknown {
                    owner.resource_unknown.store(true, Ordering::SeqCst);
                    owner.wake.notify_waiters();
                } else { owner.native_audit_cutoff.send_replace(Instant::now()); }
                prefix
            };
            let (returned, prefix) = tokio::join!(write, narrow);
            assert!(!returned); assert_eq!(&prefix, b"stop");
            assert!(*owner.stop.borrow());
        }
    }

    #[tokio::test]
    async fn certificate_ack_does_not_open_another_mode_or_ignore_unknown() {
        for mode in [wire::Mode::Review, wire::Mode::CertificateReview] {
            let (_, owner) = session(mode);
            if mode.certificate() { owner.resource_unknown.store(true, Ordering::SeqCst); }
            let (mut writer, mut reader) = duplex(64);
            assert!(!write_ack(&owner, &mut writer, b"no-write\n", true).await);
            drop(writer);
            let mut bytes = Vec::new(); reader.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty());
        }
    }
}
