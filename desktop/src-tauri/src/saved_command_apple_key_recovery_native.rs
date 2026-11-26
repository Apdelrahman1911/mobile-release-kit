//! KeyRecover uses the existing eleven-job ledger, verifier and Asset loan.
//! This is a fixed finish branch, not an executor or recovered native owner.
use super::super::super::apple_key::{self as key, recovery};
use super::*;

pub(super) async fn finish(inner: &Arc<Inner>, owner: &Arc<Session>) -> bool {
    {
        let book = owner.resources.lock().await;
        if !worker_joined(inner, owner, &book) {
            return false;
        }
    }
    {
        let jobs = owner.apple.native.lock().await;
        if jobs.sealed || !jobs.pre_joined() {
            return false;
        }
    }
    if key::producer_joined(owner, None).is_err() {
        return false;
    }
    let mut positive = {
        let registry = inner.lock();
        registry.active.as_ref().is_some_and(|active| {
            original_session(&registry, owner)
                && !active.unknown
                && active.first_stop.is_none()
                && active.projection.outcome == Some(Outcome::Complete)
        })
    };
    if positive {
        let checked = async {
            recovery::post_worker_clear(inner, owner)?;
            owner.apple.input()?.check_key_recovery_source().await?;
            recovery::source_returned(owner)?;
            recovery::post_worker_clear(inner, owner)
        }
        .await;
        if let Err(error) = checked {
            local_error(owner, error);
            positive = false;
        }
    }
    if owner.resource_unknown.load(Ordering::SeqCst) || key::dispatch_save(owner, None).is_err() {
        return false;
    }
    // None alone means nothing: this is the actual same original Asset
    // coordinator/child/source join, followed later by its private retirement.
    if !matches!(key::join_asset(owner).await, Ok(None)) {
        return false;
    }
    let mut jobs = owner.apple.native.lock().await;
    let lease = {
        let Ok(hold) = jobs.hold.try_lock() else {
            return false;
        };
        match (&hold.lease, &hold.journal) {
            (Some(lease), Some(journal)) if journal.is_for(lease.store(), lease.native_use()) => {
                Some(lease.clone())
            }
            (None, None) => None,
            _ => return false,
        }
    };
    let Some(lease) = lease else {
        jobs.sealed = true;
        jobs.complete = jobs.slots.iter().all(Slot::known);
        return jobs.complete;
    };
    if positive {
        let checked = (|| {
            recovery::post_worker_clear(inner, owner)?;
            let binding = owner.apple.request_binding()?;
            let selected = binding
                .scope
                .key
                .as_ref()
                .and_then(|key| key.recovery.as_ref())
                .ok_or_else(apple_wire::invalid)?;
            if selected.needs_record() {
                let (record, proof) = recovery::verified(inner, owner, lease.native_use().clone())?;
                Ok(Some((binding.revision, record, proof)))
            } else {
                Ok(None)
            }
        })();
        match checked {
            Ok(Some((revision, record, proof))) => {
                if call(
                    inner,
                    owner,
                    &mut jobs,
                    PROFILE_FINISH,
                    Call::KeyRecover(revision, record, proof),
                )
                .await
                .is_err()
                    && owner.resource_unknown.load(Ordering::SeqCst)
                {
                    return false;
                }
            }
            Ok(None) => {}
            Err(error) => {
                local_error(owner, error);
            }
        }
    }
    if owner.resource_unknown.load(Ordering::SeqCst) || !jobs.slots.iter().all(Slot::known) {
        return false;
    }
    jobs.sealed = true;
    let joined = AppleProvisioningAllJobsJoined {
        native_use: lease.native_use().clone(),
    };
    if call(
        inner,
        owner,
        &mut jobs,
        PROFILE_RETIRE,
        Call::Retire(joined),
    )
    .await
    .is_err()
    {
        return false;
    }
    jobs.complete = jobs.slots.iter().all(Slot::known)
        && matches!(
            jobs.slots[PROFILE_RETIRE].returned.as_ref(),
            Some(Ok(Value::Retired))
        )
        && !owner.resource_unknown.load(Ordering::SeqCst);
    jobs.complete
}
