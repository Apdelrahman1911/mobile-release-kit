//! Census of the SAME Apple registry's retained inputs. No currentness query,
//! status projection, expiration, native receipt or new material loan is made.
use super::*;
use crate::asset_session::{AppleProvisioningDocumentInput as Input, OriginalWork};

struct Root {
    input: Arc<Input>,
    profile: Option<Arc<OriginalWork>>,
    key: Option<Arc<OriginalWork>>,
}

pub(crate) struct Snapshot {
    // The prior review and the current preparation are the only distinct
    // input allocations. Consumed reviews alias the prior input, not a third.
    roots: [Option<Root>; 2],
}

// Two move/return snapshots, the original registry guard and getter's two
// retained Arc cells. No Vec/history, cloning of material or new Seen table.
pub(super) const CONTROL_BYTES: usize = 2 * std::mem::size_of::<Snapshot>()
    + std::mem::size_of::<std::sync::MutexGuard<'static, super::super::Registry>>()
    + 2 * std::mem::size_of::<[Option<Arc<OriginalWork>>; 2]>()
    + 4 * std::mem::size_of::<usize>();
const _: () = assert!(CONTROL_BYTES <= 32 * 1024);

impl Snapshot {
    fn new() -> Self {
        Self {
            roots: [None, None],
        }
    }

    fn add(&mut self, input: &Arc<Input>) -> Result<(), BridgeError> {
        if self
            .roots
            .iter()
            .flatten()
            .any(|root| Arc::ptr_eq(&root.input, input))
        {
            return Ok(());
        }
        let slot = self
            .roots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(BridgeError::cleanup_unknown)?;
        let [profile, key] = input.census_assets()?;
        *slot = Some(Root {
            input: Arc::clone(input),
            profile,
            key,
        });
        Ok(())
    }

    fn intent(&mut self, intent: &Intent) -> Result<(), BridgeError> {
        self.add(&intent.input)?;
        if let Some(review) = &intent.review {
            self.add(&review.input)?;
        }
        if let Some(review) = &intent.profile_review {
            self.add(review.census_input())?;
        }
        if let Some(review) = &intent.key_review {
            self.add(review.census_input())?;
        }
        if let Some(review) = &intent.certificate_review {
            self.add(review.census_input())?;
        }
        if let Some(review) = &intent.p12_review {
            self.add(review.census_input())?;
        }
        Ok(())
    }

    fn active_matches(&self, owner: &Session, current: &Arc<OriginalWork>) -> bool {
        let Ok(input) = owner.apple.input() else {
            return false;
        };
        let Some(root) = self
            .roots
            .iter()
            .flatten()
            .find(|root| Arc::ptr_eq(&root.input, input))
        else {
            return false;
        };
        // Use the actual parent, including KeyRecover's AppleKeySession. A
        // mode label, operation ID or public phase cannot stand in for it.
        match (owner.apple_profile.get(), owner.apple_key.get()) {
            (Some(parent), None) => {
                parent.same_asset(current)
                    && root.key.is_none()
                    && root
                        .profile
                        .as_ref()
                        .is_some_and(|asset| Arc::ptr_eq(asset, current))
            }
            (None, Some(parent)) => {
                parent.same_asset(current)
                    && root.profile.is_none()
                    && root
                        .key
                        .as_ref()
                        .is_some_and(|asset| Arc::ptr_eq(asset, current))
            }
            _ => false,
        }
    }

    pub(crate) fn members(
        &self,
    ) -> impl Iterator<Item = (&Arc<Input>, Option<&Arc<OriginalWork>>)> {
        self.roots
            .iter()
            .flatten()
            .map(|root| (&root.input, root.profile.as_ref().or(root.key.as_ref())))
    }
}

impl SavedCommandOwner {
    pub(crate) fn apple_retained_census(
        &self,
        current: Option<&Arc<OriginalWork>>,
    ) -> Result<Snapshot, BridgeError> {
        if self.inner.domain != SavedCommandDomain::AppleProvisioning
            || self.inner.poisoned.load(Ordering::SeqCst)
        {
            return Err(BridgeError::cleanup_unknown());
        }
        // Do not use inner.lock/reconcile/snapshot_locked: those can publish,
        // stop or allocate status. Drop this guard before Source/vault visits.
        let registry = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if registry.disabled
            || registry.exhausted
            || registry.stopping
            || registry.document_lost
            || registry.prepared.is_some() && registry.active.is_some()
        {
            return Err(BridgeError::cleanup_unknown());
        }
        if registry.active.is_some() && current.is_none() {
            // Temporary NEW-admission refusal, including pre-attach/post-Asset
            // gaps. Status/cancel/retirement never use this accessor. No poison,
            // STOP, missing-input zero or blanket six-MiB fallback is published.
            return Err(self.inner.domain.busy());
        }
        let mut snapshot = Snapshot::new();
        let apple = &registry.apple;
        if let Some(review) = &apple.review {
            snapshot.add(&review.input)?;
        }
        if let Some(review) = &apple.profile_review {
            snapshot.add(review.census_input())?;
        }
        if let Some(review) = &apple.key_review {
            snapshot.add(review.census_input())?;
        }
        if let Some(review) = &apple.certificate_review {
            snapshot.add(review.census_input())?;
        }
        if let Some(review) = &apple.p12_review {
            snapshot.add(review.census_input())?;
        }
        if let Some(prepared) = &registry.prepared {
            let intent = prepared
                .apple
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?;
            if !matches!(&prepared.projection.context, Context::AppleProvisioning(context) if context == intent.input.context())
            {
                return Err(BridgeError::cleanup_unknown());
            }
            snapshot.intent(intent)?;
        }
        if let Some(active) = &registry.active {
            let owner = &active.owner;
            let intent = owner
                .apple
                .intent
                .as_ref()
                .ok_or_else(BridgeError::cleanup_unknown)?;
            if active.unknown
                || owner.resource_unknown.load(Ordering::SeqCst)
                || owner.domain != SavedCommandDomain::AppleProvisioning
                || !matches!(&owner.context, Context::AppleProvisioning(context) if context == intent.input.context())
            {
                return Err(BridgeError::cleanup_unknown());
            }
            snapshot.intent(intent)?;
            if !snapshot.active_matches(owner, current.ok_or_else(|| self.inner.domain.busy())?) {
                return Err(self.inner.domain.busy());
            }
        }
        drop(registry);
        Ok(snapshot)
    }
}

#[cfg(test)]
#[path = "saved_command_apple_memory_tests.rs"]
mod tests;
