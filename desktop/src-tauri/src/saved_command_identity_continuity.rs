//! A bounded, read-only continuity veto in the SAME original SavedCommandOwner.
//! No persistence, provider lookup, Store absence, current eligibility or new
//! finality is inferred. Old identities survive display/context replacement.
use super::*;
use crate::project_identity_edit_protocol::Platform as IdentityPlatform;

const MAX_VETOES: usize = 128; // At least the fixed64-project ×2-platform picker.
const PROJECT_BYTES: usize = 128;
const IDENTITY_BYTES: usize = 255;

struct Binding {
    project_id: String,
    registration: u32,
    root: RegisteredRoot,
    platform: IdentityPlatform,
    identity: String,
}
impl Binding {
    fn matches(&self, project_id: &str, root: &RegisteredRoot, platform: IdentityPlatform) -> bool {
        // Registration is GLOBAL roster provenance, not a per-project epoch.
        // Picking an unrelated project must never turn a retained veto into
        // Unknown. Full original root + project + platform still match.
        self.project_id == project_id && &self.root == root && self.platform == platform
    }
    fn bounded(&self) -> bool {
        self.registration != 0
            && crate::protocol::valid_id(&self.project_id)
            && self.project_id.capacity() <= PROJECT_BYTES
            && self.root.path.capacity() <= crate::asset_source::PATH_LIMIT
            && !self.identity.is_empty()
            && self.identity.capacity() <= IDENTITY_BYTES
    }
}
#[derive(Default)]
pub(super) struct Vetoes {
    rows: Vec<Binding>,
    exhausted: bool,
}
impl Vetoes {
    /// Called only after original positive watchdog return, material retirement,
    /// final-clock inspection and active-pointer comparison in reconcile().
    pub(super) fn record_original(&mut self, active: &Active, owner: &Arc<Session>) {
        if !Arc::ptr_eq(&active.owner, owner)
            || !active.accepted
            || !active.terminal
            || !active.final_join_seen
            || active.unknown
            || active.projection.phase != Phase::Terminal
            || active.projection.outcome != Some(Outcome::Complete)
            || active.projection.reason != Reason::None
            || active.projection.context != owner.context
            || active.projection.operation_id != owner.id
            || active.projection.owner_generation != owner.generation
            || !owner.watchdog_joined.load(Ordering::SeqCst)
            || owner.watchdog_failed.load(Ordering::SeqCst)
            || owner.resource_unknown.load(Ordering::SeqCst)
            || owner.manager_failed.load(Ordering::SeqCst)
            || !owner.material_retired.load(Ordering::SeqCst)
            || !owner
                .watchdog_return
                .lock()
                .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(true))))
        {
            return;
        }
        let Some(terminal) = &active.projection.result else {
            return;
        };
        let (platform, identity) = match (owner.domain, &owner.context, terminal) {
            (
                SavedCommandDomain::LocalStoreExecute,
                Context::LocalStoreExecute(context),
                Terminal::LocalStoreExecute(result),
            ) => {
                let Some(identity) = result.known_existing_identity(context) else {
                    return;
                };
                (
                    if context.platform == execute_wire::Platform::Ios {
                        IdentityPlatform::Ios
                    } else {
                        IdentityPlatform::Android
                    },
                    identity,
                )
            }
            (
                SavedCommandDomain::LocalStoreReconcile,
                Context::LocalStoreReconcile(context),
                Terminal::LocalStoreReconcile(result),
            ) => {
                let Some(identity) = result.known_existing_identity(context) else {
                    return;
                };
                (
                    if context.platform == reconcile_wire::Platform::Ios {
                        IdentityPlatform::Ios
                    } else {
                        IdentityPlatform::Android
                    },
                    identity,
                )
            }
            _ => return, // Access checks/history files/errors/empty results prove no absence or existence here.
        };
        if owner.context.project_id().len() > PROJECT_BYTES
            || owner.project.path.as_os_str().as_encoded_bytes().len()
                > crate::asset_source::PATH_LIMIT
            || identity.len() > IDENTITY_BYTES
        {
            self.exhausted = true;
            return;
        }
        self.retain(Binding {
            project_id: owner.context.project_id().to_owned(),
            registration: owner.registration,
            root: owner.project.clone(),
            platform,
            identity: identity.to_owned(),
        });
    }
    fn retain(&mut self, binding: Binding) {
        if !binding.bounded() {
            self.exhausted = true;
            return;
        }
        if self.rows.iter().any(|row| {
            row.matches(&binding.project_id, &binding.root, binding.platform)
                && row.identity == binding.identity
        }) {
            return;
        }
        if self.exhausted || self.rows.len() == MAX_VETOES {
            self.exhausted = true;
            return;
        }
        if self.rows.capacity() == 0 {
            // Allocate the fixed row array once, never grow it behind the
            // original Document's two-owner reservation. This is not a reset:
            // the first allocation has no history, and failure stays sticky.
            if self.rows.try_reserve_exact(MAX_VETOES).is_err() {
                self.exhausted = true;
                return;
            }
            if self.rows.capacity() != MAX_VETOES {
                self.rows = Vec::new();
                self.exhausted = true;
                return;
            }
        }
        self.rows.push(binding);
    }
    fn known(
        &self,
        project_id: &str,
        registration: u32,
        root: &RegisteredRoot,
        platform: IdentityPlatform,
    ) -> Result<bool, BridgeError> {
        if registration == 0 {
            return Err(BridgeError::cleanup_unknown());
        }
        if self
            .rows
            .iter()
            .any(|row| row.matches(project_id, root, platform))
        {
            return Ok(true);
        }
        if self.exhausted {
            return Err(BridgeError::new("project_identity_history_full",
            "Application identity changes are unavailable because the retained Store history limit was reached."));
        }
        Ok(false) // UNKNOWN only; not proof that any identity is new/available.
    }
}

/// Root must charge this fixed reservation ONCE in the existing global
/// Document census, including when both Store owners are idle. It covers both
/// sticky tables, their fixed row capacity, bounded owned strings/path and one
/// incoming row per owner. Registry inline bytes alone do not cover this heap.
pub(crate) fn document_backing_bytes() -> Option<usize> {
    let row = std::mem::size_of::<Binding>()
        .checked_add(PROJECT_BYTES)?
        .checked_add(crate::asset_source::PATH_LIMIT)?
        .checked_add(IDENTITY_BYTES)?;
    let owner = (MAX_VETOES + 1)
        .checked_mul(row)?
        .checked_add(std::mem::size_of::<Vetoes>())?;
    owner.checked_mul(2)
}
impl SavedCommandOwner {
    /// Exact native registration + selected platform, not renderer result DATA.
    /// A true result is a veto only. Errors MUST refuse admission, not become
    /// Unknown. The original document must still perform all its usual gates.
    pub(crate) fn known_existing_identity(
        &self,
        project_id: &str,
        registration: u32,
        root: &RegisteredRoot,
        platform: IdentityPlatform,
    ) -> Result<bool, BridgeError> {
        if !matches!(
            self.inner.domain,
            SavedCommandDomain::LocalStoreExecute | SavedCommandDomain::LocalStoreReconcile
        ) || !crate::protocol::valid_id(project_id)
        {
            return Err(BridgeError::invalid());
        }
        self.reconcile(); // Joins only the original already-retained watchdog.
        let r = self.inner.lock();
        if r.disabled || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        r.identity_vetoes
            .known(project_id, registration, root, platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> RegisteredRoot {
        RegisteredRoot {
            path: std::path::PathBuf::from("/inert-identity-veto-never-opened"),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        }
    }
    fn binding(id: &str, identity: &str) -> Binding {
        Binding {
            project_id: id.to_owned(),
            registration: 7,
            root: root(),
            platform: IdentityPlatform::Android,
            identity: identity.to_owned(),
        }
    }
    #[test]
    fn identity_veto_is_sticky_and_exact_project_root_and_platform_bound() {
        // Private table DATA, no fabricated original completion/native receipt.
        let project = "a".repeat(32);
        let mut table = Vetoes::default();
        assert!(!table
            .known(&project, 7, &root(), IdentityPlatform::Android)
            .unwrap());
        table.retain(binding(&project, "com.example.original"));
        table.retain(binding(&project, "com.example.original"));
        table.retain(binding(&project, "com.example.second"));
        assert_eq!(table.rows.len(), 2);
        assert!(table
            .known(&project, 7, &root(), IdentityPlatform::Android)
            .unwrap());
        assert_eq!(table.rows[0].identity, "com.example.original");
        assert!(table
            .known(&project, 8, &root(), IdentityPlatform::Android)
            .unwrap());
        assert!(!table
            .known(&"b".repeat(32), 7, &root(), IdentityPlatform::Android)
            .unwrap());
        assert!(!table
            .known(&project, 7, &root(), IdentityPlatform::Ios)
            .unwrap());
        let mut replacement = root();
        replacement.path = "/inert-other-root-never-opened".into();
        assert!(!table
            .known(&project, 7, &replacement, IdentityPlatform::Android)
            .unwrap());
        replacement = root();
        replacement.identity = crate::asset_source::ProjectIdentity::Windows {
            volume: 1,
            file_id: [0; 16],
        };
        assert!(!table
            .known(&project, 7, &replacement, IdentityPlatform::Android)
            .unwrap());
    }
    #[test]
    fn unrelated_roster_generation_change_never_clears_published_continuity() {
        let project = "a".repeat(32);
        let mut table = Vetoes::default();
        table.retain(binding(&project, "com.example.original"));
        for generation in [1, 7, 8, 100, u32::MAX] {
            assert!(table
                .known(&project, generation, &root(), IdentityPlatform::Android)
                .unwrap());
        }
        let mut later = binding(&project, "com.example.original");
        later.registration = 8;
        table.retain(later);
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].registration, 7); // Original provenance retained.
        assert!(table
            .known(&project, 0, &root(), IdentityPlatform::Android)
            .is_err());
    }
    #[test]
    fn fixed_two_owner_heap_reservation_and_overcap_refusal_preserve_old_rows() {
        let reserved = document_backing_bytes().unwrap();
        assert!(reserved > 2 * MAX_VETOES * crate::asset_source::PATH_LIMIT);
        assert!(reserved < 2 * 1024 * 1024);
        let project = "a".repeat(32);
        for overflow in 0..3 {
            let mut table = Vetoes::default();
            table.retain(binding(&project, "com.example.original"));
            let mut bad = binding(&"b".repeat(32), "com.example.other");
            match overflow {
                0 => bad.project_id.reserve(PROJECT_BYTES + 1),
                1 => bad.root.path.reserve(crate::asset_source::PATH_LIMIT + 1),
                _ => bad.identity.reserve(IDENTITY_BYTES + 1),
            }
            table.retain(bad);
            assert!(table.exhausted);
            assert_eq!(table.rows.len(), 1);
            assert!(table
                .known(&project, 9, &root(), IdentityPlatform::Android)
                .unwrap());
            assert!(table
                .known(&"b".repeat(32), 9, &root(), IdentityPlatform::Android)
                .is_err());
        }
    }
    #[test]
    fn identity_veto_bound_exhaustion_never_evicts_history_or_returns_false_absence() {
        let mut table = Vetoes::default();
        for n in 1..=MAX_VETOES {
            table.retain(binding(&format!("{n:032x}"), "com.example.original"));
        }
        let next = format!("{:032x}", MAX_VETOES + 1);
        table.retain(binding(&next, "com.example.another"));
        assert_eq!(table.rows.len(), MAX_VETOES);
        assert!(table
            .known(
                &format!("{:032x}", 1),
                7,
                &root(),
                IdentityPlatform::Android
            )
            .unwrap());
        assert!(table
            .known(&next, 7, &root(), IdentityPlatform::Android)
            .is_err());
        table.retain(binding(&format!("{:032x}", 1), "com.example.original"));
        assert!(table
            .known(&next, 7, &root(), IdentityPlatform::Android)
            .is_err());
    }
    #[test]
    fn ordinary_display_context_changes_do_not_clear_retained_vetoes() {
        // No prepare/start/entropy/tasks/native inspection; exact owner table
        // lifetime only. These predicates are not installed Store qualification.
        let saved = SavedCommandOwner::local_store_execute(RuntimeConfig::packaged(
            std::path::PathBuf::from("/inert-identity-veto-runtime-never-opened"),
        ));
        let project = "a".repeat(32);
        saved
            .inner
            .lock()
            .identity_vetoes
            .retain(binding(&project, "com.example.original"));
        saved.context_changed();
        assert!(saved
            .known_existing_identity(&project, 7, &root(), IdentityPlatform::Android)
            .unwrap());
        saved.inner.lock().last = None;
        assert!(saved
            .known_existing_identity(&project, 7, &root(), IdentityPlatform::Android)
            .unwrap());
        saved.document_lost();
        assert!(saved
            .inner
            .lock()
            .identity_vetoes
            .known(&project, 7, &root(), IdentityPlatform::Android)
            .unwrap());
    }
}
