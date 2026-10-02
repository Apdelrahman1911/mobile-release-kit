//! Allocation-free snapshot census for the explicit installation check.
//!
//! This is not a lookup Admission or a second lifecycle owner. The caller keeps
//! the original Document mutex and, BEFORE this function, refuses opaque external
//! picker-original/fixture histories through its separate read-only gates. The
//! snapshot covers document-retained DATA, not the global bridge, allocator,
//! renderer, SDK internals or whole-process RSS. Live/unknown native holdings are
//! refused, never measured as zero, disposed, polled, reconciled or retried here.
use super::*;

pub(super) fn admitted(state: &DocumentState, control: usize) -> Result<(), Reason> {
    // The one native/JSON/index/control partition is fixed, inside the unchanged
    // 64MiB session quota. A smaller caller value cannot create payload credit.
    if control != 16 * 1024 * 1024 { return Err(Reason::Capacity); }
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_arch = "aarch64")))]
    { known::admitted(state, control) }
    #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(target_os = "macos", target_arch = "aarch64"))))]
    { let _ = state; Err(Reason::Capacity) }
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "macos", target_arch = "aarch64")))]
mod known {
    use super::*;
    use std::{alloc::Layout, mem::size_of};

    const IDENTITIES: usize = 128;
    const ARC_CELLS: usize = 2 * size_of::<usize>();
    // Bounded existing document watch/notification cells. This is a conservative
    // control row, not inferred from serialized lengths or private token values.
    const SESSION_SIGNAL_BYTES: usize = 4 * 1024;
    type Count<T> = Result<T, Reason>;
    fn capacity<T>(value: Option<T>) -> Count<T> { value.ok_or(Reason::Capacity) }
    fn fits(live: usize, control: usize) -> Count<()> {
        if capacity(live.checked_add(control))? > SESSION_BYTES { return Err(Reason::Capacity); }
        Ok(())
    }
    fn arc_bytes<T>() -> Count<usize> {
        // Fixed value + two reference-count cells with alignment. Allocation
        // identity, not value equality, deduplicates this complete allocation.
        let (layout, _) = Layout::new::<[usize; 2]>().extend(Layout::new::<T>()).map_err(|_| Reason::Capacity)?;
        Ok(layout.pad_to_align().size())
    }
    struct Seen { ids: [usize; IDENTITIES], used: usize }
    impl Seen {
        fn new() -> Self { Self { ids: [0; IDENTITIES], used: 0 } }
        fn insert<T>(&mut self, value: &Arc<T>) -> Count<bool> {
            let id = Arc::as_ptr(value) as usize;
            if self.ids[..self.used].contains(&id) { return Ok(false); }
            if self.used == self.ids.len() { return Err(Reason::Capacity); }
            self.ids[self.used] = id; self.used += 1; Ok(true)
        }
    }
    struct Census { bytes: usize, seen: Seen }
    impl Census {
        fn new() -> Self { Self { bytes: 0, seen: Seen::new() } }
        fn add(&mut self, bytes: usize) -> Count<()> {
            let total = capacity(self.bytes.checked_add(bytes))?;
            if total > SESSION_BYTES { return Err(Reason::Capacity); }
            self.bytes = total; Ok(())
        }
        fn cells<T>(&mut self, count: usize) -> Count<()> { self.add(capacity(count.checked_mul(size_of::<T>()))?) }
        fn arc<T>(&mut self) -> Count<()> { self.add(arc_bytes::<T>()?) }
        fn heap<T>(&mut self, including_inline: Option<usize>) -> Count<()> {
            self.add(capacity(including_inline.and_then(|bytes| bytes.checked_sub(size_of::<T>())))?)
        }
        fn token(&mut self, token: &Token) -> Count<()> { self.add(token.0.capacity()) }
        fn key(&mut self, key: &RecordKey) -> Count<()> { self.token(&key.id) }
        fn context(&mut self, value: &Arc<NativeContext>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<NativeContext>()?;
            self.add(value.project_id.capacity())?; self.add(value.project.path.capacity())?; self.add(value.draft.capacity())
        }
        fn origin(&mut self, value: &Arc<OriginWitness>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<OriginWitness>()?; self.heap::<OriginWitness>(value.retained_bytes())
        }
        fn material(&mut self, value: &Arc<Material>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<Material>()?;
            // Count the original origin Arc separately: distinct Material values
            // may share it. Material::retained_bytes alone cannot deduplicate it.
            match &value.origin {
                MaterialOrigin::Selected(source) => { self.add(source.bytes.capacity())?; self.origin(&source.origin) },
                MaterialOrigin::Stored(source) => self.heap::<crate::vault_crypto::StoredBytes>(source.bytes.retained_bytes().ok()),
            }
        }
        fn payload(&mut self, value: &Arc<Payload>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<Payload>()?;
            // Preserve the existing conservative per-payload metadata allowance.
            // It covers the private bounded FileObservation projection; no
            // serializer, parser arena or logical string length is a heap proof.
            self.add(RECORD_METADATA_BYTES)?;
            if let Some(fields) = &value.fields { self.add(capacity(fields.retained_bytes())?)?; }
            if let Some(material) = &value.material { self.material(material)?; }
            Ok(())
        }
        fn assessment(&mut self, value: &SafeAssessment) -> Count<()> {
            if !self.seen.insert(&value.0)? { return Ok(()); }
            self.arc::<AssessmentResult>()?; self.heap::<AssessmentResult>(value.0.retained_bytes())
        }
        fn candidate(&mut self, value: &Candidate) -> Count<()> {
            self.payload(&value.payload)?; self.token(&value.record_id)?;
            if let Some(key) = &value.existing { self.key(key)?; } Ok(())
        }
        fn records(&mut self, values: &Vec<Record>) -> Count<()> {
            if values.len() > RECORD_LIMIT { return Err(Reason::Capacity); }
            self.cells::<Record>(values.capacity())?;
            for value in values { self.key(&value.key)?; self.payload(&value.payload)?; } Ok(())
        }
        fn assignments(&mut self, values: &Vec<Assignment>) -> Count<()> {
            if values.len() > RECORD_LIMIT { return Err(Reason::Capacity); }
            self.cells::<Assignment>(values.capacity())?;
            for value in values { self.token(&value.record_id)?; } Ok(())
        }
        fn evidence_binding(&mut self, value: &EvidenceBinding) -> Count<()> {
            self.add(value.selection_id.as_ref().map_or(0, String::capacity))
        }
        fn evidence(&mut self, value: &EvidenceRegistry) -> Count<()> {
            if matches!(value.phase, evidence_wire::Phase::Choosing | evidence_wire::Phase::Observing
                | evidence_wire::Phase::Stopping | evidence_wire::Phase::Unknown)
                || value.problem == Some(EvidenceProblem::CleanupUnknown) { return Err(Reason::Capacity); }
            if let Some(selection) = &value.selection {
                self.add(selection.view.selection_id.capacity())?; self.add(selection.view.display_name.capacity())?;
                self.add(selection.root.path.capacity())?;
            }
            if let Some(operation) = &value.operation { self.evidence_binding(operation)?; }
            if let Some(result) = &value.result {
                self.add(capacity(match result {
                    EvidenceResult::Candidate(value) => value.retained_heap_bytes(),
                    EvidenceResult::Lifecycle(value) => value.retained_heap_bytes(),
                })?)?;
            }
            Ok(())
        }
        fn project_path(&mut self, value: &Arc<ProjectPathBinding>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<ProjectPathBinding>()?; self.add(value.project_id.capacity())?; self.add(value.root.path.capacity())
        }
        fn android_source(&mut self, value: &Arc<AndroidSourceBinding>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<AndroidSourceBinding>()?; self.add(value.project_id.capacity())?; self.add(value.root.path.capacity())
        }
        fn image_binding(&mut self, value: &Arc<images::Binding>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<images::Binding>()?;
            // The existing checked helper already includes its inline value and
            // two Arc cells; do not charge that shared allocation twice.
            self.add(capacity(value.retained_bytes().and_then(|bytes|
                bytes.checked_sub(size_of::<images::Binding>())?.checked_sub(ARC_CELLS)))?)
        }
        fn vault_store(&mut self, value: &Arc<Mutex<crate::vault_store::StoreBook>>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            let book = value.try_lock().map_err(|_| Reason::Capacity)?;
            if (!book.not_started() && !book.operation_quiescent() && !book.settled())
                || book.problem() == Some(crate::vault_store::Problem::CleanupUnknown)
                || book.storage_outcome().is_some_and(|outcome| outcome.cleanup == crate::vault_store::Cleanup::Unknown) {
                return Err(Reason::Capacity);
            }
            self.arc::<Mutex<crate::vault_store::StoreBook>>()?;
            // StoreBook's helper includes its value, but not the outer Mutex/Arc.
            // The Mac helper itself refuses opaque pending/unknown ACL backing.
            self.heap::<crate::vault_store::StoreBook>(book.retained_bytes())
        }
        fn vault_key(&mut self, value: &Arc<crate::vault_crypto::VaultKey>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            self.arc::<crate::vault_crypto::VaultKey>()?;
            self.heap::<crate::vault_crypto::VaultKey>(Some(value.retained_bytes()))
        }
        fn vault_loan(&mut self, value: &vault::BoundLoan) -> Count<()> {
            self.context(&value.context)?; self.payload(&value.payload)?; self.vault_store(&value.store)?; self.vault_key(&value.key)
        }
        fn vault_session(&mut self, value: &vault::Session) -> Count<()> {
            self.heap::<vault::Session>(value.data_bytes())?; self.vault_store(value.store())?;
            if let Some(key) = value.key() { self.vault_key(key)?; }
            for loan in value.bound.iter().flatten() { self.vault_loan(loan)?; } Ok(())
        }
        fn gui(&mut self, value: &Arc<GuiCall>, owner: &Arc<OriginalWork>) -> Count<()> {
            if value.owner.as_ptr() != Arc::as_ptr(owner) { return Err(Reason::Capacity); }
            if !self.seen.insert(value)? { return Ok(()); }
            let facts = value.facts.try_lock().map_err(|_| Reason::Capacity)?;
            if facts.constructing || facts.showing || !facts.released
                || !(facts.not_created && !facts.created || facts.created && facts.destroyed && !facts.not_created)
                || facts.refusal == Some(Reason::CleanupUnknown) { return Err(Reason::Capacity); }
            self.arc::<GuiCall>()?;
            if let Some(path) = &facts.selected { self.add(path.capacity())?; }
            let selected = value.selected_images.try_lock().map_err(|_| Reason::Capacity)?;
            if let Some(paths) = &*selected {
                if paths.len() > crate::metadata_images_edit_protocol::MAX_FILES { return Err(Reason::Capacity); }
                self.cells::<std::path::PathBuf>(paths.capacity())?;
                for path in paths { self.add(path.capacity())?; }
            }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
                feature = "macos-installed-observation", not(feature = "development-runtime"),
                not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"),
                target_os = "macos", target_arch = "aarch64"))]
            {
                let witness = value.installed_native_response_witness.try_lock().map_err(|_| Reason::Capacity)?;
                if let Some(witness) = &*witness {
                    if let Some(path) = &witness.selected { self.add(path.capacity())?; }
                }
            }
            Ok(())
        }
        fn owner(&mut self, value: &Arc<OriginalWork>) -> Count<()> {
            if !self.seen.insert(value)? { return Ok(()); }
            // These Linux-only fixture traces/checkpoints have opaque backing
            // beyond SourceBook::retained_bytes. Typed refusal is visible test-
            // configuration debt, never an invented partial or zero-byte census.
            #[cfg(all(test, debug_assertions, feature = "desktop-shell",
                target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            { return Err(Reason::Capacity); }
            #[allow(unreachable_code)]
            {
                let coordinator = value.coordinator.try_lock().map_err(|_| Reason::Capacity)?;
                let child = value.child.try_lock().map_err(|_| Reason::Capacity)?;
                if coordinator.receipt != JoinReceipt::Returned || coordinator.handle.is_some()
                    || !matches!(child.receipt, JoinReceipt::New | JoinReceipt::Returned) || child.handle.is_some() {
                    return Err(Reason::Capacity);
                }
                let retirement = value.retirement.try_lock().map_err(|_| Reason::Capacity)?;
                if !value.retired.load(Ordering::SeqCst) || !lookup_memory::retirement_empty(&retirement) {
                    return Err(Reason::Capacity);
                }
                // Fixed cells still count; a released SDK/child does not by
                // itself prove its prior query/result/secret allocation disposal.
                let keyring = value.keyring.try_lock().map_err(|_| Reason::Capacity)?;
                if !keyring.resources_settled() || !keyring.allocations_released() || keyring.cleanup_unknown() {
                    return Err(Reason::Capacity);
                }
                let _deadline = value.deadline.try_lock().map_err(|_| Reason::Capacity)?;
                let _cleanup = value.cleanup_end.try_lock().map_err(|_| Reason::Capacity)?;
                let _image_failure = value.image_failure.try_lock().map_err(|_| Reason::Capacity)?;
                #[cfg(all(test, debug_assertions, not(feature = "desktop-shell"),
                    target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
                if value.gnome_transport_gate.try_lock().map_err(|_| Reason::Capacity)?.is_some() { return Err(Reason::Capacity); }
                self.arc::<OriginalWork>()?;
                self.gui(&value.gui, value)?;
                let source = value.source.try_lock().map_err(|_| Reason::Capacity)?;
                if !source.not_started() && !source.settled() { return Err(Reason::Capacity); }
                if self.seen.insert(&value.source)? {
                    self.arc::<Mutex<SourceBook>>()?; self.add(capacity(source.retained_bytes())?)?;
                }
                let work = value.vault.try_lock().map_err(|_| Reason::Capacity)?;
                if !work.settled() { return Err(Reason::Capacity); }
                if let Some(store) = work.store_ref() { self.vault_store(store)?; }
                if let Some(key) = work.key_ref() { self.vault_key(key)?; }
                if let Some(work) = &value.installation { self.add(capacity(work.retained_bytes_if_settled())?)?; }
                Ok(())
            }
        }
        fn slot(&mut self, value: &Slot) -> Count<()> {
            if value.phase != Phase::Idle || value.settlement != Settlement::Known
                || matches!(value.source, SourceState::Pending | SourceState::Unknown)
                || value.reason == Reason::CleanupUnknown || value.staged.is_some() { return Err(Reason::Capacity); }
            // The old Slot still exists at this admission point; it has NOT yet
            // moved into the next owner's retirement. Its inline cells are in
            // DocumentState; all heap holdings and the actual old owner count now.
            if let Some(context) = &value.context { self.context(context)?; }
            if let Some(key) = &value.target { self.key(key)?; }
            if let Some(candidate) = &value.candidate { self.candidate(candidate)?; }
            if let Some(token) = &value.selection { self.token(token)?; }
            if let Some(assessment) = &value.assessment { self.assessment(assessment)?; }
            if let Some(preview) = &value.preview {
                self.token(&preview.token)?;
                if let Some(token) = &preview.bind_token { self.token(token)?; }
                if let Some(key) = &preview.record { self.key(key)?; }
                if let PreviewSubject::Record { record_id: Some(token), .. } = &preview.subject { self.token(token)?; }
            }
            if value.error.is_some() {
                // Sole CommandError position because staged/retirement refuse.
                // Its private Arc enum has two fixed/static-string alternatives.
                self.add(size_of::<AssetError>())?; self.add(size_of::<crate::credential_assessment::AssessmentError>())?;
                self.add(2 * ARC_CELLS)?;
            }
            if let Some(project) = &value.project {
                self.add(project.id.capacity())?; self.add(project.name.capacity())?; self.add(project.path.capacity())?;
            }
            if let Some(result) = &value.path_result { self.add(capacity(result.retained_heap_bytes())?)?; }
            if let Some(key) = &value.result_record { self.key(key)?; }
            if let Some(payload) = &value.retired_payload { self.payload(payload)?; }
            if let Some(binding) = &value.evidence { self.evidence_binding(binding)?; }
            if let Some(binding) = &value.project_path { self.project_path(binding)?; }
            if let Some(binding) = &value.android_source { self.android_source(binding)?; }
            if let Some(binding) = &value.images { self.image_binding(binding)?; }
            if let Some(batch) = &value.image_batch { self.heap::<asset_source::CapturedPublicImageBatch>(batch.retained_bytes())?; }
            if let Some(label) = &value.vault.label { self.add(label.capacity())?; }
            if let Some(payload) = &value.vault.loaded { self.payload(payload)?; }
            if let Some(loan) = &value.vault.previous_bound { self.vault_loan(loan)?; }
            if let Some(store) = &value.vault.lease { self.vault_store(store)?; }
            // installation_result and the remainder of SlotData are inline DATA.
            self.owner(&value.owner)
        }
        fn document(&mut self, state: &DocumentState) -> Count<()> {
            if state.unknown || state.exhausted || state.stopping || state.retiring || state.lock_pending
                || state.quit_pending || state.compatibility_picker_pending
                || state.session_owner_reason == Some(Reason::CleanupUnknown) { return Err(Reason::Capacity); }
            #[cfg(all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol",
                not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"),
                target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
            if state.first_origin.is_some() { return Err(Reason::Capacity); }
            // Inner contains the Mutex<DocumentState>, including the inline old
            // Slot, image/evidence/installation/GitHub/vault registry cells.
            // External test-history gates must prove their optional holds absent.
            self.arc::<Inner>()?; self.arc::<()>()?; self.add(SESSION_SIGNAL_BYTES)?;
            self.records(&state.records)?; self.assignments(&state.assignments)?;
            if let Some(context) = &state.context { self.context(context)?; }
            if let Some(slot) = &state.slot { self.slot(slot)?; }
            if let Some(quit) = &state.quit { self.owner(quit)?; }
            self.add(capacity(state.github.retained_heap_bytes_if_quiescent())?)?;
            self.evidence(&state.evidence)?;
            self.heap::<images::Registry>(state.images.retained_bytes())?;
            if let Some(vault) = &state.vault { self.vault_session(vault)?; }
            Ok(())
        }
    }
    pub(super) fn admitted(state: &DocumentState, control: usize) -> Count<()> {
        let mut census = Census::new();
        census.document(state)?;
        fits(census.bytes, control)
    }

    #[cfg(all(test, not(feature = "desktop-shell")))]
    mod tests {
        use super::*;

        // Only inert DATA. No source, child, GUI, native settlement or runtime
        // admission is produced by these synthetic bookkeeping arrangements.
        fn state() -> DocumentState {
            DocumentState { lifetime: DocumentLifetime::default(), revision: 0, next_operation: 7, next_context: 3,
                exhausted: false, lost_observed: false, session: false, stopping: false, unknown: false,
                quit_pending: false, retiring: false, lock_pending: false, compatibility_picker_pending: false,
                session_owner_reason: None, context: None, slot: None, records: Vec::new(), assignments: Vec::new(),
                quit: None, quit_accepted: false, quit_cleanup_end: None, github: ConnectionState::new(),
                evidence: EvidenceRegistry::new(), images: images::Registry::new(),
                installation: installation::Registry::new(), vault: None }
        }
        fn tally(value: &DocumentState) -> Option<usize> {
            let mut census = Census::new(); census.document(value).ok()?; Some(census.bytes)
        }
        fn idle_owner_data() -> Arc<OriginalWork> {
            let owner = OriginalWork::new(7, false, Weak::new());
            owner.coordinator.lock().unwrap().receipt = JoinReceipt::Returned;
            owner.ended.store(true, Ordering::SeqCst);
            owner
        }
        #[test]
        fn fixed_session_partition_and_overflow_refuse_without_credit() {
            assert!(fits(SESSION_BYTES - 16 * 1024 * 1024, 16 * 1024 * 1024).is_ok());
            assert!(fits(SESSION_BYTES - 16 * 1024 * 1024 + 1, 16 * 1024 * 1024).is_err());
            assert!(fits(usize::MAX, 1).is_err());
            let state = state();
            assert!(super::super::admitted(&state, 16 * 1024 * 1024).is_ok());
            assert!(super::super::admitted(&state, 0).is_err());
            assert!(super::super::admitted(&state, usize::MAX).is_err());
            assert_eq!((state.next_operation, state.next_context), (7, 3));
            assert!(state.slot.is_none());
        }
        #[test]
        fn arc_identity_is_not_value_equality_and_set_exhaustion_is_closed() {
            let first = Arc::new(7u32); let alias = first.clone(); let equal = Arc::new(7u32);
            let mut seen = Seen::new();
            assert!(seen.insert(&first).ok().unwrap());
            assert!(!seen.insert(&alias).ok().unwrap());
            assert!(seen.insert(&equal).ok().unwrap());
            let others: Vec<_> = (0..IDENTITIES - 2).map(|_| Arc::new(7u32)).collect();
            for value in &others { assert!(seen.insert(value).ok().unwrap()); }
            assert!(seen.insert(&Arc::new(7u32)).is_err());
            assert!(!seen.insert(&first).ok().unwrap());
        }
        #[test]
        fn spare_record_and_assignment_cells_are_not_free() {
            let mut state = state(); let before = tally(&state).unwrap();
            state.records.reserve_exact(4); state.assignments.reserve_exact(3);
            let extra = state.records.capacity() * size_of::<Record>() + state.assignments.capacity() * size_of::<Assignment>();
            assert_eq!(tally(&state), Some(before + extra));
            assert!(state.records.is_empty() && state.assignments.is_empty());
        }
        #[test]
        fn aliased_payload_charges_once_and_equal_distinct_payloads_charge_again() {
            let payload = Arc::new(Payload { kind: Kind::AndroidFirebase, material: None, fields: None });
            let alias = payload.clone(); let distinct = Arc::new(Payload { kind: Kind::AndroidFirebase, material: None, fields: None });
            let mut census = Census::new();
            assert!(census.payload(&payload).is_ok()); let once = census.bytes;
            assert!(census.payload(&alias).is_ok()); assert_eq!(census.bytes, once);
            assert!(census.payload(&distinct).is_ok()); assert_eq!(census.bytes, 2 * once);
        }
        #[test]
        fn old_idle_project_is_counted_without_disposal_or_owner_replacement() {
            let owner = idle_owner_data(); let mut slot = Slot::new(owner.clone(), Operation::ChooseProject, None, None, None);
            slot.phase = Phase::Idle; slot.settlement = Settlement::Known; slot.source = SourceState::NotRun;
            let mut state = state(); state.slot = Some(slot); let before = tally(&state).unwrap();
            let project = Project { id: String::with_capacity(91), name: String::with_capacity(513), path: String::with_capacity(4097) };
            let extra = project.id.capacity() + project.name.capacity() + project.path.capacity();
            state.slot.as_mut().unwrap().project = Some(project);
            assert_eq!(tally(&state), Some(before + extra));
            assert!(Arc::ptr_eq(&state.slot.as_ref().unwrap().owner, &owner));
            assert!(state.slot.as_ref().unwrap().project.is_some());
            state.slot.as_mut().unwrap().staged = Some(Staged::Refused(Reason::SourceRefused));
            assert!(tally(&state).is_none());
            assert!(state.slot.as_ref().unwrap().staged.is_some());
        }
        #[test]
        fn actual_book_conditions_not_an_empty_retirement_or_end_flag() {
            let owner = idle_owner_data();
            owner.retired.store(false, Ordering::SeqCst);
            assert!(Census::new().owner(&owner).is_err());
            owner.retired.store(true, Ordering::SeqCst);
            owner.retirement.lock().unwrap().records.reserve_exact(1);
            assert!(Census::new().owner(&owner).is_err());
            owner.retirement.lock().unwrap().records = Vec::new();
            owner.child.try_lock().unwrap().receipt = JoinReceipt::Failed;
            assert!(Census::new().owner(&owner).is_err());
            owner.child.try_lock().unwrap().receipt = JoinReceipt::New;
            owner.coordinator.lock().unwrap().receipt = JoinReceipt::Failed;
            assert!(Census::new().owner(&owner).is_err());
        }
        #[test]
        fn busy_and_poisoned_books_refuse_without_blocking_or_changing_flags() {
            let owner = idle_owner_data();
            let held = owner.source.lock().unwrap();
            assert!(Census::new().owner(&owner).is_err()); drop(held);
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = owner.source.lock().unwrap(); panic!("inert census poison");
            }));
            assert!(poisoned.is_err());
            assert!(Census::new().owner(&owner).is_err());
            assert!(owner.source.is_poisoned());
            assert!(owner.retired.load(Ordering::SeqCst));
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        #[test]
        fn unstarted_source_spare_backing_is_still_charged() {
            let owner = idle_owner_data(); let mut first = Census::new();
            assert!(first.owner(&owner).is_ok());
            *owner.source.lock().unwrap() = SourceBook::unstarted_backing_data();
            let extra = owner.source.lock().unwrap().retained_bytes().unwrap();
            let mut after = Census::new(); assert!(after.owner(&owner).is_ok());
            assert!(extra > 0); assert_eq!(after.bytes, first.bytes + extra);
        }
        #[test]
        fn sticky_unknown_is_not_an_admission_or_repair() {
            let mut state = state(); state.unknown = true;
            assert!(super::super::admitted(&state, 16 * 1024 * 1024).is_err());
            assert!(state.unknown); assert_eq!(state.next_operation, 7);
            assert!(state.slot.is_none());
        }
    }
}
