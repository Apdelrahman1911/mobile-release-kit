//! GenerateUploadKey facet of SAME SavedCommandOwner. No second runner,
//! exported private result DTO, receipt factory, path adopter or replay owner.
use super::*;
use crate::android_upload_key_protocol as wire;
use std::sync::Weak;
use zeroize::{Zeroize, Zeroizing};

#[path = "saved_command_upload_key_private.rs"]
mod private;
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub(crate) use private::GeneratedUploadCandidate;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
#[path = "android_upload_key_native_macos.rs"]
pub(crate) mod native;

/// A read-only loan of the actual published Android catalogue original.
/// Creation lives beside that original, not in a renderer/parser constructor.
pub(crate) struct UploadKeyToolLoan {
    pub(super) original: Arc<Inner>,
    pub(super) selected: Arc<android_catalog::Selection>,
    pub(super) document: Weak<()>,
}
impl UploadKeyToolLoan {
    pub(crate) fn current(&self) -> bool {
        let Some(document) = self.document.upgrade() else {
            return false;
        };
        self.original
            .android_original_document_matches(Some(&document))
            && android_catalog::upload_selection_current(&self.original, &self.selected)
    }
    pub(super) fn data(&self) -> Option<&android_wire::MacToolchainSelection> {
        self.current().then_some(self.selected.data())
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    pub(crate) fn census(
        &self,
    ) -> Option<(usize, [Option<Arc<crate::asset_session::OriginalWork>>; 3])> {
        if !self.current() {
            return None;
        }
        let document = self.document.upgrade()?;
        // The same catalogue/producer/picker originals are counted by the
        // existing Document census, never replaced with selected-path DATA.
        android_registration::execute_owner_census(&self.original, &document)
    }
}

/// Non-Clone capability minted from the SAME private Prepared row. The
/// durable vault intent uses these exact existing nonce IDs; no AssetSlot ID.
pub(crate) struct UploadKeyPreparation {
    original: Weak<Inner>,
    id: String,
    generation: String,
    context: wire::UploadKeyContext,
    registration: u32,
    root: RegisteredRoot,
    tools: Arc<UploadKeyToolLoan>,
    saved: Arc<crate::asset_session::UploadKeySavedInput>,
    session: Mutex<Option<Weak<Session>>>,
}

fn original_belongs_to(original: &Weak<Inner>, owner: &SavedCommandOwner) -> bool {
    original
        .upgrade()
        .is_some_and(|same| Arc::ptr_eq(&same, &owner.inner))
}

// Finite slot predicate only, shared by the real Prepared check and inert
// comparison tests. This cannot create a preparation, grant or native owner.
fn prepared_slot_current<T>(
    slot: Option<&Arc<T>>,
    expected: &T,
    active: bool,
    expires: Instant,
    now: Instant,
) -> bool {
    !active && now < expires && slot.is_some_and(|same| std::ptr::eq(&**same, expected))
}
impl UploadKeyPreparation {
    pub(crate) fn operation_id(&self) -> &str {
        &self.id
    }
    pub(crate) fn owner_generation(&self) -> &str {
        &self.generation
    }
    pub(crate) fn context(&self) -> &wire::UploadKeyContext {
        &self.context
    }
    pub(crate) fn registration(&self) -> u32 {
        self.registration
    }
    pub(crate) fn root(&self) -> &RegisteredRoot {
        &self.root
    }
    pub(crate) fn saved(&self) -> &Arc<crate::asset_session::UploadKeySavedInput> {
        &self.saved
    }
    pub(crate) fn tools(&self) -> &Arc<UploadKeyToolLoan> {
        &self.tools
    }
    /// Existing installed-code partition, separate from the unchanged private
    /// vault budget. The parent keeps this reserved while either inspected
    /// graph can grow; it is never replaced by a small constructor/READY size.
    pub(crate) fn inspection_reservation_bytes(&self) -> usize {
        wire::INSPECTION_RESERVE
    }
    pub(crate) fn belongs_to(&self, owner: &SavedCommandOwner) -> bool {
        original_belongs_to(&self.original, owner)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // The existing Document census visits the actual Android catalog and
        // its published Selection; this counts this distinct loan/preparation
        // plus the retained saved-lane/context graph conservatively again.
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<UploadKeyToolLoan>())?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(self.saved.retained_bytes()?)?
            .checked_add(self.root.path.capacity())?;
        for value in [
            &self.id,
            &self.generation,
            &self.context.project_id,
            &self.context.runtime_project_id,
            &self.context.config_sha256,
            &self.context.draft_sha256,
            &self.context.app_identity_sha256,
        ] {
            bytes = bytes.checked_add(value.capacity())?;
        }
        Some(bytes)
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.original, &other.original)
            && self.id == other.id
            && self.generation == other.generation
            && self.registration == other.registration
            && self.root == other.root
            && self.context == other.context
            && Arc::ptr_eq(&self.tools, &other.tools)
            && Arc::ptr_eq(&self.saved, &other.saved)
    }
    /// Sole exact-prepared exception for the original vault parent's own
    /// admission. Active generations are NEVER a busy-gate exception.
    pub(crate) fn admission_current(&self, owner: &SavedCommandOwner, now: Instant) -> bool {
        if !self.belongs_to(owner)
            || !self.saved.current()
            || !self.tools.current()
            || owner.inner.poisoned.load(Ordering::SeqCst)
        {
            return false;
        }
        let Ok(r) = owner.inner.registry.try_lock() else {
            return false;
        };
        !r.disabled
            && !r.exhausted
            && !r.stopping
            && !r.document_lost
            && r.prepared.as_ref().is_some_and(|p| {
                prepared_slot_current(p.upload_key_preparation.as_ref(), self,
                    r.active.is_some(), p.expires, now)
                    && p.projection.operation_id == self.id
                    && p.projection.owner_generation == self.generation
                    && p.registration == self.registration
                    && p.project == self.root
                    && matches!(&p.projection.context, Context::GenerateUploadKey(context) if context == &self.context)
            })
    }
    pub(crate) fn current(&self) -> bool {
        let Some(original) = self.original.upgrade() else {
            return false;
        };
        if !self.saved.current()
            || !self.tools.current()
            || original.poisoned.load(Ordering::SeqCst)
        {
            return false;
        }
        let Ok(r) = original.registry.try_lock() else {
            return false;
        };
        if r.disabled || r.exhausted || r.stopping || r.document_lost {
            return false;
        }
        r.prepared.as_ref().is_some_and(|p| {
            p.projection.operation_id == self.id
                && p.projection.owner_generation == self.generation
                && p.registration == self.registration
                && p.project == self.root
                && matches!(&p.projection.context, Context::GenerateUploadKey(context) if context == &self.context)
                && Instant::now() < p.expires
                && p.upload_key_preparation
                    .as_ref()
                    .is_some_and(|p| std::ptr::eq(&**p, self))
        }) || r.active.as_ref().is_some_and(|a| {
            a.owner.id == self.id
                && a.owner.generation == self.generation
                && a.owner.registration == self.registration
                && a.owner.project == self.root
                && matches!(&a.owner.context, Context::GenerateUploadKey(context) if context == &self.context)
                && a.owner.upload_key.intent.as_ref().is_some_and(|intent|
                    std::ptr::eq(&*intent.preparation, self))
                && !a.unknown
                && !a.context_invalidated
                && !*a.owner.stop.borrow()
        })
    }
}

pub(super) struct Intent {
    preparation: Arc<UploadKeyPreparation>,
    receive: Arc<private::ReceiveBook>,
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    gate: Mutex<Option<Arc<crate::asset_session::UploadKeyGoGate>>>,
}
impl Intent {
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    fn gate(&self) -> Result<Arc<crate::asset_session::UploadKeyGoGate>, BridgeError> {
        self.gate
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?
            .as_ref()
            .cloned()
            .ok_or_else(wire::invalid)
    }
}
pub(super) struct State {
    intent: Option<Arc<Intent>>,
    receive: Option<Arc<private::ReceiveBook>>,
    writer: AsyncMutex<Option<PrivateUploadKeyInput>>,
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
    candidate: Mutex<Option<GeneratedUploadCandidate>>,
    invalid: AtomicBool,
    native_bytes: AtomicUsize,
    disposed: AtomicBool,
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    disposal: Mutex<Option<crate::asset_session::UploadKeyDisposal>>,
    final_seen: AtomicBool,
    final_wake: Notify,
}
impl State {
    pub(super) fn new(intent: Option<Arc<Intent>>) -> Self {
        Self {
            receive: intent.as_ref().map(|i| i.receive.clone()),
            intent,
            writer: AsyncMutex::new(None),
            #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
            candidate: Mutex::new(None),
            invalid: AtomicBool::new(false),
            native_bytes: AtomicUsize::new(0),
            disposed: AtomicBool::new(false),
            #[cfg(all(
                feature = "desktop-shell",
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            disposal: Mutex::new(None),
            final_seen: AtomicBool::new(false),
            final_wake: Notify::new(),
        }
    }
}

/// Fixed private stdin frame. It remains in the Session until the original
/// writer AND native tail are joined, including partial/uncertain handoffs.
pub(crate) struct PrivateUploadKeyInput {
    preparation: Arc<UploadKeyPreparation>,
    bytes: Zeroizing<[u8; wire::GO_LENGTH]>,
    filled: bool,
    send_claimed: bool,
    sent: bool,
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    go: Option<crate::asset_session::PreparedGenerationGo>,
}
impl PrivateUploadKeyInput {
    fn reserved(preparation: Arc<UploadKeyPreparation>, digest: [u8; 32]) -> Self {
        let mut bytes = Zeroizing::new([0; wire::GO_LENGTH]);
        bytes[..wire::GO_MAGIC.len()].copy_from_slice(wire::GO_MAGIC);
        bytes[wire::GO_MAGIC.len()..wire::GO_MAGIC.len() + 32].copy_from_slice(&digest);
        Self {
            preparation,
            bytes,
            filled: false,
            send_claimed: false,
            sent: false,
            #[cfg(all(
                feature = "desktop-shell",
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            go: None,
        }
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn passwords(
        &mut self,
        go: crate::asset_session::PreparedGenerationGo,
        store: &[u8],
        key: &[u8],
    ) -> Result<(), BridgeError> {
        if self.go.is_some() || self.filled || self.send_claimed {
            return Err(wire::invalid());
        }
        self.go = Some(go); // Root the actual token BEFORE validating/consuming; never remint.
        self.go
            .as_mut()
            .ok_or_else(wire::invalid)?
            .consume_for_writer(&self.preparation, &self.preparation.context)
            .map_err(|_| wire::invalid())?;
        if store.len() != wire::PASSWORD_LENGTH
            || key.len() != wire::PASSWORD_LENGTH
            || store == key
            || !store
                .iter()
                .chain(key)
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        {
            return Err(wire::invalid());
        }
        let at = wire::GO_MAGIC.len() + 32;
        self.bytes[at..at + wire::PASSWORD_LENGTH].copy_from_slice(store);
        self.bytes[at + wire::PASSWORD_LENGTH..].copy_from_slice(key);
        self.filled = true;
        Ok(())
    }
    async fn send(&mut self, owner: &Session, writer: &mut ChildStdin) -> Result<(), BridgeError> {
        if !self.filled
            || self.send_claimed
            || *owner.stop.borrow()
            || Instant::now() >= owner.clocks.work
            || !self.preparation.current()
        {
            return Err(wire::invalid());
        }
        self.send_claimed = true;
        writer
            .write_all(&self.bytes[..])
            .await
            .map_err(|_| wire::invalid())?;
        writer.flush().await.map_err(|_| wire::invalid())?;
        self.sent = true;
        Ok(())
    }
}

/// The vault OriginalWork retains this exact run BEFORE the original release
/// sender can leave its parent. It is NOT a second lifecycle supervisor.
pub(crate) struct UploadKeyRun {
    original: SavedCommandOwner,
    session: Arc<Session>,
}
#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
impl UploadKeyRun {
    pub(crate) fn native_settled(&self) -> bool {
        original_joined(&self.session)
    }
    pub(crate) fn cleanup_unknown(&self) -> bool {
        self.session.resource_unknown.load(Ordering::SeqCst)
    }
    pub(crate) fn private_disposed(&self) -> bool {
        self.session.upload_key.disposed.load(Ordering::SeqCst)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let base = document_backing_bytes()?.checked_add(
            self.session
                .upload_key
                .intent
                .as_ref()?
                .preparation
                .retained_bytes()?,
        )?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        ))]
        {
            if self.native_settled() {
                let resources = self.session.resources.try_lock().ok()?;
                let observations = resources
                    .android_observations
                    .as_ref()?
                    .returned
                    .as_ref()?
                    .as_ref()
                    .ok()?;
                return wire::measured_native_charge(base, observations.retained_bytes?);
            }
            // This atomic is written ONLY by the actual original native
            // inspector/acquisition at its quiescent return; no book lock or
            // native IO can block a Document census. Zero means unavailable.
            let measured = self.session.upload_key.native_bytes.load(Ordering::SeqCst);
            return (!self.cleanup_unknown())
                .then(|| wire::measured_native_charge(base, measured))
                .flatten();
        }
        #[allow(unreachable_code)]
        None
    }
    pub(crate) async fn wait_candidate(&self) -> Result<(), BridgeError> {
        let mut changes = self.original.subscribe();
        loop {
            let wake = self.session.upload_key.final_wake.notified();
            self.original.reconcile();
            if self.session.upload_key.final_seen.load(Ordering::SeqCst) {
                return self
                    .session
                    .upload_key
                    .candidate
                    .try_lock()
                    .ok()
                    .filter(|c| c.is_some())
                    .map(|_| ())
                    .ok_or_else(wire::invalid);
            }
            if self.session.resource_unknown.load(Ordering::SeqCst) {
                return Err(BridgeError::cleanup_unknown());
            }
            tokio::select! {_=wake=>{},result=changes.changed()=>if result.is_err(){return Err(BridgeError::cleanup_unknown());}}
        }
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn seal_new(
        &self,
        key: &crate::vault_crypto::VaultKey,
        record: crate::vault_format::Id,
        allowance: usize,
        parent: &crate::asset_session::OriginalWork,
    ) -> Result<crate::vault_crypto::SealedRecord, crate::vault_crypto::Error> {
        use crate::vault_crypto::Error;
        let intent = self
            .session
            .upload_key
            .intent
            .as_ref()
            .ok_or(Error::Authentication)?;
        let gate = intent.gate().map_err(|_| Error::Authentication)?;
        if !gate.matches_original(parent) || parent.interrupted() {
            return Err(Error::Authentication);
        }
        let sealed = self
            .session
            .upload_key
            .candidate
            .try_lock()
            .map_err(|_| Error::Authentication)?
            .as_mut()
            .ok_or(Error::Authentication)?
            .seal_new(key, record, allowance)?;
        if !gate.matches_original(parent) || parent.interrupted() {
            return Err(Error::Authentication);
        }
        Ok(sealed)
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    pub(crate) fn dispose_private(
        &self,
        proof: crate::asset_session::UploadKeyDisposal,
    ) -> Result<(), BridgeError> {
        let state = &self.session.upload_key;
        let mut retained = state
            .disposal
            .lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if retained.is_some() || state.disposed.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        *retained = Some(proof); // Root actual publication/disposal proof BEFORE any consume.
        let result = (|| {
            let intent = state.intent.as_ref().ok_or_else(wire::invalid)?;
            let proof = retained.as_mut().ok_or_else(wire::invalid)?;
            if !proof.matches(&intent.preparation) || !original_joined(&self.session) {
                return Err(wire::invalid());
            }
            let book = state.receive.as_ref().ok_or_else(wire::invalid)?;
            let mut bytes = book
                .backing
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut writer = state
                .writer
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut candidate = state
                .candidate
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            let mut gate = intent
                .gate
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            proof
                .consume(&intent.preparation)
                .map_err(|_| BridgeError::cleanup_unknown())?;
            // Every consuming native/pipe task is joined. No bytes or new owner
            // escape; failures before this point preserve the original slots.
            bytes.bytes.zeroize();
            bytes.length = 0;
            bytes.target = 0;
            bytes.header = None;
            if let Some(writer) = writer.as_mut() {
                writer.bytes.zeroize();
                writer.go.take();
            }
            writer.take();
            candidate.take();
            gate.take();
            state.disposed.store(true, Ordering::SeqCst);
            Ok(())
        })();
        if result.is_err() {
            state.invalid.store(true, Ordering::SeqCst);
            self.session.resource_unknown.store(true, Ordering::SeqCst);
        }
        result
    }
    pub(crate) fn matches_authenticated_readback(
        &self,
        record: &crate::vault_crypto::AuthenticatedRecord,
    ) -> bool {
        self.session
            .upload_key
            .candidate
            .try_lock()
            .is_ok_and(|mut c| {
                c.as_mut()
                    .is_some_and(|c| c.matches_authenticated_readback(record))
            })
    }
    pub(crate) fn observed_certificate_sha256(&self) -> Option<[u8; 32]> {
        self.session
            .upload_key
            .candidate
            .try_lock()
            .ok()?
            .as_ref()?
            .observed_certificate_sha256()
    }
    pub(crate) fn failed_at(&self, reason: crate::asset_commands::Reason, at: Instant) {
        self.session
            .upload_key
            .invalid
            .store(true, Ordering::SeqCst);
        self.session.upload_key.final_wake.notify_waiters();
        let reason = match reason {
            crate::asset_commands::Reason::Deadline => Reason::TimedOut,
            crate::asset_commands::Reason::CleanupUnknown => Reason::CleanupUnknown,
            crate::asset_commands::Reason::UserCancelled => Reason::Cancelled,
            _ => Reason::ContextChanged,
        };
        let mut r = self.original.inner.lock();
        self.original
            .inner
            .stop_locked(&mut r, &self.session, reason, at);
    }
}
pub(crate) struct UploadKeyRelease(Option<oneshot::Sender<()>>);
impl UploadKeyRelease {
    pub(crate) fn release(mut self) {
        if let Some(go) = self.0.take() {
            let _ = go.send(());
        }
    }
}
pub(crate) struct UploadKeyAdmitted {
    pub(crate) run: Option<UploadKeyRun>,
    pub(crate) release: UploadKeyRelease,
    pub(crate) status: wire::Status,
}

pub(super) fn installed_selected(inner: &Inner) -> bool {
    inner.domain == SavedCommandDomain::GenerateUploadKey
        && cfg!(all(
            feature = "desktop-shell",
            feature = "custom-protocol",
            target_os = "macos",
            not(feature = "development-runtime"),
            not(feature = "ubuntu-runtime-publisher"),
            not(feature = "windows-runtime-publisher"),
            not(feature = "macos-installed-installer"),
            not(feature = "macos-android-registration-helper")
        ))
        && wire::Profile::current().is_some()
        && inner.runtime.upload_key_installed_profile_available()
}
/// Called under the SAME SavedCommand Registry after consuming Prepared.
/// No hidden self-registry relock, Document borrow, shared-state read or IO.
pub(super) fn start_matches(inner: &Arc<Inner>, prepared: &Prepared, clocks: Clocks) -> bool {
    if inner.domain != SavedCommandDomain::GenerateUploadKey {
        return prepared.upload_key.is_none() && prepared.upload_key_preparation.is_none();
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        let Some(intent) = prepared.upload_key.as_ref() else {
            return false;
        };
        let p = &intent.preparation;
        let Ok(gate) = intent.gate() else {
            return false;
        };
        return p
            .original
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, inner))
            && prepared
                .upload_key_preparation
                .as_ref()
                .is_some_and(|same| Arc::ptr_eq(same, p))
            && p.id == prepared.projection.operation_id
            && p.generation == prepared.projection.owner_generation
            && p.registration == prepared.registration
            && p.root == prepared.project
            && prepared.projection.context == Context::GenerateUploadKey(p.context.clone())
            && p.saved.current()
            && p.tools.current()
            && gate.matches(p, &p.context)
            && gate.original_bounds() == (clocks.admitted, clocks.work, clocks.finality);
    }
    #[allow(unreachable_code)]
    {
        let _ = (prepared, clocks);
        false
    }
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
pub(super) fn native_new(
    prepared: &Prepared,
    audit: watch::Receiver<Instant>,
    cleanup: watch::Receiver<Instant>,
    clocks: Clocks,
) -> Result<Option<native::UploadKeyNativeBooks>, BridgeError> {
    if !matches!(prepared.projection.context, Context::GenerateUploadKey(_)) {
        return Ok(None);
    }
    let intent = prepared.upload_key.as_ref().ok_or_else(wire::invalid)?;
    let selected = intent
        .preparation
        .tools
        .data()
        .ok_or_else(wire::invalid)?
        .clone();
    let books = native::UploadKeyNativeBooks::new(selected, audit, cleanup, clocks);
    if books
        .pre_go_bytes()
        .zip(document_backing_bytes())
        .is_none_or(|(actual, reserved)| actual > reserved)
    {
        return Err(wire::unavailable());
    }
    Ok(Some(books))
}

impl SavedCommandOwner {
    pub(crate) fn generate_upload_key(runtime: RuntimeConfig) -> Self {
        Self::new(runtime, SavedCommandDomain::GenerateUploadKey)
    }
    pub(crate) fn prepare_upload_key(
        &self,
        context: wire::UploadKeyContext,
        registration: u32,
        root: RegisteredRoot,
        gate: wire::Availability,
        tools: Arc<UploadKeyToolLoan>,
        saved: Arc<crate::asset_session::UploadKeySavedInput>,
    ) -> Result<Arc<UploadKeyPreparation>, BridgeError> {
        self.require_domain(SavedCommandDomain::GenerateUploadKey)?;
        let document = tools.document.upgrade().ok_or_else(wire::invalid)?;
        if !context.valid()
            || !tools.current()
            || !saved.matches(&document, registration, &root, &context.runtime_project_id)
            || saved.config_bytes() != context.config_bytes
            || saved.config_sha256() != context.config_sha256
            || saved.draft_sha256() != context.draft_sha256
        {
            return Err(wire::invalid());
        }
        let status = self.prepare_bound(
            Context::GenerateUploadKey(context.clone()),
            registration,
            root.clone(),
            availability(gate),
            None,
            None,
        )?;
        let Status::GenerateUploadKey(status) = status else {
            return Err(wire::invalid());
        };
        let current = status.current.ok_or_else(wire::invalid)?;
        if !wire::id(&current.operation_id) || !wire::id(&current.owner_generation) {
            return Err(wire::invalid());
        }
        let preparation = Arc::new(UploadKeyPreparation {
            original: Arc::downgrade(&self.inner),
            id: current.operation_id,
            generation: current.owner_generation,
            context,
            registration,
            root,
            tools,
            saved,
            session: Mutex::new(None),
        });
        let mut r = self.inner.lock();
        let row = r
            .prepared
            .as_mut()
            .filter(|p| {
                p.projection.operation_id == preparation.id
                    && p.projection.owner_generation == preparation.generation
            })
            .ok_or_else(wire::invalid)?;
        if row.upload_key_preparation.is_some() {
            return Err(wire::invalid());
        }
        row.upload_key_preparation = Some(preparation.clone());
        Ok(preparation)
    }
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    pub(crate) fn start_upload_key(
        &self,
        preparation: Arc<UploadKeyPreparation>,
        gate: Arc<crate::asset_session::UploadKeyGoGate>,
        registered: Option<(u32, RegisteredRoot)>,
        available: wire::Availability,
    ) -> Result<UploadKeyAdmitted, BridgeError> {
        self.require_domain(SavedCommandDomain::GenerateUploadKey)?;
        if !preparation
            .original
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&self.inner, &original))
            || !preparation.current()
            || !gate.matches(&preparation, &preparation.context)
        {
            return Err(wire::invalid());
        }
        let (t, w, h) = gate.original_bounds();
        if w.checked_duration_since(t) != Some(Duration::from_secs(wire::WORK_SECONDS))
            || h.checked_duration_since(t) != Some(Duration::from_secs(wire::FINALITY_SECONDS))
            || Instant::now() >= w
        {
            return Err(wire::invalid());
        }
        let receive = private::ReceiveBook::reserved()?;
        {
            let mut r = self.inner.lock();
            let p = r
                .prepared
                .as_mut()
                .filter(|p| {
                    p.upload_key_preparation
                        .as_ref()
                        .is_some_and(|original| Arc::ptr_eq(original, &preparation))
                })
                .ok_or_else(wire::invalid)?;
            if p.upload_key.is_some() {
                return Err(wire::invalid());
            }
            p.upload_key = Some(Arc::new(Intent {
                preparation: preparation.clone(),
                receive,
                gate: Mutex::new(Some(gate)),
            }));
        }
        let admitted = self.start_bound(
            Start {
                operation_id: preparation.id.clone(),
                owner_generation: preparation.generation.clone(),
            },
            t,
            registered,
            availability(available),
            None,
        )?;
        let Status::GenerateUploadKey(status) = admitted.status else {
            return Err(wire::invalid());
        };
        let session = {
            let r = self.inner.lock();
            r.active
                .as_ref()
                .filter(|a| {
                    a.owner.id == preparation.id && a.owner.generation == preparation.generation
                })
                .map(|a| a.owner.clone())
        };
        if let Some(session) = session.as_ref() {
            let mut slot = preparation.session.lock().map_err(|_| wire::invalid())?;
            if slot.is_some() {
                return Err(wire::invalid());
            }
            *slot = Some(Arc::downgrade(session));
        }
        Ok(UploadKeyAdmitted {
            run: session.map(|session| UploadKeyRun {
                original: self.clone(),
                session,
            }),
            release: UploadKeyRelease(admitted.release),
            status,
        })
    }
}

pub(super) fn availability(value: wire::Availability) -> Availability {
    match value {
        wire::Availability::Available => Availability::Available,
        wire::Availability::Busy => Availability::Busy,
        wire::Availability::Shutdown => Availability::Shutdown,
        wire::Availability::CleanupUnknown => Availability::CleanupUnknown,
        wire::Availability::DocumentLost => Availability::DocumentLost,
        wire::Availability::UnsupportedPlatform => Availability::UnsupportedPlatform,
        wire::Availability::RuntimeUnqualified => Availability::RuntimeUnqualified,
        wire::Availability::ToolchainUnqualified => Availability::ToolchainUnqualified,
    }
}
pub(super) fn snapshot(
    revision: u32,
    available: Availability,
    current: Option<RunProjection>,
) -> wire::Status {
    wire::Status {
        revision,
        availability: match available {
            Availability::Available => wire::Availability::Available,
            Availability::Busy => wire::Availability::Busy,
            Availability::Shutdown => wire::Availability::Shutdown,
            Availability::CleanupUnknown => wire::Availability::CleanupUnknown,
            Availability::DocumentLost => wire::Availability::DocumentLost,
            Availability::UnsupportedPlatform => wire::Availability::UnsupportedPlatform,
            Availability::RuntimeUnqualified => wire::Availability::RuntimeUnqualified,
            Availability::ToolchainUnqualified => wire::Availability::ToolchainUnqualified,
        },
        current: current.map(|c| wire::Run {
            operation_id: c.operation_id,
            owner_generation: c.owner_generation,
            phase: match c.phase {
                Phase::AwaitingConsent => wire::Phase::AwaitingConsent,
                Phase::Starting => wire::Phase::Starting,
                Phase::Running => wire::Phase::Running,
                Phase::Stopping => wire::Phase::Stopping,
                Phase::Terminal => wire::Phase::Terminal,
                Phase::Unknown => wire::Phase::Unknown,
            },
            outcome: c.outcome.map(|o| match o {
                Outcome::Complete => wire::Outcome::Complete,
                Outcome::Refused => wire::Outcome::Refused,
                Outcome::Cancelled => wire::Outcome::Cancelled,
                Outcome::TimedOut => wire::Outcome::TimedOut,
                Outcome::Failed => wire::Outcome::Failed,
                Outcome::Unknown => wire::Outcome::Unknown,
            }),
            reason: match c.reason {
                Reason::None => wire::Reason::None,
                Reason::Cancelled => wire::Reason::Cancelled,
                Reason::TimedOut => wire::Reason::TimedOut,
                Reason::CleanupUnknown => wire::Reason::CleanupUnknown,
                Reason::StaleIntent | Reason::ContextChanged => wire::Reason::StaleIntent,
                _ => wire::Reason::NativeFailure,
            },
        }),
    }
}
pub(super) fn core_outcome(status: wire::CoreStatus) -> Outcome {
    match status {
        wire::CoreStatus::Ok => Outcome::Complete,
        wire::CoreStatus::Refused => Outcome::Refused,
        wire::CoreStatus::Cancelled => Outcome::Cancelled,
        wire::CoreStatus::TimedOut => Outcome::TimedOut,
        wire::CoreStatus::CleanupUnknown => Outcome::Unknown,
    }
}
pub(super) fn core_reason(status: wire::CoreStatus) -> Reason {
    match status {
        wire::CoreStatus::Ok => Reason::None,
        wire::CoreStatus::Refused => Reason::CommandIncomplete,
        wire::CoreStatus::Cancelled => Reason::Cancelled,
        wire::CoreStatus::TimedOut => Reason::TimedOut,
        wire::CoreStatus::CleanupUnknown => Reason::CleanupUnknown,
    }
}

fn original_joined(owner: &Session) -> bool {
    owner.domain == SavedCommandDomain::GenerateUploadKey
        && owner.watchdog_joined.load(Ordering::SeqCst)
        && !owner.watchdog_failed.load(Ordering::SeqCst)
        && !owner.resource_unknown.load(Ordering::SeqCst)
        && owner.driver_joined.load(Ordering::SeqCst)
        && !owner.driver_failed.load(Ordering::SeqCst)
        && !owner.manager_failed.load(Ordering::SeqCst)
        && owner
            .watchdog_return
            .try_lock()
            .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(true))))
        && owner
            .driver_return
            .try_lock()
            .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(()))))
        && owner
            .manager_return
            .try_lock()
            .is_ok_and(|r| matches!(r.as_ref(), Some(Ok(()))))
        && owner
            .resources
            .try_lock()
            .is_ok_and(|b| native_final(&b, owner))
}
pub(super) fn after_final(active: &Active, owner: &Arc<Session>) {
    if owner.domain != SavedCommandDomain::GenerateUploadKey {
        return;
    }
    let state = &owner.upload_key;
    if let Some(book) = &state.receive {
        let complete = original_joined(owner)
            && active.final_join_seen
            && active.accepted
            && active.terminal
            && !active.unknown
            && !active.context_invalidated
            && active.first_stop.is_none()
            && active.projection.reason == Reason::None
            && active.projection.outcome == Some(Outcome::Complete)
            && !state.invalid.load(Ordering::SeqCst);
        if complete {
            book.joined.store(true, Ordering::SeqCst);
            #[cfg(all(
                feature = "desktop-shell",
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            if let Ok(candidate) = GeneratedUploadCandidate::from_joined(owner) {
                if let Ok(mut slot) = state.candidate.try_lock() {
                    if slot.is_none() {
                        *slot = Some(candidate);
                    }
                }
            }
        } else {
            book.fail();
        }
    }
    state.final_seen.store(true, Ordering::SeqCst);
    state.final_wake.notify_waiters();
}
pub(super) fn forward_failure(owner: &Session, reason: Reason, at: Instant) {
    if owner.domain != SavedCommandDomain::GenerateUploadKey {
        return;
    }
    owner.upload_key.invalid.store(true, Ordering::SeqCst);
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    if let Some(intent) = owner.upload_key.intent.as_ref() {
        use crate::asset_commands::Reason as R;
        if let Ok(gate) = intent.gate() {
            gate.failed_at(
                match reason {
                    Reason::TimedOut => R::Deadline,
                    Reason::CleanupUnknown => R::CleanupUnknown,
                    Reason::Cancelled => R::UserCancelled,
                    _ => R::ContextStale,
                },
                at,
            );
        }
    }
    let _ = (reason, at);
}
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
pub(super) fn forward_native_control(
    owner: &Session,
    data: android_leased::ControlData,
    cleanup: Instant,
) {
    if owner.domain != SavedCommandDomain::GenerateUploadKey {
        return;
    }
    let native = data.failure.and_then(|failure| failure.first_instant);
    let first = match (data.local_first, native) {
        (Some(local), Some(native)) => Some(local.min(native)),
        (local, native) => local.or(native),
    };
    if first.is_none() && !data.unknown {
        return;
    }
    owner.upload_key.invalid.store(true, Ordering::SeqCst);
    #[cfg(feature = "desktop-shell")]
    if let Some(intent) = owner.upload_key.intent.as_ref() {
        use crate::asset_commands::Reason as R;
        if let Ok(gate) = intent.gate() {
            // This is the SAME M2 control's original min cutoff, not a new
            // local event. The parent records its provenance and NEVER
            // echoes inverse-mapped native time into note_android_local.
            // Unknown without an original first-F keeps that absence.
            gate.native_cleanup_at(
                if data.unknown {
                    R::CleanupUnknown
                } else {
                    R::ContextStale
                },
                first,
                cleanup,
            );
        }
    }
    let _ = cleanup;
}
pub(super) async fn read_private<T: AsyncRead + Unpin + OriginalClose>(
    inner: Arc<Inner>,
    owner: Arc<Session>,
    slot: Arc<AsyncMutex<Pipe<T>>>,
    guard: Guard,
) -> ReadEnd {
    private::read(inner, owner, slot, guard).await
}
pub(super) async fn write_private(
    owner: &Session,
    writer: &mut ChildStdin,
) -> Result<(), BridgeError> {
    #[cfg(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let intent = owner.upload_key.intent.as_ref().ok_or_else(wire::invalid)?;
        let book = owner
            .upload_key
            .receive
            .as_ref()
            .ok_or_else(wire::invalid)?;
        let mut stop = owner.stop.subscribe();
        loop {
            let wake = book.wake.notified();
            if book.failed.load(Ordering::SeqCst) || *stop.borrow() {
                return Err(wire::invalid());
            }
            if book.ready.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {_=wake=>{},_=stop.changed()=>{}}
        }
        // Original writer owns the fixed gate call. No Doc/native/Registry lock
        // is held across durable current read; no detached helper or retry.
        let gate = intent.gate()?;
        let mut slot = owner.upload_key.writer.lock().await;
        if slot.is_some() {
            return Err(wire::invalid());
        }
        *slot = Some(PrivateUploadKeyInput::reserved(
            intent.preparation.clone(),
            book.digest()?,
        ));
        let input = slot.as_mut().ok_or_else(wire::invalid)?;
        let go = gate
            .ready_for_go(&intent.preparation.context)
            .map_err(|_| wire::invalid())?;
        gate.secrets().write_to(input, go)?;
        input.send(owner, writer).await
    }
    #[cfg(not(all(
        feature = "desktop-shell",
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    {
        let _ = (owner, writer);
        Err(wire::unavailable())
    }
}

#[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub(crate) fn document_backing_bytes() -> Option<usize> {
    // One original run retained by the vault parent; no unbounded result log.
    // Same source-informed accounting must also charge catalogue/native books.
    private::ReceiveBook::fixed_bytes()?
        .checked_add(std::mem::size_of::<PrivateUploadKeyInput>())?
        .checked_add(std::mem::size_of::<GeneratedUploadCandidate>())?
        .checked_add(wire::REQUEST_LIMIT)?
        .checked_add(2 * std::mem::size_of::<Session>())?
        .checked_add(2 * std::mem::size_of::<Resources>())?
        .checked_add(64 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_prepare_exception_rejects_wrong_or_lost_owner() {
        // Empty actual registries only: no selected catalogue, saved source,
        // native work, positive preparation or qualification is installed.
        let path = std::path::PathBuf::from("/unopened-upload-key-owner");
        let first = SavedCommandOwner::generate_upload_key(RuntimeConfig::packaged(path.clone()));
        let second = SavedCommandOwner::generate_upload_key(RuntimeConfig::packaged(path));
        let original = Arc::downgrade(&first.inner);
        assert!(original_belongs_to(&original, &first));
        assert!(!original_belongs_to(&original, &second));
        assert!(!original_belongs_to(&Weak::new(), &first));
        assert!(first.inner.lock().prepared.is_none());
        assert!(second.inner.lock().active.is_none());
    }

    #[test]
    fn same_ids_different_prepared_allocation_is_never_the_original() {
        // Equality of these inert IDs must not satisfy the exact slot test.
        let first = Arc::new(("same-operation", "same-generation"));
        let replacement = Arc::new(*first);
        let now = Instant::now();
        let expires = now + Duration::from_secs(1);
        assert_eq!(*first, *replacement);
        assert!(prepared_slot_current(
            Some(&first),
            &*first,
            false,
            expires,
            now
        ));
        assert!(!prepared_slot_current(
            Some(&replacement),
            &*first,
            false,
            expires,
            now
        ));
        assert!(!prepared_slot_current(None, &*first, false, expires, now));
    }

    #[test]
    fn exact_prepared_slot_still_refuses_active_and_expired_admission() {
        let row = Arc::new(());
        let now = Instant::now();
        assert!(!prepared_slot_current(
            Some(&row),
            &*row,
            true,
            now + INTENT,
            now
        ));
        assert!(!prepared_slot_current(Some(&row), &*row, false, now, now));
        assert!(!prepared_slot_current(
            Some(&row),
            &*row,
            false,
            now,
            now + Duration::from_nanos(1)
        ));
    }

    #[test]
    fn source_roles_use_original_180_190_clock_without_renewal() {
        let admitted = Instant::now();
        let clock = Clocks::new(SavedCommandDomain::GenerateUploadKey, admitted);
        assert_eq!(clock.admitted, admitted);
        assert_eq!(clock.work - admitted, Duration::from_secs(180));
        assert_eq!(clock.finality - admitted, Duration::from_secs(190));
        assert_eq!(
            clock.cleanup_end(Some(admitted + Duration::from_secs(3))),
            admitted + Duration::from_secs(13)
        );
    }
}
