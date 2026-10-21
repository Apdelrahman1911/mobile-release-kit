//! Fixed public-tool acquisition facet of the original saved command owner.
//! Selection/catalogue/child/cache originals are retained, never reconstructed
//! from status, a manifest, a downloaded path, or a settled-looking journal.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Weak};
use tools_wire as wire;

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
#[path = "tool_acquisition_cache_macos.rs"]
mod cache;
#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
#[path = "saved_command_tool_acquisition_macos.rs"]
mod native;
#[path = "saved_command_tool_acquisition_reuse.rs"]
mod reuse;
#[path = "saved_command_tool_acquisition_picked.rs"]
mod picked;
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
pub(crate) use picked::SourceGate;
#[path = "saved_command_tool_acquisition_sources.rs"]
mod sources;
pub(crate) use sources::SourceNomination;

#[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
#[path="saved_command_tool_acquisition_observation.rs"]
pub(super) mod observation;

// A complete source implementation is not installed-profile qualification.
// Root's native observation/packaging gate must be exercised before enabling.
const NATIVE_QUALIFIED: bool = false;
const MAX_PRODUCERS: usize = 32;
const MAX_RETAINED_SESSIONS: usize = 2 * MAX_PRODUCERS + 2;
const MIB: usize = 1024 * 1024;
// A separate NEW public-only domain partition, not an increase to any existing
// signing/Document/profile budget. The original document cap stays unchanged.
pub(crate) const PUBLIC_WORK_LIMIT: usize = 96 * MIB;
pub(crate) const INSTALLED_CODE_LIMIT: usize = 128 * MIB;
// Simultaneous fixed buffers: manifest raw8 + bounded roster8 + CA1;
// native JSON/base64 representation16 + serialized request12;
// source raw/hash/capture5 + child request/raw+decode24; FD/control/transport8.
// This is finite allocation admission, not an opaque CF/SSL or process-RSS cap.
pub(crate) const FUTURE_PUBLIC_BYTES: usize =
    8 * MIB + 8 * MIB + MIB + 16 * MIB + wire::REQUEST_LIMIT + 5 * MIB + 24 * MIB + 8 * MIB;
const _: () = assert!(FUTURE_PUBLIC_BYTES <= PUBLIC_WORK_LIMIT);

pub(super) struct Binding {
    android: Arc<Inner>,
    document: Weak<()>,
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    observation: std::sync::OnceLock<Weak<crate::shell::installed_observation::tool_setup::Control>>,
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    location: cache::Location,
}
struct Known {
    android: Arc<Inner>,
    document: Weak<()>,
    catalog: reuse::CatalogLoan,
    sources: android_sources::AcquisitionSnapshot,
    revision: u32,
    source_generation: u32,
    registration_generation: u32,
}
enum KnownFailure { Invalid, CatalogueRequired }
impl Known {
    fn capture(binding: &Binding) -> Result<Self, KnownFailure> {
        let document = binding.document.upgrade().ok_or(KnownFailure::Invalid)?;
        if !binding
            .android
            .android_original_document_matches(Some(&document))
        {
            return Err(KnownFailure::Invalid);
        }
        let r = binding.android.registry.try_lock().map_err(|_| KnownFailure::Invalid)?;
        if r.active.is_some()
            || r.prepared.is_some()
            || r.disabled
            || r.exhausted
            || r.stopping
            || r.document_lost
            || binding.android.poisoned.load(Ordering::SeqCst)
            || binding.android.android_registration_control.owns_work()
            || binding.android.android_registration_control.is_unknown()
        {
            return Err(KnownFailure::Invalid);
        }
        let sources = r.android_sources.acquisition_snapshot().ok_or(KnownFailure::Invalid)?;
        let registration_generation = r
            .android_registration
            .tool_acquisition_generation().ok_or(KnownFailure::Invalid)?;
        let catalog = reuse::CatalogLoan::capture(&r.android_catalog, &binding.android).ok_or_else(|| {
            if r.android_catalog.tool_acquisition_check_required(&binding.android) { KnownFailure::CatalogueRequired }
            else { KnownFailure::Invalid }
        })?;
        Ok(Self {
            android: binding.android.clone(),
            document: binding.document.clone(),
            catalog,
            sources,
            revision: r.revision,
            source_generation: r.android_sources.census_generation(),
            registration_generation,
        })
    }
    fn current(&self) -> bool {
        let Some(document) = self.document.upgrade() else {
            return false;
        };
        if !self
            .android
            .android_original_document_matches(Some(&document))
            || !self.catalog.joined_for(&self.android)
        {
            return false;
        }
        let Ok(r) = self.android.registry.try_lock() else {
            return false;
        };
        r.revision == self.revision
            && !r.disabled
            && !r.exhausted
            && !r.stopping
            && !r.document_lost
            && r.active.is_none()
            && r.prepared.is_none()
            && !self.android.poisoned.load(Ordering::SeqCst)
            && !self.android.android_registration_control.owns_work()
            && !self.android.android_registration_control.is_unknown()
            && self.catalog.current(&r.android_catalog, &self.android)
            && r.android_sources.census_generation() == self.source_generation
            && r.android_sources.same_acquisition_snapshot(&self.sources)
            && r.android_registration
                .tool_acquisition_generation()
                == Some(self.registration_generation)
    }
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.android, &other.android)
            && self.document.as_ptr() == other.document.as_ptr()
            && self.revision == other.revision
            && self.source_generation == other.source_generation
            && self.registration_generation == other.registration_generation
            && self.catalog.generation() == other.catalog.generation()
            && self.sources.same(&other.sources)
            && self.current()
            && other.current()
    }
}
struct Inspection {
    original: Arc<Session>,
    terminal: wire::Terminal,
}
impl Inspection {
    fn matches(&self, context: &wire::Context, registration: u32, root: &RegisteredRoot) -> bool {
        let Context::ToolAcquisition(before) = &self.original.context else {
            return false;
        };
        let Some(review) = &context.review else {
            return false;
        };
        before.action == wire::Action::Inspect
            && context.action == wire::Action::Acquire
            && before.same_saved(context)
            && review.operation_id == self.original.id
            && review.owner_generation == self.original.generation
            && self.original.registration == registration
            && self.original.project == *root
            && original_joined(&self.original)
            && self.terminal.context == *before
            && self.terminal.outcome == wire::Outcome::Complete
            && self.terminal.lifetime.settled()
            && self.terminal.protected_tools() == Some(wire::ProtectedTools::NoneInSupportedCatalogue)
            && self.terminal.components().is_some_and(|parts| parts.needs_download())
            && self
                .terminal
                .result
                .as_ref()
                .is_some_and(|v| v["requirements"]["sourcesSha256"] == review.requirements_sha256)
            && self
                .original
                .tools
                .intent
                .as_ref()
                .is_some_and(|intent| intent.current())
    }
    fn footprint(&self) -> Result<wire::Footprint, BridgeError> {
        wire::footprint(&self.terminal.result.as_ref().ok_or_else(wire::invalid)?["footprint"])
    }
}
#[path = "saved_command_agent_tool_acquisition.rs"]
pub(in crate::saved_command_owner) mod agent;
pub(crate) use agent::{Approval as AgentToolAcquisitionApproval, Binding as AgentToolAcquisitionBinding};
pub(crate) use agent::inspect::{Approval as AgentToolInspectApproval, Binding as AgentToolInspectBinding};
pub(super) struct Intent {
    agent: std::sync::OnceLock<Arc<agent::Binding>>,
    known: Arc<Known>,
    document: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
    inspection: Option<Arc<Inspection>>,
    producers: Vec<Arc<Session>>,
    generation: u32,
}
impl Intent {
    fn current(&self) -> bool {
        self.known.current()
            && self.document.current()
            && self.producers.len() < MAX_PRODUCERS
            && self.producers.iter().all(|p| original_joined(p))
    }
}
#[derive(Default)]
pub(super) struct Registry {
    generation: u32,
    review: Option<Arc<Inspection>>,
    producers: Vec<Arc<Session>>,
    // Last actual cache attempt, including a known failed namespace effect.
    // The settled root is an observation; fresh picker originals must recheck
    // it. Unknown/active attempts are never interpreted as root absence.
    application: Option<Arc<Session>>,
    // A later known pre-effect refusal must not discard the earlier actual
    // app-data nomination. This is a second original reference, not a receipt.
    application_observation: Option<Arc<Session>>,
    // Only accepted Complete Acquire/Inspect + positive original joins mint
    // locations. Discovery never supplies a cache-producer or source role.
    completed_sources: Option<Arc<sources::CompletedSources>>,
}
pub(super) struct State {
    intent: Option<Arc<Intent>>,
    expected: Mutex<Option<Expected>>,
}
impl State {
    pub(super) fn new(intent: Option<Arc<Intent>>) -> Self {
        Self {
            intent,
            expected: Mutex::new(None),
        }
    }
}
#[derive(Clone)]
struct Expected {
    context_sha256: String,
    reference_sha256: String,
    projection_sha256: String,
    components: wire::components::Partition,
    copied_sdk: Option<wire::sdk::Component>,
}

/// Native-only census from the SAME owner, original Android state and retained
/// producer Sessions. It cannot be constructed/deserialized from renderer DATA.
pub(crate) struct Census {
    owner: Weak<Inner>,
    document: Weak<()>,
    revision: u32,
    known: Arc<Known>,
    retained: usize,
    future: usize,
    pickers: picked::PickerOriginals,
}
impl Census {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained
    }
    pub(crate) fn picker_originals(&self) -> impl Iterator<Item = &Arc<crate::asset_session::OriginalWork>> {
        self.pickers.iter()
    }
    pub(crate) fn future_public_bytes(&self) -> usize { self.future }
    pub(crate) fn public_work_limit(&self) -> usize {
        PUBLIC_WORK_LIMIT
    }
    pub(crate) fn installed_code_limit(&self) -> usize {
        INSTALLED_CODE_LIMIT
    }
    pub(crate) fn same_document(&self, document: &Arc<()>) -> bool {
        self.document.as_ptr() == Arc::as_ptr(document) && self.document.upgrade().is_some()
    }
    fn matches(&self, inner: &Inner, r: &super::Registry) -> bool {
        self.owner.as_ptr() == inner as *const Inner
            && self.revision == r.revision
            && self.known.current()
            && inner
                .tool_acquisition
                .get()
                .is_some_and(|b| b.document.as_ptr() == self.document.as_ptr())
    }
}
pub(crate) struct Admitted {
    status: wire::Status,
    release: Option<oneshot::Sender<()>>,
}
impl Admitted {
    pub(crate) fn release(self) -> wire::Status {
        if let Some(go) = self.release {
            let _ = go.send(());
        }
        self.status
    }
}
impl SavedCommandOwner {
    pub(crate) fn tool_acquisition(runtime: RuntimeConfig) -> Self {
        Self::new(runtime, SavedCommandDomain::ToolAcquisition)
    }
    /// Root calls only from the original native Document binding, after the
    /// Android owner has accepted that SAME document and native path resolver.
    pub(crate) fn bind_tool_acquisition_document(
        &self,
        android: &SavedCommandOwner,
        document: &Arc<()>,
        application_data: &Path,
    ) -> Result<(), BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        ))]
        {
            if !android
                .inner
                .android_original_document_matches(Some(document))
            {
                return Err(wire::invalid());
            }
            let location =
                cache::Location::application_data(application_data).map_err(|_| wire::invalid())?;
            self.inner
                .tool_acquisition
                .set(Binding {
                    android: android.inner.clone(),
                    document: Arc::downgrade(document),
                    location,
                    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
                    observation: std::sync::OnceLock::new(),
                })
                .map_err(|_| wire::invalid())
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        )))]
        {
            let _ = (android, document, application_data);
            Err(self.inner.domain.unavailable())
        }
    }
    pub(crate) fn tool_acquisition_census(
        &self,
        document: &Arc<()>,
    ) -> Result<Census, BridgeError> {
        self.tool_acquisition_census_inner(document, false)
    }
    /// Only Document Prepare may expose a known missing prerequisite. Start
    /// keeps the old generic failure and its original retained intent.
    pub(crate) fn tool_acquisition_prepare_census(
        &self,
        document: &Arc<()>,
    ) -> Result<Census, BridgeError> {
        self.tool_acquisition_census_inner(document, true)
    }
    fn tool_acquisition_census_inner(
        &self,
        document: &Arc<()>,
        before_prepare: bool,
    ) -> Result<Census, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        if before_prepare {
            // Drop THIS registry before checking the Android original; no
            // new lock order or exemption for live/unknown work is introduced.
            let r = self.inner.registry.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
            if self.inner.availability(&r, Availability::Available) != Availability::Available
                || r.tool_acquisition.producers.len() >= MAX_PRODUCERS
                || r.tool_acquisition.generation == u32::MAX {
                return Err(wire::invalid());
            }
        }
        let binding = self
            .inner
            .tool_acquisition
            .get()
            .ok_or_else(wire::invalid)?;
        if binding.document.as_ptr() != Arc::as_ptr(document) {
            return Err(wire::invalid());
        }
        let known = Arc::new(match Known::capture(binding) {
            Ok(known) => known,
            Err(KnownFailure::CatalogueRequired) if before_prepare => {
                let r = self.inner.registry.try_lock().map_err(|_| BridgeError::cleanup_unknown())?;
                if self.inner.availability(&r, Availability::Available) != Availability::Available
                    || r.tool_acquisition.producers.len() >= MAX_PRODUCERS
                    || r.tool_acquisition.generation == u32::MAX { return Err(wire::invalid()); }
                // An unrelated retained source/producer uncertainty must not
                // be hidden by this diagnostic. Traverse the SAME originals;
                // no census or authority is returned on the refused path.
                retained_bytes(&self.inner, &r, document, &mut picked::PickerOriginals::new())
                    .ok_or_else(wire::invalid)?;
                return Err(wire::prerequisite::Required::Catalogue.error());
            }
            Err(_) => return Err(wire::invalid()),
        });
        let future = picked::future_bytes(&known).ok_or_else(wire::invalid)?;
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if r.active.is_some() || r.disabled || r.exhausted || r.stopping || r.document_lost {
            return Err(wire::invalid());
        }
        let mut pickers = picked::PickerOriginals::new();
        pickers.record(known.sources.picker_originals()).ok_or_else(wire::invalid)?;
        let retained = retained_bytes(&self.inner, &r, document, &mut pickers)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Known>() + 2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(known.sources.retained_bytes()?))
            .ok_or_else(wire::invalid)?;
        Ok(Census {
            owner: Arc::downgrade(&self.inner),
            document: Arc::downgrade(document),
            revision: r.revision,
            known,
            retained,
            future,
            pickers,
        })
    }
    pub(crate) fn prepare_tool_acquisition(
        &self,
        input: wire::Prepare,
        registration: u32,
        root: RegisteredRoot,
        gate: wire::Availability,
        census: &Census,
        document: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
    ) -> Result<wire::Status, BridgeError> {
        self.prepare_tool_acquisition_bound(input, registration, root, gate, census, document, None)
    }
    pub(crate) fn prepare_tool_acquisition_bound(&self, input: wire::Prepare, registration: u32, root: RegisteredRoot,
        gate: wire::Availability, census: &Census, document: Arc<crate::asset_session::ToolAcquisitionDocumentInput>,
        agent: Option<Arc<AgentToolInspectBinding>>) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        if !input.valid()
            || !census.known.sources.matches_project(&input.project_id, registration, &root)
            || !document.matches(&input, registration, &root)
            || !census
                .document
                .upgrade()
                .is_some_and(|d| document.same_document(&d))
        {
            return Err(wire::invalid());
        }
        #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
        if !observation::claim_prepare(&self.inner, &input, &root) { return Err(wire::invalid()); }
        let intent = {
            let r = self
                .inner
                .registry
                .try_lock()
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if !census.matches(&self.inner, &r)
                || r.tool_acquisition.producers.len() >= MAX_PRODUCERS
                || !census.known.catalog.permits_action(input.action)
            {
                return Err(wire::invalid());
            }
            let inspection = match input.action {
                wire::Action::Inspect => None,
                wire::Action::Acquire => Some(
                    r.tool_acquisition
                        .review
                        .as_ref()
                        .filter(|v| {
                            v.matches(&input, registration, &root)
                                && v.original
                                    .tools
                                    .intent
                                    .as_ref()
                                    .is_some_and(|i| document.same_saved_binding(&i.document))
                        })
                        .cloned()
                        .ok_or_else(wire::invalid)?,
                ),
            };
            Arc::new(Intent {
                agent:std::sync::OnceLock::new(),
                known: census.known.clone(),
                document,
                inspection,
                producers: r.tool_acquisition.producers.clone(),
                generation: r
                    .tool_acquisition
                    .generation
                    .checked_add(1)
                    .ok_or_else(wire::invalid)?,
            })
        };
        if let Some(binding) = agent {
            let preparation = agent::inspect::Preparation::new(binding, intent)?;
            return self.prepare_bound_requests_tools(Context::ToolAcquisition(input), registration, root,
                Availability::from_tools(gate), None, None, None, None, Some(preparation))?.tools();
        }
        let status = self
            .prepare(
                Context::ToolAcquisition(input),
                registration,
                root,
                Availability::from_tools(gate),
            )?
            .tools()?;
        let comparison = status.operation.as_ref().ok_or_else(wire::invalid)?;
        let mut r = self.inner.lock();
        let p = r.prepared.as_mut().ok_or_else(wire::invalid)?;
        if p.tools.is_some()
            || p.projection.operation_id != comparison.operation_id
            || p.projection.owner_generation != comparison.owner_generation
            || p.projection.context != Context::ToolAcquisition(comparison.context.clone())
            || !intent.current()
        {
            return Err(wire::invalid());
        }
        p.tools = Some(intent);
        r.tool_acquisition.completed_sources = None;
        Ok(status)
    }
    pub(crate) fn prepared_tool_acquisition_document(
        &self,
        operation: &str,
        generation: &str,
    ) -> Result<Arc<crate::asset_session::ToolAcquisitionDocumentInput>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        let r = self.inner.lock();
        let prepared = r
            .prepared
            .as_ref()
            .filter(|p| {
                p.projection.operation_id == operation
                    && p.projection.owner_generation == generation
            })
            .ok_or_else(wire::invalid)?;
        let intent = prepared.tools.as_ref().ok_or_else(wire::invalid)?;
        let Context::ToolAcquisition(context) = &prepared.projection.context else {
            return Err(wire::invalid());
        };
        if intent.document.context() != context {
            return Err(wire::invalid());
        }
        Ok(intent.document.clone())
    }
    pub(crate) fn start_tool_acquisition(
        &self,
        input: wire::Start,
        at: Instant,
        registered: Option<(u32, RegisteredRoot)>,
        gate: wire::Availability,
        census: &Census,
        budget: &crate::asset_session::ToolAcquisitionMemoryAdmission<'_>,
    ) -> Result<Admitted, BridgeError> {
        self.start_tool_acquisition_agent(input,at,registered,gate,census,budget,None)
    }
    pub(crate) fn start_tool_acquisition_agent(&self,input:wire::Start,at:Instant,registered:Option<(u32,RegisteredRoot)>,gate:wire::Availability,census:&Census,budget:&crate::asset_session::ToolAcquisitionMemoryAdmission<'_>,entry:Option<&Arc<crate::service_tool_setup_requests::Entry>>) -> Result<Admitted,BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        if !input.consents() {
            return Err(wire::invalid());
        }
        let admitted = self.start_bound_requests_tools(
            Start {
                operation_id: input.operation_id,
                owner_generation: input.owner_generation,
            },
            at,
            registered,
            Availability::from_tools(gate),
            None,
            None,
            Some((census, budget)),None,None,None,entry,
        )?;
        Ok(Admitted {
            status: admitted.status.tools()?,
            release: admitted.release,
        })
    }
    pub(crate) fn status_tool_acquisition(
        &self,
        gate: wire::Availability,
    ) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        self.status(Availability::from_tools(gate))?.tools()
    }
    pub(crate) fn cancel_tool_acquisition(
        &self,
        operation: &str,
        generation: &str,
        gate: wire::Availability,
    ) -> Result<wire::Status, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        self.cancel(operation, generation, Availability::from_tools(gate))?
            .tools()
    }
    /// The original cache tail has closed its descriptors. This is its native
    /// point-in-time nomination for a FRESH picker SourceBook, not a held lease.
    /// Pending/unknown work never answers None or authorizes registration.
    pub(crate) fn tool_acquisition_native_exclusion_root(
        &self,
    ) -> Result<Option<RegisteredRoot>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        if r.disabled || r.exhausted || self.inner.poisoned.load(Ordering::SeqCst) {
            return Err(BridgeError::cleanup_unknown());
        }
        if r.stopping || r.document_lost {
            return Err(wire::invalid());
        }
        if r.active.is_some() || r.prepared.is_some() {
            return Err(BridgeError::new(
                "tool_acquisition_busy",
                "Finish or cancel build-tool preparation before choosing another project.",
            ));
        }
        if !r
            .tool_acquisition
            .producers
            .iter()
            .all(|owner| original_joined(owner))
        {
            return Err(BridgeError::cleanup_unknown());
        }
        let attempt = match &r.tool_acquisition.application {
            Some(owner) => application_root(owner)?,
            None => None,
        };
        let observed = match &r.tool_acquisition.application_observation {
            Some(owner) => Some(application_root(owner)?.ok_or_else(BridgeError::cleanup_unknown)?),
            None => None,
        };
        match (attempt, observed) {
            (Some(a), Some(b)) if a == b => Ok(Some(a)),
            (None, value) => Ok(value),
            // An actual cache root may not disappear from its retained role,
            // nor may a changed path/object be silently nominated instead.
            _ => Err(BridgeError::cleanup_unknown()),
        }
    }
    pub(crate) fn tool_acquisition_check_project_root(
        &self,
        proof: &crate::asset_source::ProjectProbe,
    ) -> Result<(), BridgeError> {
        let current = self.tool_acquisition_native_exclusion_root()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(current) = &current {
            if !proof.excludes_application(Some(current)) {
                return Err(wire::invalid());
            }
        }
        // With no cache nomination, an additional marker may belong to the
        // independent Host role. Root MUST run that validator as well.
        let _ = (proof, current);
        Ok(())
    }
}
impl Inner {
    pub(super) fn tool_acquisition_selected(&self) -> bool {
        let qualified = {
            #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
            { NATIVE_QUALIFIED || observation::selected(self) }
            #[cfg(not(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64"))))]
            { NATIVE_QUALIFIED }
        };
        qualified
            && self.domain == SavedCommandDomain::ToolAcquisition
            && cfg!(all(
                feature = "desktop-shell",
                feature = "custom-protocol",
                not(feature = "development-runtime"),
                not(feature = "macos-installed-installer"),
                not(feature = "macos-android-registration-helper"),
                target_os = "macos"
            ))
            && wire::Profile::current().is_some()
            && self.runtime.tool_acquisition_installed_profile_available()
            && self.tool_acquisition.get().is_some_and(|binding| {
                binding.document.upgrade().is_some_and(|doc| {
                    binding
                        .android
                        .android_original_document_matches(Some(&doc))
                })
            })
    }
}
pub(super) fn start_admitted(
    inner: &Inner,
    r: &super::Registry,
    p: &Prepared,
    admission: Option<(
        &Census,
        &crate::asset_session::ToolAcquisitionMemoryAdmission<'_>,
    )>,
) -> bool {
    if inner.domain != SavedCommandDomain::ToolAcquisition {
        return admission.is_none() && p.tools.is_none();
    }
    let Some((census, budget)) = admission else {
        return false;
    };
    let Some(intent) = &p.tools else {
        return false;
    };
    let Context::ToolAcquisition(context) = &p.projection.context else {
        return false;
    };
    census.matches(inner, r)
        && budget.accepts(census, census.future_public_bytes())
        && census.known.same(&intent.known)
        && intent.document.matches(context, p.registration, &p.project)
        && intent.current()
        && intent.generation == r.tool_acquisition.generation.checked_add(1).unwrap_or(0)
        && intent.producers.len() == r.tool_acquisition.producers.len()
        && intent
            .producers
            .iter()
            .zip(&r.tool_acquisition.producers)
            .all(|(a, b)| Arc::ptr_eq(a, b))
        && match (context.action, &intent.inspection) {
            (wire::Action::Inspect, None) => true,
            (wire::Action::Acquire, Some(review)) => {
                r.tool_acquisition.review.as_ref().is_some_and(|v| {
                    Arc::ptr_eq(v, review) && review.matches(context, p.registration, &p.project)
                })
            }
            _ => false,
        }
}
fn original_joined(owner: &Session) -> bool {
    owner.domain == SavedCommandDomain::ToolAcquisition
        && owner.watchdog_joined.load(Ordering::SeqCst)
        && !owner.watchdog_failed.load(Ordering::SeqCst)
        && !owner.resource_unknown.load(Ordering::SeqCst)
        && owner.driver_joined.load(Ordering::SeqCst)
        && !owner.driver_failed.load(Ordering::SeqCst)
        && !owner.manager_failed.load(Ordering::SeqCst)
        && owner.material_retired.load(Ordering::SeqCst)
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
            .is_ok_and(|book| native_final(&book, owner))
}
fn application_root(owner: &Session) -> Result<Option<RegisteredRoot>, BridgeError> {
    if !original_joined(owner) {
        return Err(BridgeError::cleanup_unknown());
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        let resources = owner
            .resources
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        let original = resources
            .tools
            .original
            .as_ref()
            .ok_or_else(BridgeError::cleanup_unknown)?
            .try_lock()
            .map_err(|_| BridgeError::cleanup_unknown())?;
        original
            .cache
            .application_root()
            .map_err(|_| BridgeError::cleanup_unknown())
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        Err(BridgeError::cleanup_unknown())
    }
}
pub(super) fn after_final(inner: &Inner, r: &mut super::Registry, active: &mut Active, owner: &Arc<Session>) {
    let _ = inner;
    if owner.domain != SavedCommandDomain::ToolAcquisition {
        return;
    }
    r.tool_acquisition.completed_sources = None;
    // Retain the SAME attempt even when POST/closure later fails. A pending
    // attempt is already retained in Active; no guessed path or JSON can stand
    // in for its original cache book after retirement.
    if matches!(&owner.context, Context::ToolAcquisition(c) if c.action == wire::Action::Acquire) {
        r.tool_acquisition.application = Some(owner.clone());
    }
    if active.unknown || !active.final_join_seen || !original_joined(owner) {
        r.disabled = true;
        return;
    }
    if matches!(&owner.context, Context::ToolAcquisition(c) if c.action == wire::Action::Acquire) {
        match application_root(owner) {
            Ok(Some(current)) => {
                if let Some(prior) = &r.tool_acquisition.application_observation {
                    if !application_root(prior).is_ok_and(|root| root.as_ref() == Some(&current)) {
                        r.disabled = true;
                        return;
                    }
                }
                r.tool_acquisition.application_observation = Some(owner.clone());
            }
            Ok(None) => {} // Prior original nomination stays retained.
            Err(_) => {
                r.disabled = true;
                return;
            }
        }
    }
    // A known cancelled/refused child may still have produced an owned cache.
    // Only the SAME joined native cache tail, not terminal success, mints origin.
    if producer(owner) {
        if r.tool_acquisition.producers.len() >= MAX_PRODUCERS {
            r.disabled = true;
            return;
        }
        r.tool_acquisition.producers.push(owner.clone());
        let Some(next) = r.tool_acquisition.generation.checked_add(1) else {
            r.disabled = true;
            return;
        };
        r.tool_acquisition.generation = next;
    }
    r.tool_acquisition.review = None;
    if !active.context_invalidated
        && !r.document_lost
        && !r.stopping
        && active.accepted
        && active.terminal
        && active.first_stop.is_none()
        && active.projection.outcome == Some(Outcome::Complete)
    {
        observe_protected_tools(owner, active);
        if let Some(Terminal::ToolAcquisition(t)) = &active.projection.result {
            r.tool_acquisition.completed_sources = sources::CompletedSources::capture(owner, active);
            if t.context.action == wire::Action::Inspect
                && t.outcome == wire::Outcome::Complete
                && t.lifetime.settled()
                && t.protected_tools() == Some(wire::ProtectedTools::NoneInSupportedCatalogue)
                && t.components().is_some_and(|parts| parts.needs_download())
                && !t.discovered_sources().is_some_and(|found| found.needs_selection())
            {
                r.tool_acquisition.review = Some(Arc::new(Inspection {
                    original: owner.clone(), terminal: t.clone(),
                }));
            }
        }
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    observation::returned(inner, r, active, owner);
}
fn observe_protected_tools(owner: &Session, active: &mut Active) {
    let (Some(intent), Profile::ToolAcquisition(profile)) = (&owner.tools.intent, owner.profile) else { return; };
    let Some(Terminal::ToolAcquisition(terminal)) = &mut active.projection.result else { return; };
    if terminal.context.action != wire::Action::Inspect || !intent.current() { return; }
    let finding = intent.known.catalog.finding(&intent.known.android, profile, terminal);
    // Only post-join public DATA is added. A selected loan creates no download
    // Review and thus retains no orphaned catalogue/Session after retirement.
    terminal.observe_protected_tools(finding);
    match finding {
        wire::ProtectedTools::ReuseSelected => terminal.observe_components(wire::components::Partition::compatible_all()),
        wire::ProtectedTools::NoneInSupportedCatalogue => {
            #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"),not(feature="macos-android-registration-helper")))]
            if let Some((parts, _)) = native::picked_finding(owner) {
                terminal.observe_components(parts);
                if let Some(found) = native::discovery(owner) { terminal.observe_discovered_sources(found); }
            }
        },
        wire::ProtectedTools::ManualCheckRequired => {},
    }
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Finite original capacity traversal. No current work/unknown owner is omitted.
fn value_bytes(value: &Value) -> Option<usize> {
    fn visit(v: &Value, n: &mut usize, d: usize) -> Option<usize> {
        *n = n.checked_add(1)?;
        if *n > 8192 || d > 16 {
            return None;
        }
        let own = std::mem::size_of::<Value>();
        match v {
            Value::String(v) => own.checked_add(v.capacity()),
            Value::Array(v) => {
                let mut b =
                    own.checked_add(v.capacity().checked_mul(std::mem::size_of::<Value>())?)?;
                for v in v {
                    b = b.checked_add(visit(v, n, d + 1)?)?;
                }
                Some(b)
            }
            Value::Object(v) => {
                let mut b = own;
                for (k, v) in v {
                    b = b
                        .checked_add(k.capacity())?
                        .checked_add(visit(v, n, d + 1)?)?
                        .checked_add(256)?;
                }
                Some(b)
            }
            _ => Some(own),
        }
    }
    visit(value, &mut 0, 0)
}
fn context_bytes(value: &wire::Context) -> Option<usize> {
    let mut b = value
        .project_id
        .capacity()
        .checked_add(value.saved_config.sha256.capacity())?;
    if let Some(r) = &value.review {
        b = b
            .checked_add(r.operation_id.capacity())?
            .checked_add(r.owner_generation.capacity())?
            .checked_add(r.requirements_sha256.capacity())?;
    }
    Some(b)
}
fn retained_bytes(inner: &Inner, r: &super::Registry, document: &Arc<()>, pickers: &mut picked::PickerOriginals) -> Option<usize> {
    let binding = inner.tool_acquisition.get()?;
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    let android = android_registration::tool_acquisition_owner_bytes(&binding.android, document)?;
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    let android = {
        let _ = (binding, document);
        return None;
        #[allow(unreachable_code)]
        0usize
    };
    let mut bytes = android
        .checked_add(std::mem::size_of::<Inner>())?
        .checked_add(std::mem::size_of::<super::Registry>())?
        .checked_add(std::mem::size_of::<Census>())?
        .checked_add(256 * 1024)?; // finite channel/registry bookkeeping reserve
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        bytes = bytes
            .checked_add(binding.location.retained_bytes()?)?
            .checked_add(
                inner
                    .runtime
                    .android_registration_retained_heap_bytes(document)?,
            )?;
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    { bytes = bytes.checked_add(observation::charge(inner)?)?; }
    let mut seen = BTreeSet::new();
    let mut queue = r.tool_acquisition.producers.clone();
    if let Some(completed) = &r.tool_acquisition.completed_sources {
        queue.push(completed.original().clone()); // SAME original Session, deduplicated below.
        bytes = bytes.checked_add(completed.retained_bytes()?)?;
    }
    if let Some(application) = &r.tool_acquisition.application {
        queue.push(application.clone());
    }
    if let Some(application) = &r.tool_acquisition.application_observation {
        queue.push(application.clone());
    }
    if let Some(review) = &r.tool_acquisition.review {
        queue.push(review.original.clone());
        bytes = bytes
            .checked_add(std::mem::size_of::<Inspection>())?
            .checked_add(context_bytes(&review.terminal.context)?)?;
        if let Some(v) = &review.terminal.result {
            bytes = bytes.checked_add(value_bytes(v)?)?;
        }
    }
    if let Some(prepared) = &r.prepared {
        let Context::ToolAcquisition(c) = &prepared.projection.context else {
            return None;
        };
        bytes = bytes
            .checked_add(context_bytes(c)?)?
            .checked_add(prepared.project.path.capacity())?
            .checked_add(prepared.projection.operation_id.capacity())?
            .checked_add(prepared.projection.owner_generation.capacity())?;
        if let Some(intent) = &prepared.tools {
            // A selected loan is read-only and cannot become a producer. Its
            // actual catalogue backing is counted by the SAME Android census;
            // a retired prepared selection must be cancelled, not omitted.
            if intent.known.catalog.empty().is_none() && !intent.known.current() { return None; }
            pickers.record(intent.known.sources.picker_originals())?;
            bytes = bytes
                .checked_add(std::mem::size_of::<Intent>())?
                .checked_add(std::mem::size_of::<Known>())?
                .checked_add(intent.known.sources.retained_bytes()?)?
                .checked_add(intent.document.retained_bytes()?)?
                .checked_add(
                    intent
                        .producers
                        .capacity()
                        .checked_mul(std::mem::size_of::<Arc<Session>>())?,
                )?;
            queue.extend(intent.producers.iter().cloned());
            if let Some(i) = &intent.inspection {
                queue.push(i.original.clone());
                bytes = bytes
                    .checked_add(std::mem::size_of::<Inspection>())?
                    .checked_add(context_bytes(&i.terminal.context)?)?;
                if let Some(v) = &i.terminal.result {
                    bytes = bytes.checked_add(value_bytes(v)?)?;
                }
            }
        }
    }
    if let Some(last) = &r.last {
        let Context::ToolAcquisition(c) = &last.context else {
            return None;
        };
        bytes = bytes
            .checked_add(context_bytes(c)?)?
            .checked_add(last.operation_id.capacity())?
            .checked_add(last.owner_generation.capacity())?;
        if let Some(Terminal::ToolAcquisition(t)) = &last.result {
            bytes = bytes.checked_add(context_bytes(&t.context)?)?;
            if let Some(v) = &t.result {
                bytes = bytes.checked_add(value_bytes(v)?)?;
            }
        }
    }
    while let Some(owner) = queue.pop() {
        if !seen.insert(Arc::as_ptr(&owner) as usize) {
            continue;
        }
        if seen.len() > MAX_RETAINED_SESSIONS || !original_joined(&owner) {
            return None;
        }
        let Context::ToolAcquisition(c) = &owner.context else {
            return None;
        };
        bytes = bytes
            .checked_add(std::mem::size_of::<Session>())?
            .checked_add(std::mem::size_of::<super::Resources>())?
            .checked_add(context_bytes(c)?)?
            .checked_add(owner.id.capacity())?
            .checked_add(owner.generation.capacity())?
            .checked_add(owner.project.path.capacity())?
            .checked_add(64 * 1024)?; // retained finite watch/task cells, not native SDK allocations
        let resources = owner.resources.try_lock().ok()?;
        bytes = bytes.checked_add(resources.tools.retained_bytes()?)?;
        drop(resources);
        if owner.request.try_lock().ok()?.is_some() {
            return None;
        }
        if let Some(expected) = owner.tools.expected.try_lock().ok()?.as_ref() {
            bytes = bytes
                .checked_add(expected.context_sha256.capacity())?
                .checked_add(expected.reference_sha256.capacity())?
                .checked_add(expected.projection_sha256.capacity())?;
        }
        if let Some(intent) = &owner.tools.intent {
            // Only empty-catalogue Inspect/Acquire Sessions are retained as
            // cache producers, discovery locations or download Reviews.
            // No uncounted old selected loan.
            if intent.known.catalog.empty().is_none() { return None; }
            pickers.record(intent.known.sources.picker_originals())?;
            bytes = bytes
                .checked_add(std::mem::size_of::<Intent>())?
                .checked_add(std::mem::size_of::<Known>())?
                .checked_add(intent.known.sources.retained_bytes()?)?
                .checked_add(intent.document.retained_bytes()?)?
                .checked_add(
                    intent
                        .producers
                        .capacity()
                        .checked_mul(std::mem::size_of::<Arc<Session>>())?,
                )?;
            queue.extend(intent.producers.iter().cloned());
            if let Some(i) = &intent.inspection {
                queue.push(i.original.clone());
                bytes = bytes
                    .checked_add(std::mem::size_of::<Inspection>())?
                    .checked_add(context_bytes(&i.terminal.context)?)?;
                if let Some(v) = &i.terminal.result {
                    bytes = bytes.checked_add(value_bytes(v)?)?;
                }
            }
        }
        if bytes > PUBLIC_WORK_LIMIT {
            return None;
        }
    }
    Some(bytes)
}

impl Phase {
    pub(super) fn tools(self) -> wire::Phase {
        match self {
            Self::AwaitingConsent => wire::Phase::AwaitingConsent,
            Self::Starting => wire::Phase::Starting,
            Self::Running => wire::Phase::Running,
            Self::Stopping => wire::Phase::Stopping,
            Self::Terminal => wire::Phase::Terminal,
            Self::Unknown => wire::Phase::Unknown,
        }
    }
}
impl Outcome {
    pub(super) fn from_tools(v: wire::Outcome) -> Self {
        match v {
            wire::Outcome::Complete => Self::Complete,
            wire::Outcome::Refused => Self::Refused,
            wire::Outcome::Cancelled => Self::Cancelled,
            wire::Outcome::TimedOut => Self::TimedOut,
            wire::Outcome::Failed => Self::Failed,
            wire::Outcome::Unknown => Self::Unknown,
        }
    }
    pub(super) fn tools(self) -> wire::Outcome {
        match self {
            Self::Complete => wire::Outcome::Complete,
            Self::Refused => wire::Outcome::Refused,
            Self::Cancelled => wire::Outcome::Cancelled,
            Self::TimedOut => wire::Outcome::TimedOut,
            Self::Failed => wire::Outcome::Failed,
            Self::Unknown => wire::Outcome::Unknown,
        }
    }
}
impl Reason {
    pub(super) fn from_tools(v: wire::Reason) -> Self {
        match v {
            wire::Reason::None => Self::None,
            wire::Reason::Cancelled => Self::Cancelled,
            wire::Reason::TimedOut => Self::TimedOut,
            wire::Reason::ContextChanged => Self::ContextChanged,
            wire::Reason::DocumentLost => Self::DocumentLost,
            wire::Reason::Shutdown => Self::Shutdown,
            wire::Reason::RuntimeUnavailable => Self::RuntimeUnavailable,
            wire::Reason::ProtocolError => Self::ProtocolError,
            wire::Reason::IntentExpired => Self::IntentExpired,
            wire::Reason::StaleIntent => Self::StaleIntent,
            wire::Reason::CleanupUnknown => Self::CleanupUnknown,
            wire::Reason::InputLimit => Self::InputLimit,
            wire::Reason::ResultLimit => Self::ResultLimit,
            other => Self::ToolAcquisition(other),
        }
    }
    pub(super) fn tools(self) -> Result<wire::Reason, BridgeError> {
        Ok(match self {
            Self::None => wire::Reason::None,
            Self::Cancelled => wire::Reason::Cancelled,
            Self::TimedOut => wire::Reason::TimedOut,
            Self::ContextChanged => wire::Reason::ContextChanged,
            Self::DocumentLost => wire::Reason::DocumentLost,
            Self::Shutdown => wire::Reason::Shutdown,
            Self::RuntimeUnavailable => wire::Reason::RuntimeUnavailable,
            Self::ProtocolError | Self::CommandIncomplete | Self::CommandFailed => {
                wire::Reason::ProtocolError
            }
            Self::IntentExpired => wire::Reason::IntentExpired,
            Self::StaleIntent => wire::Reason::StaleIntent,
            Self::CleanupUnknown => wire::Reason::CleanupUnknown,
            Self::InputLimit => wire::Reason::InputLimit,
            Self::ResultLimit => wire::Reason::ResultLimit,
            Self::ToolAcquisition(v) => v,
            _ => return Err(BridgeError::protocol()),
        })
    }
}
impl Availability {
    pub(super) fn from_tools(v: wire::Availability) -> Self {
        match v {
            wire::Availability::Available => Self::Available,
            wire::Availability::Busy => Self::Busy,
            wire::Availability::Shutdown => Self::Shutdown,
            wire::Availability::CleanupUnknown => Self::CleanupUnknown,
            wire::Availability::DocumentLost => Self::DocumentLost,
            wire::Availability::UnsupportedPlatform => Self::UnsupportedPlatform,
            wire::Availability::RuntimeUnqualified => Self::RuntimeUnqualified,
        }
    }
    pub(super) fn tools(self) -> wire::Availability {
        match self {
            Self::Available => wire::Availability::Available,
            Self::Busy => wire::Availability::Busy,
            Self::Shutdown => wire::Availability::Shutdown,
            Self::CleanupUnknown => wire::Availability::CleanupUnknown,
            Self::DocumentLost => wire::Availability::DocumentLost,
            Self::UnsupportedPlatform => wire::Availability::UnsupportedPlatform,
            Self::RuntimeUnqualified | Self::ToolchainUnqualified => {
                wire::Availability::RuntimeUnqualified
            }
        }
    }
}
impl Status {
    pub(super) fn tools(self) -> Result<wire::Status, BridgeError> {
        match self {
            Self::ToolAcquisition(v) => Ok(v),
            _ => Err(BridgeError::protocol()),
        }
    }
}
impl RunProjection {
    pub(super) fn tools(self) -> Result<wire::Projection, BridgeError> {
        let Context::ToolAcquisition(context) = self.context else {
            return Err(BridgeError::protocol());
        };
        if self.stage.is_some() {
            return Err(BridgeError::protocol());
        }
        let result = match self.result {
            Some(Terminal::ToolAcquisition(t)) => t.public_result(),
            None => None,
            _ => return Err(BridgeError::protocol()),
        };
        Ok(wire::Projection {
            operation_id: self.operation_id,
            owner_generation: self.owner_generation,
            context,
            phase: self.phase.tools(),
            intent_usable: self.intent_usable,
            outcome: self.outcome.map(Outcome::tools),
            reason: self.reason.tools()?,
            result,
        })
    }
}
pub(super) fn check_frame(owner: &Session, frame: wire::Frame) -> Result<wire::Frame, BridgeError> {
    if let wire::Frame::Terminal(t) = &frame {
        if t.context.action == wire::Action::Acquire && t.outcome == wire::Outcome::Complete {
            let expected = owner
                .tools
                .expected
                .try_lock()
                .map_err(|_| BridgeError::protocol())?;
            let expected = expected.as_ref().ok_or_else(BridgeError::protocol)?;
            let result = t.result.as_ref().ok_or_else(BridgeError::protocol)?;
            if result["contextSha256"] != expected.context_sha256
                || result["referenceSha256"] != expected.reference_sha256
                || result["projectionSha256"] != expected.projection_sha256
                || !wire::staged_matches_partition(result, expected.components)
                || wire::sdk::copied(result) != Ok(expected.copied_sdk)
            {
                return Err(BridgeError::protocol());
            }
        }
    }
    Ok(frame)
}

#[cfg(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
))]
pub(super) use native::Original;
#[cfg(not(all(
    target_os = "macos",
    target_pointer_width = "64",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")
)))]
pub(super) enum Original {}
#[derive(Default)]
pub(super) struct Resources {
    selected: bool,
    original: Option<Arc<Mutex<Original>>>,
    runtime_task: Option<JoinHandle<bool>>,
    runtime_return: Option<Result<bool, tokio::task::JoinError>>,
    runtime_started: bool,
    runtime_joined: bool,
    runtime_failed: bool,
    tail: Option<JoinHandle<bool>>,
    tail_return: Option<Result<bool, tokio::task::JoinError>>,
    tail_started: bool,
    tail_joined: bool,
    tail_failed: bool,
}
impl Resources {
    pub(super) fn new(selected: bool) -> Self {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        ))]
        let original = selected.then(|| Arc::new(Mutex::new(Original::new())));
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        )))]
        let original = None;
        Self {
            selected,
            original,
            ..Self::default()
        }
    }
    pub(super) fn original(&self) -> Option<Arc<Mutex<Original>>> {
        self.original.clone()
    }
    fn runtime_joined(&self) -> bool {
        self.selected
            && self.runtime_started
            && self.runtime_joined
            && !self.runtime_failed
            && self.runtime_task.is_none()
            && matches!(self.runtime_return, Some(Ok(true)))
    }
    fn tail_joined(&self) -> bool {
        self.tail_started
            && self.tail_joined
            && !self.tail_failed
            && self.tail.is_none()
            && matches!(self.tail_return, Some(Ok(true)))
    }
    fn retained_bytes(&self) -> Option<usize> {
        #[cfg(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        ))]
        {
            self.original.as_ref()?.try_lock().ok()?.retained_bytes()
        }
        #[cfg(not(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64"),
            not(feature = "macos-android-registration-helper")
        )))]
        {
            None
        }
    }
}
fn producer(owner: &Session) -> bool {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        owner.resources.try_lock().is_ok_and(|r| {
            r.tools.tail_joined()
                && r.tools
                    .original
                    .as_ref()
                    .is_some_and(|o| o.try_lock().is_ok_and(|o| o.cache.origin().is_some()))
        })
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        let _ = owner;
        false
    }
}
pub(super) fn inspect(
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
    original: Option<&Arc<Mutex<Original>>>,
    runtime: &RuntimeConfig,
) -> Result<VerifiedRuntime, BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        native::inspect(inner, owner, original.ok_or_else(wire::invalid)?, runtime)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        let _ = (inner, original, runtime);
        Err(owner.domain.unavailable())
    }
}
pub(super) fn request(
    owner: &Session,
    book: &super::Resources,
    context: &wire::Context,
    profile: wire::Profile,
    runtime: &VerifiedRuntime,
) -> Result<Vec<u8>, BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        native::request(owner, book, context, profile, runtime)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        let _ = (book, context, profile, runtime);
        Err(owner.domain.unavailable())
    }
}
pub(super) fn transfer(
    book: &super::Resources,
    inner: &Inner,
    owner: &Session,
) -> Result<(), BridgeError> {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        native::transfer(book, inner, owner)
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        let _ = (book, inner);
        Err(owner.domain.unavailable())
    }
}
pub(super) fn acquire(inner: &Inner, owner: &Session, original: Option<&Arc<Mutex<Original>>>) {
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        if let Some(original) = original {
            native::acquire(inner, owner, original);
            return;
        }
    }
    let _ = original;
    inner.stop(owner, Reason::RuntimeUnavailable);
}
pub(super) fn worker_lost(book: &super::Resources, owner: &Session) {
    owner.resource_unknown.store(true, Ordering::SeqCst);
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    if let Some(original) = &book.tools.original {
        match original.try_lock() {
            Ok(mut o) => o.interrupted(),
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner().interrupted(),
            _ => {}
        }
    }
    let _ = book;
}
pub(super) fn native_final(book: &super::Resources, owner: &Session) -> bool {
    if owner.domain != SavedCommandDomain::ToolAcquisition {
        return false;
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        book.tools.runtime_joined()
            && book.tools.tail_joined()
            && book
                .tools
                .original
                .as_ref()
                .is_some_and(|o| o.try_lock().is_ok_and(|o| o.settled()))
    }
    #[cfg(not(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    )))]
    {
        let _ = book;
        false
    }
}
pub(super) async fn settle_runtime(
    book: &mut super::Resources,
    inner: &Arc<Inner>,
    owner: &Arc<Session>,
) {
    if owner.domain != SavedCommandDomain::ToolAcquisition {
        return;
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        native::settle_runtime(book, inner, owner).await;
    }
    let _ = (book, inner, owner);
}
pub(super) async fn settle_cache_after_manager(inner: &Arc<Inner>, owner: &Arc<Session>) {
    if owner.domain != SavedCommandDomain::ToolAcquisition {
        return;
    }
    #[cfg(all(
        target_os = "macos",
        target_pointer_width = "64",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(feature = "macos-android-registration-helper")
    ))]
    {
        native::settle_cache_after_manager(inner, owner).await;
    }
    let _ = (inner, owner);
}

#[cfg(test)]
mod tests {
    // No runtime path is opened and no native/child/cache work is admitted.
    use super::*;
    #[test]
    fn cache_exclusion_unknown_is_not_no_cache() {
        let owner = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged(
            "/never-opened-tool-cache-exclusion-fixture".into(),
        ));
        assert!(owner
            .tool_acquisition_native_exclusion_root()
            .unwrap()
            .is_none());
        owner.inner.lock().disabled = true;
        assert!(owner.tool_acquisition_native_exclusion_root().is_err());
        assert!(owner.tool_acquisition_native_exclusion_root().is_err());
    }
    #[test]
    fn supported_profile_data_never_mints_original_census_or_qualification() {
        let owner = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged(
            "/synthetic-unopened-runtime".into(),
        ));
        let document = Arc::new(());
        assert!(owner.tool_acquisition_census(&document).is_err());
        assert!(!owner.inner.tool_acquisition_selected());
        assert!(!owner.inner.qualified(None));
        let status = owner
            .status_tool_acquisition(wire::Availability::Available)
            .unwrap();
        assert_ne!(status.availability, wire::Availability::Available);
        assert!(status.operation.is_none());
        let resources = Resources::default();
        assert!(!resources.selected && !resources.runtime_joined() && !resources.tail_joined());
    }
    #[test]
    fn unqualified_prepare_census_is_not_a_resumable_missing_prerequisite() {
        let owner = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged(
            "/never-opened-prerequisite-runtime".into(),
        ));
        let document = Arc::new(());
        let error = owner.tool_acquisition_prepare_census(&document).err().unwrap();
        assert_eq!(error.code, wire::invalid().code);
        assert_ne!(error.code, wire::prerequisite::Required::Catalogue.error().code);
        assert_ne!(error.code, wire::prerequisite::Required::SavedInputs.error().code);
        let r = owner.inner.registry.try_lock().unwrap();
        assert!(r.active.is_none() && r.prepared.is_none() && r.last.is_none());
        assert_eq!(r.revision, 0);
    }
    #[test]
    fn fixed_acquisition_deadline_and_buffers_are_not_renewed_by_later_phases() {
        let t = Instant::now();
        let clock = Clocks::new(SavedCommandDomain::ToolAcquisition, t);
        assert_eq!(clock.work, t + Duration::from_secs(1200));
        assert_eq!(clock.finality, t + Duration::from_secs(1210));
        let first = t + Duration::from_secs(2);
        assert_eq!(
            clock.settlement(Some(first)),
            first + Duration::from_secs(10)
        );
        assert_eq!(
            clock.cleanup_end(Some(first)),
            first + Duration::from_secs(10)
        );
        assert_eq!(SavedCommandDomain::ToolAcquisition.frame_limit(), 2);
        assert_eq!(
            SavedCommandDomain::ToolAcquisition.request_limit(),
            12 * MIB
        );
        assert_eq!(
            SavedCommandDomain::ToolAcquisition.response_limit(),
            64 * 1024
        );
        assert!(FUTURE_PUBLIC_BYTES <= PUBLIC_WORK_LIMIT);
        assert_eq!(INSTALLED_CODE_LIMIT, 128 * MIB);
    }
    #[test]
    fn acquisition_refusals_do_not_cross_other_execution_domains() {
        for reason in [
            wire::Reason::CacheConflict,
            wire::Reason::CensusIncomplete,
            wire::Reason::RecoveryRequired,
            wire::Reason::ArchiveDigest,
            wire::Reason::DiskSpace,
            wire::Reason::AlreadyUsed,
        ] {
            let internal = Reason::from_tools(reason);
            assert_eq!(internal.tools().unwrap(), reason);
            assert!(
                internal.offline().is_err()
                    && internal.android().is_err()
                    && internal.ios().is_err()
                    && internal.recovery().is_err()
            );
        }
        assert_eq!(
            Reason::from_tools(wire::Reason::Cancelled),
            Reason::Cancelled
        );
        assert_eq!(
            Reason::CleanupUnknown.tools().unwrap(),
            wire::Reason::CleanupUnknown
        );
        assert!(Reason::CandidateInputsUnavailable.tools().is_err());
    }
}
