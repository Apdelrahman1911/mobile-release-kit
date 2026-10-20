//! Completed acquisition/discovery LOCATION nomination for the ordinary source picker.
//! No source/copy/tool authority, new filesystem walk, task, or restart receipt.
use super::*;
use crate::{android_tool_sources as source_wire, asset_session::OriginalWork};
use std::{path::PathBuf, sync::OnceLock};

/// Minted only in the existing positive after_final branch. The original
/// Session remains in the existing bounded retained-session census; its joins
/// are rechecked. Discovery does not acquire a cache-producer role.
pub(super) struct CompletedSources {
    original: Arc<Session>,
    locations: [Option<PathBuf>; 3],
    origin: Origin,
    roles: u8,
    progress: Mutex<Progress>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin { Acquired, Discovered }
struct Progress {
    epoch: u64,
    picker: Option<Weak<OriginalWork>>,
    published: bool,
    retired: bool,
}
/// Only native original lookup creates this. Neither IPC nor an arbitrary path
/// constructor can turn a staging directory into a SourceBook/registered tool.
pub(crate) struct SourceNomination {
    completed: Arc<CompletedSources>,
    role: source_wire::Role,
    initial: PathBuf,
    before: u64,
    continuing: bool,
    work: OnceLock<Weak<OriginalWork>>,
}

fn index(role: source_wire::Role) -> usize { match role { source_wire::Role::Jdk => 0, source_wire::Role::Sdk => 1, source_wire::Role::Gradle => 2 } }
fn bit(role: source_wire::Role) -> u8 {
    match role { source_wire::Role::Jdk => 1, source_wire::Role::Sdk => 2, source_wire::Role::Gradle => 4 }
}
fn folder(role: source_wire::Role) -> &'static str {
    match role { source_wire::Role::Jdk => "jdk.jdk", source_wire::Role::Sdk => "android-sdk", source_wire::Role::Gradle => "gradle" }
}
// The full terminal already passed wire::decode/check_frame on the SAME owner.
// This small projection additionally refuses a grouped SDK with only one part.
fn complete_roles(value: &Value) -> Option<u8> {
    if value["kind"] != "staged-tool-sources" { return None; }
    let rows = value["groups"].as_array()?;
    if rows.len() > 3 { return None; }
    let mut seen = 0u8;
    let mut roles = 0u8;
    for row in rows {
        let (role, required): (_, &[&str]) = match row["group"].as_str()? {
            "jdk" => (source_wire::Role::Jdk, &["jdk"]),
            "sdk" => (source_wire::Role::Sdk, &["sdk-platform", "sdk-build-tools"]),
            "gradle" => (source_wire::Role::Gradle, &["gradle"]),
            _ => return None,
        };
        if seen & bit(role) != 0 { return None; }
        seen |= bit(role);
        let parts = row["components"].as_array()?;
        if row["allRequiredComponentsStaged"] == true && row["next"] == "choose-native-source"
            && parts.len() == required.len() && parts.iter().zip(required).all(|(a, b)| a.as_str() == Some(*b)) {
            roles |= bit(role);
        }
    }
    Some(roles)
}
fn bounded_initial(root: &Path, role: source_wire::Role) -> Option<PathBuf> {
    let text = root.to_str()?;
    let bytes = text.len().checked_add(1 + folder(role).len())?;
    if bytes > 4096 || !root.is_absolute() || !text.starts_with('/') || text.as_bytes().contains(&0)
        || text[1..].split('/').any(|p| p.is_empty() || p == "." || p == ".." || p.len() > 255) { return None; }
    let mut path = PathBuf::new();
    path.try_reserve_exact(bytes).ok()?;
    path.push(root); path.push(folder(role));
    (path.capacity() <= 4096).then_some(path)
}
#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")))]
fn original_root(owner: &Session) -> Option<PathBuf> {
    let resources = owner.resources.try_lock().ok()?;
    let original = resources.tools.original.as_ref()?.try_lock().ok()?;
    original.cache.prepared_sources_location(&owner.id)
}
#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper"))))]
fn original_root(_: &Session) -> Option<PathBuf> { None }

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper")))]
fn discovered_location(owner: &Session, role: usize) -> Option<PathBuf> { native::discovered_directory(owner, role) }
#[cfg(not(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"),
    not(feature = "macos-android-registration-helper"))))]
fn discovered_location(_: &Session, _: usize) -> Option<PathBuf> { None }
fn copy_location(path: &Path) -> Option<PathBuf> {
    let text = path.to_str()?;
    if text.len() > 4096 || !text.starts_with('/') || text == "/" || text.as_bytes().contains(&0)
        || text[1..].split('/').any(|p|p.is_empty() || p == "." || p == ".." || p.len() > 255) { return None; }
    let mut copy = PathBuf::new(); copy.try_reserve_exact(text.len()).ok()?; copy.push(path);
    (copy.capacity() <= 4096).then_some(copy)
}
// The original common Terminal handler sets stop=true even on success to close
// its already-finished input. Only the SAME Active's first failure/context and
// accepted terminal distinguish cancellation here. This is not native finality.
fn accepted_terminal<'a>(owner: &Arc<Session>, active: &'a Active) -> Option<&'a wire::Terminal> {
    if owner.domain != SavedCommandDomain::ToolAcquisition || !Arc::ptr_eq(&active.owner, owner)
        || active.context_invalidated || active.unknown || !active.accepted || !active.terminal
        || active.first_stop.is_some() || active.projection.reason != Reason::None
        || active.projection.outcome != Some(Outcome::Complete) || active.projection.context != owner.context { return None; }
    let Context::ToolAcquisition(context) = &owner.context else { return None; };
    let Some(Terminal::ToolAcquisition(terminal)) = &active.projection.result else { return None; };
    (terminal.context == *context
        && terminal.outcome == wire::Outcome::Complete && terminal.reason == wire::Reason::None
        && terminal.lifetime.settled()).then_some(terminal)
}

impl CompletedSources {
    pub(super) fn capture(owner: &Arc<Session>, active: &Active) -> Option<Arc<Self>> {
        let terminal = accepted_terminal(owner, active)?;
        if !active.final_join_seen || !original_joined(owner) { return None; }
        let intent = owner.tools.intent.as_ref()?;
        if !intent.current() { return None; }
        let mut locations = std::array::from_fn(|_| None);
        let (roles, origin) = match terminal.context.action {
            wire::Action::Acquire => {
                if !producer(owner) { return None; }
                let roles = complete_roles(terminal.result.as_ref()?)?;
                let root = original_root(owner)?;
                for role in [source_wire::Role::Jdk, source_wire::Role::Sdk, source_wire::Role::Gradle] {
                    if roles & bit(role) != 0 { locations[index(role)] = Some(bounded_initial(&root, role)?); }
                }
                (roles, Origin::Acquired)
            },
            wire::Action::Inspect => {
                // Native post-join finding exists only after exact PROJECT
                // requirements admit the protected profile, not version DATA.
                let found = terminal.discovered_sources()?;
                if !found.needs_selection() || terminal.protected_tools() != Some(wire::ProtectedTools::NoneInSupportedCatalogue)
                    || !terminal.components().is_some_and(|parts|found.matches(parts)) { return None; }
                let roles = found.candidate_roles();
                for (role, location) in locations.iter_mut().enumerate() {
                    if roles & (1 << role) != 0 { *location = Some(discovered_location(owner, role)?); }
                }
                (roles, Origin::Discovered)
            },
        };
        Some(Arc::new(Self { original: owner.clone(), locations, origin, roles,
            progress: Mutex::new(Progress { epoch: intent.document.source_picker_epoch(), picker: None, published: false, retired: false }) }))
    }
    #[cfg(all(test, debug_assertions, feature="desktop-shell", feature="custom-protocol", feature="macos-installed-observation", not(feature="development-runtime"), not(feature="ubuntu-runtime-publisher"), not(feature="macos-installed-installer"), target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64")))]
    pub(super) fn observed_sdk(&self, operation: &str, generation: &str) -> Option<PathBuf> {
        let progress=self.progress.try_lock().ok()?;
        if self.origin!=Origin::Acquired || self.roles & bit(source_wire::Role::Sdk)==0
            || self.original.id!=operation || self.original.generation!=generation
            || progress.retired || progress.picker.is_some() || progress.published
            || !self.original.tools.intent.as_ref()?.current() || !original_joined(&self.original) { return None; }
        copy_location(self.locations[index(source_wire::Role::Sdk)].as_deref()?)
    }
    pub(super) fn original(&self) -> &Arc<Session> { &self.original }
    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.locations.iter().flatten().try_fold(std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())?,
            |bytes, path| bytes.checked_add(path.capacity()))
    }
}

impl SourceNomination {
    pub(crate) fn role(&self) -> source_wire::Role { self.role }
    pub(crate) fn initial_directory(&self) -> &Path { &self.initial }
    pub(crate) fn document(&self) -> &crate::asset_session::ToolAcquisitionDocumentInput {
        // Only capture()+original native lookup can construct this type.
        &self.completed.original.tools.intent.as_ref().expect("retained acquisition intent").document
    }
    pub(crate) fn continuing(&self) -> bool { self.continuing }
    fn same_publisher(&self, publisher: &android_registration::Publisher) -> bool {
        self.completed.original.tools.intent.as_ref().is_some_and(|intent|
            publisher.same_slot(&intent.known.android.android_registration_control))
    }
    pub(crate) fn admitted_to(&self, owner: &Arc<OriginalWork>) -> bool {
        self.work.get().is_some_and(|work| work.as_ptr() == Arc::as_ptr(owner))
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // Includes the sole new shared location/continuation allocation. The
        // original Session is separately traversed by its existing owner roster.
        std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.initial.capacity())?.checked_add(self.completed.retained_bytes()?)?
            .checked_add(4096 + std::mem::size_of::<PathBuf>()) // SAME main-thread initial-path clone, not native SDK/RSS.
    }
    /// Called under the same Doc AFTER actual AndroidSource admission and while
    /// its original GO is still closed. Only this exact publisher advances it.
    pub(crate) fn admitted(&self, owner: &Arc<OriginalWork>, publisher: &android_registration::Publisher) -> Result<(), BridgeError> {
        let epoch = publisher.tool_source_epoch()?;
        let mut progress = self.completed.progress.try_lock().map_err(|_| source_wire::invalid())?;
        if progress.retired || progress.epoch != self.before || !self.same_publisher(publisher) || !publisher.accepted()
            || self.before.checked_add(1) != Some(epoch) || self.work.get().is_some() { return Err(source_wire::invalid()); }
        self.work.set(Arc::downgrade(owner)).map_err(|_| source_wire::invalid())?;
        progress.epoch = epoch; progress.picker = Some(Arc::downgrade(owner)); progress.published = false;
        Ok(())
    }
    /// Observe BEFORE the same selected-source publication accepts its original
    /// lifecycle publisher. Other pending/cancel/accepted publishers give none.
    pub(crate) fn publication_epoch(&self, owner: &Arc<OriginalWork>, publisher: &android_registration::Publisher) -> Option<u64> {
        let epoch = publisher.tool_source_epoch().ok()?;
        let progress = self.completed.progress.try_lock().ok()?;
        (!publisher.accepted() && self.same_publisher(publisher) && !progress.retired && !progress.published && self.admitted_to(owner)
            && progress.picker.as_ref().is_some_and(|work| work.as_ptr() == Arc::as_ptr(owner))
            && progress.epoch == epoch && owner.android_source_selected_settled()).then_some(epoch)
    }
    /// Only AFTER the original fresh SourceBook proof was published. Failure
    /// retires this convenience; it never changes that proof's authority.
    pub(crate) fn published(&self, owner: &Arc<OriginalWork>, publisher: &android_registration::Publisher, before: Option<u64>) {
        let Ok(mut progress) = self.completed.progress.try_lock() else { return; };
        let after = publisher.tool_source_epoch().ok();
        if progress.retired || progress.published || !self.same_publisher(publisher) || !publisher.accepted() || !self.admitted_to(owner)
            || !progress.picker.as_ref().is_some_and(|work| work.as_ptr() == Arc::as_ptr(owner))
            || !owner.android_source_selected_settled() || before != Some(progress.epoch)
            || before.and_then(|epoch| epoch.checked_add(1)) != after {
            progress.retired = true; return;
        }
        progress.epoch = after.expect("matched original epoch"); progress.published = true;
    }
}

impl SavedCommandOwner {
    pub(crate) fn nominate_acquired_tool_source(&self, document: &Arc<()>, input: &source_wire::Choose,
        registration: u32, root: &RegisteredRoot, publisher: &android_registration::Publisher) -> Result<Arc<SourceNomination>, BridgeError> {
        self.require_domain(SavedCommandDomain::ToolAcquisition)?;
        if !self.inner.tool_acquisition_selected() { return Err(source_wire::unavailable()); }
        let (acquired, origin) = match (&input.acquired, &input.discovered) {
            (Some(ids), None) => (ids, Origin::Acquired),
            (None, Some(ids)) => (ids, Origin::Discovered),
            _ => return Err(source_wire::invalid()),
        };
        let binding = self.inner.tool_acquisition.get().ok_or_else(source_wire::unavailable)?;
        if binding.document.as_ptr() != Arc::as_ptr(document) || !publisher.same_slot(&binding.android.android_registration_control)
            || publisher.accepted() || !binding.android.android_original_document_matches(Some(document)) { return Err(source_wire::invalid()); }
        let epoch = publisher.tool_source_epoch()?;
        let completed = {
            let r = self.inner.registry.try_lock().map_err(|_| source_wire::invalid())?;
            if r.disabled || r.exhausted || r.document_lost || r.stopping || r.active.is_some() || r.prepared.is_some()
                || self.inner.poisoned.load(Ordering::SeqCst) { return Err(source_wire::unavailable()); }
            r.tool_acquisition.completed_sources.clone().ok_or_else(source_wire::invalid)?
        };
        let owner = &completed.original;
        let Context::ToolAcquisition(context) = &owner.context else { return Err(source_wire::invalid()); };
        let intent = owner.tools.intent.as_ref().ok_or_else(source_wire::invalid)?;
        if completed.origin != origin || owner.id != acquired.operation_id || owner.generation != acquired.owner_generation || owner.registration != registration
            || owner.project != *root || context.project_id != input.project_id || completed.roles & bit(input.role) == 0
            || !original_joined(owner) || origin == Origin::Acquired && !producer(owner) || !intent.document.same_document(document)
            || !intent.known.catalog.joined_for(&binding.android) {
            return Err(source_wire::invalid());
        }
        let progress = completed.progress.try_lock().map_err(|_| source_wire::invalid())?;
        if progress.retired || progress.epoch != epoch || progress.picker.as_ref().is_some_and(|previous|
            !progress.published || !previous.upgrade().is_some_and(|original| original.android_source_selected_settled())) {
            return Err(source_wire::invalid());
        }
        let continuing = progress.picker.is_some();
        drop(progress);
        let r = binding.android.registry.try_lock().map_err(|_| source_wire::invalid())?;
        if r.android_sources.census_generation() != input.source_generation || r.android_sources.busy() || r.android_sources.unknown()
            || r.android_registration.busy() || r.android_registration.unknown() || r.android_catalog.busy() || r.android_catalog.unknown()
            || !r.android_catalog.same_source_picker_empty_loan(intent.known.catalog.empty().ok_or_else(source_wire::invalid)?, continuing)
            || r.android_registration.tool_acquisition_generation() != Some(intent.known.registration_generation)
            || r.disabled || r.document_lost || r.stopping || r.exhausted || r.active.is_some() || r.prepared.is_some()
            || binding.android.poisoned.load(Ordering::SeqCst) { return Err(source_wire::invalid()); }
        drop(r);
        let initial = copy_location(completed.locations[index(input.role)].as_deref().ok_or_else(source_wire::invalid)?).ok_or_else(source_wire::invalid)?;
        Ok(Arc::new(SourceNomination { completed, role: input.role, initial, before: epoch, continuing, work: OnceLock::new() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acquire_terminal_input_shutdown_is_not_an_original_cancel() {
        // Reuse the original owner's inert fixture and actual frame/STOP
        // transitions. No child, cache permit or positive native join is made.
        let context = wire::prepare(&json!({"projectId":"synthetic-project","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"action":"acquire",
            "review":{"operationId":"c".repeat(32),"ownerGeneration":"d".repeat(32),"requirementsSha256":"e".repeat(64)}})).unwrap();
        let payload = json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
            "result":{"schemaVersion":1,"kind":"staged-tool-sources","operationId":"a".repeat(32),
                "contextSha256":"a".repeat(64),"referenceSha256":"b".repeat(64),"projectionSha256":"c".repeat(64),
                "cacheJob":format!("tool-{}","a".repeat(32)),"lookupScope":"registered-selected-known",
                "reusedArchives":[],"downloadedArchives":wire::COMPONENTS,
                "groups":[{"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                    {"group":"sdk","components":["sdk-platform","sdk-build-tools"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                    {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}],
                "assurance":{"nativeFinality":false,"registered":false,"readyToBuild":false}},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,
                "inputClosed":true,"handlersRestored":true,"resourcesClosed":true,"stopObserved":"none"}});
        for cancel_first in [false, true] {
            let application = SavedCommandOwner::tool_acquisition(RuntimeConfig::packaged("/unopened-tools-terminal-runtime".into()));
            let (application, owner) = crate::saved_command_owner::tests::active_with_context(application, Context::ToolAcquisition(context.clone()));
            let at = owner.clocks.admitted;
            let frame = |sequence, kind, payload| {
                let mut bytes = serde_json::to_vec(&json!({"protocol":wire::PROTOCOL,"operationId":owner.id,
                    "ownerGeneration":owner.generation,"sequence":sequence,"kind":kind,"payload":payload})).unwrap();
                bytes.push(b'\n'); wire::decode(&bytes,&owner.id,&owner.generation,&context).unwrap()
            };
            application.inner.accept_at(&owner,Frame::ToolAcquisition(frame(0,"accepted",json!({"schemaVersion":1,"context":context}))),at);
            if cancel_first { application.inner.stop_locked(&mut application.inner.lock(),&owner,Reason::Cancelled,at); }
            application.inner.accept_at(&owner,Frame::ToolAcquisition(frame(1,"terminal",payload.clone())),at);
            {
                let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
                assert!(*owner.stop.borrow()); // SAME signal also closes successful terminal input.
                assert_eq!(active.first_stop, cancel_first.then_some(at));
                assert_eq!(accepted_terminal(&owner,active).is_some(), !cancel_first);
                assert!(!active.final_join_seen && !original_joined(&owner));
                assert!(CompletedSources::capture(&owner,active).is_none());
                assert!(r.tool_acquisition.completed_sources.is_none() && owner.watchdog_return.lock().unwrap().is_none());
            }
            // A real cancel after the successful terminal is still first F;
            // the already-true input-close signal cannot hide that transition.
            application.inner.stop_locked(&mut application.inner.lock(),&owner,Reason::Cancelled,at);
            let r = application.inner.lock(); let active = r.active.as_ref().unwrap();
            assert_eq!(active.first_stop,Some(at)); assert_eq!(active.projection.reason,Reason::Cancelled);
            assert!(accepted_terminal(&owner,active).is_none());
            assert!(CompletedSources::capture(&owner,active).is_none());
        }
    }
    #[test]
    fn prepared_folder_roles_do_not_promote_a_partial_sdk_or_duplicate_group() {
        let mut value = json!({"kind":"staged-tool-sources","groups":[
            {"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
            {"group":"sdk","components":["sdk-platform"],"allRequiredComponentsStaged":false,"next":"complete-sdk-manually"},
            {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}]});
        assert_eq!(complete_roles(&value), Some(5));
        value["groups"][1]["allRequiredComponentsStaged"] = json!(true);
        value["groups"][1]["next"] = json!("choose-native-source");
        assert_eq!(complete_roles(&value), Some(5));
        value["groups"][1]["components"] = json!(["sdk-platform", "sdk-build-tools"]);
        assert_eq!(complete_roles(&value), Some(7));
        value["groups"][1]["group"] = json!("jdk");
        assert_eq!(complete_roles(&value), None);
    }
    #[test]
    fn folder_location_is_fixed_component_data_not_a_renderer_path_or_source_receipt() {
        let root = Path::new("/native-appdata/tool-cache-v1/archives/tool-012345678901234567890123456789ab/sources");
        for (role, suffix) in [(source_wire::Role::Jdk,"jdk.jdk"),(source_wire::Role::Sdk,"android-sdk"),(source_wire::Role::Gradle,"gradle")] {
            assert_eq!(bounded_initial(root, role).unwrap(), root.join(suffix));
        }
        for path in ["relative", "/bad/../cache", "/bad//cache", "/bad/./cache", "/bad\0/cache"] {
            assert!(bounded_initial(Path::new(path), source_wire::Role::Jdk).is_none());
        }
        assert!(bounded_initial(Path::new(&format!("/{}", "a".repeat(4096))), source_wire::Role::Sdk).is_none());
    }
}
