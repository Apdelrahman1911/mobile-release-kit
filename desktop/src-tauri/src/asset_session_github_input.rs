//! One private immutable P2 loan from the original successful asset Bind.
//! No path reload, second decryption, renderer value getter, or new native owner.
use super::*;
use std::io::{self, Write};
use crate::github_input_group_protocol as wire;
use zeroize::Zeroizing;

pub(crate) struct GitHubInputMaterial {
    document: Weak<()>, native: Arc<NativeContext>, holding: Arc<AssignedPayload>,
    assignment: wire::AssignmentRef, native_config_sha256: String,
}
/// Runner reads retain only Weak original document/context identities. They
/// never borrow an AssignedPayload or keep plaintext signing material alive.
pub(crate) struct GitHubRunnerContext {
    document: Weak<()>, native: Weak<NativeContext>, revision: u32, generation: u32,
    root: asset_source::RegisteredRoot, native_config_sha256: String,
}
impl GitHubRunnerContext {
    pub(crate) fn config_digest(&self) -> &str { &self.native_config_sha256 }
    pub(crate) fn generation(&self) -> u32 { self.generation }
    pub(crate) fn root(&self) -> &asset_source::RegisteredRoot { &self.root }
    pub(super) fn current(&self, state: &DocumentState, identity: &Arc<()>) -> bool {
        Weak::ptr_eq(&self.document, &Arc::downgrade(identity)) && state.lifetime.original_bound()
            && !state.stopping && !state.unknown && !state.exhausted && !state.lock_pending
            && state.context.as_ref().is_some_and(|context| Weak::ptr_eq(&self.native, &Arc::downgrade(context))
                && context.revision == self.revision && context.registry_generation == self.generation && context.project == self.root)
    }
    pub(crate) fn matches_material(&self, material: &GitHubInputMaterial) -> bool {
        Weak::ptr_eq(&self.document, &material.document) && Weak::ptr_eq(&self.native, &Arc::downgrade(&material.native))
            && self.revision == material.assignment.context_revision && self.generation == material.native.registry_generation
            && self.root == material.native.project && self.native_config_sha256 == material.native_config_sha256
    }
}
fn refused(reason: wire::Reason) -> BridgeError { crate::github_input_group_session::refused(reason) }
impl GitHubInputMaterial {
    pub(crate) fn assignment(&self) -> &wire::AssignmentRef { &self.assignment }
    pub(crate) fn scope(&self) -> wire::Scope { wire::Scope { platform: self.native.platform, stage: self.native.stage, purpose: self.native.purpose } }
    pub(crate) fn config_digest(&self) -> &str { &self.native_config_sha256 }
    pub(super) fn census_parts(&self) -> (&Arc<NativeContext>, &Arc<AssignedPayload>) { (&self.native, &self.holding) }
    pub(crate) fn control_capacity(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.assignment.record_id.capacity())?.checked_add(self.native_config_sha256.capacity())
    }
    pub(crate) fn fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::with_capacity(4);
        if self.holding.payload.kind.file().is_some() { fields.push("file"); }
        fields.extend_from_slice(commands::field_names(self.holding.payload.kind)); fields
    }
    fn current(&self, state: &DocumentState, identity: &Arc<()>, generation: u32, root: &asset_source::RegisteredRoot) -> bool {
        if !Weak::ptr_eq(&self.document, &Arc::downgrade(identity)) || !state.lifetime.original_bound() || state.stopping
            || state.unknown || state.exhausted || state.lock_pending || state.retiring || !state.assignment_retirement.empty()
            || !state.context.as_ref().is_some_and(|v| Arc::ptr_eq(v, &self.native))
            || self.native.registry_generation != generation || self.native.project != *root
            || !state.assignments.iter().any(|a| a.kind == self.assignment.kind && a.record_id.0 == self.assignment.record_id
                && a.record_revision == self.assignment.record_revision && a.context_revision == self.assignment.context_revision
                && assignment_available(state,a) && a.holding.as_ref().is_some_and(|v| Arc::ptr_eq(v,&self.holding))) { return false; }
        let key = RecordKey { id: Token(self.assignment.record_id.clone()), revision: self.assignment.record_revision };
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        if let Some(reference) = self.holding.reference {
            return encrypted_mode(state) && vault::assignment_current(state, &key, self.assignment.kind, &self.holding.payload, reference);
        }
        state.session && !encrypted_mode(state) && state.records.iter().any(|r| r.key == key && !r.mutation_pending
            && Arc::ptr_eq(&r.payload,&self.holding.payload) && r.payload.usable_source())
    }
    /// Count the EXACT serialization without copying private values or file
    /// backing. Base64 is an ASCII string with a deterministic checked size.
    pub(crate) fn envelope_size(&self) -> Result<usize, BridgeError> {
        let mut count = Count(0); encode_envelope(&self.holding.payload, &mut count)?; Ok(count.0)
    }
    /// The original registered Apply writer alone calls this after RECHECKED.
    /// Partial/error buffers are zeroizing; no reusable plaintext cache is made.
    pub(crate) fn envelope(&self) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        let expected = self.envelope_size()?;
        let mut out = wire::PrivateWriter::new(wire::ENVELOPE_LIMIT)?;
        encode_envelope(&self.holding.payload, &mut out)?;
        let bytes = out.finish();
        if bytes.len() != expected || bytes.capacity() > wire::ENVELOPE_LIMIT { return Err(refused(wire::Reason::DestinationLimit)); }
        Ok(bytes)
    }
}
trait EnvelopeOutput: Write { fn file_base64(&mut self, bytes: &[u8]) -> Result<(), BridgeError>; }
impl EnvelopeOutput for wire::PrivateWriter { fn file_base64(&mut self, bytes: &[u8]) -> Result<(), BridgeError> { self.base64(bytes) } }
struct Count(usize);
impl Count {
    fn add(&mut self, count: usize) -> Result<(), BridgeError> {
        self.0 = self.0.checked_add(count).filter(|v| *v <= wire::ENVELOPE_LIMIT).ok_or_else(|| refused(wire::Reason::DestinationLimit))?; Ok(())
    }
}
impl Write for Count {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.add(data.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData,"P2 envelope bound"))?; Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl EnvelopeOutput for Count {
    fn file_base64(&mut self, bytes: &[u8]) -> Result<(), BridgeError> {
        let size = bytes.len().checked_add(2).and_then(|v| v.checked_div(3)).and_then(|v| v.checked_mul(4))
            .ok_or_else(|| refused(wire::Reason::DestinationLimit))?; self.add(size)
    }
}
fn encode_envelope(payload: &Payload, out: &mut impl EnvelopeOutput) -> Result<(), BridgeError> {
    let file = if payload.kind.file().is_some() {
        Some(payload.material.as_ref().filter(|v| v.observation.is_observed())
            .ok_or_else(|| refused(wire::Reason::InputInvalid))?.bytes())
    } else { None };
    encode_parts(payload.kind,file,|name| payload.fields.as_ref().and_then(|f| f.borrow_value(name)),out)
}
// Serializer only, not material/assignment admission. The production caller
// above borrows solely from its original authenticated Payload. Separating this
// finite codec permits all eleven core formats to share DATA corpus coverage
// without manufacturing platform/native source witnesses in serializer tests.
fn encode_parts<'a>(kind: Kind, file: Option<&'a [u8]>, field: impl Fn(&str)->Option<&'a str>,
    out: &mut impl EnvelopeOutput) -> Result<(), BridgeError> {
    if kind.file().is_some()!=file.is_some() {return Err(refused(wire::Reason::InputInvalid));}
    let io_error = |_| refused(wire::Reason::DestinationLimit);
    out.write_all(b"{\"protocol\":\"mrk-github-input-group/1\",\"kind\":").map_err(io_error)?;
    serde_json::to_writer(&mut *out, kind.name()).map_err(|_| refused(wire::Reason::DestinationLimit))?;
    out.write_all(b",\"values\":{").map_err(io_error)?;
    if let Some(bytes)=file {
        out.write_all(b"\"file\":\"").map_err(io_error)?; out.file_base64(bytes)?;
        out.write_all(b"\"").map_err(io_error)?;
    }
    for (index, name) in commands::field_names(kind).iter().enumerate() {
        let value = field(name).ok_or_else(|| refused(wire::Reason::InputInvalid))?;
        if file.is_some() || index > 0 { out.write_all(b",").map_err(io_error)?; }
        serde_json::to_writer(&mut *out, name).map_err(|_| refused(wire::Reason::DestinationLimit))?;
        out.write_all(b":").map_err(io_error)?;
        serde_json::to_writer(&mut *out, value).map_err(|_| refused(wire::Reason::DestinationLimit))?;
    }
    out.write_all(b"}}").map_err(io_error)
}

impl DocumentBinding {
    fn input_runner_context(&self, state: &DocumentState, args: &crate::github_runner_prerequisite_protocol::CheckArgs,
        generation: u32, root: &asset_source::RegisteredRoot) -> Result<Arc<GitHubRunnerContext>, BridgeError> {
        if state.revision != args.expected_asset_status_revision { return Err(refused(wire::Reason::ContextStale)); }
        let native = state.context.as_ref().filter(|context| context.revision == args.context_revision
            && context.registry_generation == generation && context.project == *root && context.platform != Platform::Project)
            .ok_or_else(|| refused(wire::Reason::ContextStale))?;
        let value = crate::protocol::strict_json(&native.draft).map_err(|_| refused(wire::Reason::ConfigMismatch))?;
        let canonical = wire::canonical(&value, commands::DRAFT_LIMIT).map_err(|_| refused(wire::Reason::ConfigMismatch))?;
        let context = Arc::new(GitHubRunnerContext { document: Arc::downgrade(&self.inner.session_identity),
            native: Arc::downgrade(native), revision: native.revision, generation, root: root.clone(),
            native_config_sha256: wire::digest(&canonical) });
        if !context.current(state, &self.inner.session_identity) { return Err(refused(wire::Reason::ContextStale)); }
        Ok(context)
    }
    fn input_material(&self, state: &DocumentState, args: &wire::PrepareArgs, generation: u32,
        root: &asset_source::RegisteredRoot) -> Result<Arc<GitHubInputMaterial>, BridgeError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        lookup_memory::github_input_admission(state).map_err(|_| refused(wire::Reason::DestinationLimit))?;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        return Err(refused(wire::Reason::Unqualified));
        if state.revision != args.expected_asset_status_revision { return Err(refused(wire::Reason::ContextStale)); }
        let native = state.context.as_ref().filter(|c| c.revision == args.assignment.context_revision
            && c.registry_generation == generation && c.project == *root && c.platform != Platform::Project)
            .ok_or_else(|| refused(wire::Reason::ContextStale))?;
        let assignment = state.assignments.iter().find(|a| a.kind == args.assignment.kind && a.record_id.0 == args.assignment.record_id
            && a.record_revision == args.assignment.record_revision && a.context_revision == args.assignment.context_revision
            && assignment_available(state,a)).ok_or_else(|| refused(wire::Reason::AssignmentUnavailable))?;
        let holding = assignment.holding.as_ref().ok_or_else(|| refused(wire::Reason::AssignmentUnavailable))?;
        // The core assessment for this exact Bind/context already accepted the
        // draft; remote core schema/requirement validation remains mandatory.
        let value = crate::protocol::strict_json(&native.draft).map_err(|_| refused(wire::Reason::ConfigMismatch))?;
        let canonical = wire::canonical(&value, commands::DRAFT_LIMIT).map_err(|_| refused(wire::Reason::ConfigMismatch))?;
        let material = Arc::new(GitHubInputMaterial { document: Arc::downgrade(&self.inner.session_identity), native: native.clone(),
            holding: holding.clone(), assignment: args.assignment.clone(), native_config_sha256: wire::digest(&canonical) });
        if !material.current(state,&self.inner.session_identity,generation,root) { return Err(refused(wire::Reason::AssignmentUnavailable)); }
        material.envelope_size()?; Ok(material)
    }
    pub(crate) fn github_input_group_status(&self) -> wire::Status {
        self.reconcile();let mut state=self.lock();let now=Instant::now();self.expire(&mut state,now);
        let gate=self.github_gate(&state);
        state.github.input_status(self.inner.bridge.supervisor.github_input_group_profile_available(),now,gate)
    }
    pub(crate) fn github_input_group_command(&self,name:&str,value:&Value) -> Result<wire::Status,BridgeError> {
        let command=wire::decode_command(name,value).map_err(|_| refused(wire::Reason::InvalidInput))?;
        if matches!(command,wire::Command::Status) {return Ok(self.github_input_group_status());}
        // Only inert marker/account DATA before the document lock. No new
        // helper, path reload, account query or token/private payload copy.
        let marker=if matches!(command,wire::Command::Prepare(_)) {
            let mut bytes=[0u8;16];getrandom::fill(&mut bytes).map_err(|_| refused(wire::Reason::RuntimeUnavailable))?;
            Some(bytes.iter().map(|v| format!("{v:02x}")).collect::<String>())
        } else {None};
        let home=if matches!(command,wire::Command::Apply(_)|wire::Command::Reconcile(_)|wire::Command::Pending(_)) {
            Some(github_preflight_home().map_err(|_| refused(wire::Reason::RuntimeUnavailable))?)
        } else {None};
        self.reconcile();let mut state=self.lock();self.expire(&mut state,Instant::now());
        if let wire::Command::Cancel(args)=command {return state.github.input_cancel(&args.operation_id);}
        self.input_document_gate(&state)?;
        let external=self.github_gate(&state);
        let supervisor=&self.inner.bridge.supervisor;
        let status=state.github.input_status(supervisor.github_input_group_profile_available(),Instant::now(),external);
        if !status.available {return Err(refused(status.reason));}
        #[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
        lookup_memory::github_input_admission(&state).map_err(|_| refused(wire::Reason::DestinationLimit))?;
        #[cfg(not(all(target_os="linux",target_arch="x86_64",target_env="gnu")))]
        return Err(refused(wire::Reason::Unqualified));
        let (project,original_generation)=state.github.registration().map(|(id,generation)| (id.to_owned(),generation))
            .ok_or_else(|| refused(wire::Reason::NotConnected))?;
        let (generation,root)=self.registry_result(&mut state,self.inner.bridge.native_project(&project),None)
            .map_err(|_| refused(wire::Reason::TargetChanged))?;
        if original_generation!=generation {return Err(refused(wire::Reason::TargetChanged));}
        let binding=github_preflight_project_binding(&root).map_err(|_| refused(wire::Reason::TargetChanged))?;
        let gate=GitHubInputGoGate {inner:Arc::downgrade(&self.inner)};let now=Instant::now();
        match command {
            wire::Command::RunnerCheck(args)=>{
                let context=self.input_runner_context(&state,&args,generation,&root)?;
                state.github.input_runner_check(args,generation,root,&binding,context,supervisor,now)
            },
            wire::Command::Prepare(args)=>{
                let material=self.input_material(&state,&args,generation,&root)?;
                state.github.input_prepare(args,generation,root,&binding,marker.ok_or_else(BridgeError::invalid)?,material,gate,supervisor,now)
            },
            wire::Command::Apply(args)=>state.github.input_apply(args,generation,root,&binding,home.ok_or_else(BridgeError::invalid)?,gate,supervisor,now),
            wire::Command::Reconcile(args)=>state.github.input_observe(args,generation,root,&binding,home.ok_or_else(BridgeError::invalid)?,gate,supervisor,now),
            wire::Command::Pending(args)=>state.github.input_pending(args,generation,root,&binding,home.ok_or_else(BridgeError::invalid)?,gate,supervisor,now),
            wire::Command::Status|wire::Command::Cancel(_)=>Err(refused(wire::Reason::InvalidInput)),
        }
    }
    fn input_document_gate(&self, state: &DocumentState) -> Result<(), BridgeError> {
        let reason = self.github_gate(state);
        if reason != GitHubReason::None { return Err(refused(crate::github_input_group_session::connection_reason(reason))); }
        if !state.assignment_retirement.empty() || state.github.input_retirement_pending()
            || state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled()) {
            return Err(refused(wire::Reason::Busy));
        }
        Ok(())
    }
}
/// Weak reference to the SAME document; no replacement registry or token owner.
#[derive(Clone)]
pub(crate) struct GitHubInputGoGate { inner: Weak<Inner> }
pub(crate) struct ReadLoan { pub(crate) frame: wire::PrivateFrame, pub(crate) material: Option<Arc<GitHubInputMaterial>> }
impl GitHubInputGoGate {
    pub(crate) fn read(&self, id: &str, digest: &str, request: &wire::Request,
        claim: impl FnOnce() -> bool) -> Result<ReadLoan, BridgeError> {
        let inner = self.inner.upgrade().ok_or_else(|| refused(wire::Reason::Cancelled))?;
        let document = DocumentBinding { inner }; let mut state = document.lock(); document.expire(&mut state, Instant::now());
        document.input_document_gate(&state)?;
        let (project_id, original_generation, original_root) = state.github.input_active_registration()
            .map(|(id,generation,root)| (id.to_owned(),generation,root.clone())).ok_or_else(|| refused(wire::Reason::TargetChanged))?;
        let (generation, root) = document.registry_result(&mut state,document.inner.bridge.native_project(&project_id),None)
            .map_err(|_| refused(wire::Reason::TargetChanged))?;
        if generation != original_generation || root != original_root { return Err(refused(wire::Reason::TargetChanged)); }
        let material = state.github.input_active_material();
        if material.as_ref().is_some_and(|m| !m.current(&state,&document.inner.session_identity,generation,&root)) {
            return Err(refused(wire::Reason::AssignmentUnavailable));
        }
        let frame = state.github.input_read(id,digest,request,Instant::now(),claim)?;
        Ok(ReadLoan { frame, material })
    }
    pub(crate) fn claim_go(&self, id: &str, request: &wire::Request, rechecked: &wire::Rechecked,
        material: &Arc<GitHubInputMaterial>, claim: impl FnOnce() -> bool) -> Result<(), BridgeError> {
        let inner = self.inner.upgrade().ok_or_else(|| refused(wire::Reason::Cancelled))?;
        let document = DocumentBinding { inner }; let mut state = document.lock(); document.expire(&mut state,Instant::now());
        document.input_document_gate(&state)?;
        let (project_id,original_generation,original_root) = state.github.input_active_registration()
            .map(|(id,generation,root)| (id.to_owned(),generation,root.clone())).ok_or_else(|| refused(wire::Reason::TargetChanged))?;
        let (generation,root) = document.registry_result(&mut state,document.inner.bridge.native_project(&project_id),None)
            .map_err(|_| refused(wire::Reason::TargetChanged))?;
        if generation != original_generation || root != original_root
            || !material.current(&state,&document.inner.session_identity,generation,&root)
            || !state.github.input_active_material().as_ref().is_some_and(|current| Arc::ptr_eq(current,material)) {
            return Err(refused(wire::Reason::AssignmentUnavailable));
        }
        // All plaintext encoding/sealing and complete frame allocation happened
        // off this gate. It performs no IO/await/entropy/encoding after the claim.
        state.github.input_go(id,request,rechecked,Instant::now(),claim)
    }
}

#[cfg(test)]
#[path = "asset_session_github_input_tests.rs"]
mod tests;
