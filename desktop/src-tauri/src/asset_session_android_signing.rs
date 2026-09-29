//! Private borrowers for the SAME saved Android signing operation.
//! No credential readback, native IO, body clone or replacement resource owner.
use super::*;
use crate::android_build_protocol as wire;
use sha2::{Digest, Sha256};

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-ANDROID-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-ANDROID-MATERIAL-END\n";

// Fixed incremental borrower + transient header/slice metadata, not a second
// body allocation. The ordinary owner already budgets its public request.
const CONTROL_RESERVATION: usize = 16 * 1024;
pub(super) struct MemoryReservation { _private: () }
pub(super) fn capacity() -> BridgeError {
    BridgeError::new("android_build_signing_capacity", "The current credential session has no room for this signing operation. Remove unused session inputs and review again.")
}
impl MemoryReservation {
    pub(super) fn checked(live: usize) -> Result<Self, BridgeError> {
        if live.checked_add(CONTROL_RESERVATION).is_none_or(|total| total > SESSION_BYTES) { return Err(capacity()); }
        Ok(Self { _private: () })
    }
}
pub(crate) struct AndroidSigningMaterial {
    // Kept inside the SAME Arc through actual final join, not writer return.
    _memory: MemoryReservation,
    context: wire::Context,
    native: Arc<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Arc<Payload>>,
}

fn invalid() -> BridgeError {
    BridgeError::new("android_build_signing_inputs", "Assign the current session upload keystore, both passwords, key alias and required build inputs for this saved Android configuration, then review again.")
}

impl AndroidSigningMaterial {
    pub(crate) fn retirement_exclusive(original: &Arc<Self>) -> bool { Arc::strong_count(original) == 1 }
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        self.context == *context && self.native.registry_generation == registration && self.native.project == *project
            && self.native.project_id == context.project_id && self.native.platform == Platform::Android
            && self.native.stage == Stage::Candidate && self.native.purpose == Purpose::Signing
            && context.signing.as_ref().is_some_and(|policy| policy.context_revision == self.native.revision)
    }

    fn control_capacity(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(self.keys.capacity().checked_mul(std::mem::size_of::<RecordKey>())?)?
            .checked_add(self.payloads.capacity().checked_mul(std::mem::size_of::<Arc<Payload>>())?)?;
        for key in &self.keys { bytes = bytes.checked_add(key.id.0.capacity())?; }
        for text in [&self.context.project_id, &self.context.saved_config.sha256, &self.context.saved_version.source,
            &self.context.saved_version.sha256, &self.context.saved_version.name] { bytes = bytes.checked_add(text.capacity())?; }
        if let Some(text) = &self.context.artifact_validation.upload_certificate_sha256 { bytes = bytes.checked_add(text.capacity())?; }
        if let Some(policy) = &self.context.signing {
            bytes = bytes.checked_add(policy.source.capacity())?.checked_add(policy.assignments.capacity().checked_mul(std::mem::size_of::<wire::SigningAssignment>())?)?;
            for row in &policy.assignments { bytes = bytes.checked_add(row.kind.capacity())?.checked_add(row.record_id.capacity())?; }
        }
        // Both header construction and writer can hold one bounded header plus
        // six role/length JSON entries and two six-element borrowed-slice lists.
        bytes.checked_add(8 * 1024)
    }
    pub(crate) fn context_data(&self) -> wire::Content {
        wire::Content { bytes: self.native.draft.len() as u32, sha256: format!("{:x}", Sha256::digest(&self.native.draft)) }
    }

    /// Only slices of actual retained payload backing cross the private writer.
    /// The header contains role names and lengths, never paths or scalar values.
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let mut result = Vec::new();
        result.try_reserve_exact(6).map_err(|_| invalid())?;
        for payload in &self.payloads {
            match payload.kind {
                Kind::AndroidKeystore | Kind::AndroidFirebase => {
                    let value = payload.material.as_ref().filter(|m| m.observation.is_observed()).ok_or_else(invalid)?;
                    let maximum = if payload.kind == Kind::AndroidKeystore { 32 * 1024 * 1024 } else { 4 * 1024 * 1024 };
                    if value.bytes().is_empty() || value.bytes().len() > maximum { return Err(invalid()); }
                    result.push((payload.kind.name(), value.bytes()));
                    if payload.kind == Kind::AndroidKeystore {
                        for (field, role) in [("storePassword", "store-password"), ("keyAlias", "key-alias"), ("keyPassword", "key-password")] {
                            let value = payload.fields.as_ref().and_then(|f| f.borrow_value(field)).ok_or_else(invalid)?;
                            if value.is_empty() || value.len() > 4096 || value.contains('\0') { return Err(invalid()); }
                            result.push((role, value.as_bytes()));
                        }
                    }
                },
                Kind::ProjectReadToken => {
                    let value = payload.fields.as_ref().and_then(|f| f.borrow_value("token")).ok_or_else(invalid)?;
                    if value.is_empty() || value.len() > 4096 || value.contains('\0') { return Err(invalid()); }
                    result.push(("project-read-token", value.as_bytes()));
                },
                _ => return Err(invalid()),
            }
        }
        let roles: Vec<_> = result.iter().map(|(role, _)| *role).collect();
        if !matches!(roles.as_slice(), ["android-keystore", "store-password", "key-alias", "key-password"]
            | ["android-keystore", "store-password", "key-alias", "key-password", "android-firebase"]
            | ["android-keystore", "store-password", "key-alias", "key-password", "project-read-token"]
            | ["android-keystore", "store-password", "key-alias", "key-password", "android-firebase", "project-read-token"])
            || result.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() > 37_765_120 { return Err(invalid()); }
        Ok(result)
    }

    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
        let parts = self.parts()?;
        let files: Vec<_> = parts.iter().map(|(role, bytes)| serde_json::json!({"role":role,"bytes":bytes.len()})).collect();
        let mut header = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"files":files})).map_err(|_| invalid())?;
        header.push(b'\n');
        if header.len() > 1024 { return Err(invalid()); }
        Ok(header)
    }

    fn current(&self, state: &DocumentState, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        if !state.session || !state.context.as_ref().is_some_and(|c| Arc::ptr_eq(c, &self.native))
            || !self.matches(&self.context, registration, project) || self.keys.len() != self.payloads.len() { return false; }
        self.keys.iter().zip(&self.payloads).all(|(key, payload)| {
            state.records.iter().any(|record| record.key == *key && !record.mutation_pending && Arc::ptr_eq(&record.payload, payload))
                && state.assignments.iter().any(|assignment| assignment.record_id == key.id && assignment.record_revision == key.revision
                    && assignment.context_revision == self.native.revision && assignment.kind == payload.kind
                    && assignment.availability == AssignmentAvailability::Available
                    && assignment.holding.as_ref().is_some_and(|holding| Arc::ptr_eq(&holding.payload, payload)))
        })
    }
}

impl DocumentBinding {
    pub(super) fn review_android_material(&self, state: &DocumentState, context: &wire::Context,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<AndroidSigningMaterial>, BridgeError> {
        // Called while the original document mutex and all outer conflict gates
        // are held. Neither a public revision nor matching bytes create custody.
        if !context.signed() || !state.session || !self.native_qualified() { return Err(invalid()); }
        let memory = reserve_memory(state)?;
        capture(state, context, registration, project, memory)
    }

    pub(super) fn recheck_android_material(&self, state: &DocumentState, original: &Arc<AndroidSigningMaterial>,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<(), BridgeError> {
        if !self.native_qualified() || !original.current(state, registration, project) { return Err(invalid()); }
        original.parts()?; Ok(())
    }
}
fn reserve_memory(state: &DocumentState) -> Result<MemoryReservation, BridgeError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    { lookup_memory::android_signing_admission(state) }
    // Initial saved Android profile remains Linux-only. Other profiles need
    // their reviewed live census before enabling this original borrower.
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
    { let _ = state; Err(capacity()) }
}
fn capture(state: &DocumentState, context: &wire::Context, registration: u32,
    project: &asset_source::RegisteredRoot, memory: MemoryReservation) -> Result<Arc<AndroidSigningMaterial>, BridgeError> {
        let native = state.context.as_ref().ok_or_else(invalid)?.clone();
        let policy = context.signing.as_ref().ok_or_else(invalid)?;
        if native.project_id != context.project_id || native.registry_generation != registration || native.project != *project
            || native.platform != Platform::Android || native.stage != Stage::Candidate || native.purpose != Purpose::Signing
            || native.revision != policy.context_revision || native.draft.is_empty() || native.draft.len() > 512 * 1024
            || !policy.valid() { return Err(invalid()); }
        let mut keys = Vec::new(); let mut payloads = Vec::new();
        keys.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
        payloads.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
        for required in &policy.assignments {
            let assignment = state.assignments.iter().find(|a| a.kind.name() == required.kind.as_str()
                && a.record_id.0 == required.record_id && a.record_revision == required.record_revision
                && a.context_revision == required.context_revision && a.availability == AssignmentAvailability::Available).ok_or_else(invalid)?;
            let record = state.records.iter().find(|r| r.key.id == assignment.record_id && r.key.revision == assignment.record_revision
                && r.payload.kind == assignment.kind && !r.mutation_pending && r.payload.usable_source()
                && assignment.holding.as_ref().is_some_and(|holding| Arc::ptr_eq(&holding.payload, &r.payload))).ok_or_else(invalid)?;
            if keys.iter().any(|key: &RecordKey| key.id == record.key.id) { return Err(invalid()); }
            keys.push(record.key.clone()); payloads.push(record.payload.clone());
        }
        let original = Arc::new(AndroidSigningMaterial { _memory: memory, context: context.clone(), native, keys, payloads });
        if original.control_capacity().is_none_or(|bytes| bytes > CONTROL_RESERVATION) { return Err(capacity()); }
        original.parts()?;
        if !original.current(state, registration, project) { return Err(invalid()); }
        Ok(original)
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod tests {
    // Synthetic backing/predicates only: no native source, credential validity,
    // process/worker, IO, qualification or production issuance is claimed.
    use super::*;
    use serde_json::json;

    fn payload(kind: Kind, fields: Value) -> Arc<Payload> {
        let bytes = match kind {
            Kind::AndroidKeystore => Some(vec![0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 0]),
            Kind::AndroidFirebase => Some(br#"{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.app"}}}]}"#.to_vec()),
            _ => None,
        };
        let material = bytes.map(|bytes| {
            let observation = credential_format::inspect(kind.file().unwrap(), &bytes, &mut || false).ok().unwrap();
            assert!(observation.is_observed());
            Arc::new(Material { origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(bytes)), observation })
        });
        Arc::new(Payload { kind, material, fields: Some(commands::own_fields(kind, &fields).ok().unwrap()) })
    }
    fn state() -> DocumentState {
        let mut state = super::super::tests::empty_state();
        let context = wire::tests::signed_context();
        state.context = Some(Arc::new(NativeContext { revision: 1, project_id: context.project_id,
            project: asset_source::RegisteredRoot { path: "/never-opened/android-signing-data".into(),
                identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
            registry_generation: 1, draft: b"{}".to_vec(), platform: Platform::Android, stage: Stage::Candidate, purpose: Purpose::Signing }));
        for (kind, id, fields) in [
            (Kind::AndroidKeystore, 'a', json!({"storePassword":" store password ","keyAlias":"upload-key","keyPassword":" key password "})),
            (Kind::AndroidFirebase, 'b', json!({})),
            (Kind::ProjectReadToken, 'c', json!({"token":" token canary "})),
        ] {
            let key = RecordKey { id: Token(id.to_string().repeat(32)), revision: 1 };
            let payload = payload(kind, fields);
            state.assignments.push(Assignment { kind, record_id: key.id.clone(), record_revision: 1,
                context_revision: 1, availability: AssignmentAvailability::Available,
                holding: Some(Arc::new(AssignedPayload { payload: payload.clone(), reference: None })) });
            state.records.push(Record { key, payload, mutation_pending: false });
        }
        state
    }
    fn material(state: &DocumentState) -> Arc<AndroidSigningMaterial> {
        let native = state.context.as_ref().unwrap();
        capture(state, &wire::tests::signed_context(), 1, &native.project, reserve_memory(state).unwrap()).unwrap()
    }
    #[test]
    fn android_material_borrows_exact_backing_and_framing_without_private_projection() {
        let state = state(); let material = material(&state); let parts = material.parts().unwrap();
        assert_eq!(parts.iter().map(|(role, _)| *role).collect::<Vec<_>>(),
            ["android-keystore", "store-password", "key-alias", "key-password", "android-firebase", "project-read-token"]);
        assert_eq!(parts[0].1.as_ptr(), state.records[0].payload.material.as_ref().unwrap().bytes().as_ptr());
        assert_eq!(parts[1].1, b" store password "); assert_eq!(parts[3].1, b" key password ");
        assert_eq!(parts[1].1.as_ptr(), state.records[0].payload.fields.as_ref().unwrap().borrow_value("storePassword").unwrap().as_ptr());
        let header = material.header().unwrap(); assert!(header.len() <= 1024 && header.ends_with(b"\n"));
        let header: Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["schemaVersion"], 1); assert_eq!(header["files"].as_array().unwrap().len(), 6);
        let text = header.to_string();
        for private in ["store password", "key password", "upload-key", "token canary", "never-opened"] { assert!(!text.contains(private)); }
        assert_eq!(MATERIAL_PREFIX, b"MRK-ANDROID-MATERIAL/1\n"); assert_eq!(MATERIAL_SUFFIX, b"\nMRK-ANDROID-MATERIAL-END\n");
        assert_eq!(material.context_data().bytes, 2);
        assert_eq!(material.context_data().sha256, format!("{:x}", Sha256::digest(b"{}")));
        assert!(material.control_capacity().unwrap() <= CONTROL_RESERVATION);
    }
    #[test]
    fn android_current_loan_rejects_same_bytes_in_a_replaced_original_and_changed_assignment() {
        for change in 0..8 {
            let mut state = state(); let original = material(&state); let native = state.context.as_ref().unwrap().clone();
            assert!(original.current(&state, 1, &native.project));
            match change {
                0 => state.records[0].mutation_pending = true,
                1 => state.records[0].key.revision += 1,
                2 => state.assignments[0].context_revision += 1,
                3 => state.assignments[0].availability = AssignmentAvailability::Unavailable,
                4 => state.session = false,
                5 => state.records[0].payload = payload(Kind::AndroidKeystore,
                    json!({"storePassword":" store password ","keyAlias":"upload-key","keyPassword":" key password "})),
                6 => state.assignments[0].holding = None,
                _ => state.context = Some(Arc::new(NativeContext { revision: native.revision,
                    project_id: native.project_id.clone(), project: native.project.clone(), registry_generation: native.registry_generation,
                    draft: native.draft.clone(), platform: native.platform, stage: native.stage, purpose: native.purpose })),
            }
            assert!(!original.current(&state, 1, &native.project));
            assert!(!original.matches(&wire::tests::signed_context(), 2, &native.project));
        }
    }
    #[test]
    fn android_material_rejects_missing_empty_nul_and_overlong_utf8_scalars() {
        for field in ["storePassword", "keyAlias", "keyPassword"] {
            for value in [Value::Null, json!(""), json!("x\0y")] {
                let mut fields = json!({"storePassword":"s","keyAlias":"a","keyPassword":"k"}); fields[field] = value;
                let mut state = state(); state.records[0].payload = payload(Kind::AndroidKeystore, fields);
                state.assignments[0].holding = Some(Arc::new(AssignedPayload { payload: state.records[0].payload.clone(), reference: None }));
                let root = &state.context.as_ref().unwrap().project;
                assert!(capture(&state, &wire::tests::signed_context(), 1, root, reserve_memory(&state).unwrap()).is_err());
            }
        }
        let fields = json!({"storePassword":"é".repeat(2048),"keyAlias":"a","keyPassword":"k"});
        let mut state = state(); state.records[0].payload = payload(Kind::AndroidKeystore, fields.clone());
        state.assignments[0].holding = Some(Arc::new(AssignedPayload { payload: state.records[0].payload.clone(), reference: None }));
        assert_eq!(material(&state).parts().unwrap()[1].1.len(), 4096);
        let mut too_long = fields; too_long["storePassword"] = json!("é".repeat(2049));
        assert!(commands::own_fields(Kind::AndroidKeystore, &too_long).is_err());
    }
    #[test]
    fn android_borrower_charge_survives_writer_return_and_never_uses_body_headroom() {
        assert!(MemoryReservation::checked(SESSION_BYTES - CONTROL_RESERVATION).is_ok());
        assert!(MemoryReservation::checked(SESSION_BYTES - CONTROL_RESERVATION + 1).is_err());
        assert!(MemoryReservation::checked(usize::MAX).is_err());
        let state = state(); let original = material(&state); let witness = Arc::downgrade(&original);
        let writer = original.clone(); assert!(!AndroidSigningMaterial::retirement_exclusive(&original));
        drop(writer); assert!(witness.upgrade().is_some()); assert!(AndroidSigningMaterial::retirement_exclusive(&original));
        // Actual owner additionally gates release on original native finality.
        drop(original); assert!(witness.upgrade().is_none());
    }
}
