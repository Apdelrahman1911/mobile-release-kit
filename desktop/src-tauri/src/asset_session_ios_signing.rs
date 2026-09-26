//! Private immutable session borrowers for the SAME saved iOS operation.
//! No native IO, credential JSON/readback, scalar clone or persistent provider.
use super::*;
use crate::ios_archive_protocol as wire;
use sha2::{Digest, Sha256};

pub(crate) const MATERIAL_PREFIX: &[u8] = b"MRK-IOS-MATERIAL/1\n";
pub(crate) const MATERIAL_SUFFIX: &[u8] = b"\nMRK-IOS-MATERIAL-END\n";

pub(crate) struct IOSSigningMaterial {
    context: wire::Context,
    native: Arc<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Arc<Payload>>,
}

fn invalid() -> BridgeError {
    BridgeError::new("ios_archive_signing_inputs", "Assign the current session P12, password, provisioning profile and required build inputs for this saved iOS configuration, then review again.")
}

impl IOSSigningMaterial {
    pub(crate) fn matches(&self, context: &wire::Context, registration: u32, project: &asset_source::RegisteredRoot) -> bool {
        self.context == *context && self.native.registry_generation == registration && self.native.project == *project
            && self.native.project_id == context.project_id && self.native.platform == Platform::Ios
            && self.native.stage == Stage::Candidate && self.native.purpose == Purpose::Signing
    }

    pub(crate) fn context_data(&self) -> wire::Content {
        wire::Content { bytes: self.native.draft.len() as u32, sha256: format!("{:x}", Sha256::digest(&self.native.draft)) }
    }

    /// Borrow slices from actual Arc<Payload> backing. No base64, files reopened
    /// by name, body Vec copy or values in the public/native request JSON.
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let mut result = Vec::new();
        result.try_reserve_exact(5).map_err(|_| invalid())?;
        for payload in &self.payloads {
            match payload.kind {
                Kind::AppleP12 | Kind::AppleProfile | Kind::IosFirebase => {
                    let value = payload.material.as_ref().filter(|m| m.observation.is_observed()).ok_or_else(invalid)?;
                    let maximum = if payload.kind == Kind::AppleP12 { 32 * 1024 * 1024 } else { 4 * 1024 * 1024 };
                    if value.captured.bytes.is_empty() || value.captured.bytes.len() > maximum { return Err(invalid()); }
                    result.push((payload.kind.name(), value.captured.bytes.as_slice()));
                    if payload.kind == Kind::AppleP12 {
                        let value = payload.fields.as_ref().and_then(|f| f.borrow_value("password")).ok_or_else(invalid)?;
                        if value.is_empty() || value.len() > 8192 || value.contains('\0') { return Err(invalid()); }
                        result.push(("p12-password", value.as_bytes()));
                    }
                },
                Kind::ProjectReadToken => {
                    let value = payload.fields.as_ref().and_then(|f| f.borrow_value("token")).ok_or_else(invalid)?;
                    if value.is_empty() || value.len() > 8192 || value.contains('\0') { return Err(invalid()); }
                    result.push(("project-read-token", value.as_bytes()));
                },
                _ => return Err(invalid()),
            }
        }
        let roles: Vec<_> = result.iter().map(|(name, _)| *name).collect();
        if !matches!(roles.as_slice(), ["apple-p12", "p12-password", "apple-profile"]
            | ["apple-p12", "p12-password", "apple-profile", "ios-firebase"]
            | ["apple-p12", "p12-password", "apple-profile", "project-read-token"]
            | ["apple-p12", "p12-password", "apple-profile", "ios-firebase", "project-read-token"]) { return Err(invalid()); }
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
                    && assignment.availability == AssignmentAvailability::Available)
        })
    }
}

impl DocumentBinding {
    pub(super) fn review_ios_material(&self, state: &DocumentState, context: &wire::Context,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<Arc<IOSSigningMaterial>, BridgeError> {
        // Same actual document lock held by prepare_ios_archive. Idle assigned
        // records are permitted; its outer gate still refuses live mutations.
        if !context.signed() || !state.session || !self.native_qualified() { return Err(invalid()); }
        let native = state.context.as_ref().ok_or_else(invalid)?.clone();
        let policy = context.signing.as_ref().ok_or_else(invalid)?;
        if native.project_id != context.project_id || native.registry_generation != registration || native.project != *project
            || native.platform != Platform::Ios || native.stage != Stage::Candidate || native.purpose != Purpose::Signing
            || native.draft.is_empty() || native.draft.len() > 512 * 1024 || !(2..=4).contains(&policy.assignments.len()) { return Err(invalid()); }
        let mut keys = Vec::new(); let mut payloads = Vec::new();
        keys.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
        payloads.try_reserve_exact(policy.assignments.len()).map_err(|_| invalid())?;
        for required in &policy.assignments {
            if required.context_revision != native.revision { return Err(invalid()); }
            let assignment = state.assignments.iter().find(|a| a.kind.name() == required.kind.as_str()
                && a.record_id.0 == required.record_id && a.record_revision == required.record_revision
                && a.context_revision == required.context_revision && a.availability == AssignmentAvailability::Available).ok_or_else(invalid)?;
            let record = state.records.iter().find(|r| r.key.id == assignment.record_id && r.key.revision == assignment.record_revision
                && r.payload.kind == assignment.kind && !r.mutation_pending && r.payload.usable_source()).ok_or_else(invalid)?;
            if keys.iter().any(|key: &RecordKey| key.id == record.key.id) { return Err(invalid()); }
            keys.push(record.key.clone()); payloads.push(record.payload.clone());
        }
        let original = Arc::new(IOSSigningMaterial { context: context.clone(), native, keys, payloads });
        original.parts()?;
        if !original.current(state, registration, project) { return Err(invalid()); }
        Ok(original)
    }

    pub(super) fn recheck_ios_material(&self, state: &DocumentState, original: &Arc<IOSSigningMaterial>,
        registration: u32, project: &asset_source::RegisteredRoot) -> Result<(), BridgeError> {
        if !self.native_qualified() || !original.current(state, registration, project) { return Err(invalid()); }
        original.parts()?; Ok(())
    }
}
