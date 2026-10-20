//! Dedicated local/iOS/candidate key setup material. The selected P8 keeps its
//! original BoundLoan; neither old Store/Signing contexts nor a public record
//! counter can provide the complete vault inventory or generation consent.
use super::*;
use crate::apple_provisioning_protocol as provisioning;
use vault::key_sources::AppleKeySources;

pub(super) fn borrow(
    document: &DocumentBinding,
    state: &DocumentState,
    context: &provisioning::Context,
    registration: u32,
    root: &asset_source::RegisteredRoot,
) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
    if !(context.mode.local_key() || context.mode.certificate()) || !context.valid() {
        return Err(refused());
    }
    let native = state
        .context
        .as_ref()
        .filter(|native| {
            native.revision == context.credential_context_revision
                && native.execution_mode == commands::ExecutionMode::Local
                && native.platform == Platform::Ios
                && native.stage == Stage::Candidate
                && native.purpose == Purpose::Provisioning
                && native.registry_generation == registration
                && native.project == *root
                && native.project_id == context.project_id
                && !native.draft.is_empty()
                && native.draft.len() <= 512 * 1024
        })
        .ok_or_else(refused)?
        .clone();
    let key = RecordKey {
        id: Token(context.record_id.clone()),
        revision: context.record_revision,
    };
    let payload = github_secret::assigned(state, &key, Kind::AscP8, &native)
        .ok_or_else(refused)?
        .clone();
    let selected_key = if context.mode.certificate() { Some(RecordKey {
        id: Token(context.key_record_id.clone().ok_or_else(refused)?), revision: context.key_record_revision.ok_or_else(refused)?,
    }) } else { None };
    let sources = AppleKeySources::capture(document, state, &native, &key, &payload, selected_key.as_ref())
        .map_err(|_| refused())?;
    let result = Arc::new(SelectedStoreMaterial {
        native,
        key,
        payload,
        command: Some(StoreCommand::Provisioning(context.clone())),
        prepare_document: Some(Arc::downgrade(&document.inner)),
        execute_tools: None,
        supplemental: std::array::from_fn(|_| None),
        profile_sources: None,
        key_sources: Some(sources),
    });
    if !result.provisioning_matches(context, registration, root)
        || !result.current(state, registration, root)
    {
        return Err(refused());
    }
    if context.mode.certificate() { apple_parts(&result.payload).ok_or_else(refused)?; } else { result.parts()?; }
    Ok(result)
}

// This is a fixed borrow on the SAME original stdin writer, not another owner
// or a reusable credential. Its sole strong key-payload reference is held
// outside the writer's STOP select until that original writer really returns.
pub(crate) struct CertificateMaterial<'a> {
    material: &'a SelectedStoreMaterial,
    payload: Arc<Payload>,
}
impl CertificateMaterial<'_> {
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let sources = self.material.key_sources.as_ref().ok_or_else(refused)?;
        let (p8,key,issuer) = apple_parts(&self.material.payload).ok_or_else(refused)?;
        let selected = sources.certificate_parts(&self.payload).map_err(|_| refused())?;
        let mut values=Vec::new(); values.try_reserve_exact(6).map_err(|_| refused())?;
        values.extend([("asc-p8",p8),("asc-key-id",key),("asc-issuer-id",issuer)]);
        values.extend(selected); Ok(values)
    }
    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
        let parts=self.parts()?;
        #[derive(Clone,Copy,serde::Serialize)] struct Row<'a>{bytes:usize,role:&'a str}
        #[derive(serde::Serialize)] struct Header<'a>{files:&'a [Row<'a>],#[serde(rename="schemaVersion")] schema_version:u8}
        let mut rows=[Row{bytes:0,role:""};6];
        for(row,(role,bytes))in rows.iter_mut().zip(&parts){*row=Row{bytes:bytes.len(),role};}
        let mut header=Vec::new();header.try_reserve_exact(1024).map_err(|_|refused())?;
        serde_json::to_writer(&mut header,&Header{files:&rows,schema_version:1}).map_err(|_|refused())?;
        header.push(b'\n');if header.len()>1024{return Err(refused());}Ok(header)
    }
}
impl SelectedStoreMaterial {
    pub(super) fn certificate_material(&self) -> bool { matches!(&self.command, Some(StoreCommand::Provisioning(context)) if context.mode.certificate()) }
    pub(crate) fn certificate_input(&self) -> Result<Option<CertificateMaterial<'_>>, BridgeError> {
        if !self.certificate_material() { return Ok(None); }
        let payload=self.key_sources.as_ref().and_then(|sources|sources.certificate_payload()).ok_or_else(refused)?;
        Ok(Some(CertificateMaterial { material:self,payload }))
    }
    pub(crate) fn key_sources(&self) -> Option<&Arc<AppleKeySources>> {
        self.key_sources.as_ref()
    }
    pub(super) fn key_current(
        &self,
        state: &DocumentState,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        let Some(StoreCommand::Provisioning(context)) = &self.command else {
            return false;
        };
        let Some(sources) = &self.key_sources else {
            return false;
        };
        let Some(document) = self.prepare_document.as_ref().and_then(Weak::upgrade) else {
            return false;
        };
        (context.mode.local_key() || context.mode.certificate())
            && self.provisioning_matches(context, registration, root)
            && self.profile_sources.is_none()
            && self.supplemental.iter().all(Option::is_none)
            && sources.current(&DocumentBinding { inner: document }, state)
            && Arc::ptr_eq(&self.native, sources.native())
            && apple_parts(&self.payload).is_some()
    }
    pub(in crate::asset_session) fn key_preservation_current(
        &self,
        document: &DocumentBinding,
        state: &DocumentState,
        original: &Arc<OriginalWork>,
        parent: &crate::saved_command_owner::AppleKeySession,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        context.mode == provisioning::Mode::KeyPrepare
            && self.provisioning_matches(context, registration, root)
            && self
                .prepare_document
                .as_ref()
                .is_some_and(|held| Weak::ptr_eq(held, &Arc::downgrade(&document.inner)))
            && self.profile_sources.is_none()
            && self.supplemental.iter().all(Option::is_none)
            && self.key_sources.as_ref().is_some_and(|sources| {
                Arc::ptr_eq(&self.native, sources.native())
                    && sources.preservation_current(document, state, original, parent)
            })
            && apple_parts(&self.payload).is_some()
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn certificate_writer_borrow_keeps_original_arc_until_its_actual_return() {
        let material=SelectedStoreMaterial {
            native:Arc::new(NativeContext { execution_mode:commands::ExecutionMode::Local,
                revision:1,project_id:"inert-certificate".into(),
                project:asset_source::RegisteredRoot { path:"/inert/never-opened".into(),
                    identity:asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) },
                registry_generation:1,draft:b"{}".to_vec(),platform:Platform::Ios,
                stage:Stage::Candidate,purpose:Purpose::Provisioning }),
            key:RecordKey { id:Token("a".repeat(32)),revision:1 },
            payload:Arc::new(Payload { kind:Kind::AscP8,material:None,fields:None }),
            command:None,prepare_document:None,execute_tools:None,
            supplemental:std::array::from_fn(|_|None),profile_sources:None,key_sources:None,
        };
        let original=Arc::new(Payload { kind:Kind::AppleDistributionKey,material:None,fields:None });
        let weak=Arc::downgrade(&original);
        let writer=CertificateMaterial { material:&material,payload:original.clone() };
        // This inert borrow has no Source/Load/Check and cannot emit a header
        // or body. It exercises the actual writer-held type, not a fake loan.
        assert!(writer.parts().is_err() && writer.header().is_err());
        assert!(Arc::ptr_eq(&writer.payload,&original));
        drop(original);
        assert!(weak.upgrade().is_some());
        // Cancelling an inner write future does not own/drop this outer value.
        // The real write_request keeps it until close_original and its return.
        drop(writer);
        assert!(weak.upgrade().is_none());
        assert!(material.key_sources.is_none());
    }
}
