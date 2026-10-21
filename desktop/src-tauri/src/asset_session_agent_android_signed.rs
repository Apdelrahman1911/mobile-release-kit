//! Comparison-only pins from the genuine ordinary signing-material borrower.
//! Completed permissions retain no strong context or private payload graph.
use super::*;
use std::sync::Weak;
use crate::asset_session::{AndroidSigningMaterial, NativeContext, Payload, RecordKey};

pub(super) struct Pins {
    native: Weak<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Weak<Payload>>,
}
impl Pins {
    pub(super) fn capture(material: &Arc<AndroidSigningMaterial>) -> Result<Self, BridgeError> {
        let (native, keys, payloads, context) = material.candidate_census();
        Self::borrowed(native, keys, payloads, context)
    }
    // Fixed comparison-only constructor used solely with the actual original
    // material above. No record/status DTO can call or recover this borrower.
    fn borrowed(native: &Arc<NativeContext>, keys: &[RecordKey], payloads: &[Arc<Payload>], context: &wire::Context) -> Result<Self, BridgeError> {
        if context.operation != wire::Operation::AndroidBuildSign || context.action.is_some()
            || !(1..=2).contains(&keys.len()) || keys.len() != payloads.len()
        { return Err(public(Error::Conflict)); }
        let mut held_keys = Vec::new(); let mut held_payloads = Vec::new();
        held_keys.try_reserve_exact(keys.len()).map_err(|_| public(Error::StateUnknown))?;
        held_payloads.try_reserve_exact(payloads.len()).map_err(|_| public(Error::StateUnknown))?;
        for (key, payload) in keys.iter().zip(payloads) {
            if key.id.0.capacity() > 64 { return Err(public(Error::StateUnknown)); }
            held_keys.push(key.clone()); held_payloads.push(Arc::downgrade(payload));
        }
        Ok(Self { native: Arc::downgrade(native), keys: held_keys, payloads: held_payloads })
    }
    fn backing(&self) -> Option<usize> {
        let cells = std::mem::size_of::<Self>()
            + std::mem::size_of::<NativeContext>() + 2 * std::mem::size_of::<usize>()
            + self.payloads.len() * (std::mem::size_of::<Payload>() + 2 * std::mem::size_of::<usize>());
        self.keys.iter().try_fold(cells.checked_add(self.keys.capacity().checked_mul(std::mem::size_of::<RecordKey>())?)?
            .checked_add(self.payloads.capacity().checked_mul(std::mem::size_of::<Weak<Payload>>())?)?,
            |n, key| n.checked_add(key.id.0.capacity()))
    }
    pub(super) fn admitted(&self, approval: &crate::saved_command_owner::AgentAndroidBuildApproval) -> Result<(), BridgeError> {
        let quote = self.backing().and_then(|n| n.checked_add(approval.signing_backing()?));
        if quote.is_none_or(|n| n > crate::agent_build_requests::SIGNED_BINDING_BYTES) {
            return Err(public(Error::StateUnknown));
        }
        Ok(())
    }
    pub(super) fn matches(&self, material: &Arc<AndroidSigningMaterial>) -> bool {
        let (native, keys, payloads, _) = material.candidate_census();
        self.matches_borrow(native, keys, payloads)
    }
    fn matches_borrow(&self, native: &Arc<NativeContext>, keys: &[RecordKey], payloads: &[Arc<Payload>]) -> bool {
        self.native.as_ptr() == Arc::as_ptr(native) && self.keys == keys
            && self.payloads.len() == payloads.len()
            && self.payloads.iter().zip(payloads).all(|(a, b)| a.as_ptr() == Arc::as_ptr(b))
    }
}

impl DocumentBinding {
    pub(super) fn agent_android_signing_material(&self, state: &DocumentState, grant: &Grant,
        registration: u32, root: &asset_source::RegisteredRoot) -> Result<Option<Arc<AndroidSigningMaterial>>, BridgeError> {
        match (&grant.signing, grant.approval.input().signing.as_ref()) {
            (None, None) => Ok(None),
            (Some(pins), Some(_)) => {
                let material = self.review_android_material(state, &grant.approval.input().context(), registration, root)?;
                if !pins.matches(&material) { return Err(public(Error::Conflict)); }
                pins.admitted(&grant.approval)?;
                Ok(Some(material))
            },
            _ => Err(public(Error::Conflict)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_weak_binding_and_policy_fit_without_retaining_private_bodies_or_reusing_equal_data() {
        let mut context = wire::tests::signed_context();
        context.signing.as_mut().unwrap().assignments.push(wire::SigningAssignment {
            kind: "android-firebase".into(), record_id: "f".repeat(32), record_revision: 1, context_revision: 2,
        });
        context.artifact_validation.upload_certificate_sha256 = Some(["AF"; 32].join(":"));
        let root = asset_source::RegisteredRoot { path: "/inert/never-opened".into(),
            identity: asset_source::ProjectIdentity::Posix(asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        let native = Arc::new(NativeContext { revision: 2, project_id: context.project_id.clone(), project: root,
            registry_generation: 1, draft: b"{}".to_vec(), platform: Platform::Android,
            stage: Stage::Candidate, purpose: Purpose::Signing, execution_mode: commands::ExecutionMode::Local });
        let keys:Vec<_> = context.signing.as_ref().unwrap().assignments.iter().map(|a|RecordKey {
            id:Token(a.record_id.clone()), revision:a.record_revision }).collect();
        // Deliberately unusable payloads: no source/fields, file, native lease,
        // signing material, original Ready or generation proof is fabricated.
        let payloads = vec![Arc::new(Payload { kind:Kind::AndroidKeystore, material:None, fields:None }),
            Arc::new(Payload { kind:Kind::AndroidFirebase, material:None, fields:None })];
        let pin = Pins::borrowed(&native,&keys,&payloads,&context).unwrap();
        assert!(pin.matches_borrow(&native,&keys,&payloads));
        assert_eq!(Arc::strong_count(&native),1);assert!(payloads.iter().all(|p|Arc::strong_count(p)==1));
        let input = wire::prepare(&serde_json::json!({"projectId":context.project_id,"draftRevision":context.draft_revision,
            "baselineGeneration":context.baseline_generation,"savedConfig":context.saved_config,"savedVersion":context.saved_version,
            "artifactValidation":context.artifact_validation,"signing":context.signing})).unwrap();
        let review = agent::Review { mode:agent::Mode::SavedAndroidLocalUploadKeySign,
            signing:Some(crate::agent_android_build::signed::Selection { mode:crate::agent_android_build::signed::SigningMode::LocalUploadKey,
                assignments:keys.iter().enumerate().map(|(i,k)|crate::agent_android_build::signed::Assignment {
                    kind:if i==0 {crate::agent_android_build::signed::Kind::AndroidKeystore} else {crate::agent_android_build::signed::Kind::AndroidFirebase},
                    record_id:crate::service_protocol::Id::parse(&k.id.0).unwrap(),record_revision:k.revision,context_revision:2 }).collect() }),
            upload_certificate_sha256:Some("af".repeat(32)),
            saved_config:agent::Config { bytes:context.saved_config.bytes,sha256:context.saved_config.sha256.clone() },
            saved_version:agent::Version { bytes:context.saved_version.bytes,sha256:context.saved_version.sha256.clone(),
                name:context.saved_version.name.clone(),build:context.saved_version.build },
            tools:agent::Tools { instance:crate::service_protocol::Id::parse(&"a".repeat(32)).unwrap(),catalog_generation:1,record_sha256:"b".repeat(64) } };
        let policy=crate::saved_command_owner::AgentAndroidBuildApproval::signing_backing_data(&input,&review).unwrap();
        let charge=pin.backing().unwrap();assert!(charge+policy<=crate::agent_build_requests::SIGNED_BINDING_BYTES);
        let mut changed=payloads.clone();changed[0]=Arc::new(Payload {kind:Kind::AndroidKeystore,material:None,fields:None});
        assert!(!pin.matches_borrow(&native,&keys,&changed));drop(changed);
        let mut candidate=context.clone();candidate.operation=wire::Operation::AndroidCandidateInputs;candidate.action=Some(wire::CreateAction::Create);
        assert!(Pins::borrowed(&native,&keys,&payloads,&candidate).is_err());
        drop(native);drop(payloads);
        assert!(pin.native.upgrade().is_none()&&pin.payloads.iter().all(|w|w.upgrade().is_none()));
        assert_eq!(pin.backing(),Some(charge)); // Weak allocations survive their last strong owner.
        let mut over=pin;over.keys[0].id.0.reserve(crate::agent_build_requests::SIGNED_BINDING_BYTES);
        assert!(over.backing().unwrap()+policy>crate::agent_build_requests::SIGNED_BINDING_BYTES);
    }
}
