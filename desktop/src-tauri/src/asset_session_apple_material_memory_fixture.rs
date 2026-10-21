//! cfg(test) only. Actual retained allocations with empty unobserved bytes;
//! these are neither a credential nor a private native read/assignment loan.
use super::*;

impl SelectedStoreMaterial {
    pub(crate) fn apple_census_data(
        context: &crate::apple_provisioning_protocol::Context,
        draft_capacity: usize,
        p8_capacity: usize,
        p12_capacity: usize,
    ) -> Arc<Self> {
        assert!(
            draft_capacity <= 524_288
                && p8_capacity <= 16 * 1024
                && p12_capacity <= 4 * 1024 * 1024
        );
        let payload = |kind, file_kind, capacity| {
            let observation = credential_format::inspect(file_kind, &[], &mut || false)
                .ok()
                .expect("inert empty observation");
            Arc::new(Payload {
                kind,
                fields: None,
                material: Some(Arc::new(Material {
                    origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                        Vec::with_capacity(capacity),
                    )),
                    observation,
                })),
            })
        };
        let mut draft = Vec::with_capacity(draft_capacity);
        draft.extend_from_slice(b"{}");
        Arc::new(Self {
            native: Arc::new(NativeContext {
                revision: context.credential_context_revision,
                project_id: context.project_id.clone(),
                project: asset_source::RegisteredRoot {
                    path: "/never-registered-material-census".into(),
                    identity: asset_source::ProjectIdentity::Windows {
                        volume: 0,
                        file_id: [0; 16],
                    },
                },
                registry_generation: 0,
                draft,
                platform: Platform::Ios,
                stage: Stage::Candidate,
                purpose: Purpose::Provisioning,
                execution_mode: commands::ExecutionMode::Local,
            }),
            key: RecordKey {
                id: Token(context.record_id.clone()),
                revision: context.record_revision,
            },
            payload: payload(Kind::AscP8, credential_format::FileKind::AscP8, p8_capacity),
            command: Some(StoreCommand::Provisioning(context.clone())),
            prepare_document: None,
            execute_tools: None,
            supplemental: [
                if p12_capacity == 0 {
                    None
                } else {
                    Some((
                        RecordKey {
                            id: Token("inert-unbound-p12".into()),
                            revision: 1,
                        },
                        payload(
                            Kind::AppleP12,
                            credential_format::FileKind::AppleP12,
                            p12_capacity,
                        ),
                    ))
                },
                None,
                None,
            ],
            profile_sources: None,
            key_sources: None,
        })
    }

    pub(in crate::asset_session) fn apple_census_alias(&self) -> Arc<Self> {
        // Distinct wrapper; identical underlying context/payload allocations.
        // Deliberately no selected sources or toolchain/native receipts.
        assert!(
            self.profile_sources.is_none()
                && self.key_sources.is_none()
                && self.execute_tools.is_none()
        );
        Arc::new(Self {
            native: self.native.clone(),
            key: self.key.clone(),
            payload: self.payload.clone(),
            command: self.command.clone(),
            prepare_document: None,
            execute_tools: None,
            supplemental: self.supplemental.clone(),
            profile_sources: None,
            key_sources: None,
        })
    }
}
