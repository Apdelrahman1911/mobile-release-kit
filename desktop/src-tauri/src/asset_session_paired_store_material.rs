//! The same SelectedStoreMaterial retains exactly Google + P8 for the closed
//! paired query. No second context, provider, plaintext export or renewed loan.
use super::*;

impl StoreCommand {
    pub(super) fn paired_context(&self) -> Option<&wire::Context> {
        match self {
            Self::Access(c) if wire::paired_versions::selected(c) => Some(c),
            _ => None,
        }
    }
}
impl SelectedStoreMaterial {
    pub(super) fn paired_context(&self) -> Option<&wire::Context> {
        self.command.as_ref().and_then(StoreCommand::paired_context)
    }
    pub(super) fn access_scope(&self, c: &wire::Context) -> bool {
        if wire::paired_versions::selected(c) {
            return paired_versions::selected(&self.native);
        }
        self.native.platform
            == match c.platform {
                wire::AccessPlatform::Android => Platform::Android,
                wire::AccessPlatform::Ios => Platform::Ios,
                wire::AccessPlatform::Both => return false,
            }
            && matches!(self.native.purpose, Purpose::Full | Purpose::Store)
    }
    pub(super) fn pair_parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
        let c = self.paired_context().ok_or_else(refused)?;
        if !paired_versions::selected(&self.native)
            || self.supplemental[1..].iter().any(Option::is_some)
        {
            return Err(refused());
        }
        let r = c.ios_record.as_ref().ok_or_else(refused)?;
        let (key, payload) = self.supplemental[0].as_ref().ok_or_else(refused)?;
        if key.id.0 != r.record_id || key.revision != r.record_revision || !r.valid(&self.key.id.0)
        {
            return Err(refused());
        }
        let google = bytes(&self.payload).ok_or_else(refused)?;
        let (p8, key_id, issuer) = apple_parts(payload).ok_or_else(refused)?;
        let mut parts = Vec::new();
        parts.try_reserve_exact(4).map_err(|_| refused())?;
        parts.extend([
            ("google-service-account", google),
            ("asc-p8", p8),
            ("asc-key-id", key_id),
            ("asc-issuer-id", issuer),
        ]);
        Ok(parts)
    }
    pub(super) fn pair_current(&self, state: &DocumentState) -> bool {
        let Some(c) = self.paired_context() else {
            return false;
        };
        let (Some(r), Some((key, payload))) = (&c.ios_record, &self.supplemental[0]) else {
            return false;
        };
        paired_versions::selected(&self.native)
            && r.valid(&self.key.id.0)
            && r.record_id == key.id.0
            && r.record_revision == key.revision
            && self.supplemental[1..].iter().all(Option::is_none)
            && apple_parts(payload).is_some()
            && github_secret::assigned(state, key, Kind::AscP8, &self.native)
                .is_some_and(|current| Arc::ptr_eq(current, payload))
    }
}
fn capture_pair(
    state: &DocumentState,
    native: &Arc<NativeContext>,
    command: Option<&StoreCommand>,
    slots: &mut [Option<(RecordKey, Arc<Payload>)>; 3],
) -> Result<(), BridgeError> {
    let Some(c) = command.and_then(StoreCommand::paired_context) else {
        return Ok(());
    };
    if !paired_versions::selected(native) || slots.iter().any(Option::is_some) {
        return Err(refused());
    }
    let r = c
        .ios_record
        .as_ref()
        .filter(|r| r.valid(&c.record_id))
        .ok_or_else(refused)?;
    let key = RecordKey {
        id: Token(r.record_id.clone()),
        revision: r.record_revision,
    };
    let payload = github_secret::assigned(state, &key, Kind::AscP8, native)
        .ok_or_else(refused)?
        .clone();
    if apple_parts(&payload).is_none() {
        return Err(refused());
    }
    slots[0] = Some((key, payload));
    Ok(())
}

// In addition to the original deduplicated native payload/context census:
// two parts vectors, 1KiB header + reused fixed eleven-row stack, four full
// 32,814-byte data copies
// (received, selected, bounded read/postcheck scratch) and 16KiB extra fixed
// runner/source-control backing. Providers' existing bounded private raw/frame
// buffers are sequential; this is a data reservation, NOT a CPython/RSS bound.
pub(super) const FRAME_BYTES: usize = 2 * 4 * std::mem::size_of::<(&str, &[u8])>()
    + 1024
    + 11 * std::mem::size_of::<(&str, usize)>()
    + 4 * (2 * 16 * 1024 + 46)
    + 16 * 1024;
pub(super) fn capture(
    state: &DocumentState,
    native: &Arc<NativeContext>,
    command: Option<&StoreCommand>,
    slots: &mut [Option<(RecordKey, Arc<Payload>)>; 3],
) -> Result<(), BridgeError> {
    capture_pair(state, native, command, slots)
}

#[cfg(all(
    test,
    any(
        all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
        all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )
))]
mod tests {
    use super::*;
    #[test]
    fn original_pair_uses_two_assessments_four_parts_and_loses_both_on_either_revocation() {
        // Existing inert format/assignment fixture only, not a valid private key,
        // account, current Store receipt or successful native capture.
        let mut state = super::super::tests::apple_model();
        let context = Arc::get_mut(state.context.as_mut().unwrap()).unwrap();
        context.platform = Platform::Both;
        context.purpose = Purpose::VersionInventory;
        context.draft = br#"{"android":{"enabled":true},"ios":{"enabled":true}}"#.to_vec();
        let key = RecordKey {
            id: Token("b".repeat(32)),
            revision: 1,
        };
        let raw = super::super::tests::sample();
        let observation = credential_format::inspect(
            credential_format::FileKind::GoogleServiceAccount,
            &raw,
            &mut || false,
        )
        .ok()
        .unwrap();
        state.records.push(Record {
            key: key.clone(),
            mutation_pending: false,
            payload: Arc::new(Payload {
                kind: Kind::GoogleServiceAccount,
                // Linux can exercise the original weak material DATA but does
                // not gain the Mac-only Google credential admission route.
                fields: if Kind::GoogleServiceAccount.enabled() {
                    Some(
                        commands::own_fields(Kind::GoogleServiceAccount, &serde_json::json!({}))
                            .ok()
                            .unwrap(),
                    )
                } else {
                    None
                },
                material: Some(Arc::new(Material {
                    observation,
                    origin: MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(
                        raw,
                    )),
                })),
            }),
        });
        state.assignments.push(Assignment {
            kind: Kind::GoogleServiceAccount,
            record_id: key.id,
            record_revision: 1,
            context_revision: 2,
            availability: AssignmentAvailability::Available,
        });
        let native = state.context.as_ref().unwrap();
        for (index, platform) in [(0, "ios"), (1, "android")] {
            if state.records[index].payload.fields.is_none() {
                assert!(!Kind::GoogleServiceAccount.enabled());
                assert!(
                    super::super::super::session_kind_gate(native, Kind::GoogleServiceAccount)
                        .is_err()
                );
                let (selected, purpose) = paired_versions::assessment_scope(
                    Kind::GoogleServiceAccount,
                    native,
                    &serde_json::from_slice(&native.draft).unwrap(),
                )
                .ok()
                .unwrap();
                assert!(selected == Platform::Android && purpose == Purpose::Store);
                continue;
            }
            let actual =
                super::super::super::assemble_request(&state.records[index].payload, native)
                    .ok()
                    .unwrap();
            let data = serde_json::to_value(actual).unwrap();
            assert_eq!(data["context"]["platform"], platform);
            assert_eq!(data["context"]["purpose"], "store");
            assert!(paired_versions::selected(native)); // Projection does not rewrite the actual context.
        }
        let mut value = serde_json::json!(wire::tests::context());
        value.as_object_mut().unwrap().remove("operation");
        value["projectId"] = serde_json::json!("inert-project");
        value["credentialContextRevision"] = serde_json::json!(2);
        value["recordId"] = serde_json::json!("b".repeat(32));
        value["recordRevision"] = serde_json::json!(1);
        value["platform"] = serde_json::json!("both");
        value["query"] = serde_json::json!(wire::paired_versions::QUERY);
        value["iosRecord"] = serde_json::json!({"recordId":"a".repeat(32),"recordRevision":1});
        let context = wire::prepare(&value).unwrap().context();
        let root = native.project.clone();
        let original = borrow_preflight_material(&state, &context, 7, &root).unwrap();
        let witness = original.version_inventory_witness().unwrap().unwrap();
        let parts = original.parts().unwrap();
        assert_eq!(
            parts.iter().map(|(role, _)| *role).collect::<Vec<_>>(),
            [
                "google-service-account",
                "asc-p8",
                "asc-key-id",
                "asc-issuer-id"
            ]
        );
        assert_eq!(
            parts[0].1.as_ptr(),
            state.records[1]
                .payload
                .material
                .as_ref()
                .unwrap()
                .bytes()
                .as_ptr()
        );
        assert_eq!(
            parts[1].1.as_ptr(),
            state.records[0]
                .payload
                .material
                .as_ref()
                .unwrap()
                .bytes()
                .as_ptr()
        );
        assert_eq!(original.supplemental_frame_bytes(), FRAME_BYTES);
        assert!(FRAME_BYTES > 4 * (2 * 16 * 1024 + 46));
        drop(parts);
        assert!(witness.current(&state, 7, &root));
        let mut called = false;
        assert!(original
            .with_bytes(&state, 7, &root, |_, _| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called); // Pair cannot lend the old single-Google callback.
        for index in 0..2 {
            state.assignments[index].availability = AssignmentAvailability::Unavailable;
            assert!(!original.current(&state, 7, &root));
            assert!(!witness.current(&state, 7, &root));
            state.assignments[index].availability = AssignmentAvailability::Available;
        }
        let old = state.context.take().unwrap();
        state.context = Some(Arc::new(NativeContext {
            revision: old.revision,
            execution_mode: old.execution_mode,
            project_id: old.project_id.clone(),
            project: old.project.clone(),
            registry_generation: old.registry_generation,
            draft: old.draft.clone(),
            platform: old.platform,
            stage: old.stage,
            purpose: old.purpose,
        }));
        assert!(!witness.current(&state, 7, &root));
        state.context = Some(old);
        let held: Vec<_> = state
            .records
            .iter()
            .map(|r| Arc::downgrade(&r.payload))
            .collect();
        drop(original);
        state.records.clear();
        state.assignments.clear();
        assert!(held.iter().all(|p| p.upgrade().is_none()));
        assert!(!witness.current(&state, 7, &root));
    }
}
