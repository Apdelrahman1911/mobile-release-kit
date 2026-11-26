//! Weak comparison pins for one original signed iOS Desktop approval. Payload
//! ownership stays in the Asset graph and then the actual Prepared/Session.
use super::*;
use std::sync::Weak;

pub(in crate::asset_session) struct Pin {
    native: Weak<NativeContext>,
    keys: Vec<RecordKey>,
    payloads: Vec<Weak<Payload>>,
}
impl Pin {
    pub(in crate::asset_session) fn capture(
        original: &Arc<IOSSigningMaterial>,
    ) -> Result<Self, BridgeError> {
        if original.context.operation != wire::Operation::IOSSignedExport
            || original.context.action.is_some()
            || original.context.recovery.is_some()
            || !(2..=4).contains(&original.keys.len())
            || original.keys.len() != original.payloads.len()
            || original.keys.iter().any(|k| {
                !crate::edit_protocol::token(&k.id.0) || !(1..u32::MAX).contains(&k.revision)
            })
        {
            return Err(invalid());
        }
        let mut keys = Vec::new();
        let mut payloads = Vec::new();
        keys.try_reserve_exact(original.keys.len())
            .map_err(|_| invalid())?;
        payloads
            .try_reserve_exact(original.payloads.len())
            .map_err(|_| invalid())?;
        for (key, payload) in original.keys.iter().zip(&original.payloads) {
            keys.push(RecordKey {
                id: Token(key.id.0.as_str().to_owned()),
                revision: key.revision,
            });
            payloads.push(Arc::downgrade(payload));
        }
        let pin = Self {
            native: Arc::downgrade(&original.native),
            keys,
            payloads,
        };
        if pin
            .retained_bytes()
            .is_none_or(|n| n > crate::agent_build_requests::SIGNED_BINDING_BYTES)
        {
            return Err(invalid());
        }
        Ok(pin)
    }
    pub(in crate::asset_session) fn matches(&self, original: &Arc<IOSSigningMaterial>) -> bool {
        original.context.operation == wire::Operation::IOSSignedExport
            && self.native.as_ptr() == Arc::as_ptr(&original.native)
            && self.keys == original.keys
            && self.payloads.len() == original.payloads.len()
            && self
                .payloads
                .iter()
                .zip(&original.payloads)
                .all(|(a, b)| a.as_ptr() == Arc::as_ptr(b))
    }
    pub(in crate::asset_session) fn current(
        &self,
        state: &DocumentState,
        context: &wire::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        let Some(native) = self.native.upgrade() else {
            return false;
        };
        context.operation == wire::Operation::IOSSignedExport
            && context.action.is_none()
            && context.recovery.is_none()
            && native.project_id == context.project_id
            && native.registry_generation == registration
            && native.project == *root
            && native.platform == Platform::Ios
            && native.stage == Stage::Candidate
            && native.purpose == Purpose::Signing
            && context.signing.as_ref().is_some_and(|p| {
                p.assignments.len() == self.keys.len()
                    && p.assignments.iter().zip(&self.keys).all(|(a, k)| {
                        a.record_id == k.id.0
                            && a.record_revision == k.revision
                            && a.context_revision == native.revision
                    })
            })
            && self.keys.len() == self.payloads.len()
            && context.signing.as_ref().is_some_and(|policy| {
                self.keys
                    .iter()
                    .zip(&self.payloads)
                    .zip(&policy.assignments)
                    .all(|((key, payload), assignment)| {
                        payload.upgrade().is_some_and(|p| {
                            assignment.kind == p.kind.name()
                                && assigned_payload(state, key, p.kind, &native)
                                    .is_some_and(|current| Arc::ptr_eq(current, &p))
                        })
                    })
            })
    }
    pub(in crate::asset_session) fn retained_bytes(&self) -> Option<usize> {
        let mut n = std::mem::size_of::<Self>()
            .checked_add(
                self.keys
                    .capacity()
                    .checked_mul(std::mem::size_of::<RecordKey>())?,
            )?
            .checked_add(
                self.payloads
                    .capacity()
                    .checked_mul(std::mem::size_of::<Weak<Payload>>())?,
            )?
            // A Weak keeps the inline Arc allocation after its last strong
            // reference drops. Descendant bodies are not retained by the Pin.
            .checked_add(std::mem::size_of::<NativeContext>() + 2 * std::mem::size_of::<usize>())?
            .checked_add(self.payloads.len().checked_mul(
                std::mem::size_of::<Payload>() + 2 * std::mem::size_of::<usize>(),
            )?)?;
        for key in &self.keys {
            n = n.checked_add(key.id.0.capacity())?;
        }
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Actual Arc/Weak cells with deliberately unusable payload DATA: these
    // tests cannot acquire a file, signing lease, native grant or Start.
    fn material() -> Arc<IOSSigningMaterial> {
        let context = wire::tests::signed_context();
        let root = asset_source::RegisteredRoot {
            path: "/inert/signed-ios".into(),
            identity: asset_source::ProjectIdentity::Posix(
                asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        let native = Arc::new(NativeContext {
            execution_mode: commands::ExecutionMode::Local,
            revision: 3,
            project_id: context.project_id.clone(),
            project: root,
            registry_generation: 7,
            draft: b"{}".to_vec(),
            platform: Platform::Ios,
            stage: Stage::Candidate,
            purpose: Purpose::Signing,
        });
        let keys = context
            .signing
            .as_ref()
            .unwrap()
            .assignments
            .iter()
            .map(|a| RecordKey {
                id: Token(a.record_id.clone()),
                revision: a.record_revision,
            })
            .collect();
        let payloads = vec![
            Arc::new(Payload {
                kind: Kind::AppleP12,
                material: None,
                fields: None,
            }),
            Arc::new(Payload {
                kind: Kind::AppleProfile,
                material: None,
                fields: None,
            }),
        ];
        Arc::new(IOSSigningMaterial {
            context,
            candidate_document: None,
            native,
            keys,
            payloads,
        })
    }
    #[test]
    fn signed_grant_pins_only_the_same_native_and_payload_graph_without_retaining_private_bodies() {
        let original = material();
        assert!(original.parts().is_err());
        let pin = Pin::capture(&original).unwrap();
        assert!(pin.matches(&original));
        assert_eq!(Arc::strong_count(&original.native), 1);
        for p in &original.payloads {
            assert_eq!(Arc::strong_count(p), 1);
        }
        assert!(pin.retained_bytes().unwrap() < crate::agent_build_requests::SIGNED_BINDING_BYTES);
        let same_data = material();
        assert!(!pin.matches(&same_data));
        drop(original);
        assert!(pin.native.upgrade().is_none());
        assert!(pin.payloads.iter().all(|p| p.upgrade().is_none()));
    }
    #[test]
    fn signed_grant_does_not_adopt_a_changed_payload_or_candidate_material() {
        let mut original = material();
        let pin = Pin::capture(&original).unwrap();
        let p = Arc::get_mut(&mut original).unwrap();
        p.payloads[1] = Arc::new(Payload {
            kind: Kind::AppleProfile,
            material: None,
            fields: None,
        });
        assert!(!pin.matches(&original));
        let p = Arc::get_mut(&mut original).unwrap();
        p.context.operation = wire::Operation::IOSCandidateInputs;
        p.context.action = Some(wire::CreateAction::Create);
        assert!(Pin::capture(&original).is_err());
        assert!(!pin.matches(&original));
    }
    #[test]
    fn four_signed_inputs_and_weak_tombstones_fit_existing_build_ancillary_quote() {
        let mut original = material();
        let m = Arc::get_mut(&mut original).unwrap();
        for (name, kind, id) in [
            ("ios-firebase", Kind::IosFirebase, '3'),
            ("project-read-token", Kind::ProjectReadToken, '4'),
        ] {
            let record_id = id.to_string().repeat(32);
            m.context
                .signing
                .as_mut()
                .unwrap()
                .assignments
                .push(wire::SigningAssignment {
                    kind: name.into(),
                    record_id: record_id.clone(),
                    record_revision: 1,
                    context_revision: 3,
                });
            m.keys.push(RecordKey {
                id: Token(record_id),
                revision: 1,
            });
            m.payloads.push(Arc::new(Payload {
                kind,
                material: None,
                fields: None,
            }));
        }
        let c = &m.context;
        let input=wire::prepare(&serde_json::json!({"projectId":c.project_id,"draftRevision":c.draft_revision,
            "baselineGeneration":c.baseline_generation,"savedConfig":c.saved_config,"savedVersion":c.saved_version,"signing":c.signing})).unwrap();
        let policy =
            crate::saved_command_owner::AgentIOSArchiveApproval::signing_backing_data(&input)
                .unwrap();
        let pin = Pin::capture(&original).unwrap();
        let charged = pin.retained_bytes().unwrap();
        assert!(
            charged.checked_add(policy).unwrap()
                <= crate::agent_build_requests::SIGNED_BINDING_BYTES
        );
        drop(original);
        assert_eq!(pin.retained_bytes(), Some(charged)); // Weak allocation survives, never zero credit.
        assert!(
            pin.native.upgrade().is_none() && pin.payloads.iter().all(|p| p.upgrade().is_none())
        );
        let mut over = pin;
        over.keys[0]
            .id
            .0
            .reserve(crate::agent_build_requests::SIGNED_BINDING_BYTES);
        assert!(
            over.retained_bytes().unwrap() + policy
                > crate::agent_build_requests::SIGNED_BINDING_BYTES
        );
    }
}
