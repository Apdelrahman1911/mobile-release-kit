//! Existing AssetSession/vault adapter, compiled as a CHILD of asset_session_vault.
//!
//! A preference can request the ordinary existing Load/assessment operation. It
//! cannot recreate Bind, a decrypted cache, a native certificate observation or
//! a material loan. No new worker/process/runtime or credential read is added.
//! Root wires these methods under the shared project coordinator; no public
//! pathname/ref-shaped JSON is accepted as a native project or credential.
use super::*;
use crate::{application_service::ApplicationService, credential_setup as setup};
use setup::{Assessment, Continuity, KeyReference, Observation, Plan, ProjectBinding, RecordObservation,
    Role, SavedAssignment, SetupObservation, SetupStatus, Storage, persistence};
use sha2::{Digest, Sha256};

fn data_error(error: setup::Error) -> AssetError {
    AssetError::new(match error {
        setup::Error::Shape => Reason::InvalidRequest,
        setup::Error::Bounds => Reason::Capacity,
        setup::Error::Stale | setup::Error::Conflict | setup::Error::Continuity => Reason::ContextStale,
        setup::Error::RecoveryRequired => Reason::VaultInterrupted,
        setup::Error::Unavailable => Reason::Unqualified,
    })
}
fn service_error(error: crate::service_protocol::Error) -> AssetError {
    use crate::service_protocol::Error as E;
    AssetError::new(match error {
        E::InvalidRequest => Reason::InvalidRequest,
        E::Conflict => Reason::ContextStale,
        E::Busy => Reason::Busy,
        E::RecoveryRequired => Reason::VaultInterrupted,
        E::StateUnknown => Reason::VaultDurabilityUnknown,
        _ => Reason::Unqualified,
    })
}
fn preference_error(error: persistence::Failure) -> AssetError {
    match error {
        persistence::Failure::Data(error) => data_error(error),
        persistence::Failure::Storage(error) => {
            use crate::application_state_store::{Cleanup, Durability, Effect};
            if error.effect == Effect::Unknown || error.durability == Durability::Unknown || error.cleanup == Cleanup::Unknown {
                AssetError::new(Reason::VaultDurabilityUnknown)
            } else { service_error(error.code) }
        }
    }
}
fn kind(role: Role) -> Result<Kind, AssetError> {
    match role {
        Role::AndroidUpload => Ok(Kind::AndroidKeystore),
        Role::AppleDistribution => Ok(Kind::AppleP12),
        // A local Apple signing private key is NOT an ASC P8 or PKCS12 record.
        // Its dedicated new kind/producer must be independently admitted.
        Role::AppleSigningKey => Err(AssetError::new(Reason::UnsupportedFormat)),
    }
}
fn pending(state: &DocumentState) -> bool {
    state.stopping || state.unknown || state.exhausted || state.quit_pending || state.retiring || state.lock_pending
        || !state.lifetime.original_bound()
        || state.slot.as_ref().is_some_and(|slot| slot.phase != Phase::Idle || !slot.owner.resources_settled())
}

/// Stable *app identity*, not the entire versioned configuration or an expected
/// signer fingerprint. Adding the generated public fingerprint must not make
/// the app appear to be a new empty signing slot. The native admitted draft is
/// already bounded and duplicate-checked; no project source code is executed.
fn app_policy(draft: &[u8], role: Role) -> Result<(String, Option<String>), AssetError> {
    if draft.len() > commands::DRAFT_LIMIT { return Err(AssetError::new(Reason::Capacity)); }
    let value: Value = serde_json::from_slice(draft).map_err(|_| AssetError::invalid())?;
    let (section, names, fingerprint): (&str, &[&str], &str) = match role {
        Role::AndroidUpload => ("android", &["applicationId"], "uploadCertificateSha256"),
        Role::AppleDistribution | Role::AppleSigningKey => ("ios", &["bundleId", "teamId"], "distributionCertificateSha256"),
    };
    let section = value.get(section).and_then(Value::as_object).ok_or_else(AssetError::invalid)?;
    let mut hash = Sha256::new();
    hash.update(b"dev.mobile-release-kit.desktop/credential-app-identity/v1\0");
    hash.update([match role { Role::AndroidUpload => 1, Role::AppleDistribution => 2, Role::AppleSigningKey => 3 }]);
    for name in names {
        let text = section.get(*name).and_then(Value::as_str).ok_or_else(AssetError::invalid)?;
        if text.is_empty() || text.len() > 1024 || !text.is_ascii() || text.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) {
            return Err(AssetError::invalid());
        }
        hash.update((text.len() as u32).to_be_bytes()); hash.update(text.as_bytes());
    }
    let expected = section.get(fingerprint).map(|value| {
        let text = value.as_str().ok_or_else(AssetError::invalid)?;
        if text.len() > 95 { return Err(AssetError::invalid()); }
        let normalized: String = text.bytes().filter(|b| *b != b':').map(|b| char::from(b.to_ascii_lowercase())).collect();
        if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(AssetError::invalid());
        }
        Ok(normalized)
    }).transpose()?;
    Ok((crate::service_protocol::hex(&hash.finalize()), expected))
}

struct RecordFact { reference: KeyReference, assigned: bool, mutation_pending: bool }
struct NativeObservation {
    project: ProjectBinding, role: Role, revision: u32, identity: String, expected: Option<String>,
    storage: Storage, vault_identity: Option<format::Identity>, pending: bool, records: Vec<RecordFact>,
}
impl NativeObservation {
    fn with<R>(&self, action: impl FnOnce(&Observation<'_>) -> R) -> R {
        let records: Vec<_> = self.records.iter().map(|record| RecordObservation {
            reference: &record.reference, certificate_sha256: None,
            assessment: if record.assigned { Assessment::Current } else { Assessment::NotChecked },
            current_assignment: record.assigned, mutation_pending: record.mutation_pending,
        }).collect();
        // Current format assessment+Bind does NOT prove a certificate
        // fingerprint. Native signing validation must provide that evidence in
        // its own admitted facet; never copy the expected fingerprint here.
        action(&Observation { project: &self.project, role: self.role, revision: self.revision,
            identity_sha256: &self.identity, expected_certificate_sha256: self.expected.as_deref(),
            storage: self.storage, vault_identity: self.vault_identity, continuity: Continuity::Unknown,
            operation_pending: self.pending, records: &records })
    }
}

#[cfg(feature = "desktop-shell")]
impl DocumentBinding {
    fn credential_observation(&self, state: &DocumentState, service: &ApplicationService, role: Role) -> Result<NativeObservation, AssetError> {
        if state.revision == 0 || !state.lifetime.original_bound() { return Err(AssetError::new(Reason::DocumentLost)); }
        let context = state.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?;
        if !self.context_matches(state, context)? { return Err(AssetError::new(Reason::ContextStale)); }
        let known = service.native_binding(&context.project_id).map_err(service_error)?;
        let actual = context.project.identity.posix().map_err(AssetError::new)?.preflight_identity();
        if context.project.path.to_str() != Some(known.canonical_root.as_str())
            || actual.device.parse::<u64>().ok() != Some(known.device) || actual.inode.parse::<u64>().ok() != Some(known.inode) {
            return Err(AssetError::new(Reason::ContextStale));
        }
        let project = ProjectBinding { project_id: known.project_id.as_str().to_owned(), canonical_root: known.canonical_root,
            device: known.device, inode: known.inode };
        project.validate().map_err(data_error)?;
        let (identity, expected) = app_policy(&context.draft, role)?;
        let selected_kind = kind(role)?;
        session_kind_gate(context, selected_kind)?;
        let mut storage = Storage::Unavailable;
        let mut vault_identity = None;
        let mut records = Vec::new();
        if self.native_qualified() && self.persistence_qualified() && !state.session {
            if let Some(session) = &state.vault {
                vault_identity = session.identity;
                storage = match session.state {
                    State::Locked => Storage::Locked,
                    State::Unlocked if session.writable() => Storage::Unlocked,
                    State::Initializing | State::Mutating | State::Interrupted | State::Unknown => Storage::RecoveryRequired,
                    _ => Storage::Unavailable,
                };
                if session.revoked || session.read_only { storage = Storage::RecoveryRequired; }
                if let Some(vault_identity) = vault_identity {
                    if session.rows.len() > format::DESCRIPTOR_COUNT { return Err(AssetError::new(Reason::Capacity)); }
                    for row in session.rows.iter().filter(|row| row.authenticated.descriptor.kind == selected_kind) {
                        let key = row.key();
                        let assigned = state.assignments.iter().any(|assignment| assignment.kind == selected_kind
                            && assignment.record_id == key.id && assignment.record_revision == key.revision
                            && assignment.context_revision == context.revision && assignment_available(state, assignment));
                        records.push(RecordFact { reference: KeyReference::native(vault_identity, row.authenticated.record, row.authenticated.revision),
                            assigned, mutation_pending: row.mutation_pending });
                    }
                }
            }
        }
        Ok(NativeObservation { project, role, revision: state.revision, identity, expected, storage,
            vault_identity, pending: pending(state), records })
    }

    /// Safe project-bound status. Does not open a vault, grant a material loan,
    /// confirm new-app history or launch key generation on a wizard rerun.
    pub(crate) fn credential_setup_observe(&self, service: &ApplicationService, role: Role) -> Result<SetupObservation, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        let native = self.credential_observation(&state, service, role)?;
        let preference = persistence::observe(service.state_directory(), &native.project, role).map_err(preference_error)?;
        let plan = native.with(|observation| setup::classify(observation, preference.preference.as_ref())).map_err(data_error)?;
        Ok(SetupObservation { status: SetupStatus { schema_version: 1, project_id: native.project.project_id,
            observation_revision: native.revision, role, plan }, preference_revision: preference.store_revision })
    }

    /// Run after the real existing Bind has completed and its originals have
    /// joined, under the same per-project coordinator. It saves preference DATA
    /// only. Failure cannot turn the current Bind into a fabricated vault save;
    /// an unknown reference-store result remains blocked for explicit recovery.
    pub(crate) fn credential_remember_assignment(&self, service: &ApplicationService, expected_revision: u32,
        expected_preference_revision: u64, role: Role, operation_id: &str, reassign: bool) -> Result<u64, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?;
        if state.revision != expected_revision || pending(&state) { return Err(AssetError::new(Reason::ContextStale)); }
        let native = self.credential_observation(&state, service, role)?;
        let current: Vec<_> = native.records.iter().filter(|record| record.assigned && !record.mutation_pending).collect();
        if current.len() != 1 { return Err(AssetError::new(Reason::SourceChanged)); }
        let reference = current[0].reference.clone();
        // Require the actual settled Bind publication, not a newly supplied
        // JSON assessment or an assignment-shaped record from another owner.
        let slot = state.slot.as_ref().ok_or_else(|| AssetError::new(Reason::SourceChanged))?;
        if slot.operation != Operation::Bind || slot.reason != Reason::None || slot.error.is_some() || slot.cleanup_end.is_some()
            || !slot.assessment.as_ref().is_some_and(SafeAssessment::permits)
            || !slot.vault.reference.is_some_and(|bound| KeyReference::native(bound.identity, bound.record, bound.revision) == reference) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let saved = SavedAssignment { reference, identity_sha256: native.identity.clone(), certificate_sha256: None,
            operation_id: operation_id.to_owned() };
        native.with(|observation| persistence::remember_bound(service.state_directory(), expected_preference_revision,
            &native.project, role, saved, observation, reassign)).map_err(preference_error)
    }

    /// Explicit "Check saved key" adapter. Full random vault+record revision
    /// rematch happens under the original document gate, then the SAME existing
    /// prepare_stored_vault loads/authenticates/assesses it. A separate normal
    /// one-use preview+Bind is still required; restart never restores it.
    pub(crate) fn credential_prepare_saved_assignment(&self, service: &ApplicationService, expected_revision: u32,
        expected_preference_revision: u64, role: Role) -> Result<u32, AssetError> {
        self.reconcile(); let mut state = self.lock(); self.expire(&mut state, Instant::now());
        self.durable_gate(&state, true)?;
        if state.revision != expected_revision || pending(&state) { return Err(AssetError::new(Reason::ContextStale)); }
        let native = self.credential_observation(&state, service, role)?;
        let preference = persistence::observe(service.state_directory(), &native.project, role).map_err(preference_error)?;
        if preference.store_revision != expected_preference_revision { return Err(AssetError::new(Reason::ContextStale)); }
        let saved = preference.preference.as_ref().and_then(setup::Preference::saved).ok_or_else(|| AssetError::new(Reason::VaultInterrupted))?;
        if saved.identity_sha256 != native.identity || !native.records.iter().any(|record| record.reference == saved.reference && !record.mutation_pending) {
            return Err(AssetError::new(Reason::SourceChanged));
        }
        let (identity, record, revision) = saved.reference.parts().map_err(data_error)?;
        if native.vault_identity != Some(identity) { return Err(AssetError::new(Reason::SourceChanged)); }
        let key = RecordKey { id: Token(record.token()), revision: revision.counter };
        let context = state.context.as_ref().ok_or_else(|| AssetError::new(Reason::ContextStale))?.clone();
        let (operation, start) = self.prepare_stored_vault(&mut state, key, context)?;
        drop(state); let _ = start.send(()); Ok(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn app_identity_ignores_release_version_and_expected_fingerprint_but_not_application_or_team() {
        let first = br#"{"android":{"applicationId":"example.test","versionCode":1}}"#;
        let second = format!(r#"{{"android":{{"applicationId":"example.test","versionCode":2,"uploadCertificateSha256":"{}"}}}}"#, "AB:".repeat(31) + "AB");
        let a = app_policy(first, Role::AndroidUpload).ok().unwrap(); let b = app_policy(second.as_bytes(), Role::AndroidUpload).ok().unwrap();
        assert_eq!(a.0, b.0); assert_eq!(b.1, Some("ab".repeat(32)));
        assert_ne!(a.0, app_policy(br#"{"android":{"applicationId":"example.other"}}"#, Role::AndroidUpload).ok().unwrap().0);
        let a = app_policy(br#"{"ios":{"bundleId":"example.test","teamId":"ABCDE12345"}}"#, Role::AppleDistribution).ok().unwrap();
        let b = app_policy(br#"{"ios":{"bundleId":"example.test","teamId":"ABCDE12346"}}"#, Role::AppleDistribution).ok().unwrap();
        assert_ne!(a.0, b.0);
        assert!(kind(Role::AppleSigningKey).is_err());
    }
}
