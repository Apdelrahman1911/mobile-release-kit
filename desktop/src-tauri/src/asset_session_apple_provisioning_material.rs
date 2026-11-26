//! Child of the existing selected-Store-material owner. No key import, API
//! credential invention, release consent or private signing-key/CSR capability.
use super::*;
use crate::{
    apple_provisioning_journal::{AccountRef, BundleTarget},
    apple_provisioning_protocol as provisioning,
};

fn selected_target(
    value: &Value,
    context: &provisioning::Context,
) -> Result<BundleTarget, BridgeError> {
    let ios = value
        .get("ios")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let identity = ios
        .get("identityStatus")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    if ios.get("enabled").and_then(Value::as_bool) != Some(true)
        || !matches!(identity, "approved" | "unverified")
    {
        return Err(refused());
    }
    let bundle = ios
        .get("bundleId")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let team = ios
        .get("teamId")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let app = ios.get("appStoreAppId");
    // Empty/missing application selection is DATA, not proof that this is a
    // new app. Register ALSO requires the explicit new-app declaration, the
    // retained original review and the independent native continuity veto.
    let has_app = match app {
        None | Some(Value::Null) => false,
        Some(Value::String(value)) => !value.is_empty(),
        _ => return Err(refused()),
    };
    let existing = identity == "approved" || has_app;
    if context.mode == provisioning::Mode::Register
        && (!context.new_application || identity != "unverified" || existing)
    {
        return Err(refused());
    }
    let target = BundleTarget {
        bundle_id: bundle.into(),
        team_id: team.into(),
        // Initial registration supports only the modern prefix policy. It is
        // never a provider-derived seedId/team assertion or a profile grant.
        app_id_prefix: team.into(),
        display_name: context.display_name.clone(),
        existing_application: existing,
    };
    if !context.accepts_target(&target) {
        return Err(refused());
    }
    Ok(target)
}

fn issuer_bytes(value: &[u8]) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    let mut output = [0u8; 16];
    let mut input = 0usize;
    for byte in &mut output {
        if [8, 13, 18, 23].contains(&input) {
            if value.get(input) != Some(&b'-') {
                return None;
            }
            input += 1;
        }
        *byte = digit(*value.get(input)?)? * 16 + digit(*value.get(input + 1)?)?;
        input += 2;
    }
    if input == value.len() {
        Some(output)
    } else {
        None
    }
}

impl SelectedStoreMaterial {
    /// Review and Register use distinct closed command wrappers, but MUST
    /// borrow the same original selected native context, key and payload.
    /// Matching public record counters alone cannot preserve that loan.
    pub(in crate::asset_session) fn same_provisioning_source(&self, other: &Self) -> bool {
        matches!(&self.command, Some(StoreCommand::Provisioning(_)))
            && matches!(&other.command, Some(StoreCommand::Provisioning(_)))
            && Arc::ptr_eq(&self.native, &other.native)
            && Arc::ptr_eq(&self.payload, &other.payload)
            && self.key == other.key
            && match (&self.key_sources,&other.key_sources) {
                (None,None)=>true,(Some(left),Some(right))=>left.same_selection(right),_=>false
            }
            && match (&self.profile_sources,&other.profile_sources) {
                (None,None)=>true,(Some(left),Some(right))=>left.same_selection(right),_=>false
            }
            && self
                .prepare_document
                .as_ref()
                .zip(other.prepare_document.as_ref())
                .is_some_and(|(left, right)| Weak::ptr_eq(left, right))
    }
    pub(crate) fn accepts_provisioning_consent(&self, input: &provisioning::Start) -> bool {
        matches!(&self.command, Some(StoreCommand::Provisioning(context)) if input.matches_context(context))
    }
    pub(crate) fn provisioning_matches(
        &self,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        matches!(&self.command, Some(StoreCommand::Provisioning(selected)) if selected == context)
            && self.native.registry_generation == registration
            && self.native.project == *root
            && self.native.project_id == context.project_id
            && self.native.revision == context.credential_context_revision
            && self.key.id.0 == context.record_id
            && self.key.revision == context.record_revision
            && self.native.execution_mode == commands::ExecutionMode::Local
            && self.native.platform == Platform::Ios
            && if context.mode.local_key() || context.mode == provisioning::Mode::KeyRecover || context.mode.certificate() || context.mode.p12() { self.native.purpose == Purpose::Provisioning
                && self.native.stage == Stage::Candidate && self.key_sources.is_some() && self.profile_sources.is_none()
            } else if context.mode.profile() { self.key_sources.is_none() && self.native.purpose == Purpose::Provisioning
                && self.native.stage == Stage::Candidate && self.profile_sources.is_some()
            } else { matches!(self.native.purpose, Purpose::Full | Purpose::Store) && self.profile_sources.is_none() && self.key_sources.is_none() }
    }
    fn provisioning_document_matches(
        &self,
        document: &Arc<Inner>,
        state: &DocumentState,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        self.provisioning_matches(context, registration, root)
            && self
                .prepare_document
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|held| Arc::ptr_eq(&held, document))
            && !state.lost_observed
            && !state.compatibility_picker_pending
            && self.current(state, registration, root)
            && document.bridge.registry_generation() == registration
            && document
                .bridge
                .native_project(&context.project_id)
                .is_ok_and(|(generation, current)| generation == registration && current == *root)
    }
    /// Only public account digest and selected target leave this owner. The
    /// actual P8/key-ID/issuer byte loans stay in the original private writer.
    pub(crate) fn provisioning_account_target(
        &self,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(AccountRef, BundleTarget), BridgeError> {
        if !self.provisioning_matches(context, registration, root) {
            return Err(refused());
        }
        let descriptor = self.context_data()?;
        if descriptor.bytes != context.saved_config.bytes
            || descriptor.sha256 != context.saved_config.sha256
        {
            return Err(refused());
        }
        let (_, _, issuer) = apple_parts(&self.payload).ok_or_else(refused)?;
        let account = AccountRef::from_selected_issuer(issuer_bytes(issuer).ok_or_else(refused)?);
        let config = crate::protocol::strict_json(&self.native.draft).map_err(|_| refused())?;
        let target = selected_target(&config, context)?;
        Ok((account, target))
    }
    pub(crate) fn provisioning_context_data(
        &self,
    ) -> Result<crate::android_build_protocol::Content, BridgeError> {
        if !matches!(&self.command, Some(StoreCommand::Provisioning(_))) {
            return Err(refused());
        }
        let content = self.context_data()?;
        Ok(crate::android_build_protocol::Content {
            bytes: content.bytes,
            sha256: content.sha256,
        })
    }
    pub(in crate::asset_session) fn provisioning_current_locked(
        &self,
        document: &Arc<Inner>,
        state: &DocumentState,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> bool {
        self.provisioning_document_matches(document, state, context, registration, root)
    }
}

impl DocumentBinding {
    pub(in crate::asset_session) fn review_apple_provisioning_material(
        &self,
        state: &DocumentState,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<Arc<SelectedStoreMaterial>, BridgeError> {
        if !cfg!(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )) || !self.native_qualified()
            || encrypted_mode(state) && !self.persistence_qualified()
        {
            return Err(refused());
        }
        if context.mode.local_key() || context.mode == provisioning::Mode::KeyRecover || context.mode.certificate() || context.mode.p12() { return super::apple_key::borrow(self, state, context, registration, root); }
        if context.mode.profile() {
            return super::apple_profile::borrow(self, state, context, registration, root);
        }
        let mut material = borrow_selected_material(
            state,
            commands::RecordRef {
                record_id: &context.record_id,
                expected_revision: context.record_revision,
            },
            context.credential_context_revision,
            Some(StoreCommand::Provisioning(context.clone())),
        )?;
        Arc::get_mut(&mut material)
            .ok_or_else(refused)?
            .prepare_document = Some(Arc::downgrade(&self.inner));
        if !material.provisioning_document_matches(&self.inner, state, context, registration, root)
        {
            return Err(refused());
        }
        material.parts()?;
        Ok(material)
    }
    pub(in crate::asset_session) fn recheck_apple_provisioning_material(
        &self,
        state: &DocumentState,
        material: &Arc<SelectedStoreMaterial>,
        context: &provisioning::Context,
        registration: u32,
        root: &asset_source::RegisteredRoot,
    ) -> Result<(), BridgeError> {
        if !cfg!(all(
            target_os = "macos",
            target_pointer_width = "64",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )) || !self.native_qualified()
            || encrypted_mode(state) && !self.persistence_qualified()
            || !material.provisioning_document_matches(
                &self.inner,
                state,
                context,
                registration,
                root,
            )
        {
            return Err(refused());
        }
        if context.mode == provisioning::Mode::KeyRecover || context.mode.certificate() || context.mode.p12() { apple_parts(&material.payload).ok_or_else(refused)?; } else { material.parts()?; }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn context(mode: &str) -> provisioning::Context {
        provisioning::prepare(&json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,"executionMode":"local","platform":"ios",
            "mode":mode,"reference":if mode == "review" { Value::Null } else { json!({"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32)}) },
            "newApplication":mode == "register","displayName":"Explicit name"})).unwrap().context
    }
    fn config() -> Value {
        json!({"ios":{"enabled":true,"bundleId":"com.example.fixture","teamId":"TESTTEAM01",
        "identityStatus":"unverified","appStoreAppId":""}})
    }
    #[test]
    fn pure_target_comparison_requires_unverified_saved_identity_and_exact_explicit_label() {
        let context = context("register");
        let target = selected_target(&config(), &context).unwrap();
        assert_eq!(target.display_name, "Explicit name");
        assert!(!target.existing_application);
        for (field, value) in [
            ("identityStatus", json!("approved")),
            ("identityStatus", json!("blocked")),
            ("identityStatus", Value::Null),
            ("appStoreAppId", json!("12345")),
            ("appStoreAppId", json!(12345)),
            ("enabled", json!(false)),
            ("enabled", json!("true")),
            ("bundleId", json!("*")),
            ("teamId", json!("lowercase")),
        ] {
            let mut value_config = config();
            value_config["ios"][field] = value;
            assert!(selected_target(&value_config, &context).is_err(), "{field}");
        }
        let mut value = config();
        value["ios"]["identityStatus"] = json!("approved");
        assert!(
            selected_target(&value, &self::context("review"))
                .unwrap()
                .existing_application
        );
    }
    #[test]
    fn same_decoded_issuer_not_key_id_or_project_selects_account_namespace() {
        let lower = issuer_bytes(b"aabbccdd-0102-0304-0506-0708090a0b0c").unwrap();
        let upper = issuer_bytes(b"AABBCCDD-0102-0304-0506-0708090A0B0C").unwrap();
        assert_eq!(lower, upper);
        assert!(AccountRef::from_selected_issuer(lower) == AccountRef::from_selected_issuer(upper));
        for bad in [
            b"aabbccdd_0102-0304-0506-0708090a0b0c".as_slice(),
            b"aabbccdd-0102-0304-0506-0708090a0b0g".as_slice(),
            b"".as_slice(),
        ] {
            assert!(issuer_bytes(bad).is_none());
        }
    }
}
