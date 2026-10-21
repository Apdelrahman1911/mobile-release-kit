//! cfg(test) only, inert original-object memory inputs. No registered root,
//! returned saved lane, NativeUse, file, process or provider is constructed.
use super::*;

impl AppleProvisioningDocumentInput {
    pub(crate) fn census_context(mode: wire::Mode) -> wire::Context {
        use serde_json::json;
        let mut value = json!({"projectId":"memory-data","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"version.properties","bytes":25,"sha256":"b".repeat(64),"name":"1.2.3","build":2},
            "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,
            "executionMode":"local","platform":"ios","mode":mode,
            "reference":null,"newApplication":false,"displayName":"Inert memory comparison"});
        if mode.profile() || mode.p12() {
            value["p12RecordId"] = json!("d".repeat(32));
            value["p12RecordRevision"] = json!(1);
        }
        if mode.certificate() || mode.p12() || mode == wire::Mode::KeyRecover {
            value["keyRecordId"] = json!("e".repeat(32));
            value["keyRecordRevision"] = json!(1);
        }
        // Fixtures deliberately use only review/KeyRecover: no write consent.
        assert!(matches!(
            mode,
            wire::Mode::Review
                | wire::Mode::ProfileReview
                | wire::Mode::KeyReview
                | wire::Mode::KeyRecover
                | wire::Mode::CertificateReview
                | wire::Mode::P12Review
        ));
        wire::prepare(&value).unwrap().context
    }

    pub(crate) fn census_data(
        context: wire::Context,
        material: Arc<SelectedStoreMaterial>,
        state: Arc<NativeStateReady>,
        original: Option<Arc<OriginalWork>>,
    ) -> Arc<Self> {
        let (profile, key) = if context.mode.profile() {
            (original, None)
        } else if context.mode.key() {
            (None, original)
        } else {
            assert!(original.is_none());
            (None, None)
        };
        let value = Arc::new(Self {
            document: Weak::new(),
            registration: 0,
            root: asset_source::RegisteredRoot {
                path: "/never-registered-apple-census".into(),
                identity: asset_source::ProjectIdentity::Windows {
                    volume: 0,
                    file_id: [0; 16],
                },
            },
            saved: AppleProvisioningSavedInput::unreturned_census_data(),
            material,
            state,
            account: AccountRef::from_selected_issuer([0; 16]),
            target: BundleTarget {
                bundle_id: "invalid.memory.data".into(),
                team_id: "0000000000".into(),
                app_id_prefix: "0000000000".into(),
                display_name: context.display_name.clone(),
                existing_application: false,
            },
            context,
            profile_asset: Mutex::new(profile),
            key_asset: Mutex::new(key),
        });
        assert!(value.current().is_err());
        assert!(value.ready().begin_use().is_err());
        value
    }
}

#[test]
fn input_census_never_treats_contended_poisoned_or_dual_assets_as_absence() {
    let context = AppleProvisioningDocumentInput::census_context(wire::Mode::KeyReview);
    let material = SelectedStoreMaterial::apple_census_data(&context, 32, 32, 0);
    let input = AppleProvisioningDocumentInput::census_data(
        context,
        material,
        NativeStateReady::closed_apple_census_data(),
        None,
    );
    assert!(input.census_assets().unwrap().iter().all(Option::is_none));
    let guard = input.key_asset.lock().unwrap();
    assert!(input.census_assets().is_err());
    drop(guard);
    let first = OriginalWork::new(1, false, Weak::new());
    *input.key_asset.lock().unwrap() = Some(first.clone());
    assert!(Arc::ptr_eq(
        input.census_assets().unwrap()[1].as_ref().unwrap(),
        &first
    ));
    *input.profile_asset.lock().unwrap() = Some(first);
    assert!(input.census_assets().is_err());
    input.profile_asset.lock().unwrap().take();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = input.key_asset.lock().unwrap();
        panic!("inert census mutex poison");
    }));
    assert!(input.census_assets().is_err());
    assert!(input.current().is_err() && input.ready().begin_use().is_err());
}
