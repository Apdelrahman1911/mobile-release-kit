use super::*;
use serde_json::json;
fn base() -> Value {
    json!({"schemaVersion":1,"source":{"candidateBranch":"main","productionBranch":"production","repository":"owner/private"},
 "android":{"enabled":true,"module":":app","variant":"release","applicationId":"example.app"},"ios":{"enabled":true,"project":"App.xcodeproj","scheme":"App","archiveConfiguration":"Release","bundleId":"example.app"},
 "commands":{"private":"never projected"},"version":{"mode":"manual"},"credentials":{"sentinel":"never projected"}})
}
#[test]
fn closed_groups_preserve_unselected_and_forbidden_fields_without_exporting_them() {
    let original = base();
    for change in [
        Change::Source {
            candidate_branch: "candidate".into(),
            production_branch: "release".into(),
        },
        Change::Android {
            module: ":mobile".into(),
            variant: "debug".into(),
        },
        Change::Ios {
            container: Container::Workspace("App.xcworkspace".into()),
            scheme: "Mobile".into(),
            archive_configuration: "Archive".into(),
        },
    ] {
        let next = change.derive(&original).unwrap();
        for key in ["commands", "credentials", "version"] {
            assert_eq!(next[key], original[key]);
        }
        assert_eq!(
            next["android"]["applicationId"],
            original["android"]["applicationId"]
        );
        assert_eq!(next["ios"]["bundleId"], original["ios"]["bundleId"]);
        let bytes = serde_json::to_string(&Settings::from_base(&next).unwrap()).unwrap();
        for forbidden in [
            "credentials",
            "sentinel",
            "commands",
            "never projected",
            "applicationId",
            "bundleId",
            "repository",
        ] {
            assert!(!bytes.contains(forbidden));
        }
        if matches!(change, Change::Ios { .. }) {
            assert!(next["ios"].get("project").is_none());
            assert_eq!(next["ios"]["workspace"], "App.xcworkspace");
        }
    }
    assert_eq!(original, base());
}
#[test]
fn change_grammar_rejects_identity_enabled_commands_and_unbounded_or_unsafe_containers() {
    for value in [
        json!({"kind":"identity","applicationId":"other"}),
        json!({"kind":"android","module":":app","variant":"release","enabled":true}),
        json!({"kind":"source","candidateBranch":"main","productionBranch":"production","commands":{}}),
        json!({"kind":"ios","container":{"kind":"project","path":"../App.xcodeproj"},"scheme":"App","archiveConfiguration":"Release"}),
        json!({"kind":"source","candidateBranch":"main\nsecret","productionBranch":"prod"}),
    ] {
        assert!(serde_json::from_value::<Change>(value).map_or(true, |c| c.validate().is_err()));
    }
    let mut disabled = base();
    disabled["android"]["enabled"] = json!(false);
    assert!(Change::Android {
        module: ":app".into(),
        variant: "release".into()
    }
    .derive(&disabled)
    .is_err());
}
#[test]
fn required_nullable_projection_fields_keep_missing_and_wrong_type_distinct() {
    let settings = Settings::from_base(&base()).unwrap();
    let value = serde_json::to_value(&settings).unwrap();
    let mut null = value.clone();
    null["android"] = Value::Null;
    null["ios"] = Value::Null;
    assert!(serde_json::from_value::<Settings>(null)
        .unwrap()
        .validate()
        .is_ok());
    for path in ["android", "ios"] {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(path);
        assert!(serde_json::from_value::<Settings>(bad).is_err());
    }
    let mut missing = value.clone();
    missing["android"].as_object_mut().unwrap().remove("module");
    assert!(serde_json::from_value::<Settings>(missing).is_err());
    let mut scalar = value;
    scalar["ios"]["container"] = json!(3);
    assert!(serde_json::from_value::<Settings>(scalar).is_err());
}
#[test]
fn full_derivation_is_bounded_before_clone_and_does_not_reset_the_original() {
    let change = Change::Source {
        candidate_branch: "next".into(),
        production_branch: "production".into(),
    };
    let mut many = base();
    many["retained"] = Value::Array((0..4096).map(|_| json!({"k":{}})).collect());
    assert!(serde_json::to_vec(&many).unwrap().len() < 256 * 1024);
    assert!(change.derive(&many).is_err());
    assert_eq!(many["retained"].as_array().unwrap().len(), 4096);
    let mut bytes = base();
    bytes["retained"] = json!("x".repeat(256 * 1024));
    assert!(change.derive(&bytes).is_err());
    assert_eq!(bytes["retained"].as_str().unwrap().len(), 256 * 1024);
    let mut deep = json!(0);
    for _ in 0..21 {
        deep = json!([deep]);
    }
    let mut original = base();
    original["retained"] = deep;
    assert!(change.derive(&original).is_err());
    assert!(change.derive(&base()).is_ok());
}
#[test]
fn final_combinations_never_invent_a_saved_configuration() {
    let mut value = Final {
        effect: Effect::Committed,
        journal: Journal::Clean,
        cancelled: false,
        apply_submitted: true,
    };
    assert!(value.saved());
    value.apply_submitted = false;
    assert!(!value.saved());
    value.apply_submitted = true;
    value.cancelled = true;
    assert!(!value.saved());
    value.cancelled = false;
    value.journal = Journal::RecoveryRequired;
    assert!(!value.saved());
    value.effect = Effect::Unchanged;
    value.journal = Journal::Clean;
    assert!(!value.saved());
    value.journal = Journal::NotCreated;
    assert!(value.saved());
}

fn metadata_base() -> Value {
    let mut value = base();
    value["metadata"] =
        json!({"root":"store/metadata","androidLocales":["en-US"],"iosLocales":["en"]});
    value
}
fn metadata_change() -> Change {
    serde_json::from_value(json!({"kind":"metadata","root":"store/資料","androidLocales":["fr","zh-Hant-TW","es-419"],"iosLocales":["en"]})).unwrap()
}
#[test]
fn metadata_change_reuses_original_derivation_without_other_fields_or_asset_authority() {
    let before = metadata_base();
    let change = metadata_change();
    let after = change.derive(&before).unwrap();
    for key in before
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| k.as_str() != "metadata")
    {
        assert_eq!(after[key], before[key]);
    }
    assert_eq!(before, metadata_base());
    assert_eq!(
        after["metadata"]["androidLocales"],
        json!(["fr", "zh-Hant-TW", "es-419"])
    );
    let raw = serde_json::to_vec(&change).unwrap();
    assert!(raw.len() <= CHANGE_BYTES);
    let decoded: Change = serde_json::from_slice(&raw).unwrap();
    assert_eq!(decoded, change);
    for bad in [
        json!({"kind":"metadata","root":"x","androidLocales":[],"iosLocales":[],"enabled":false}),
        json!({"kind":"metadata","root":"x","androidLocales":null,"iosLocales":[]}),
        json!({"kind":"metadata","root":"x","androidLocales":[]}),
    ] {
        assert!(serde_json::from_value::<Change>(bad).is_err());
    }
}
#[test]
fn metadata_root_and_locale_grammar_match_core_enabled_and_disabled_platform_policy() {
    for root in ["store/資料", " store ", "store/meta:data", "\u{feff}"] {
        assert!(metadata_root(root));
    }
    assert!(metadata_root(&format!("{}listing", "a/".repeat(20))));
    assert!(metadata_root(&"😀".repeat(512)));
    for root in [
        "",
        " ",
        "\u{85}",
        "\u{1c}",
        "\u{3000}",
        "../listing",
        "/listing",
        "C:listing",
        "store//listing",
        "store/./listing",
        "store/../listing",
        "store\\listing",
        "store/",
        "bad\nname",
        "bad\rname",
        "bad\0name",
    ] {
        assert!(!metadata_root(root), "{root:?}");
    }
    assert!(!metadata_root(&"a".repeat(513)));
    for value in [
        "en",
        "eng",
        "zh-Hant",
        "zh-Hant-TW",
        "es-419",
        "abc-Latn-001",
    ] {
        assert!(locale(value));
    }
    for value in [
        "EN",
        "en-us",
        "en_US",
        "en-US-extra",
        "en\n",
        "e",
        "abcd",
        "en-",
        "en-Latn-",
    ] {
        assert!(!locale(value));
    }
    let empty: Change = serde_json::from_value(
        json!({"kind":"metadata","root":"listing","androidLocales":[],"iosLocales":[]}),
    )
    .unwrap();
    assert!(empty.validate().is_ok()); // Shape is not an enabled-platform claim.
    assert!(empty.derive(&metadata_base()).is_err());
    let mut disabled = metadata_base();
    disabled["android"]["enabled"] = json!(false);
    disabled["ios"]["enabled"] = json!(false);
    let next = empty.derive(&disabled).unwrap();
    assert_eq!(next["android"], disabled["android"]);
    assert_eq!(next["ios"], disabled["ios"]);
    assert_eq!(next["metadata"]["androidLocales"], json!([]));
    let both = json!({"root":"listing","androidLocales":(0..17).map(|n|format!("en-{n:03}")).collect::<Vec<_>>(),"iosLocales":(0..16).map(|n|format!("en-{n:03}")).collect::<Vec<_>>()});
    assert!(Metadata::from_value(&both, true, true).is_none());
}
#[test]
fn metadata_omission_preserves_old_groups_without_inventing_a_new_before_image() {
    let many: Vec<_> = (0..33).map(|n| format!("en-{n:03}")).collect();
    for metadata in [
        Value::Null,
        json!({"root":"listing","androidLocales":["en"],"iosLocales":["en"],"unknown":true}),
        json!({"root":"listing","androidLocales":many,"iosLocales":["en"]}),
        json!({"root":"😀".repeat(512),"androidLocales":["en"],"iosLocales":["en"]}),
    ] {
        let mut old = metadata_base();
        old["metadata"] = metadata;
        let settings = Settings::from_base(&old).unwrap();
        assert!(settings.metadata.is_none());
        assert!(serde_json::to_value(&settings)
            .unwrap()
            .get("metadata")
            .is_none());
        for change in [
            Change::Source {
                candidate_branch: "next".into(),
                production_branch: "production".into(),
            },
            Change::Android {
                module: ":mobile".into(),
                variant: "release".into(),
            },
            Change::Ios {
                container: Container::Workspace("App.xcworkspace".into()),
                scheme: "App".into(),
                archive_configuration: "Release".into(),
            },
        ] {
            let next = change.derive(&old).unwrap();
            assert_eq!(next["metadata"], old["metadata"]);
        }
        assert!(metadata_change().derive(&old).is_err());
    }
    let old = serde_json::to_value(Settings::from_base(&base()).unwrap()).unwrap();
    assert!(serde_json::from_value::<Settings>(old.clone()).is_ok());
    for bad in [
        Value::Null,
        json!({}),
        json!({"root":"listing","androidLocales":[],"iosLocales":[],"unknown":true}),
    ] {
        let mut value = old.clone();
        value["metadata"] = bad;
        assert!(serde_json::from_value::<Settings>(value).is_err());
    }
}
#[test]
fn metadata_status_requires_exact_paired_review_not_a_legacy_or_foreign_projection() {
    let before = metadata_base();
    let change = metadata_change();
    let after = change.derive(&before).unwrap();
    let origin = json!({"serviceInstance":"1".repeat(32),"projectId":"2".repeat(32),"requestId":"3".repeat(32)});
    let original = json!({"sessionId":"4".repeat(32),"ownerGeneration":"5".repeat(32),"revision":"6".repeat(32)});
    let value = json!({"schemaVersion":1,"origin":origin,"revision":1,"runtimeProjectId":"project-a","phase":"reviewing","operationId":"4".repeat(32),"ownerGeneration":"5".repeat(32),"original":original,
        "settings":Settings::from_base(&before).unwrap(),"change":change,"review":{"planToken":"7".repeat(32),"nativeStatusRevision":5,"before":Settings::from_base(&before).unwrap(),"after":Settings::from_base(&after).unwrap(),
        "files":[{"path":"release/mobile-release.json","action":"replace","beforeBytes":240,"afterBytes":260},{"path":".gitignore","action":"preserve","beforeBytes":130,"afterBytes":130}],"createReleaseDirectory":false,"rewritesConfigFormatting":true,"ignoreAdditions":[]},
        "permissionLive":false,"remainingMs":0,"applyConsumed":false,"cancelRequested":false,"result":null,"doNotReplay":true});
    let good: Status = serde_json::from_value(value.clone()).unwrap();
    assert!(good.validate().is_ok());
    for field in ["before", "after"] {
        let mut bad = value.clone();
        bad["review"][field]
            .as_object_mut()
            .unwrap()
            .remove("metadata");
        assert!(serde_json::from_value::<Status>(bad)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut bad = value.clone();
    bad["review"]["after"]["source"]["candidateBranch"] = json!("foreign");
    assert!(serde_json::from_value::<Status>(bad)
        .unwrap()
        .validate()
        .is_err());
    let mut bad = value;
    bad["review"]["after"]["metadata"]["root"] = json!("foreign");
    assert!(serde_json::from_value::<Status>(bad)
        .unwrap()
        .validate()
        .is_err());
}
