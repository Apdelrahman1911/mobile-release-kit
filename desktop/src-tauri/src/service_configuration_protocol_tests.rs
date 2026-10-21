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
