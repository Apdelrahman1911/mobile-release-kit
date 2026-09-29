// DATA grammar/correlation tests, not installed runtime or filesystem qualification.
use super::*;
use serde_json::json;
fn row(kind: &str, id: &str, path: Option<String>, locale: Option<&str>, required: bool) -> Value {
    json!({"kind":kind,"id":id,"path":path,"locale":locale,"required":required,"state":"checked","issues":[]})
}
fn fixture(platform: Platform) -> Value {
    let root = "release/metadata";
    let mut files = Vec::new();
    for locale in ["en-US", "fr-FR"] {
        for id in platform.ids() {
            files.push(row("public-text", id.name(), Some(format!("{root}/{}/{locale}/{}", platform.name(), id.name())), Some(locale), true));
        }
        if platform == Platform::Android {
            files.push(row("android-note", "release-notes", Some(format!("{root}/android/{locale}/changelogs/42.txt")), Some(locale), true));
        }
    }
    if platform == Platform::Ios {
        for name in IOS_NOTES {
            files.push(row("ios-note", name.rsplit('/').next().unwrap(), Some(format!("{root}/{name}")), None, true));
        }
    }
    json!({"schemaVersion":1,"platform":platform,"metadataRoot":root,"locales":["en-US","fr-FR"],
        "androidBuild":if platform == Platform::Android { Some(42) } else { None },
        "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"scope":"configured-locales-canonical-images-fixed-notes",
        "observationScope":"single-request-non-atomic","valid":true,"state":"checked","files":files,"imageSets":[],
        "assurance":{"basis":"static-text","projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,
            "gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"}})
}
#[test]
fn renderer_request_is_only_a_registered_project_and_one_platform() {
    assert!(request(&json!({"projectId":"project-1","platform":"android"})).is_ok());
    for key in ["root","path","metadataRoot","locale","locales","draft","policy","content","credentials"] {
        let mut value = json!({"projectId":"project-1","platform":"ios"}); value[key] = Value::Null;
        assert!(request(&value).is_err());
    }
    for value in [json!({}), json!({"projectId":"../root","platform":"android"}), json!({"projectId":"p","platform":"both"})] {
        assert!(request(&value).is_err());
    }
}
#[test]
fn report_requires_every_locale_required_field_and_fixed_note() {
    for platform in [Platform::Android, Platform::Ios] {
        let good = fixture(platform);
        assert!(result(good.clone(), platform).is_ok());
        for index in 0..good["files"].as_array().unwrap().len() {
            let mut bad = good.clone(); bad["files"].as_array_mut().unwrap().remove(index);
            assert!(result(bad, platform).is_err(), "required row {index}");
        }
        let mut duplicate = good.clone();
        duplicate["files"].as_array_mut().unwrap().push(good["files"][0].clone());
        assert!(result(duplicate, platform).is_err());
        let mut missing = good.clone();
        missing["files"][0]["state"] = json!("missing"); missing["files"][0]["issues"] = json!(["metadata.missing"]);
        assert!(result(missing.clone(), platform).is_err()); // cannot retain a green headline
        missing["state"] = json!("issues"); missing["valid"] = json!(false);
        assert!(result(missing, platform).is_ok());
        assert!(result(good, if platform == Platform::Android { Platform::Ios } else { Platform::Android }).is_err());
    }
}
#[test]
fn no_omitted_nullable_keys_contents_or_private_targets_are_admitted() {
    let good = fixture(Platform::Ios);
    for key in ["androidBuild", "savedConfig", "assurance", "locales"] {
        let mut bad = good.clone(); bad.as_object_mut().unwrap().remove(key);
        assert!(result(bad, Platform::Ios).is_err());
    }
    for key in ["path", "locale"] {
        let mut bad = good.clone(); bad["files"][0].as_object_mut().unwrap().remove(key);
        assert!(result(bad, Platform::Ios).is_err());
    }
    let index = good["files"].as_array().unwrap().len() - 1;
    for key in ["text", "sha256", "bytes", "characterCount", "summary"] {
        let mut bad = good.clone(); bad["files"][index][key] = json!("inert-do-not-echo");
        assert!(result(bad, Platform::Ios).is_err());
    }
    for path in ["release/metadata/review/contact.json", "../notes.txt", "release/metadata/testflight/demo-password.txt"] {
        let mut bad = good.clone(); bad["files"][index]["path"] = json!(path);
        assert!(result(bad, Platform::Ios).is_err());
    }
    for (key, value) in [("credentialsRead", json!(true)), ("releaseReadiness", json!("ready")), ("basis", json!("visual-inspection"))] {
        let mut bad = good.clone(); bad["assurance"][key] = value;
        assert!(result(bad, Platform::Ios).is_err());
    }
}
#[test]
fn invalid_android_version_is_explicit_for_all_locales() {
    let mut value = fixture(Platform::Android); value["androidBuild"] = Value::Null;
    assert!(result(value.clone(), Platform::Android).is_err());
    for row in value["files"].as_array_mut().unwrap() {
        if row["kind"] == "android-note" {
            row["path"] = Value::Null; row["state"] = json!("invalid"); row["issues"] = json!(["metadata.android-version"]);
        }
    }
    value["valid"] = json!(false); value["state"] = json!("issues");
    assert!(result(value.clone(), Platform::Android).is_ok());
    value["files"][3]["path"] = json!("release/metadata/android/en-US/changelogs/default.txt");
    assert!(result(value, Platform::Android).is_err());
}
#[test]
fn optional_images_still_require_canonical_paths_exact_groups_and_counts() {
    let mut value = fixture(Platform::Android);
    value["files"].as_array_mut().unwrap().push(row("image", "icon", Some("release/metadata/android/en-US/images/icon.png".into()), Some("en-US"), false));
    assert!(result(value.clone(), Platform::Android).is_err());
    value["imageSets"] = json!([{"locale":"en-US","id":"icon","count":1,"required":false,"issues":[]}]);
    assert!(result(value.clone(), Platform::Android).is_ok());
    let mut bad = value.clone(); bad["imageSets"][0]["count"] = json!(2);
    assert!(result(bad, Platform::Android).is_err());
    let mut bad = value.clone(); bad["files"][8]["path"] = json!("release/metadata/android/en-US/images/ICON.png");
    assert!(result(bad, Platform::Android).is_err());
    value["files"].as_array_mut().unwrap().push(row("image", "icon", Some("release/metadata/android/en-US/images/icon.jpg".into()), Some("en-US"), false));
    value["imageSets"][0]["count"] = json!(2); value["imageSets"][0]["issues"] = json!(["image.count"]);
    value["valid"] = json!(false); value["state"] = json!("issues");
    assert!(result(value.clone(), Platform::Android).is_ok());
    value["files"][9]["state"] = json!("invalid"); value["files"][9]["issues"] = json!(["image.duplicate"]);
    assert!(result(value.clone(), Platform::Android).is_err());
    value["imageSets"][0]["issues"] = json!(["image.count","image.duplicate"]);
    assert!(result(value, Platform::Android).is_ok());
}
#[test]
fn image_names_and_case_aliases_cannot_invent_a_complete_scope() {
    let folder = "release/metadata/android/en-US/images/phoneScreenshots";
    let mut good = fixture(Platform::Android);
    good["files"].as_array_mut().unwrap().push(row("image", "phoneScreenshots", Some(format!("{folder}/shot.png")), Some("en-US"), false));
    good["imageSets"] = json!([{"locale":"en-US","id":"phoneScreenshots","count":1,"required":false,"issues":[]}]);
    assert!(result(good.clone(), Platform::Android).is_ok());
    for name in ["-shot.png", "shot..png", "shot+.png", "é.png", "CON.png"] {
        let mut bad = good.clone(); bad["files"][8]["path"] = json!(format!("{folder}/{name}"));
        assert!(result(bad, Platform::Android).is_err());
    }
    let mut alias = good.clone();
    alias["files"].as_array_mut().unwrap().push(row("image", "phoneScreenshots", Some(format!("{folder}/SHOT.png")), Some("en-US"), false));
    alias["imageSets"][0]["count"] = json!(2);
    assert!(result(alias, Platform::Android).is_err());
    let mut text_alias = fixture(Platform::Android);
    text_alias["files"].as_array_mut().unwrap().push(row("public-text", "TITLE.txt",
        Some("release/metadata/android/en-US/TITLE.txt".into()), Some("en-US"), false));
    assert!(result(text_alias, Platform::Android).is_err());
}
#[test]
fn error_envelope_is_fixed_redacted_bounded_and_domain_specific() {
    for (code, message) in PASSIVE_ERRORS {
        let bytes = format!("{}\n", json!({"protocol":1,"id":"q","ok":false,"error":{"code":code,"message":message,"retryable":false}}));
        let error = decode_envelope(bytes.as_bytes(), "q").unwrap_err();
        assert_eq!(error, BridgeError::new(code, message));
        let bad = format!("{}\n", json!({"protocol":1,"id":"q","ok":false,"error":{"code":code,"message":"inert-sensitive-exception","retryable":false}}));
        assert_eq!(decode_envelope(bad.as_bytes(), "q").unwrap_err(), BridgeError::protocol());
    }
    let bytes = format!("{}\n", json!({"protocol":1,"id":"q","ok":true,"result":fixture(Platform::Ios)}));
    assert!(decode_envelope(bytes.as_bytes(), "q").is_ok());
    assert!(decode_envelope(bytes.as_bytes(), "other").is_err());
    assert!(decode_envelope(&vec![b' '; RESPONSE_LIMIT + 1], "q").is_err());
    assert!(decode_envelope(br#"{"protocol":1,"protocol":1,"id":"q","ok":true,"result":{}}\n"#, "q").is_err());
}
#[test]
fn one_named_command_has_exact_build_acl_handler_parity_and_original_owner() {
    let command = "metadata_validate";
    assert!(include_str!("../build.rs").contains(&format!("\"{command}\"")));
    assert!(include_str!("../capabilities/main.json").contains("\"allow-metadata-validate\""));
    let shell = include_str!("shell.rs");
    assert!(shell.contains("async fn metadata_validate("));
    assert!(shell.split("tauri::generate_handler![").nth(1).unwrap().contains(command));
    let bridge = include_str!("bridge.rs");
    let method = bridge.split("async fn validate_metadata(").nth(1).unwrap().split("async fn observe_metadata_text(").next().unwrap();
    assert!(method.contains("self.project_root(&input.project_id)?"));
    assert!(method.contains("document.passive_query(self, Method::MetadataValidate"));
    assert!(!method.contains("spawn") && !method.contains("Command::"));
}

#[test]
fn all_locales_cross_the_exact_python_frame_without_widening_other_profiles() {
    // Python's transport test requires encode_response to equal this shared
    // synthetic byte fixture. No engine, subprocess or native path runs here.
    let frame = include_bytes!("../../../tests/desktop/fixtures/metadata-validation-250-locales-response.json");
    let value = decode_envelope(frame, "metadata-large").expect("bounded metadata envelope");
    assert!(frame.len() <= RESPONSE_LIMIT);
    assert!(protocol::decode_response(frame, "metadata-large").is_err());
    assert!(protocol::check_value(&value).is_err());
    assert!(value_bounds(&value, 12, RESULT_LIMIT).is_err());
    let report = result(value.clone(), Platform::Ios).expect("all configured missing rows");
    assert_eq!(report.locales.len(), 250);
    assert_eq!(report.files.len(), 1253);
    assert!(!report.valid && report.state == State::Issues);
    assert!(report.files.iter().all(|row| row.state == FileState::Missing));
    assert_eq!(serde_json::to_value(report).unwrap(), value);
    // The old workflow ceiling remains 8000, independently of ordinary20k.
    let old_over = Value::Array(vec![Value::Null; 8_000]);
    assert!(protocol::check_value(&old_over).is_ok());
    assert!(value_bounds(&old_over, 12, RESULT_LIMIT).is_err());
    assert_eq!(protocol::NODE_LIMIT, 20_000);
    assert_eq!(RESULT_NODE_LIMIT, 32_768);
    let at_limit = Value::Array(vec![Value::Null; RESULT_NODE_LIMIT - 1]);
    assert!(protocol::check_metadata_validation_result(&at_limit).is_ok());
    let exact_frame = format!("{}\n", json!({"protocol":1,"id":"q","ok":true,"result":at_limit}));
    let decoded = decode_envelope(exact_frame.as_bytes(), "q").expect("eight envelope nodes reserved");
    assert!(result(decoded, Platform::Ios).is_err()); // no DTO shape widening
    let over = Value::Array(vec![Value::Null; RESULT_NODE_LIMIT]);
    assert!(protocol::check_metadata_validation_result(&over).is_err());
    let bad_frame = format!("{}\n", json!({"protocol":1,"id":"q","ok":true,"result":over}));
    assert!(decode_envelope(bad_frame.as_bytes(), "q").is_err());
    let mut nested = Value::Null;
    for _ in 0..RESULT_DEPTH_LIMIT { nested = json!([nested]); }
    let depth_frame = format!("{}\n", json!({"protocol":1,"id":"q","ok":true,"result":nested.clone()}));
    assert!(decode_envelope(depth_frame.as_bytes(), "q").is_ok());
    let deep_frame = format!("{}\n", json!({"protocol":1,"id":"q","ok":true,"result":[nested]}));
    assert!(decode_envelope(deep_frame.as_bytes(), "q").is_err());
}
