//! Inert protocol/finality DATA only; no picker, filesystem or child execution.
use super::*;

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REVISION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PLAN: &str = "cccccccccccccccccccccccccccccccc";
const PATH: &str = "public/store/android/en-US/images/phoneScreenshots/01.png";

fn identity() -> RegisteredIdentity {
    RegisteredIdentity::deserialize(json!({"device":"1","inode":"2","mode":16832,"uid":1000,"gid":1000})).unwrap()
}
fn original() -> ImportData {
    ImportData { context: Context { platform:Platform::Android,locale:"en-US".into(),asset_type:"phoneScreenshots".into() },
        images:vec![SelectedImageData { item_id:SESSION.into(),display_name:"01.png".into(),bytes:b"M".to_vec(),sha256:digest(b"M") }],
        protected_sources:Vec::new(),protected_objects:vec![SourceObject { device:"1".into(),inode:"7".into() }] }
}
fn baseline() -> Baseline {
    Baseline { config:ContentDigest { byte_length:2,sha256:"1".repeat(64) },ignore:ContentDigest { byte_length:0,sha256:"2".repeat(64) },inventory_sha256:"3".repeat(64) }
}
fn summary(hash: &str) -> Value {
    json!({"byteLength":1,"sha256":hash,"format":"png","width":1,"height":1,"headerChecked":true})
}
fn import_fixture(existing: bool, identical: bool, replace: bool) -> Value {
    let selected = summary(&digest(b"M"));
    let before = if existing { if identical { selected.clone() } else { summary(&"4".repeat(64)) } } else { Value::Null };
    let action = if !existing { "create" } else if replace && !identical { "replace" } else { "preserve" };
    json!({"kind":"import","policy":"metadata-images-v1","platform":"android","locale":"en-US","assetType":"phoneScreenshots",
        "metadataRoot":"public/store","folder":"public/store/android/en-US/images/phoneScreenshots",
        "files":[{"itemId":SESSION,"displayName":"01.png","path":PATH,"action":action,"before":before,"selected":selected,
            "after":if action == "preserve" { before.clone() } else { selected.clone() },"canReplace":existing && !identical,"issues":[]}],
        "existing":if existing { json!([{"path":PATH,"summary":before}]) } else { json!([]) },"finalOrder":[PATH],"valid":true,"issues":[],
        "assurance":{"localCopyOnly":true,"sourceFilesUnchanged":true,"storeContacted":false,"fullDecode":false,"contentApproved":false,"storeAccepted":false}})
}
pub(crate) fn recovery_fixture(action: &str) -> Value {
    json!({"kind":"recover","state":"recoverable","action":action,"transactionId":SESSION,
        "platform":"android","locale":"en-US","assetType":"phoneScreenshots",
        "files":[{"path":PATH,"effect":if action == "committed_cleanup" { "keep_committed" } else { "restore_original" },
            "original":{"byteLength":1,"sha256":"4".repeat(64)},"new":{"byteLength":1,"sha256":digest(b"M")}}],
        "privateCleanup":{"fileCount":5,"directoryCount":0,"scope":"original-image-journal-only"},"valid":true,"issues":[],
        "assurance":{"newRestorationAttempt":true,"sourceFilesUnchanged":true,"storeContacted":false,"importRetried":false}})
}
pub(crate) fn recovery_details(action: &str) -> Details {
    let view = recovery_fixture(action);
    Details { intent:Intent::Recover,context:None,selected:Vec::new(),submission:Some(Submission { expected_baseline:baseline(),choices:Vec::new() }),
        checkout:Some(Checkout { revision:REVISION.into(),baseline:baseline(),view:view.clone() }),
        prepared:Some(Prepared { revision:REVISION.into(),plan_token:PLAN.into(),draft_revision:1,baseline_generation:0,view }) }
}
fn outcome(effect: Effect, journal: Journal, reason: CoreReason) -> CoreEditOutcome {
    CoreEditOutcome { effect,journal,resources:ResourceState::Settled,reason }
}

#[test]
fn private_original_roster_and_canonical_base64_are_consumed_into_only_the_initial_frame() {
    let data = original();
    assert!(data.valid());
    let retained = serde_json::to_value(data.details()).unwrap();
    for forbidden in ["protectedObjects","protectedSources","base64","device","inode"] { assert!(retained.get(forbidden).is_none()); }
    let params = import_params("/inert/project",identity(),data).unwrap();
    let frame = request(SESSION,0,"open",params.clone()).unwrap();
    let decoded: Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(decoded["params"]["images"][0]["base64"],"TQ==");
    assert_eq!(decoded["params"]["protectedObjects"],json!([{"device":"1","inode":"7"}]));
    for value in [json!("TR=="),json!("TQ="),json!("TQ==\n"),json!("TQ--")] {
        let mut bad = params.clone(); bad["images"][0]["base64"] = value;
        assert!(request(SESSION,0,"open",bad).is_err());
    }
    for objects in [json!([]),json!([{"device":1,"inode":"7"}]),json!([{"device":"01","inode":"7"}]),
        json!([{"device":"1","inode":"18446744073709551616"}]),json!([{"device":"1","inode":"7","path":"original.png"}])] {
        let mut bad = params.clone(); bad["protectedObjects"] = objects; assert!(request(SESSION,0,"open",bad).is_err());
    }
    let mut duplicate = original();
    duplicate.images.push(SelectedImageData { item_id:REVISION.into(),display_name:"02.png".into(),bytes:b"N".to_vec(),sha256:digest(b"N") });
    duplicate.protected_objects.push(SourceObject { device:"1".into(),inode:"7".into() });
    assert!(!duplicate.valid());
    assert!(request(SESSION,1,"prepare",params).is_err());
}

#[test]
fn large_frame_accounting_keeps_image_allowance_separate_and_checks_escaped_size_before_reserve() {
    let mut data = original();
    data.images[0].bytes = vec![b'M';1024*1024]; data.images[0].sha256 = digest(&data.images[0].bytes);
    let params = import_params("/inert/project",identity(),data).unwrap();
    let frame = request(SESSION,0,"open",params).unwrap();
    assert!(frame.len() > edit::REQUEST_LIMIT && frame.len() < REQUEST_LIMIT);
    assert_eq!(edit::REQUEST_LIMIT,1024*1024); assert_eq!(SMALL_REQUEST_LIMIT,64*1024);
    let recovery = json!({"root":"/inert/project","registeredIdentity":identity(),"intent":"recover"});
    assert!(request(SESSION,0,"open",recovery.clone()).is_ok());
    let mut bad = recovery; bad["images"] = json!([]); assert!(request(SESSION,0,"open",bad).is_err());
    let escaped = json!({"text":"\"\\"});
    let exact = serde_json::to_vec(&escaped).unwrap().len() + 1;
    assert!(frame_exact(&escaped,exact-1).is_err());
    let bytes = frame_exact(&escaped,exact).unwrap(); assert_eq!(bytes.len(),exact);
    assert_eq!(bytes.last(),Some(&b'\n'));
    for (raw, encoded) in [(b"M".as_slice(),"TQ=="),(b"Ma".as_slice(),"TWE="),(b"Man".as_slice(),"TWFu")] {
        assert_eq!(base64(raw).unwrap(),encoded); assert!(canonical_base64(encoded,raw.len()));
    }
    assert!(!canonical_base64("TWF=",2)); assert!(!canonical_base64("TQ==",0)); assert!(!canonical_base64("TQ==",FILE_LIMIT+1));
}

#[test]
fn checkout_binds_original_selection_and_prepared_preserve_is_not_the_selected_image() {
    for (existing, identical, replace) in [(false,false,false),(true,false,false),(true,false,true),(true,true,true)] {
        let view = import_fixture(existing,identical,false);
        let opened = Opened { intent:Intent::Import,revision:REVISION.into(),baseline:baseline(),view:view.clone(),scope_resources:ResourceState::Settled };
        let mut details = original().details();
        assert!(view_valid(&view,false)); assert!(details.opened_matches(&opened));
        details.checkout = Some(Checkout { revision:REVISION.into(),baseline:baseline(),view });
        let submission = Submission { expected_baseline:baseline(),choices:vec![Choice { item_id:SESSION.into(),replace_existing:replace }] };
        assert!(submission.valid_for(&details)); details.submission = Some(submission);
        let prepared = PreparedReply { revision:REVISION.into(),plan_token:PLAN.into(),view:import_fixture(existing,identical,replace),scope_resources:ResourceState::Settled };
        assert!(details.prepared_matches(&prepared));
        let mut wrong = prepared.view.clone(); wrong["files"][0]["selected"]["sha256"] = json!("5".repeat(64));
        assert!(!details.prepared_matches(&PreparedReply { view:wrong,..prepared }));
        if existing && !replace && !identical { assert_ne!(details.checkout.as_ref().unwrap().view["files"][0]["selected"],details.checkout.as_ref().unwrap().view["files"][0]["after"]); }
    }
    let mut details = original().details(); let view = import_fixture(false,false,false);
    details.checkout = Some(Checkout { revision:REVISION.into(),baseline:baseline(),view });
    assert!(!Submission { expected_baseline:baseline(),choices:Vec::new() }.valid_for(&details));
    let mut changed = baseline(); changed.inventory_sha256 = "8".repeat(64);
    assert!(!Submission { expected_baseline:changed,choices:vec![Choice { item_id:SESSION.into(),replace_existing:false }] }.valid_for(&details));
}

#[test]
fn invalid_image_is_displayable_but_never_preparable_and_no_generic_success_assurance_is_admitted() {
    let mut invalid = import_fixture(false,false,false);
    let problem = json!({"code":"image.header","severity":"error","message":"The image's dimension-bearing header is incomplete or invalid."});
    invalid["valid"] = json!(false); invalid["issues"] = json!([problem.clone()]); invalid["files"][0]["issues"] = json!([problem]);
    let unchecked = json!({"byteLength":1,"sha256":digest(b"M"),"format":null,"width":null,"height":null,"headerChecked":false});
    invalid["files"][0]["selected"] = unchecked.clone(); invalid["files"][0]["after"] = unchecked;
    assert!(view_valid(&invalid,false)); assert!(!view_valid(&invalid,true));
    for key in ["storeContacted","fullDecode","contentApproved","storeAccepted"] {
        let mut bad = import_fixture(false,false,false); bad["assurance"][key] = json!(true); assert!(!view_valid(&bad,false));
    }
    let mut false_summary = import_fixture(true,false,false); false_summary["files"][0]["after"] = false_summary["files"][0]["selected"].clone();
    assert!(!view_valid(&false_summary,false));
    let mut absent_replace = import_fixture(false,false,false); absent_replace["files"][0]["action"] = json!("replace");
    assert!(!view_valid(&absent_replace,true));
}

#[test]
fn recovery_context_effect_and_cleanup_are_an_immutable_closed_action_not_generic_paths() {
    for action in ["rollback","committed_cleanup","rolled_back_cleanup","preparing_cleanup"] {
        let view = recovery_fixture(action); assert!(view_valid(&view,true));
        let expected = match action { "committed_cleanup" => Effect::Committed,"preparing_cleanup" => Effect::NotStarted,_ => Effect::RolledBack };
        assert_eq!(expected_success(&view),Some((expected,Journal::Clean)));
        for path in ["release/mobile-release.json","other/android/en-US/images/phoneScreenshots/sub/01.png",
            "public/store/android/fr-FR/images/phoneScreenshots/01.png","private/android/en-US/images/phoneScreenshots/01.png"] {
            let mut bad = view.clone(); bad["files"][0]["path"] = json!(path); assert!(!view_valid(&bad,true));
        }
        let mut bad = view.clone(); bad["files"][0]["effect"] = json!("preserve"); assert!(!view_valid(&bad,true));
        let mut bad = view.clone(); bad["files"][0]["new"] = Value::Null; assert!(!view_valid(&bad,true));
        let mut bad = view.clone(); bad["privateCleanup"]["fileCount"] = json!(0); assert!(!view_valid(&bad,true));
        let mut bad = view; bad["assetType"] = json!("not_a_store_type"); assert!(!view_valid(&bad,true));
    }
    let details = recovery_details("committed_cleanup");
    let mut wrong = PreparedReply { revision:REVISION.into(),plan_token:PLAN.into(),view:recovery_fixture("rollback"),scope_resources:ResourceState::Settled };
    assert!(!details.prepared_matches(&wrong)); wrong.view = recovery_fixture("committed_cleanup"); assert!(details.prepared_matches(&wrong));
    let mut new = details.clone(); new.submission = None;
    assert!(Submission { expected_baseline:baseline(),choices:Vec::new() }.valid_for(&new));
    assert!(!Submission { expected_baseline:baseline(),choices:vec![Choice { item_id:SESSION.into(),replace_existing:false }] }.valid_for(&new));
}

#[test]
fn inspected_commit_is_retained_on_cancel_but_none_late_or_unsubmitted_cannot_be_success() {
    for action in ["rollback","committed_cleanup","rolled_back_cleanup","preparing_cleanup"] {
        let details = recovery_details(action);
        let (effect,journal) = expected_success(&details.prepared.as_ref().unwrap().view).unwrap();
        let success = outcome(effect.clone(),journal,CoreReason::None);
        assert!(details.terminal_admissible(true,&success)); assert!(!details.terminal_admissible(false,&success));
        let inspected = if action == "rollback" { Effect::NotStarted } else { effect.clone() };
        assert!(details.terminal_admissible(false,&outcome(inspected,Journal::RecoveryRequired,CoreReason::Cancelled)));
        assert!(!details.terminal_admissible(false,&outcome(effect.clone(),Journal::Clean,CoreReason::Cancelled)));
        let mut wrong = success.clone(); wrong.resources = ResourceState::Unknown; assert!(!details.terminal_admissible(true,&wrong));
        let mut missing = details.clone(); missing.checkout = None; assert!(!missing.terminal_admissible(true,&success));
    }
    let unopened = Details::recovery();
    assert!(unopened.terminal_admissible(false,&outcome(Effect::NotStarted,Journal::RecoveryRequired,CoreReason::PendingState)));
    assert!(!unopened.terminal_admissible(false,&outcome(Effect::Committed,Journal::RecoveryRequired,CoreReason::PendingState)));
}

#[test]
fn strict_response_domain_session_sequence_and_unknown_fields_are_not_accepted() {
    let result = json!({"intent":"import","revision":REVISION,"baseline":baseline(),"view":import_fixture(false,false,false),"scopeResources":"settled"});
    let body = json!({"protocol":PROTOCOL,"session":SESSION,"seq":0,"kind":"opened","result":result});
    let bytes = frame_exact(&body,RESPONSE_LIMIT).unwrap();
    assert!(matches!(decode(&bytes,SESSION),Ok(ChildFrame::MetadataImagesOpened(_))));
    assert!(decode(&bytes,REVISION).is_err());
    for (key,value) in [("protocol",json!(edit::PROTOCOL)),("seq",json!(1)),("seq",json!(true)),("unexpected",Value::Null)] {
        let mut bad = body.clone(); bad[key] = value; assert!(decode(&frame_exact(&bad,RESPONSE_LIMIT).unwrap(),SESSION).is_err());
    }
    let mut bad = body; bad["result"]["raw"] = json!("must-not-be-retained"); assert!(decode(&frame_exact(&bad,RESPONSE_LIMIT).unwrap(),SESSION).is_err());
}
