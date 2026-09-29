//! Closed protocol and policy DATA. No native receipt, permission, API, child,
//! signing material or installed runtime is created by these tests.
use super::*;
use serde_json::{json, Value};
fn frame(value: &Value) -> Vec<u8> { let mut raw=serde_json::to_vec(value).unwrap();raw.push(b'\n');raw }
fn control() -> Value { json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}) }
fn positive() -> Value { json!({"protocol":PROTOCOL,"id":"runner-1","result":{"schemaVersion":1,"reason":"none",
    "facts":{"accountId":"11","repositoryId":"22","repository":"owner/app","owner":{"id":"33","type":"User"},
        "repositoryRunners":[{"id":"101","labels":["linux","self-hosted"]}],"groups":[],"observedAt":"2026-09-28T12:00:00Z"},
    "control":control(),"networkCleanup":"confirmed"}}) }
#[test]
fn request_and_public_check_are_closed_and_old_action_protocol_cannot_accept_them() {
    let raw=encode_request("runner-1","owner/app","11","22","INERT_TOKEN").unwrap();
    let value:Value=serde_json::from_slice(&raw).unwrap();
    assert_eq!(value,json!({"protocol":PROTOCOL,"id":"runner-1","params":{"repository":"owner/app","expectedAccountId":"11",
        "expectedRepositoryId":"22","token":"INERT_TOKEN"}}));
    assert!(raw.len()<=REQUEST_LIMIT && raw.capacity()<=REQUEST_LIMIT && raw.ends_with(b"\n"));
    for (account,repository,token) in [("0","22","INERT_TOKEN"),("11","00","INERT_TOKEN"),("11","22","bad token")] {
        assert!(encode_request("runner-1","owner/app",account,repository,token).is_err());
    }
    let body=json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":2,"expectedAssetStatusRevision":3,"contextRevision":4});
    assert!(matches!(input::decode_command("github_input_runner_check",&body),Ok(input::Command::RunnerCheck(_))));
    for name in ["repository","token","groups","labels","branch","assignment","runnerApproved"] {
        let mut wrong=body.clone();wrong[name]=json!("caller-supplied");
        assert!(input::decode_command("github_input_runner_check",&wrong).is_err());
    }
    let mut wrong=body.clone();wrong.as_object_mut().unwrap().remove("contextRevision");
    assert!(input::decode_command("github_input_runner_check",&wrong).is_err());
    wrong=body.clone();wrong["expectedRevision"]=json!(0);
    assert!(input::decode_command("github_input_runner_check",&wrong).is_err());
    assert!(serde_json::from_value::<input::Kind>(json!("runner-check")).is_err());
}
#[test]
fn accepted_inventories_reduce_to_bounded_redacted_summary_only() {
    let personal=decode_reply("runner-1",&frame(&positive())).unwrap();
    let facts=personal.facts.unwrap();assert_eq!(facts.runner_count,1);assert_eq!(facts.group_count,0);
    assert_eq!(facts.owner_id,"33");assert_eq!(facts.digest.len(),64);
    let summary=facts.summary("2026-09-28T12:02:00Z".into());
    assert_eq!(summary.scope,Some(Coverage::Repository));assert_eq!(summary.result,PublicResult::Safe);
    let text=serde_json::to_string(&summary).unwrap();
    assert!(!text.contains("self-hosted") && !text.contains("linux") && !text.contains("owner/app") && !text.contains("ownerId"));
    let mut largest=positive();largest["result"]["facts"]["owner"]["type"]=json!("Organization");
    largest["result"]["facts"]["repositoryRunners"]=json!((1..=100).map(|id|json!({"id":id.to_string(),"labels":[]})).collect::<Vec<_>>());
    largest["result"]["facts"]["groups"]=json!((0..8).map(|group|json!({"id":(40+group).to_string(),"inherited":group%2==0,
        "runners":(0..100).map(|index|json!({"id":(101+group*100+index).to_string(),"labels":[]})).collect::<Vec<_>>()})).collect::<Vec<_>>());
    let facts=decode_reply("runner-1",&frame(&largest)).unwrap().facts.unwrap();
    assert_eq!((facts.group_count,facts.runner_count),(8,900));
    assert_eq!(facts.summary("2026-09-28T12:02:00Z".into()).scope,Some(Coverage::OrganizationWide));
}
#[test]
fn normalized_native_boundary_rejects_collisions_duplicates_and_raw_inventory_shapes() {
    for labels in [vec!["ubuntu-24.04"],vec!["macos-26"],vec!["macoſ-26"],vec!["MACOS-26"],vec!["same","same"],vec!["z","a"],vec![""]] {
        let mut bad=positive();bad["result"]["facts"]["repositoryRunners"][0]["labels"]=json!(labels);
        assert!(decode_reply("runner-1",&frame(&bad)).is_err());
    }
    for (pointer,value) in [("/result/facts/accountId",json!("00")),("/result/facts/owner/id",json!(true)),
        ("/result/facts/owner/type",json!("Enterprise")),("/result/facts/observedAt",json!("2026-02-30T12:00:00Z")),
        ("/result/facts/repositoryRunners/0/id",json!("18446744073709551616")),("/result/networkCleanup",json!("unknown")),
        ("/result/facts/repositoryRunners/0/labels",json!([{"id":1,"name":"linux","type":"custom"}]))] {
        let mut bad=positive();*bad.pointer_mut(pointer).unwrap()=value;assert!(decode_reply("runner-1",&frame(&bad)).is_err());
    }
    let mut groups=positive();groups["result"]["facts"]["owner"]["type"]=json!("Organization");
    groups["result"]["facts"]["groups"]=json!([{"id":"40","inherited":true,"runners":[{"id":"101","labels":[]}]}]);
    assert!(decode_reply("runner-1",&frame(&groups)).is_err()); // Duplicate ID across inventories.
    groups["result"]["facts"]["groups"]=json!([{"id":"40","inherited":true,"runners":[]},{"id":"40","inherited":false,"runners":[]}]);
    assert!(decode_reply("runner-1",&frame(&groups)).is_err());
    groups["result"]["facts"]["groups"]=json!((0..9).map(|i|json!({"id":(40+i).to_string(),"inherited":false,"runners":[]})).collect::<Vec<_>>());
    assert!(decode_reply("runner-1",&frame(&groups)).is_err());
    let mut raw=positive();raw["result"]["facts"]["repositoryRunners"][0]["name"]=json!("PRIVATE_NAME");
    assert!(decode_reply("runner-1",&frame(&raw)).is_err());
}
#[test]
fn result_control_cleanup_framing_and_bounds_cannot_supply_success_by_field_salvage() {
    let mut refusal=positive();refusal["result"]["reason"]=json!("rate-limited");refusal["result"]["facts"]=Value::Null;
    refusal["result"]["control"]["reason"]=json!("rate-limited");refusal["result"]["control"]["cooldownSeconds"]=json!(7);
    let parsed=decode_reply("runner-1",&frame(&refusal)).unwrap();assert!(parsed.facts.is_none());assert_eq!(parsed.control.cooldown_seconds,Some(7));
    refusal["result"]["networkCleanup"]=json!("unknown");
    assert_eq!(decode_reply("runner-1",&frame(&refusal)).unwrap().network_cleanup,input::Settlement::Unknown);
    refusal["result"]["facts"]=positive()["result"]["facts"].clone();assert!(decode_reply("runner-1",&frame(&refusal)).is_err());
    let original=frame(&positive());
    for bytes in [original[..original.len()-1].to_vec(),[original.clone(),b"\n".to_vec()].concat(),
        String::from_utf8(original.clone()).unwrap().replacen("\"schemaVersion\":1","\"schemaVersion\":1,\"schemaVersion\":1",1).into_bytes(),
        vec![b' ';RESPONSE_LIMIT+1]] {assert!(decode_reply("runner-1",&bytes).is_err());}
    assert!(decode_reply("other-original",&original).is_err());
    let mut fake=positive();fake["result"]["control"]["extra"]=json!(true);assert!(decode_reply("runner-1",&frame(&fake)).is_err());
    let mut refusal=Summary::refused(input::Reason::RunnerCollision);refusal.expire(input::Reason::Expired);
    assert_eq!(refusal.result,PublicResult::Refused);assert!(refusal.checked_at.is_none() && refusal.group_count.is_none());
}
#[test]
fn production_requires_valid_nonempty_reviewers_without_inventing_global_bypass_rules() {
    let mut value=serde_json::to_value(input::test_data::prepared()).unwrap();
    value["target"]["scope"]["stage"]=json!("production");
    let prepared:input::Prepared=serde_json::from_value(value.clone()).unwrap();assert!(prepared.production_reviewed());
    value["environmentPolicy"]["canAdminsBypass"]=json!(true);
    value["environmentPolicy"]["rules"][0]["preventSelfReview"]=json!(false);
    let prepared:input::Prepared=serde_json::from_value(value.clone()).unwrap();assert!(prepared.production_reviewed());
    value["environmentPolicy"]["rules"][0]["reviewers"]=json!([]);
    let prepared:input::Prepared=serde_json::from_value(value.clone()).unwrap();assert!(!prepared.production_reviewed());
    value["environmentPolicy"]["rules"]=json!([]);
    let prepared:input::Prepared=serde_json::from_value(value.clone()).unwrap();assert!(!prepared.production_reviewed());
    value["target"]["scope"]["stage"]=json!("candidate");
    let prepared:input::Prepared=serde_json::from_value(value).unwrap();assert!(prepared.production_reviewed());
}
