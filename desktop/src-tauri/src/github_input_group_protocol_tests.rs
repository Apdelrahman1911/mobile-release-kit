// Focused in-memory wire/identity regressions; not installed/native evidence.
use super::*;
use super::test_data as data;
use base64::Engine as _;
use serde_json::json;
#[test]
fn canonical_domain_matches_the_shared_python_corpus() {
    let corpus:Value=serde_json::from_str(include_str!("../../../tests/fixtures/desktop/github_input_group_canonical.json")).unwrap();
    for row in corpus["accepted"].as_array().unwrap() {
        let value=strict_json(row["input"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(canonical(&value,8192).unwrap(),row["canonical"].as_str().unwrap().as_bytes(),"{}",row["name"]);
    }
    for row in corpus["rejected"].as_array().unwrap() {
        assert!(strict_json(row.as_str().unwrap().as_bytes()).and_then(|v| canonical(&v,8192)).is_err());
    }
    assert!(strict_json(br#"{"a":1,"a":2}"#).is_err());
    assert!(canonical(&json!({"a":"x"}),8).is_err());
    let mut empty=json!({});for _ in 0..24 {empty=json!([empty]);}
    assert!(canonical(&empty,8192).is_ok());assert!(canonical(&json!([empty]),8192).is_err());
}
#[test]
fn recheck_keeps_original_intent_and_ignores_only_observation_times() {
    let original=data::prepared();assert!(original.valid());let digest="9".repeat(64);
    let mut fresh=original.clone();fresh.observed_at="2026-09-28T12:00:30Z".into();
    if let Metadata::Present {observed_at,..}=&mut fresh.metadata {*observed_at=fresh.observed_at.clone();}
    assert!(original.same_original(&fresh));assert_ne!(original.intent_digest().unwrap(),fresh.intent_digest().unwrap());
    let rechecked=Rechecked {request_sha256:digest.clone(),snapshot_sha256:fresh.snapshot_digest().unwrap(),
        intent_sha256:original.intent_digest().unwrap(),snapshot:fresh.clone()};
    assert!(decode_rechecked(&data::rechecked_frame("op-1",&rechecked),"op-1",&digest,&original).is_ok());
    for change in 0..8 {
        let mut drift=fresh.clone();
        match change {
            0=>drift.public_key.key="CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=".into(),1=>drift.public_key.key_id="other-key".into(),
            2=>drift.config_sha256="a".repeat(64),3=>drift.environment_id="790".into(),
            4=>drift.environment_policy.can_admins_bypass=true,5=>drift.target.native_config_sha256="b".repeat(64),
            6=>drift.source_sha="c".repeat(40),_=>if let Metadata::Present {updated_at,..}=&mut drift.metadata {*updated_at="2026-09-03T00:00:00Z".into();},
        }
        let changed=Rechecked {snapshot_sha256:drift.snapshot_digest().unwrap(),snapshot:drift,..rechecked.clone()};
        assert!(decode_rechecked(&data::rechecked_frame("op-1",&changed),"op-1",&digest,&original).is_err());
    }
    let mut bad=rechecked.clone();bad.intent_sha256=fresh.intent_digest().unwrap();
    assert!(decode_rechecked(&data::rechecked_frame("op-1",&bad),"op-1",&digest,&original).is_err());
    let mut future=original.clone();if let Metadata::Present {created_at,..}=&mut future.metadata {*created_at="2026-09-04T00:00:00Z".into();}
    assert!(!future.valid());
}
#[test]
fn read_and_go_have_closed_separate_private_frames() {
    let request=data::request(Kind::Apply);let initial=encode_initial("op-1",&request).unwrap();let digest=digest(&initial);
    assert_eq!(initial.last(),Some(&b'\n'));let value=strict_json(&initial).unwrap();assert_eq!(value.as_object().unwrap().len(),5);
    let token="fictional\\token\"not-a-credential";
    let read=encode_read("op-1",&digest,Some(token),Kind::Apply).unwrap();assert_eq!(read.retained_capacity(),READ_LIMIT);
    let decoded=strict_json(&read.into_zeroizing()).unwrap();assert_eq!(decoded["read"]["token"],token);assert!(decoded.get("go").is_none());
    assert!(encode_read("op-1",&digest,None,Kind::Apply).is_err());assert!(encode_read("op-1",&digest,Some(token),Kind::Pending).is_err());
    let pending=encode_read("op-1",&digest,None,Kind::Pending).unwrap().into_zeroizing();assert!(strict_json(&pending).unwrap()["read"]["token"].is_null());
    let checked=data::rechecked(&digest,request.action.as_ref().unwrap().prepared.as_ref().unwrap());
    let body=br#"{"encrypted_value":"fixture-only","key_id":"fixture-key"}"#;
    let go=encode_go("op-1",&checked,body).unwrap();assert!(go.retained_capacity()<=GO_LIMIT);
    let decoded=strict_json(&go.into_zeroizing()).unwrap();let base64=decoded["go"]["putBodyBase64"].as_str().unwrap();
    let mut decoded_body=[0u8;64];let count=STANDARD.decode_slice(base64,&mut decoded_body).unwrap();
    assert_eq!(&decoded_body[..count],body);assert!(decoded.get("read").is_none());
    assert!(encode_go("op-1",&checked,&[]).is_err());
    assert!(encode_go("op-1",&checked,&vec![0;crate::github_input_seal::MAX_PUT_BODY_BYTES+1]).is_err());
}
#[test]
fn observed_remote_fact_is_correlated_but_control_reason_is_independent() {
    let checked=data::rechecked(&"9".repeat(64),&data::prepared());
    let write=RemoteWrite::AcknowledgedCreated {status_code:201};
    let raw=data::remote("op-1",&checked,write.clone(),data::control(crate::github_connection_protocol::Reason::ResponseInvalid));
    let result=decode_outcome(&raw,"op-1",&checked).unwrap();assert_eq!(result.write,write);
    assert_eq!(result.control.reason,crate::github_connection_protocol::Reason::ResponseInvalid);
    assert!(decode_outcome(&raw,"wrong-op",&checked).is_err());
    let mut mismatch=checked.clone();mismatch.intent_sha256="e".repeat(64);assert!(decode_outcome(&raw,"op-1",&mismatch).is_err());
    for write in [RemoteWrite::NotAttempted,RemoteWrite::AcknowledgedUpdated {status_code:201}] {
        assert!(decode_outcome(&data::remote("op-1",&checked,write,data::control(crate::github_connection_protocol::Reason::None)),"op-1",&checked).is_err());
    }
    assert!(decode_outcome(&data::remote("op-1",&checked,RemoteWrite::AttemptedOutcomeUnknown,data::control(crate::github_connection_protocol::Reason::None)),"op-1",&checked).is_ok());
}
#[test]
fn pending_history_is_bounded_unique_and_exactly_scoped() {
    let request=data::request(Kind::Pending);let rows:Vec<_>=(0..RECORD_LIMIT).map(|n|data::record(&format!("{n:032x}"),RemoteWrite::AttemptedOutcomeUnknown)).collect();
    let value=json!({"protocol":PROTOCOL,"id":"op-1","result":null,"pending":rows});let raw=data::frame(value.clone());
    assert!(raw.len()<RESPONSE_LIMIT);assert_eq!(decode_reply(&raw,"op-1",&request).unwrap().pending.unwrap().len(),RECORD_LIMIT);
    let mut duplicate=value.clone();duplicate["pending"][1]=duplicate["pending"][0].clone();assert!(decode_reply(&data::frame(duplicate),"op-1",&request).is_err());
    let mut extra=value.clone();let row=extra["pending"][0].clone();extra["pending"].as_array_mut().unwrap().push(row);
    assert!(decode_reply(&data::frame(extra),"op-1",&request).is_err());
    let mut wrong=request.clone();wrong.pending_scope.as_mut().unwrap().account_id="124".into();assert!(decode_reply(&raw,"op-1",&wrong).is_err());
    let mut fields=value;fields["unexpected"]=json!(true);assert!(decode_reply(&data::frame(fields),"op-1",&request).is_err());
}
#[test]
fn six_ingress_commands_never_accept_private_or_extra_authority() {
    assert!(matches!(decode_command("github_input_group_status",&json!({})),Ok(Command::Status)));
    let prepare=json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":2,"expectedAssetStatusRevision":3,
        "branch":"main","assignment":{"kind":"android-keystore","recordId":"a".repeat(32),"recordRevision":1,"contextRevision":1}});
    assert!(matches!(decode_command("github_input_group_prepare",&prepare),Ok(Command::Prepare(_))));
    let apply=json!({"sessionId":"session-1","expectedRevision":1,"consentId":"a".repeat(32),"confirmUpsertWholeGroup":true});
    assert!(matches!(decode_command("github_input_group_apply",&apply),Ok(Command::Apply(_))));
    assert!(matches!(decode_command("github_input_group_reconcile",&json!({"sessionId":"session-1","expectedRevision":1,"originalOperationId":"a".repeat(32)})),Ok(Command::Reconcile(_))));
    assert!(matches!(decode_command("github_input_group_pending",&json!({"sessionId":"session-1","expectedRevision":1})),Ok(Command::Pending(_))));
    assert!(matches!(decode_command("github_input_group_cancel",&json!({"operationId":"op-1"})),Ok(Command::Cancel(_))));
    let mut refusal=apply;refusal["confirmUpsertWholeGroup"]=json!(false);assert!(decode_command("github_input_group_apply",&refusal).is_err());
    for name in ["token","putBodyBase64","home","runnerApproved"] {
        let mut extra=prepare.clone();extra[name]=json!("not-authority");assert!(decode_command("github_input_group_prepare",&extra).is_err());
    }
}
