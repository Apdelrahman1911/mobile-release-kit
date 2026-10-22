//! The real installed CLI parser/codec only. No IPC/server/native call.
use super::*;
use crate::service_store_prepare_protocol as flow;
fn status() -> flow::Status {
    let r = review();
    flow::Status {
        schema_version: 1,
        origin: store::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(5),
        },
        prepare_grant_id: id(3),
        selection_id: id(4),
        revision: 1,
        selection: flow::Selection {
            kind: flow::Kind::AndroidAccess,
            saved_config: r.saved_config,
            saved_version: r.saved_version,
            candidate: None,
            later: None,
            execute: None,
            release: None,
        },
        phase: flow::Phase::Queued,
        settlement: p::Settlement::Pending,
        reason: store::Reason::None,
        prepared: None,
        operation: None,
        start_grant_id: None,
        prepare_returned: false,
        start_submitted: false,
        outcome: None,
        result: None,
        do_not_replay: true,
    }
}

#[test]
fn store_prepare_cli_later_stage_results_keep_fixed_calls_and_nonpublishing_limits() {
    for (kind, platform, stage) in [
        (flow::Kind::AndroidExternalTesting, store::Platform::Android, flow::Stage::ExternalTesting),
        (flow::Kind::IosExternalTesting, store::Platform::Ios, flow::Stage::ExternalTesting),
        (flow::Kind::AndroidProductionSubmit, store::Platform::Android, flow::Stage::ProductionSubmit),
        (flow::Kind::IosProductionSubmit, store::Platform::Ios, flow::Stage::ProductionSubmit),
    ] {
        let mut s = status();
        let native = p::Id::parse("22345678123442348234123456789abc").unwrap();
        let candidate = "12345678-1234-4234-8234-123456789abc";
        let predecessor = if stage == flow::Stage::ExternalTesting { candidate } else { "32345678-1234-4234-8234-123456789abc" };
        s.selection.kind = kind;
        s.selection.candidate = Some(store::Candidate { operation_id: candidate.into(), sha256: "a".repeat(64) });
        s.selection.later = Some(flow::StageSelection { stage, predecessor_operation_id: predecessor.into(), predecessor_receipt_sha256: "b".repeat(64) });
        s.phase = flow::Phase::Final; s.settlement = p::Settlement::Settled; s.prepare_returned = true;
        s.start_grant_id = Some(id(9)); s.start_submitted = true; s.outcome = Some(store::Outcome::Complete);
        let r = flow::Review { review_id: native.clone(), operation: store::Operation { operation_id: native.clone(), owner_generation: id(11), status_revision: 3 } };
        s.prepared = Some(r.clone()); s.operation = Some(r.operation.clone());
        let destination = match (platform, stage) {
            (store::Platform::Android, flow::Stage::ExternalTesting) => serde_json::json!({"channel":"Closed testing team","releaseStatus":"completed"}),
            (store::Platform::Android, flow::Stage::ProductionSubmit) => serde_json::json!({"channel":"production","releaseStatus":"draft"}),
            (store::Platform::Ios, flow::Stage::ExternalTesting) => serde_json::json!({"channel":"testflight-external"}),
            (store::Platform::Ios, flow::Stage::ProductionSubmit) => serde_json::json!({"channel":"app-store-review","automaticRelease":false}),
        };
        s.result = Some(serde_json::from_value(serde_json::json!({"kind":"stage-prepare","report":{
            "platform":platform,"stage":stage,"operationId":"22345678-1234-4234-8234-123456789abc","headSequence":stage.prepared_head(),
            "candidateOperationId":candidate,"candidateSha256":"a".repeat(64),"predecessorOperationId":predecessor,"predecessorReceiptSha256":"b".repeat(64),
            "intentSha256":"c".repeat(64),"storePreconditionSha256":"d".repeat(64),"destination":destination,"limitations":flow::STAGE_LIMITATIONS,
        }})).unwrap());
        let q = s.origin.clone();
        let r = response(s);
        let (code, bytes) = preparation::output(&r, &q, Some((true, &id(9), &native)), true).unwrap();
        assert_eq!(code, 0);
        let decoded = p::decode_response(&bytes[..bytes.len()-1], &r.request_id, &r.service_instance).unwrap();
        let p::ResponseBody::StorePreparation(s) = &decoded.response else { unreachable!() };
        s.validate().unwrap();
        assert_eq!(s.selection.kind, kind);
        assert!(s.result.as_ref().unwrap().valid_for(&s.selection, s.prepared.as_ref().unwrap()));
        assert!(output(&r, &q, Some((&id(9), &native)), true).is_err()); // old store-submit cannot adopt it.
    }
    let catalogue: serde_json::Value = serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    assert_eq!(catalogue["store"]["nativePrepareKinds"].as_array().unwrap().len(), 21);
    assert_eq!(catalogue["store"]["stagePreparationIsExecution"], false);
    assert_eq!(catalogue["store"]["kinds"], serde_json::json!(["access-check","candidate-prepare","execute","reconcile"]));
}
fn response(s: flow::Status) -> p::Response {
    p::Response {
        version: p::VERSION,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(7),
        session_id: id(8),
        response: p::ResponseBody::StorePreparation(Box::new(s)),
    }
}
#[test]
fn store_prepare_cli_has_two_fixed_separately_reviewed_id_only_commands() {
    for name in ["store-prepare", "store-start"] {
        let args = format!(
            "{name} {} {} {} {}{} --reviewed",
            id(1).as_str(),
            id(2).as_str(),
            id(3).as_str(),
            id(4).as_str(),
            if name == "store-start" {
                format!(" {}", id(5).as_str())
            } else {
                String::new()
            }
        );
        for suffix in ["", " --json"] {
            let p = parse(&words(&(args.clone() + suffix))).unwrap();
            assert!(matches!(p.command, Command::Preparation(_)));
        }
        for suffix in [" --force", " --query", " --path=/tmp", " --reviewed"] {
            assert!(parse(&words(&(args.clone() + suffix))).is_err());
        }
        assert!(parse(&words(&args.replace(" --reviewed", ""))).is_err());
    }
    assert!(parse(&words(&format!(
        "store-start {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str()
    )))
    .is_err());
    assert!(parse(&words(&format!(
        "store-prepare {} {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str(),
        id(5).as_str()
    )))
    .is_err());
}
#[test]
fn store_prepare_cli_original_response_and_start_grants_cannot_cross_use() {
    let s = status();
    let q = s.origin.clone();
    let mut response = response(s);
    let (code, bytes) =
        preparation::output(&response, &q, Some((false, &id(3), &id(4))), true).unwrap();
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.to_string().contains("doNotReplay"));
    assert!(preparation::output(&response, &q, Some((true, &id(3), &id(4))), true).is_err());
    // Existing status/cancel route accepts this exact new kind, old Submit does not.
    assert!(output(&response, &q, None, true).is_ok());
    assert!(output(&response, &q, Some((&id(3), &id(4))), true).is_err());
    let p::ResponseBody::StorePreparation(s) = &mut response.response else {
        unreachable!()
    };
    s.phase = flow::Phase::Starting;
    s.prepare_returned = true;
    s.start_submitted = true;
    s.start_grant_id = Some(id(9));
    s.prepared = Some(flow::Review {
        review_id: id(10),
        operation: store::Operation {
            operation_id: id(10),
            owner_generation: id(11),
            status_revision: 3,
        },
    });
    assert!(preparation::output(&response, &q, Some((true, &id(9), &id(10))), true).is_ok());
    assert!(preparation::output(&response, &q, Some((true, &id(3), &id(10))), true).is_err());
    response.service_instance = id(12);
    assert!(preparation::output(&response, &q, None, true).is_err());
}
#[test]
fn store_prepare_cli_unknown_keeps_ids_and_catalogue_discloses_query_effects() {
    let mut s = status();
    s.phase = flow::Phase::Unknown;
    s.settlement = p::Settlement::Unknown;
    s.reason = store::Reason::CleanupUnknown;
    s.outcome = Some(store::Outcome::Unknown);
    let q = s.origin.clone();
    let r = response(s);
    let (code, text) = preparation::output(&r, &q, None, false).unwrap();
    assert_eq!(code, 6);
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(q.request_id.as_str()));
    assert!(text.contains("Prepare does not start"));
    let catalogue: serde_json::Value =
        serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let c = &catalogue["store"];
    assert_eq!(c["commands"].as_array().unwrap().len(), 5);
    assert_eq!(c["oldSubmitQueryVariants"], false);
    assert_eq!(c["queryVariants"], true);
    assert_eq!(c["prepareAuthorizesStart"], false);
    assert_eq!(c["inventoryIsAllocationAuthority"], false);
    assert_eq!(c["nativeAvailabilityChecked"], false);
    assert_eq!(c["automaticRetry"], false);
    assert_eq!(c["oldAccessPrepareGrantsAuthorizeRelease"], false);
    let unknown: serde_json::Value =
        serde_json::from_slice(&unconfirmed(&q, Error::StateUnknown, true)).unwrap();
    assert_eq!(unknown["request"]["requestId"], q.request_id.as_str());
    assert_eq!(unknown["doNotReplay"], true);
}

#[test]
fn store_prepare_cli_candidate_upload_keeps_candidate_receipt_and_separate_start_ids() {
    for kind in [flow::Kind::AndroidCandidateUpload, flow::Kind::IosCandidateUpload] {
        let mut s = status();
        let candidate = "12345678-1234-4234-8234-123456789abc";
        s.selection.kind = kind;
        s.selection.candidate = Some(store::Candidate { operation_id: candidate.into(), sha256: "a".repeat(64) });
        s.selection.execute = Some(flow::ExecuteSelection { intent_sha256: "b".repeat(64) });
        s.phase = flow::Phase::Final; s.settlement = p::Settlement::Settled;
        s.prepare_returned = true; s.start_submitted = true; s.start_grant_id = Some(id(9));
        s.outcome = Some(store::Outcome::Complete);
        let review = flow::Review { review_id: id(10), operation: store::Operation {
            operation_id: id(10), owner_generation: id(11), status_revision: 3,
        }};
        s.prepared = Some(review.clone()); s.operation = Some(review.operation.clone());
        let mode = store::release::Mode::CandidateUpload;
        s.result = Some(flow::Report::Ordinary { report: store::Report::Execute { release: store::release::Receipt {
            mode, head_sequence: 7, operation_id: candidate.into(), candidate_operation_id: candidate.into(),
            candidate_sha256: "a".repeat(64), intent_sha256: "b".repeat(64), receipt_sha256: "c".repeat(64), basis: None,
            target: mode.target(kind.candidate_upload().unwrap()), result: store::release::ResultKind::Accepted,
            state: None, limitations: mode.limitations(),
        }}});
        s.validate().unwrap();
        let query = s.origin.clone(); let r = response(s);
        let (code, bytes) = preparation::output(&r, &query, Some((true, &id(9), &id(10))), true).unwrap();
        assert_eq!(code, 0);
        let decoded = p::decode_response(&bytes[..bytes.len()-1], &r.request_id, &r.service_instance).unwrap();
        let p::ResponseBody::StorePreparation(s) = &decoded.response else { unreachable!() };
        assert_eq!(s.selection.kind, kind);
        assert_eq!(s.prepared.as_ref().unwrap().operation.operation_id, id(10));
        let Some(flow::Report::Ordinary { report: store::Report::Execute { release } }) = &s.result else { unreachable!() };
        assert_eq!(release.operation_id, candidate);
        assert!(preparation::output(&r, &query, Some((true, &id(3), &id(4))), true).is_err());
        assert!(output(&r, &query, Some((&id(9), &id(10))), true).is_err()); // old Submit still cannot adopt.
    }
    let caps = capabilities(true).unwrap();
    assert!(caps.len() <= crate::installed_cli::CAPABILITIES_BYTES);
    let catalogue: serde_json::Value = serde_json::from_slice(&caps).unwrap();
    let kinds = catalogue["store"]["nativePrepareKinds"].as_array().unwrap();
    assert_eq!(kinds.len(), 21);
    for k in ["android-candidate-upload", "ios-candidate-upload"] { assert!(kinds.iter().any(|v| v == k)); }
    for unsupported in ["ios-recovery-settlement", "android-external-readiness", "android-production-reconcile", "ios-production-reconcile"] { assert!(!kinds.iter().any(|v|v==unsupported)); }
    assert_eq!(catalogue["store"]["prepareAuthorizesStart"], false);
    assert_eq!(catalogue["store"]["automaticRetry"], false);
    assert_eq!(catalogue["store"]["nativeAvailabilityChecked"], false);
}
#[test]
fn store_prepare_cli_lifecycle_receipts_keep_same_id_only_output_and_closed_catalogue() {
    use flow::Kind::*;
    use store::release::{Mode,ResultKind,StoreState};
    let kinds=[AndroidExternalTestingExecute,IosExternalTestingExecute,AndroidProductionSubmitExecute,IosProductionSubmitExecute,
        AndroidCurrentInternal,IosCurrentInternal,AndroidRecoverySettlement,IosExternalReadiness];
    let catalogue:serde_json::Value=serde_json::from_slice(&capabilities(true).unwrap()).unwrap();
    let names=catalogue["store"]["nativePrepareKinds"].as_array().unwrap();assert_eq!(names.len(),21);
    for kind in kinds {
        let (domain,platform,mode)=kind.release_mode().unwrap();let mut s=status();
        let candidate="12345678-1234-4234-8234-123456789abc";
        let stage=match mode {Mode::ExternalTesting|Mode::ExternalReadiness=>Some("22345678-1234-4234-8234-123456789abc"),Mode::ProductionSubmit=>Some("32345678-1234-4234-8234-123456789abc"),_=>None};
        let basis=stage.map(|_|store::release::Basis{operation_id:if mode==Mode::ExternalTesting{candidate}else{"22345678-1234-4234-8234-123456789abc"}.into(),receipt_sha256:"f".repeat(64)});
        s.selection.kind=kind;s.selection.candidate=Some(store::Candidate{operation_id:candidate.into(),sha256:"a".repeat(64)});
        s.selection.release=Some(store::release::Review{mode,intent_sha256:"b".repeat(64),stage_operation_id:stage.map(str::to_owned),basis:basis.clone()});
        let review=flow::Review{review_id:id(10),operation:store::Operation{operation_id:id(10),owner_generation:id(11),status_revision:3}};
        s.prepared=Some(review.clone());s.operation=Some(review.operation);s.phase=flow::Phase::Final;s.settlement=p::Settlement::Settled;
        s.prepare_returned=true;s.start_grant_id=Some(id(9));s.start_submitted=true;s.outcome=Some(store::Outcome::Complete);
        let release=store::release::Receipt{mode,head_sequence:*mode.heads().start(),operation_id:stage.unwrap_or(candidate).into(),candidate_operation_id:candidate.into(),
            candidate_sha256:"a".repeat(64),intent_sha256:"b".repeat(64),receipt_sha256:"c".repeat(64),basis,target:mode.target(platform),
            result:if domain==store::Kind::Execute{ResultKind::Accepted}else if mode==Mode::ExternalReadiness{ResultKind::Ready}else{ResultKind::Reconciled},
            state:match(domain,platform,mode){(store::Kind::Execute,store::Platform::Ios,_)=>Some(StoreState::SubmittedForReview),
                (store::Kind::Execute,store::Platform::Android,Mode::ProductionSubmit)=>Some(StoreState::Draft),
                (store::Kind::Execute,store::Platform::Android,_)|(_,_,Mode::ExternalReadiness)=>Some(StoreState::AvailableToTesters),_=>None},limitations:mode.limitations()};
        s.result=Some(flow::Report::Ordinary{report:if domain==store::Kind::Execute{store::Report::Execute{release}}else{store::Report::Reconcile{release}}});
        s.validate().unwrap();let query=s.origin.clone();let r=response(s);
        for json in [false,true] {
            let (code,bytes)=preparation::output(&r,&query,Some((true,&id(9),&id(10))),json).unwrap();assert_eq!(code,0);assert!(!bytes.is_empty());
            if json {let parsed=p::decode_response(&bytes[..bytes.len()-1],&r.request_id,&r.service_instance).unwrap();assert_eq!(parsed.response,r.response);}
        }
        assert!(preparation::output(&r,&query,Some((false,&id(3),&id(4))),true).is_err());
        assert!(output(&r,&query,Some((&id(9),&id(10))),true).is_err()); // no old Submit adoption
        assert!(names.contains(&serde_json::to_value(kind).unwrap()));
    }
    assert_eq!(catalogue["store"]["prepareAuthorizesStart"],false);
    assert_eq!(catalogue["store"]["automaticRetry"],false);
    assert_eq!(catalogue["store"]["nativeAvailabilityChecked"],false);
    assert!(capabilities(false).unwrap().len()<=crate::installed_cli::CAPABILITIES_BYTES);
}
