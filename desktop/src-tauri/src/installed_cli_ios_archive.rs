//! Fixed iOS DATA presentation; both families share the original CLI transport/correlation.
use super::build_requests::{framed, Parsed};
use super::*;
use crate::agent_ios_archive as build;
fn parse(args: &[OsString]) -> Result<Parsed, Error> {
    super::build_requests::parse(build::FAMILY, args)
}
fn receipt(q: &build::Query) -> String {
    super::build_requests::receipt(build::FAMILY, q)
}
fn unconfirmed(q: &build::Query, e: Error, json: bool) -> Vec<u8> {
    super::build_requests::unconfirmed(build::FAMILY, q, e, json)
}
pub(super) fn recognizes(args: &[OsString]) -> bool {
    super::build_requests::recognizes(build::FAMILY, args)
}
pub(super) fn run(args: Vec<OsString>) -> u8 {
    super::build_requests::run(build::FAMILY, args)
}
pub(super) fn human(s: &build::RequestStatus) -> String {
    match s { build::RequestStatus::Saved(s) => saved_human(s), build::RequestStatus::Recovery(s) => recovery_human(s) }
}
fn recovery_human(s: &build::recovery::Status) -> String {
    let mut out=format!("Local iOS recovery request: {:?} / Start {:?}\n{}",s.request_state,s.start_state,receipt(&s.origin));
    out.push_str(&format!("Scope: {:?}. Original local account/project recovery only; no signing, candidate or Store action.\n",s.review.recovery.action()));
    if let Some(op)=&s.operation {
        out.push_str(&format!("Operation {} / {} · {:?} · {:?}\n",op.operation_id.as_str(),op.owner_generation.as_str(),op.state,op.settlement));
        if s.request_state==build::RequestState::OriginalAvailable && s.start_state==build::StartState::NotRequested
            && op.state==p::OperationState::Prepared && op.settlement==p::Settlement::Pending && s.history_available {
            out.push_str(&format!("Start once, only for this explicitly approved action:\nmrk ios-archive-start {} {} {} {} {} --json\n",
                s.origin.project_id.as_str(),s.origin.service_instance.as_str(),s.origin.request_id.as_str(),op.operation_id.as_str(),op.owner_generation.as_str()));
        }
        if let Some(report)=&op.report { for (name,row) in [("Account",&report.account),("Project",&report.project)] {
            if let Some(row)=row { out.push_str(&format!("{name}: {:?}; next {:?}.\n",row.status,row.next)); }
        } }
    }
    out.push_str("A report is not permission to restore. Review each next action in the original Desktop; no automatic follow-on or retry.\n");
    if !s.history_available { out.push_str("Original caller/history settlement is not confirmed. Inspect the same IDs; do not replay.\n"); }
    out
}
fn saved_human(s: &build::Status) -> String {
    let mut out = format!(
        "iOS archive request: {:?} / Start {:?}\n{}",
        s.request_state,
        s.start_state,
        receipt(&s.origin)
    );
    match (&s.review.mode, &s.review.signing) {
        (build::Mode::SavedIosUnsignedArchive, None) => out.push_str("Scope: saved unsigned iOS archive observation. MRK supplies no signing credentials.\n"),
        (build::Mode::SavedIosCandidateInputs, Some(_)) => {
            out.push_str("Scope: one journalled local iOS candidate Create using the original assigned signing inputs and enrolled local history. Original READ and source/journal gates remain required; no conversion of an earlier IPA.\n");
        },
        (build::Mode::SavedIosSignedExport, Some(signing)) => {
            out.push_str(&format!("Scope: separately approved local signed iOS export. Team {} / distribution certificate {}. Assigned Firebase: {}; project read token: {}.\n",
                signing.team_id, signing.distribution_certificate_sha256, signing.firebase, signing.project_read_token));
            out.push_str("Uses the original assigned P12/password/profile and account signing lease; no credential arguments or mode override. Original read revocation stops the signed operation.\n");
        },
        _ => out.push_str("Unconfirmed iOS mode; do not start or replay.\n"),
    }
    out.push_str(if s.review.mode == build::Mode::SavedIosCandidateInputs {
        "Project scripts may read/write files, use network or sign. Not a sandbox; candidate Create is not Store publishing or release approval.\n"
    } else { "Project scripts may read/write files, use network or sign with their own configuration. Not a sandbox; no Store publishing or candidate provenance.\n" });
    if let Some(op) = &s.operation {
        out.push_str(&format!(
            "Operation {} / {} · {:?} · {:?}\n",
            op.operation_id.as_str(),
            op.owner_generation.as_str(),
            op.state,
            op.settlement
        ));
        if s.request_state == build::RequestState::OriginalAvailable
            && s.start_state == build::StartState::NotRequested
            && op.state == p::OperationState::Prepared
            && op.settlement == p::Settlement::Pending
        {
            out.push_str(&format!("Start once, only if this matches your Desktop approval:\nmrk ios-archive-start {} {} {} {} {} --json\n",s.origin.project_id.as_str(),s.origin.service_instance.as_str(),s.origin.request_id.as_str(),op.operation_id.as_str(),op.owner_generation.as_str()));
        }
        if let Some(r) = &op.result {
            out.push_str(&format!("Historical archive observation: {} entries / {} bytes.\n",r.entries,r.bytes));
            if let Some(export) = &r.export {
                out.push_str(&format!("Original validated signed IPA: {} bytes; {} native paths / {} identities / {} present symbol slices.\n",
                    export.ipa_bytes, export.pairing.native_paths, export.pairing.native_identities, export.pairing.present_symbol_slices));
            } else { out.push_str("No signed IPA is reported by this unsigned mode.\n"); }
            if let Some(candidate) = &r.candidate { out.push_str(&candidate.human()); }
            else { out.push_str("No digest or release approval is reported. Recovery uses the separate original Desktop route.\n"); }
        }
        if op.settlement == p::Settlement::Unknown {
            out.push_str(
                "Native cleanup is unknown. A reconnect or history entry cannot clear it.\n",
            );
        }
    }
    if !s.history_available {
        out.push_str("Shared history has not acknowledged this exact status. Absence does not prove settlement.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn exact_prepare_and_start_are_separate_no_arbitrary_configuration_or_commands() {
        let p = "a".repeat(32);
        let i = "b".repeat(32);
        let r = "c".repeat(32);
        let op = "d".repeat(32);
        let gen = "e".repeat(32);
        assert!(parse(&args(&["ios-archive-prepare", &p, "1", "--json"])).is_ok());
        assert!(parse(&args(&["ios-archive-start", &p, &i, &r, &op, &gen])).is_ok());
        for verb in ["ios-archive-status", "ios-archive-cancel"] {
            assert!(parse(&args(&[verb, &p, &i, &r])).is_ok());
        }
        for value in ["0", "01", "-1", "1.0", "18446744073709551616"] {
            assert!(parse(&args(&["ios-archive-prepare", &p, value])).is_err());
        }
        for flag in ["--start", "--sign", "--stdin", "--command", "--root"] {
            assert!(parse(&args(&["ios-archive-prepare", &p, "1", flag])).is_err());
        }
        assert!(parse(&args(&["ios-archive-start", &p, &i, &r])).is_err());
    }
    #[test]
    fn lost_ack_preserves_exact_correlation_and_whole_frame_stays_bounded() {
        let q = build::Query {
            project_id: Id::parse(&"a".repeat(32)).unwrap(),
            service_instance: Id::parse(&"b".repeat(32)).unwrap(),
            request_id: Id::parse(&"c".repeat(32)).unwrap(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&unconfirmed(&q, Error::Unavailable, true)).unwrap();
        assert_eq!(value["request"], serde_json::to_value(&q).unwrap());
        assert_eq!(value["doNotReplay"], true);
        assert!(receipt(&q).contains("ios-archive-status"));
        assert!(receipt(&q).contains("ios-archive-cancel"));
        let frame = framed(p::RequestBody::IosArchiveStart(build::Start {
            origin: q,
            operation_id: Id::parse(&"d".repeat(32)).unwrap(),
            owner_generation: Id::parse(&"e".repeat(32)).unwrap(),
        }))
        .unwrap();
        assert!(p::encode_request(&frame).unwrap().len() <= p::REQUEST_BYTES);
    }
    #[test]
    fn recovery_cli_keeps_explicit_start_and_never_turns_pending_report_into_restore_permission() {
        let value = serde_json::json!({"origin":{"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)},
            "expectedObservationRevision":1,"requestState":"original-available","startState":"not-requested",
            "review":{"mode":"local-ios-recovery","recovery":{"action":"inspect"}},
            "operation":{"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32),"statusRevision":1,
                "state":"prepared","settlement":"pending","outcome":null,"reason":"none","stage":null,"report":null},
            "historyAvailable":true,"doNotReplay":true});
        let mut status:build::recovery::Status=serde_json::from_value(value).unwrap();
        status.validate().unwrap();
        assert!(recovery_human(&status).contains("mrk ios-archive-start"));
        status.history_available=false;
        assert!(!recovery_human(&status).contains("mrk ios-archive-start"));
        status.history_available=true;
        status.start_state=build::StartState::Consumed;
        let op=status.operation.as_mut().unwrap();
        op.status_revision=2;op.state=p::OperationState::Succeeded;op.settlement=p::Settlement::Settled;
        op.outcome=Some(build::Outcome::Complete);op.stage=Some(build::recovery::Stage::DisposingWork);
        op.report=Some(serde_json::from_value(serde_json::json!({"schemaVersion":1,"scope":"local-ios-recovery",
            "account":{"status":"pending","session":"f".repeat(32),"next":"ordinary"},
            "project":{"status":"idle","session":null,"next":"none"},"limitations":build::recovery::LIMITATIONS})).unwrap());
        status.validate().unwrap();
        let response=build::RequestStatus::Recovery(status);
        let text=human(&response);
        assert!(text.contains("Account: Pending")&&text.contains("A report is not permission to restore"));
        assert!(!text.contains("mrk ios-archive-start")&&!text.contains(&"f".repeat(32)));
        let encoded=serde_json::to_vec(&response).unwrap();
        assert!(encoded.len()<4096);
        serde_json::from_slice::<build::RequestStatus>(&encoded).unwrap().validate().unwrap();
        for flag in ["--session","--restore","--recovery","--password","--manual"] {
            assert!(parse(&args(&["ios-archive-prepare",&"a".repeat(32),"1",flag])).is_err());
        }
    }
    #[test]
    fn signed_cli_describes_exact_approved_policy_without_credentials_or_new_commands() {
        let value=serde_json::json!({"origin":{"projectId":"a".repeat(32),"serviceInstance":"b".repeat(32),"requestId":"c".repeat(32)},
            "expectedObservationRevision":1,"requestState":"queued","startState":"not-requested",
            "review":{"mode":"saved-ios-signed-export","savedConfig":{"bytes":10,"sha256":"d".repeat(64)},
                "savedVersion":{"bytes":20,"sha256":"e".repeat(64),"name":"1.2","build":8},
                "signing":{"teamId":"ABCDE12345","distributionCertificateSha256":"f".repeat(64),"firebase":false,"projectReadToken":true}},
            "operation":null,"historyAvailable":false,"doNotReplay":true});
        let status:build::Status=serde_json::from_value(value).unwrap();
        status.validate().unwrap();
        let text=saved_human(&status);
        assert!(text.contains("ABCDE12345")&&text.contains(&"f".repeat(64)));
        assert!(text.contains("separately approved")&&text.contains("no Store publishing"));
        assert!(!text.contains("mrk ios-archive-start"));
        assert!(!text.contains("MRK supplies no signing credentials"));
        for field in ["recordId","contextRevision","privateKey","profileBytes"] { assert!(!text.contains(field)); }
    }
}
