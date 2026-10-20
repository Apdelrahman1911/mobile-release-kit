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
pub(super) fn human(s: &build::Status) -> String {
    let mut out = format!(
        "iOS archive request: {:?} / Start {:?}\n{}",
        s.request_state,
        s.start_state,
        receipt(&s.origin)
    );
    out.push_str("Scope: saved unsigned iOS archive observation. Project scripts may read/write files, use network or sign with their own configuration. MRK supplies no signing credentials and does not publish to a Store.\n");
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
            out.push_str(&format!("Historical archive observation: {} entries / {} bytes. No digest was reported; not an IPA, signing check or release approval.\n",r.entries,r.bytes));
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
}
