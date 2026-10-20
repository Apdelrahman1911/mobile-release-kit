//! Fixed Android DATA presentation; both families share the original CLI transport/correlation.
use super::*;
use crate::agent_android_build as build;
use super::build_requests::{Parsed,framed};
fn parse(args:&[OsString])->Result<Parsed,Error>{super::build_requests::parse(build::FAMILY,args)}
fn receipt(q:&build::Query)->String{super::build_requests::receipt(build::FAMILY,q)}
fn unconfirmed(q:&build::Query,e:Error,json:bool)->Vec<u8>{super::build_requests::unconfirmed(build::FAMILY,q,e,json)}
pub(super) fn recognizes(args:&[OsString])->bool{super::build_requests::recognizes(build::FAMILY,args)}
pub(super) fn run(args:Vec<OsString>)->u8{super::build_requests::run(build::FAMILY,args)}
pub(super) fn human(s: &build::Status) -> String {
    use build::RequestState as S;
    let description = match s.request_state {
        S::Queued => {
            "Queued for the Desktop's exact saved-input preparation. No Start is requested."
        }
        S::Preparing => "Original preparation is in progress. Do not prepare again.",
        S::OriginalAvailable => "The same original Android operation is linked below.",
        S::RefusedBeforePreparation => {
            "Desktop refused preparation. This request will not be replayed."
        }
        S::CancelledBeforePreparation => {
            "Cancelled before preparation. This request will not be replayed."
        }
        S::Expired => "Start authorization expired. This request will not be replayed.",
        S::AdmissionUnknown => {
            "Original admission is unconfirmed. Preserve this request; do not repeat the action."
        }
    };
    let mut text = format!(
        "{description}\n{}Saved configuration: {} bytes / {}\nSaved version: {} ({}) / {}\n",
        receipt(&s.origin),
        s.review.saved_config.bytes,
        s.review.saved_config.sha256,
        s.review.saved_version.name,
        s.review.saved_version.build,
        s.review.saved_version.sha256
    );
    text.push_str("Scope: existing Android build + structure/version inspection. Project code may read/write files, use network or sign itself; no toolkit signing, credentials, Store upload or release approval is granted.\n");
    if let Some(op) = &s.operation {
        text.push_str(&format!(
            "Operation {} / {} · {:?} · {:?}\nStart: {:?}\n",
            op.operation_id.as_str(),
            op.owner_generation.as_str(),
            op.state,
            op.settlement,
            s.start_state
        ));
        if s.request_state == S::OriginalAvailable
            && s.start_state == build::StartState::NotRequested
            && op.state == p::OperationState::Prepared
            && op.settlement == p::Settlement::Pending
        {
            text.push_str(&format!("Start once, only if this matches your Desktop approval:\nmrk android-build-start {} {} {} {} {} --json\n",
                s.origin.project_id.as_str(), s.origin.service_instance.as_str(), s.origin.request_id.as_str(), op.operation_id.as_str(), op.owner_generation.as_str()));
        }
        if let Some(result) = &op.result {
            text.push_str(&format!("Historical artifact observation: {} bytes / {}\n{} findings (completion is not PASS or release readiness).\n", result.artifact.size, result.artifact.sha256, result.summary.total));
            for (status, count) in &result.summary.counts {
                text.push_str(&format!("{status:?}: {count}\n"));
            }
        }
        if op.settlement == p::Settlement::Unknown {
            text.push_str("Native cleanup is unknown; history or a new client cannot clear it.\n");
        }
    }
    if !s.history_available {
        text.push_str("Shared history may not yet contain this original status; absence never proves settlement.\n");
    }
    text
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
        assert!(parse(&args(&["android-build-prepare", &p, "1", "--json"])).is_ok());
        assert!(parse(&args(&["android-build-start", &p, &i, &r, &op, &gen])).is_ok());
        for verb in ["android-build-status", "android-build-cancel"] {
            assert!(parse(&args(&[verb, &p, &i, &r])).is_ok());
        }
        for value in ["0", "01", "-1", "1.0", "18446744073709551616"] {
            assert!(parse(&args(&["android-build-prepare", &p, value])).is_err());
        }
        for flag in ["--start", "--sign", "--stdin", "--command", "--root"] {
            assert!(parse(&args(&["android-build-prepare", &p, "1", flag])).is_err());
        }
        assert!(parse(&args(&["android-build-start", &p, &i, &r])).is_err());
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
        assert!(receipt(&q).contains("android-build-status"));
        assert!(receipt(&q).contains("android-build-cancel"));
        let frame = framed(p::RequestBody::AndroidBuildStart(build::Start {
            origin: q,
            operation_id: Id::parse(&"d".repeat(32)).unwrap(),
            owner_generation: Id::parse(&"e".repeat(32)).unwrap(),
        }))
        .unwrap();
        assert!(p::encode_request(&frame).unwrap().len() <= p::REQUEST_BYTES);
    }
}
