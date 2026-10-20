//! Private-witness correlation DATA only, not Supervisor/process/native/Store
//! qualification. The production constructor still requires original joins.
use super::*;
use crate::git_switch_protocol::tests as data;

fn witness()->GitLocalPublication {
    let request=Arc::new(data::request(wire::Phase::Apply));let candidate=Arc::new(data::candidate(&request));
    GitLocalPublication {request,candidate,publication:wire::Publication::SwitchIndexReturned}
}

#[test]
fn switch_source_exception_needs_exact_original_request_review_and_private_projection() {
    let w=witness();let review=wire::Review::Switch(data::review());let sources=data::sources();
    let (intent,marker)=w.switch_for(&w.request.id,&w.request.native,&review,&sources).unwrap();
    assert!(intent==&data::intent() && marker==wire::Publication::SwitchIndexReturned);
    assert!(w.intent_for(&w.request.id,&w.request.native,&review).is_err());
    assert!(w.switch_for("other-original",&w.request.native,&review,&sources).is_err());
    let mut other=sources.clone();other.target_lock.identity.1+=1;
    assert!(w.switch_for(&w.request.id,&w.request.native,&review,&other).is_err());
    let mut native=w.request.native.clone();native.files.head.sha256="f".repeat(64);
    assert!(w.switch_for(&w.request.id,&native,&review,&sources).is_err());
    let mut r=data::review();r.files[0].source_sha256="f".repeat(64);
    assert!(w.switch_for(&w.request.id,&w.request.native,&wire::Review::Switch(r),&sources).is_err());
}

#[test]
fn generic_or_absent_publication_cannot_authorize_switch_old_fd_successors() {
    let mut w=witness();let r=wire::Review::Switch(data::review());let sources=data::sources();
    for marker in [wire::Publication::NotReported,wire::Publication::IndexReturned,
        wire::Publication::RefReturned,wire::Publication::BranchRefReturned] {
        w.publication=marker;assert!(w.switch_for(&w.request.id,&w.request.native,&r,&sources).is_err());
    }
}
