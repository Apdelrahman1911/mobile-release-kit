//! Actual in-memory Book/Entry methods; supplied test facts are not native receipts.
use super::*;
use std::time::Duration;

fn id(n:u64)->Id {Id::parse(&format!("{n:032x}")).unwrap()}
fn scope(doc:&Arc<()>,kind:p::Kind)->Arc<NativeScope> {
    let review=match kind {
        p::Kind::PreflightPending|p::Kind::ReleasePending|p::Kind::PublicationPending => {
            let r=p::dispatch::RequestReference{session_id:"session-a".into(),expected_revision:4,request_sha256:"b".repeat(64)};
            match kind {p::Kind::PreflightPending=>p::Review::PreflightPending(r),p::Kind::ReleasePending=>p::Review::ReleasePending(r),_=>p::Review::PublicationPending(r)}
        }
        _=>p::Review::from_prepared(kind,p::PreparedReference{session_id:"session-a".into(),expected_revision:4,
            consent_id:"a".repeat(32),prepared_sha256:"b".repeat(64)}).unwrap(),
    };
    let at=Instant::now();
    NativeScope::new(id(1),"project-1".into(),"/never-opened-dispatch-entry".into(),1,2,3,review,Arc::new(()),
        at+Duration::from_secs(100),Arc::new(crate::service_version_reserve_requests::ReadPermission::new(at+Duration::from_secs(110))),
        Arc::downgrade(doc),tokio::sync::watch::channel(1).0)
}
struct F {inbox:Inbox,scope:Arc<NativeScope>,_doc:Arc<()>}
impl F {
    fn new()->Self {let doc=Arc::new(());let scope=scope(&doc,p::Kind::PreflightPending);let inbox=Inbox::new(id(2));
        inbox.allow(scope.clone(),id(3)).unwrap();Self{inbox,scope,_doc:doc}}
    fn claim(&self)->Claim {self.inbox.submit(p::Submit{origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(4)},grant_id:id(3)}).unwrap();
        self.inbox.claim().unwrap().unwrap()}
    fn arm(e:&Entry,go:bool) {e.entering().unwrap();e.arm("github-preflight-1").unwrap();if go{e.go("github-preflight-1").unwrap();}}
    fn result()->Option<p::dispatch::Snapshot>{Some(p::dispatch::Snapshot::Pending{rows:Vec::new()})}
    fn returned(e:&Entry){e.dispatch_returned("github-preflight-1",p::Reason::None,p::Effect::None,Self::result());}
}

#[test]
fn producer_positive_requires_same_native_relay_and_latest_history_returns() {
    for native_first in [false,true] {
        let f=F::new();let c=f.claim();let e=c.entry().clone();F::arm(&e,true);
        let progress=e.claim_history().unwrap().unwrap();
        if native_first {F::returned(&e);assert!(!e.positively_returned("github-preflight-1"));}
        c.returned(Ok(()));if !native_first{F::returned(&e);}
        assert_eq!(e.status().unwrap().state,p::State::Finishing);
        assert!(!e.positively_returned("github-preflight-1"));
        progress.returned(Ok(())).unwrap(); // progress ACK cannot stand in for the final fact
        assert!(!e.positively_returned("github-preflight-1"));
        e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
        assert!(e.positively_returned("github-preflight-1"));
        assert!(!e.positively_returned("github-preflight-2"));
        assert!(f.scope.current(false).is_err()); // retired consumer is NOT producer authority
        assert!(e.status().unwrap().result.is_some());
    }
}

#[test]
fn missing_go_result_or_history_return_never_makes_a_positive_producer() {
    for cut in 0..4 {
        let f=F::new();let c=f.claim();let e=c.entry().clone();F::arm(&e,cut!=0);
        e.dispatch_returned("github-preflight-1",p::Reason::None,p::Effect::None,if cut==1{None}else{F::result()});
        if cut==2 {drop(c);} else {c.returned(Ok(()));}
        if cut==3 {drop(e.claim_history().unwrap().unwrap());}
        assert_eq!(e.status().unwrap().state,p::State::Unknown);
        assert!(!e.positively_returned("github-preflight-1"));
        F::returned(&e);assert!(!e.positively_returned("github-preflight-1"));
        assert!(e.pending());assert!(e.status().unwrap().result.is_none());
    }
}

#[test]
fn refused_before_entry_is_never_a_prepared_producer_and_stop_keeps_earliest_read() {
    let f=F::new();let c=f.claim();let e=c.entry().clone();c.returned(Err(p::Reason::ContextChanged));
    e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
    assert!(e.status().unwrap().never_admitted);assert!(!e.positively_returned("github-preflight-1"));
    let f=F::new();let c=f.claim();let e=c.entry().clone();F::arm(&e,true);
    let at=Instant::now();e.cancel(p::Reason::UserCancelled,at);f.scope.read.revoke(at-Duration::from_secs(1));
    assert_eq!(e.first_stop(),Some((false,at-Duration::from_secs(1))));
    F::returned(&e);c.returned(Ok(()));e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
    assert!(!e.positively_returned("github-preflight-1"));assert!(e.status().unwrap().result.is_none());
}

#[test]
fn completed_producer_cancel_cannot_revoke_a_different_successor_scope() {
    let f=F::new();let c=f.claim();let e=c.entry().clone();F::arm(&e,true);F::returned(&e);c.returned(Ok(()));
    e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
    let successor=scope(&f._doc,p::Kind::ReleasePending);
    f.inbox.allow(successor.clone(),id(5)).unwrap();
    f.inbox.query(e.origin(),true).unwrap();
    assert!(e.positively_returned("github-preflight-1"));assert!(successor.current(false).is_ok());
    assert_eq!(f.inbox.access().unwrap().grant_id,Some(id(5)));
}

#[test]
fn mixed_old_and_new_rows_share_original_thirty_two_limit_and_keep_all_snapshots() {
    let doc=Arc::new(());let inbox=Inbox::new(id(2));
    let kinds=[p::Kind::RepositoryCreate,p::Kind::PreflightPending,p::Kind::ReleasePending,p::Kind::PublicationPending];
    for n in 0..p::REQUEST_LIMIT {
        let kind=kinds[n%kinds.len()];let s=scope(&doc,kind);let grant=id(100+n as u64);
        inbox.allow(s,grant.clone()).unwrap();inbox.submit(p::Submit{origin:p::Query{project_id:id(1),service_instance:id(2),request_id:id(1000+n as u64)},grant_id:grant}).unwrap();
        let c=inbox.claim().unwrap().unwrap();let e=c.entry().clone();let op=format!("{}1",kind.prefix());
        e.entering().unwrap();e.arm(&op).unwrap();e.go(&op).unwrap();
        if kind==p::Kind::RepositoryCreate {e.returned_native(&op,p::Reason::None,p::Effect::CreatedObserved);}
        else {e.dispatch_returned(&op,p::Reason::None,p::Effect::None,F::result());}
        c.returned(Ok(()));e.claim_history().unwrap().unwrap().returned(Ok(())).unwrap();
        assert!(e.positively_returned(&op));
    }
    let rows=inbox.entries().unwrap();assert_eq!(rows.len(),32);
    assert_eq!(rows.iter().filter(|e|e.status().unwrap().result.is_some()).count(),24);
    assert_eq!(inbox.allow(scope(&doc,p::Kind::PreflightPending),id(999)).err(),Some(Error::Busy));
    assert_eq!(inbox.entries().unwrap().len(),32);
}
