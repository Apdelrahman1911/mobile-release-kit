// Original phase/stream predicates on supplied DATA. These tests do not spawn
// a process, exercise native pipes or qualify the original runtime/IO roster.
use super::*;
use wire::test_data as data;
fn feed(framer:&mut Framer,raw:&[u8],digest:&str,request:&wire::Request,claims:Claims) -> Result<Vec<&'static str>,BridgeError> {
    let mut events=Vec::new();
    for byte in raw {
        if let Some(event)=framer.byte(*byte,"op-1",digest,request,claims)? {
            events.push(match event {Frame::Ready=>"ready",Frame::Rechecked(_)=>"rechecked",Frame::Outcome(_)=>"outcome",Frame::Result(_)=>"result"});
            framer.consume();
        }
    }
    Ok(events)
}
fn apply() -> (wire::Request,String,wire::Rechecked) {
    let request=data::request(wire::Kind::Apply);let digest=wire::digest(&wire::encode_initial("op-1",&request).unwrap());
    let rechecked=data::rechecked(&digest,request.action.as_ref().unwrap().prepared.as_ref().unwrap());(request,digest,rechecked)
}
fn after_read(request:&wire::Request,digest:&str) -> Framer {
    let mut framer=Framer::new().unwrap();feed(&mut framer,&data::ready("op-1",digest,request.kind()),digest,request,Claims {read:false,go:false}).unwrap();framer
}
#[test]
fn lawful_split_and_coalesced_outcome_result_frames_share_one_finite_reader() {
    for chunk in [1,2,17,8192] {
        let (request,digest,rechecked)=apply();let mut framer=Framer::new().unwrap();let mut events=Vec::new();
        let ready=data::ready("op-1",&digest,wire::Kind::Apply);
        for part in ready.chunks(chunk) {events.extend(feed(&mut framer,part,&digest,&request,Claims {read:false,go:false}).unwrap());}
        for part in data::rechecked_frame("op-1",&rechecked).chunks(chunk) {events.extend(feed(&mut framer,part,&digest,&request,Claims {read:true,go:false}).unwrap());}
        let write=wire::RemoteWrite::AcknowledgedCreated {status_code:201};
        let mut both=data::remote("op-1",&rechecked,write.clone(),data::control(crate::github_connection_protocol::Reason::None));
        both.extend(data::terminal("op-1",&request,wire::Reason::None,Some(write),wire::Settlement::Confirmed,wire::Settlement::Confirmed));
        for part in both.chunks(chunk) {events.extend(feed(&mut framer,part,&digest,&request,Claims {read:true,go:true}).unwrap());}
        assert_eq!(events,["ready","rechecked","outcome","result"]);assert!(framer.finish().is_ok());
    }
}
#[test]
fn safe_apply_refusal_after_read_does_not_require_recheck_or_go() {
    let (request,digest,_)=apply();let mut framer=after_read(&request,&digest);
    let refusal=data::terminal("op-1",&request,wire::Reason::SourceChanged,None,wire::Settlement::Confirmed,wire::Settlement::Confirmed);
    assert_eq!(feed(&mut framer,&refusal,&digest,&request,Claims {read:true,go:false}).unwrap(),["result"]);assert!(framer.finish().is_ok());
    assert!(feed(&mut framer,b"x",&digest,&request,Claims {read:true,go:false}).is_err());
    let mut early=Framer::new().unwrap();assert!(feed(&mut early,&refusal,&digest,&request,Claims {read:false,go:false}).is_err());
    let mut unclaimed=after_read(&request,&digest);assert!(feed(&mut unclaimed,&refusal,&digest,&request,Claims {read:false,go:false}).is_err());
    let mut truncated=after_read(&request,&digest);feed(&mut truncated,&refusal[..refusal.len()-1],&digest,&request,Claims {read:true,go:false}).unwrap();
    assert!(truncated.finish().is_err());
}
#[test]
fn duplicate_out_of_order_missing_and_conflicting_observed_outcomes_fail_closed() {
    let (request,digest,rechecked)=apply();let ready=data::ready("op-1",&digest,wire::Kind::Apply);
    let checked=data::rechecked_frame("op-1",&rechecked);let write=wire::RemoteWrite::AcknowledgedCreated {status_code:201};
    let remote=data::remote("op-1",&rechecked,write.clone(),data::control(crate::github_connection_protocol::Reason::None));
    let mut duplicate=after_read(&request,&digest);assert!(feed(&mut duplicate,&ready,&digest,&request,Claims {read:true,go:false}).is_err());
    let mut early=after_read(&request,&digest);assert!(feed(&mut early,&remote,&digest,&request,Claims {read:true,go:false}).is_err());
    let mut unclaimed=after_read(&request,&digest);feed(&mut unclaimed,&checked,&digest,&request,Claims {read:true,go:false}).unwrap();
    assert!(feed(&mut unclaimed,&remote,&digest,&request,Claims {read:true,go:false}).is_err());
    let terminal=data::terminal("op-1",&request,wire::Reason::None,Some(write),wire::Settlement::Confirmed,wire::Settlement::Confirmed);
    let mut missing=after_read(&request,&digest);feed(&mut missing,&checked,&digest,&request,Claims {read:true,go:false}).unwrap();
    assert!(feed(&mut missing,&terminal,&digest,&request,Claims {read:true,go:true}).is_err());
    let mut conflict=after_read(&request,&digest);feed(&mut conflict,&checked,&digest,&request,Claims {read:true,go:false}).unwrap();
    feed(&mut conflict,&remote,&digest,&request,Claims {read:true,go:true}).unwrap();
    let changed=data::terminal("op-1",&request,wire::Reason::None,Some(wire::RemoteWrite::AcknowledgedUpdated {status_code:204}),wire::Settlement::Confirmed,wire::Settlement::Confirmed);
    assert!(feed(&mut conflict,&changed,&digest,&request,Claims {read:true,go:true}).is_err());
    assert_eq!(conflict.remote,Some(wire::RemoteWrite::AcknowledgedCreated {status_code:201}));
}
#[test]
fn frame_and_aggregate_ceiling_fail_promptly_without_growing_a_buffer() {
    let (request,digest,_)=apply();let mut framer=Framer::new().unwrap();
    feed(&mut framer,&vec![b'x';wire::READY_LIMIT],&digest,&request,Claims {read:false,go:false}).unwrap();
    assert_eq!(feed(&mut framer,b"x",&digest,&request,Claims {read:false,go:false}).unwrap_err().code,"stdout_limit");
    assert_eq!(framer.frame.len(),wire::READY_LIMIT);
    let mut total=Framer::new().unwrap();total.total=wire::STDOUT_LIMIT;
    assert_eq!(feed(&mut total,b"x",&digest,&request,Claims {read:false,go:false}).unwrap_err().code,"stdout_limit");assert!(total.frame.is_empty());
}
#[test]
fn read_spends_only_read_claim_and_recheck_does_not_extend_original_owner_endpoint() {
    let read=AtomicBool::new(false);let go=AtomicBool::new(false);let mut progress=Progress::default();let (_,_,checked)=apply();
    assert!(!claim_phase(wire::Kind::Apply,&read,&go,&progress,Some(&checked)));
    assert!(claim_phase(wire::Kind::Apply,&read,&go,&progress,None));assert!(read.load(Ordering::SeqCst));assert!(!go.load(Ordering::SeqCst));
    assert!(!claim_phase(wire::Kind::Apply,&read,&go,&progress,None));
    progress.rechecked=Some(checked.clone());assert!(!claim_phase(wire::Kind::Prepare,&read,&go,&progress,Some(&checked)));
    let mut wrong=checked.clone();wrong.intent_sha256="f".repeat(64);assert!(!claim_phase(wire::Kind::Apply,&read,&go,&progress,Some(&wrong)));
    assert!(claim_phase(wire::Kind::Apply,&read,&go,&progress,Some(&checked)));assert!(!claim_phase(wire::Kind::Apply,&read,&go,&progress,Some(&checked)));
    let now=Instant::now();let end=now+Duration::from_secs(10);let mut state=OwnerState::new(end,None);
    assert!(claim_clear(true,Profile::GitHubInputGroup,&state,now,false,false,false));
    assert!(!claim_clear(false,Profile::GitHubInputGroup,&state,now,false,false,false));
    assert!(!claim_clear(true,Profile::GitHubPreflight,&state,now,false,false,false));
    assert!(!claim_clear(true,Profile::GitHubInputGroup,&state,end,false,false,false));
    for (stopping,disabled,stop) in [(true,false,false),(false,true,false),(false,false,true)] {
        assert!(!claim_clear(true,Profile::GitHubInputGroup,&state,now,stopping,disabled,stop));
    }
    state.fail_at(BridgeError::protocol(),now);let cleanup=state.cleanup_endpoint;
    state.fail_at(BridgeError::timeout(),now+Duration::from_secs(1));assert_eq!(state.endpoint,end);assert_eq!(state.cleanup_endpoint,cleanup);
    assert!(!claim_clear(true,Profile::GitHubInputGroup,&state,now,false,false,false));assert_eq!(state.error.unwrap().code,"protocol_error");
}
