//! Original codec DATA tests, not native custody, private Git or real mkdir.
use super::*;
use serde_json::{json, Value};
use crate::git_switch_protocol::tests as old;
pub(crate) fn action()->Action {Action {kind:Kind::SetUpstream,expected_revision:"a".repeat(64),expected_reference_revision:"b".repeat(64),
    branch:"refs/heads/main".into(),head:"1".repeat(40),remote:"origin".into(),repository:"example/project".into(),identity:None}}
pub(crate) fn review()->Review {let a=action();Review {action:a.kind,remote:a.remote,repository:a.repository,
    expected_revision:a.expected_revision,expected_reference_revision:a.expected_reference_revision,branch:a.branch,head:a.head,
    expected_index:"2".repeat(64),original_config:"2".repeat(64),additions:vec![
        Addition{key:"remote.origin.url".into(),value:"https://github.com/example/project.git".into()},
        Addition{key:"remote.origin.fetch".into(),value:"+refs/heads/*:refs/remotes/origin/*".into()},
        Addition{key:"branch.main.remote".into(),value:"origin".into()},Addition{key:"branch.main.merge".into(),value:"refs/heads/main".into()}],
    missing_directories:paths("refs/remotes/origin/main").into_iter().filter(|p|p!=".").collect(),unchanged:false,review_digest:"f".repeat(64)}}
pub(crate) fn intent()->Intent {let r=review();Intent {action:r.action,expected_revision:r.expected_revision,expected_reference_revision:r.expected_reference_revision,
    expected_ref:r.branch,expected_head:r.head,expected_index:r.expected_index,original_config:r.original_config,candidate_config:"3".repeat(64),
    remote:r.remote,repository:r.repository,missing_directories:r.missing_directories,config_changed:true,
    working:Working{root:(1,3,0o40700,1001,1001,3,4096,123,456),locks:[20,21,22].map(|n|(1,n,0o100600,1001,1001,1,0,123,456)),
        scratch:"mrk-git-abcdefgh".into(),scratch_identity:(1,23,0o40700,1001,1001,2,4096,123,456),index_identity:(1,24,0o100600,1001,1001,1,12,123,456)}}}
fn sources()->Sources {Sources {parents:vec![Parent{name:".".into(),identity:(1,3,0o40700,1001,1001,2,4096,123,456),
    names:vec!["HEAD".into(),"config".into(),"index".into(),"objects".into()]}],missing:review().missing_directories,reference:None,log:None}}
fn request(phase:local::Phase)->local::Request {local::Request::from_upstream_original("upstream-original",&local::Action::Upstream(action()),
    &read::Context{project_id:"runtime-alias".into(),generation:1,revision:"document-2".into()},&old::native(),
    read::Clock{work_end_ns:100_000_000_000,hard_end_ns:110_000_000_000},
    (phase==local::Phase::Apply).then(||local::ApplyBinding{review:local::Review::Upstream(review()),journal_revision:4}),sources()).unwrap()}
fn candidate(r:&local::Request)->local::Candidate {r.candidate(&old::raw(json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
    "reviewDigest":review().review_digest,"intent":intent()}))).unwrap()}
#[test]
fn exact_local_action_keeps_initialize_and_other_wire_shapes_closed() {
    let v=json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":action()});
    let local::Command::Prepare(p)=local::decode_command("git_local_prepare",&old::raw(v.clone())).unwrap() else {panic!()};
    assert!(p.action.kind()==local::Kind::SetUpstream&&p.action.valid());
    assert_eq!(serde_json::to_value(p.action.public()).unwrap(),json!(action()));
    for key in ["token","url","push","fetch","targetOid","paths","argv"] {let mut bad=v.clone();bad["action"][key]=Value::Null;
        assert!(local::decode_command("git_local_prepare",&old::raw(bad)).is_err());}
    let mut absent=v.clone();absent["action"].as_object_mut().unwrap().remove("identity");
    assert!(local::decode_command("git_local_prepare",&old::raw(absent)).is_err());
    assert!(local::decode_command("git_local_prepare",&old::raw(json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":{"kind":"initialize"}}))).is_ok());
    assert!(!alias("origin.url")&&!repository("https://github.com/example/project.git"));
}
#[test]
fn source_absence_requires_exact_parent_entries_not_none_as_an_observation() {
    let n=old::native();let a=action();assert!(sources().valid(&n,&a));
    let mut s=sources();s.parents.clear();assert!(!s.valid(&n,&a));
    let mut s=sources();s.parents[0].names.push("refs".into());assert!(!s.valid(&n,&a));
    let mut s=sources();s.parents[0].names.push("Refs".into());s.parents[0].names.sort();assert!(!s.valid(&n,&a));
    let mut s=sources();s.missing.remove(0);assert!(!s.valid(&n,&a));
    assert!(local::Request::from_original("upstream-original",&local::Action::Upstream(a),&request(local::Phase::Prepare).context,
        &n,request(local::Phase::Prepare).clock,None).is_err());
}
#[test]
fn additions_preserve_original_prefix_identity_and_existing_config_limit() {
    let original=b"[core]\n\tbare = false\n# keep this exact comment\n";
    let r=review();assert!(r.matches(&action()));let mut raw=original.to_vec();
    raw.extend_from_slice(b"[remote \"origin\"]\n\turl = https://github.com/example/project.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n");
    assert_eq!(appended(original,&r.additions).unwrap(),raw);
    let mut partial=r.clone();partial.additions.remove(0);assert!(!partial.valid());
    let mut changed=r;changed.additions[0].value="https://github.com/other/project.git".into();assert!(!changed.matches(&action()));
    assert!(appended(&vec![b'\n';CONFIG_LIMIT as usize],&review().additions).is_none());
    for name in ["Guessed#Name","Bad;Name","Wrong\nName"] {assert!(!Identity{name:name.into(),email:"a@example.test".into()}.valid());}
}
#[test]
fn directory_ack_is_candidate_bound_under_original_512_bytes() {
    let r=request(local::Phase::Apply);let c=candidate(&r);let i=intent();let before=sources().parents;
    let digest=directory_digest(&i,&before,&before).unwrap();
    let raw=r.upstream_ack(&c,5,&digest).unwrap();assert!(raw.len()<=local::READY_LIMIT);
    assert!(raw.starts_with(b"MRK-GIT-UPSTREAM-ACK/1 "));assert!(r.ack(&c,5).is_err());
    assert!(r.upstream_ack(&c,6,&digest).is_err());assert!(r.upstream_ack(&c,5,"not-a-hash").is_err());
    let mut new=i.clone();new.working.locks[0].1+=100;
    assert_ne!(digest,directory_digest(&new,&before,&before).unwrap());
    let mut after=before.clone();after[0].names.push("foreign".into());
    assert_ne!(digest,directory_digest(&i,&before,&after).unwrap());
}
#[test]
fn public_result_omits_working_paths_and_stats_but_retains_uncertain_custody() {
    let i=intent();let v=json!({"intent":i,"effectPhase":"directories-returned","retainedPaths":[".git/config",".git/mrk-git-abcdefgh",".git/mrk-git-abcdefgh/index"]});
    let out=public_result(local::Kind::SetUpstream,local::Phase::Apply,v.clone());
    assert!(out["intent"].get("working").is_none());assert!(read::digest(out["intent"]["workingSha256"].as_str().unwrap()));
    assert_eq!(out["retainedPaths"],json!([".git/config"]));assert_eq!(out["retainedCandidate"],json!(true));
    assert_eq!(public_result(local::Kind::Fetch,local::Phase::Apply,v.clone()),v);
    assert!(!FinalData{effect_phase:"directories-returned".into(),retained_paths:vec![]}.successful(&i));
    assert!(FinalData{effect_phase:"config-returned".into(),retained_paths:vec![]}.successful(&i));
    let mut unchanged=review();unchanged.additions.clear();unchanged.missing_directories.clear();unchanged.unchanged=true;
    assert!(unchanged.matches(&action()));assert!(!i.matches(&unchanged));
}

#[test]
fn local_cli_selection_uses_same_closed_action_not_remote_permission() {
    use crate::service_git_repository_protocol as service;
    use crate::service_git_commit_protocol::Family;
    let raw=serde_json::to_value(action()).unwrap();
    let a:service::Action=serde_json::from_value(raw.clone()).unwrap();
    let selected=service::Selection::new(a.clone()).unwrap();
    assert!(a.validate().is_ok());
    assert_eq!(a.history_action(),crate::service_protocol::Action::GitSetUpstream);
    assert_eq!(serde_json::to_value(&selected.action).unwrap(),raw);
    let shared=service::shared::Selected::from(selected.clone());
    assert!(shared.family()==Family::Repository);
    assert!(shared.files().is_err());
    assert!(shared.validate().is_ok());
    assert!(serde_json::from_value::<crate::service_git_remote_protocol::Action>(raw.clone()).is_err());
    for key in ["identity","branch","head"] {
        let mut missing=raw.clone();missing.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<service::Action>(missing).is_err());
    }
    for key in ["url","token","trackingOid","argv","force"] {
        let mut extra=raw.clone();extra[key]=Value::Null;
        assert!(serde_json::from_value::<service::Action>(extra).is_err());
    }
    // Same public grammar without linking native modules into standalone mrk.
    // Native conversion independently checks its own Action::valid afterwards.
    let parity=|value:Value, expected:bool| {
        let wire:service::Action=serde_json::from_value(value.clone()).unwrap();
        let native:Action=serde_json::from_value(value).unwrap();
        assert_eq!(wire.validate().is_ok(),expected);
        assert_eq!(native.valid(),expected);
    };
    for (key,value,valid) in [
        ("head","f".repeat(64),true),("head","0".repeat(40),false),("head","a".repeat(39),false),
        ("expectedRevision","A".repeat(64),false),("expectedReferenceRevision","b".repeat(63),false),
        ("branch","refs/heads/team/main".into(),true),("branch","refs/heads/.hidden".into(),false),
        ("branch",format!("refs/heads/{}",vec!["a";17].join("/")),false),
        ("remote","Origin-1".into(),true),("remote","a".repeat(64),true),("remote","a".repeat(65),false),
        ("remote","_origin".into(),false),("remote","origin/path".into(),false),
        ("repository",format!("{}/{}","a".repeat(39),"b".repeat(100)),true),
        ("repository",format!("{}/repo","a".repeat(40)),false),("repository","owner/repo_".into(),false),
        ("repository","owner/repo/extra".into(),false),("repository","-owner/repo".into(),false),
    ] {let mut v=raw.clone();v[key]=json!(value);parity(v,valid);}
    for (name,email,valid) in [
        ("Émile Test".to_owned(),"User+tag@example.test".to_owned(),true),
        ("a".repeat(128),"a@bb".to_owned(),true),("a".repeat(129),"a@bb".to_owned(),false),
        (format!("{}é","a".repeat(127)),"a@bb".to_owned(),false),
        ("A\nB".into(),"a@bb".into(),false),("A#B".into(),"a@bb".into(),false),
        ("A'B".into(),"a@bb".into(),false),("A".into(),"a@b".into(),false),
        ("A".into(),"a_b@bb".into(),true),("A".into(),"a@bb-".into(),false),
        ("A".into(),"a@@bb".into(),false),("A".into(),"é@bb".into(),false),
        ("A".into(),format!("{}@bb","a".repeat(251)),true),
        ("A".into(),format!("{}@bb","a".repeat(252)),false),
    ] {let mut v=raw.clone();v["identity"]=json!({"name":name,"email":email});parity(v,valid);}
    let mut identity_extra=raw.clone();identity_extra["identity"]=json!({"name":"A","email":"a@bb","token":null});
    assert!(serde_json::from_value::<service::Action>(identity_extra).is_err());
    let mut changed=selected;changed.selection_sha256="0".repeat(64);
    assert!(changed.validate().is_err());
    assert_eq!(serde_json::to_value(service::Action::Initialize {}).unwrap(),json!({"kind":"initialize"}));
    assert!(serde_json::from_value::<service::Action>(json!({"kind":"initialize","identity":null})).is_err());
}

#[test]
fn unchanged_upstream_is_close_only_at_actual_shared_cli_start_predicate() {
    use crate::service_git_repository_protocol as service;
    let a=action();
    let selected=service::Selection::new(serde_json::from_value(json!(a)).unwrap()).unwrap();
    let r=service::Review {
        review_id:"git-local-1-review".into(),source_revision:a.expected_revision,
        reference_revision:Some(a.expected_reference_revision),expected_index:Some("2".repeat(64)),
        review_digest:"f".repeat(64),document_revision:1,registration_generation:1,
        preview:service::Preview::SetUpstream {head:a.head,branch:a.branch,remote:a.remote,
            repository:a.repository,config_changed:false,missing_directory_count:0,unchanged:true},
    };
    assert!(r.matches(&selected));
    // Original Action grammar accepts 40/64; the existing Preview remains
    // SHA1-only. This correction must not silently broaden either boundary.
    let mut wide=r.clone();
    if let service::Preview::SetUpstream {head,..}=&mut wide.preview {*head="f".repeat(64);}
    assert!(wide.validate().is_err());
    // request_start uses THIS predicate before setting row.start or queuing Apply.
    let shared=service::shared::Reviewed::from(r.clone());
    assert!(!shared.can_apply());
    assert!(shared.matches(&service::shared::Summary::Repository(selected.clone())));
    let mut changed=r.clone();
    if let service::Preview::SetUpstream {missing_directory_count,unchanged,..}=&mut changed.preview {
        *missing_directory_count=1;*unchanged=false;
    }
    assert!(changed.matches(&selected));
    assert!(service::shared::Reviewed::from(changed).can_apply());
    let mut stale=r.clone();stale.reference_revision=Some("9".repeat(64));
    assert!(!stale.matches(&selected));
    let mut malformed=r;
    if let service::Preview::SetUpstream {config_changed,..}=&mut malformed.preview {*config_changed=true;}
    assert!(malformed.validate().is_err());
    assert!(!shared.matches(&service::shared::Summary::Repository(
        service::Selection::new(service::Action::Initialize {}).unwrap())));
}
