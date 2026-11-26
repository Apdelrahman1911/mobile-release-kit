//! Same original journal codec, no Store or NativeUse receipt fabricated.
use super::*;
use crate::git_upstream_protocol::tests as data;
fn project(n:u8)->ProjectBinding{ProjectBinding{project_id:crate::service_protocol::Id::parse(&format!("{n:032x}")).unwrap(),canonical_root:"/inert/project".into(),device:1,inode:2}}
fn row(n:u8)->Row{Row::preparing(&project(n),&format!("upstream-{n}"),&wire::Review::Upstream(data::review())).unwrap()}
#[test]
fn schema_nine_is_only_explicit_upstream_write_and_preserves_old_rows() {
    let legacy=Row::preparing(&project(1),"legacy",&wire::Review::Files(wire::FileReview{action:wire::Kind::Stage,expected_revision:"a".repeat(64),
        paths:vec!["a.txt".into()],whole_index:false,head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)})).unwrap();
    for version in 1..=8 {
        let mut state=State{protocol:PROTOCOL.into(),schema_version:version,rows:vec![legacy.clone()]};
        let before=Snapshot{revision:Revision(4),bytes:state.bytes().unwrap()};
        assert_eq!(State::decode(&before).unwrap().bytes().unwrap(),before.bytes);
        assert!(!String::from_utf8(before.bytes).unwrap().contains("upstream"));
        state.reserve(row(2)).unwrap();assert_eq!(state.schema_version,9);assert!(state.rows[0]==legacy);
        let after=Snapshot{revision:Revision(5),bytes:state.bytes().unwrap()};
        assert_eq!(State::decode(&after).unwrap().bytes().unwrap(),after.bytes);
        state.schema_version=8;assert!(state.bytes().is_err());
    }
}
#[test]
fn upstream_candidate_and_partial_directories_never_allow_no_effect_or_retry() {
    let mut original=row(1);let i=wire::Intent::Upstream(data::intent());
    original.candidate(&i).unwrap();assert!(original.candidate(&i).is_err());
    assert!(original.clone().finish(Completion::Succeeded).is_err());
    assert!(original.clone().finish(Completion::Failed).is_err());assert!(original.clone().finish(Completion::Cancelled).is_err());
    let partial=crate::git_upstream_protocol::FinalData{effect_phase:"directories-returned".into(),retained_paths:vec![".git/refs/remotes/origin".into()]};
    assert!(original.clone().finish_with_upstream(Completion::Succeeded,None,None,None,None,None,Some(&partial)).is_err());
    original.finish_with_upstream(Completion::RecoveryRequired,None,None,None,None,None,Some(&partial)).unwrap();assert!(!original.replaceable());
    let mut state=State{protocol:PROTOCOL.into(),schema_version:9,rows:vec![original]};let before=state.bytes().unwrap();
    assert!(state.reserve(row(1)).is_err());assert_eq!(before,state.bytes().unwrap());
    let mut success=row(2);success.candidate(&i).unwrap();
    let done=crate::git_upstream_protocol::FinalData{effect_phase:"config-returned".into(),retained_paths:vec![]};
    success.finish_with_upstream(Completion::Succeeded,None,None,None,None,None,Some(&done)).unwrap();assert!(success.replaceable());
}
