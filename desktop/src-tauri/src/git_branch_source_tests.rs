//! Mac-source DATA selection only, not native file/Account/Book proof.
use super::*;

fn review()->wire::Review {
    wire::Review::Branch(crate::git_branch_protocol::Review {
        action:crate::git_branch_protocol::Kind::Create,name:"next".into(),target_ref:"refs/heads/next".into(),
        expected_revision:"a".repeat(64),expected_reference_revision:"c".repeat(64),head:"1".repeat(40),
        branch:Some("refs/heads/main".into()),expected_index:"2".repeat(64),review_digest:"b".repeat(64)})
}

#[test]
fn new_branch_source_head_stays_original_and_only_destination_must_be_absent() {
    let (head,target,absent)=reference_selection(&review()).unwrap();
    assert_eq!(head,"ref: refs/heads/main\n");assert_eq!(target,"refs/heads/next");assert!(absent);
    let mut detached=review();let wire::Review::Branch(v)=&mut detached else {panic!()};v.branch=None;
    let (head,target,absent)=reference_selection(&detached).unwrap();
    assert_eq!(head,format!("{}\n","1".repeat(40)));assert_eq!(target,"refs/heads/next");assert!(absent);
    let mut mismatched=review();let wire::Review::Branch(v)=&mut mismatched else {panic!()};v.target_ref="refs/heads/main".into();
    assert!(reference_selection(&mismatched).is_err());
}

#[test]
fn old_commit_ref_edge_retains_its_own_branch_and_stage_cannot_select_a_ref() {
    let mut r=wire::FileReview {action:wire::Kind::Commit,expected_revision:"a".repeat(64),
        paths:vec!["a.txt".into()],whole_index:true,head:Some("1".repeat(40)),branch:Some("refs/heads/main".into()),
        expected_index:"2".repeat(64),review_digest:"b".repeat(64)};
    let (head,target,absent)=reference_selection(&wire::Review::Files(r.clone())).unwrap();
    assert_eq!(head,"ref: refs/heads/main\n");assert_eq!(target,"refs/heads/main");assert!(!absent);
    r.head=None;assert!(reference_selection(&wire::Review::Files(r.clone())).is_ok());
    r.action=wire::Kind::Stage;r.whole_index=false;
    assert!(reference_selection(&wire::Review::Files(r.clone())).is_err());
    r.action=wire::Kind::Commit;r.whole_index=true;r.head=Some("1".repeat(40));r.branch=None;
    assert!(reference_selection(&wire::Review::Files(r)).is_err());
}
