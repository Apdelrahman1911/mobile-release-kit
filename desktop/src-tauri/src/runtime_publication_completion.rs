// Pure transaction policy shared by Linux IO and portable DATA tests.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Action { Publish, Verify, Record, Refuse }
pub(super) fn action(final_exists: bool, stage: bool, pending: bool, record: bool, settled: bool) -> Action {
    if stage || pending { return Action::Refuse; }
    match (final_exists, record, settled) {
        (false, false, false) => Action::Publish,
        (true, true, false) => Action::Verify,
        (true, false, true) => Action::Record,
        _ => Action::Refuse,
    }
}
pub(super) fn exact(record: &[u8], current: &[u8]) -> bool {
    !record.is_empty() && record == current
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn completed_reconfigure_verifies() { assert_eq!(action(true,false,false,true,false),Action::Verify); }
    #[test] fn unknown_final_refuses() { assert_eq!(action(true,false,false,false,false),Action::Refuse); }
    #[test] fn interrupted_states_refuse() {
        for final_exists in [false,true] { for record in [false,true] { for settled in [false,true] {
            assert_eq!(action(final_exists,true,false,record,settled),Action::Refuse);
            assert_eq!(action(final_exists,false,true,record,settled),Action::Refuse);
        }}}
    }
    #[test] fn original_success_required_before_record() {
        assert_eq!(action(true,false,false,false,true),Action::Record);
        assert_eq!(action(false,false,false,false,true),Action::Refuse);
        assert_eq!(action(true,false,false,true,true),Action::Refuse);
    }
    #[test] fn new_only_when_names_absent() { assert_eq!(action(false,false,false,false,false),Action::Publish); }
    #[test] fn orphan_record_refuses() { assert_eq!(action(false,false,false,true,false),Action::Refuse); }
    #[test] fn equal_hash_different_native_identity_refuses() {
        assert!(!exact(b"sha:same;dev:1;ino:2;ctime:3",b"sha:same;dev:1;ino:4;ctime:3"));
        assert!(!exact(b"sha:same;dev:1;ino:2;ctime:3",b"sha:same;dev:1;ino:2;ctime:4"));
    }
    #[test] fn unchanged_retained_data_is_not_modified_by_decision() {
        let tree = b"old unknown and completed runtimes".to_vec(); let before=tree.clone();
        for _ in 0..3 { assert_eq!(action(true,false,false,true,false),Action::Verify); assert!(exact(&tree,&before)); }
        assert_eq!(tree,before); assert!(!exact(b"",b""));
    }
}
