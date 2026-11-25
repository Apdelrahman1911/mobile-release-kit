// Original arithmetic methods with inert DATA only. No filesystem, grants,
// installed application, disk/memory availability or native admission.
#![allow(dead_code)]
/* MRK_ORIGINAL_BUDGET_CONSTANTS */
/* MRK_ORIGINAL_BUDGET_TYPES_AND_METHODS */
mod transaction {
    pub use super::MAINTENANCE_STORAGE_LIMIT;
}
mod installation_record {
    pub use super::{CONTROL_LIMIT, ORIGINAL_LIMIT};
}
mod mobile_release_desktop {
    pub mod macos_remove_record { /* MRK_ORIGINAL_REMOVAL_RECORD_LIMIT */ }
}
/* MRK_ORIGINAL_LINKED_WORK_LIMIT */
fn check(ok: bool, why: &'static str) -> std::result::Result<(), &'static str> {
    if ok { Ok(()) } else { Err(why) }
}
mod removal {
    use super::*;
    type Result<T> = std::result::Result<T, &'static str>;
    /* MRK_ORIGINAL_ARCHIVE_STORAGE_SUM */
    /* MRK_ORIGINAL_REMOVAL_PAYLOAD_ALLOCATION */
    /* MRK_ORIGINAL_REMOVAL_LINKED_QUOTE */
    pub fn exercise() {
        let old_floor = 615_746_871;
        assert_eq!(removal_archive_storage_sum_data(old_floor,1),Ok(old_floor+1));
        assert_eq!(removal_archive_storage_sum_data(MAINTENANCE_STORAGE_LIMIT-1,1),Ok(MAINTENANCE_STORAGE_LIMIT));
        assert!(removal_archive_storage_sum_data(MAINTENANCE_STORAGE_LIMIT,1).is_err());
        assert!(removal_archive_storage_sum_data(u64::MAX,1).is_err());
        let records = mobile_release_desktop::macos_remove_record::RECORD_LIMIT as u64;
        let end = MAINTENANCE_STORAGE_LIMIT-5*records-1;
        assert!(removal_payload_allocation_data(0,0,old_floor,1));
        assert!(removal_payload_allocation_data(0,0,end,1));
        assert!(!removal_payload_allocation_data(0,0,end+1,1));
        assert!(!removal_payload_allocation_data(CONTROL_LIMIT as u64,1,0,1));
        assert!(!removal_payload_allocation_data(0,0,u64::MAX,1));
        assert_eq!(removal_linked_quote_data(0,0,MAINTENANCE_STORAGE_LIMIT-5*records,0),Some((8,MAINTENANCE_STORAGE_LIMIT)));
        assert!(removal_linked_quote_data(0,0,MAINTENANCE_STORAGE_LIMIT-5*records+1,0).is_none());
        assert!(removal_linked_quote_data(ORIGINAL_LIMIT,0,0,0).is_none());
        assert!(removal_linked_quote_data(0,0,0,CONTROL_LIMIT as u64).is_none());
        assert!(removal_linked_quote_data(0,usize::MAX,0,0).is_none());
        assert!(removal_linked_quote_data(0,0,u64::MAX,0).is_none());
    }
}
/* MRK_ORIGINAL_EXISTING_BUDGET_REGRESSION */
/* MRK_ORIGINAL_UPDATE_BUDGET_REGRESSION */
fn main() {
    retained_storage_and_original_budget_arithmetic_refuse_before_effects();
    update_storage_and_first_refusal_preserve_individual_limits();
    removal::exercise();
    println!("MRK_MAINTENANCE_STORAGE_DATA=PASS");
}
