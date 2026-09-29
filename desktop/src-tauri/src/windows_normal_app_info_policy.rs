//! Qualification-observer DATA only, not a capability, invocation or native permit.
//!
//! The normal original Windows session already advertises these seven methods.
//! Project-draft still verifies six methods; credential-session verifies one;
//! lifecycle cases claim no method credit. This set must not supply that credit.
//! No producer flag, original session, DTO or operating-system resource is changed.

pub(crate) const AVAILABLE_METHODS: [&str; 7] = [
    "capabilities", "catalog", "project.snapshot", "config.validate",
    "config.suggest", "config.preview", "credentials.assess",
];
const MAX_METHOD_ROWS: usize = 64;

/// Admits a closed available set, not a schema for unavailable descriptive rows.
/// Every availability value is Boolean. A true row must name exactly one member;
/// false rows grant nothing, so their optional names retain the old semantics.
/// The slice caller supplies already-returned DATA. Even a longer iterator is
/// consumed only through the first forbidden (65th) row, without collecting it.
pub(crate) fn available_method_set<'a>(
    rows: impl IntoIterator<Item = (Option<&'a str>, Option<bool>)>,
) -> bool {
    let mut count = 0usize;
    let mut seen = 0u8;
    for (name, available) in rows.into_iter().take(MAX_METHOD_ROWS + 1) {
        count += 1; // at most65, never an unbounded counter
        if count > MAX_METHOD_ROWS { return false; }
        match available {
            Some(false) => {},
            Some(true) => {
                let Some(index) = name.and_then(|name|
                    AVAILABLE_METHODS.iter().position(|expected| *expected == name))
                    else { return false; };
                let bit = 1u8 << index;
                if seen & bit != 0 { return false; }
                seen |= bit;
            },
            None => return false,
        }
    }
    count >= AVAILABLE_METHODS.len() && seen == (1u8 << AVAILABLE_METHODS.len()) - 1
}

/// The Environment page reports advertised rows, not executed/verified methods.
/// Bound the retained total before subtraction and before any numeric conversion.
pub(crate) fn environment_counts_match(
    method_rows: usize,
    rows: Option<u64>,
    available: Option<u64>,
    unavailable: Option<u64>,
) -> bool {
    (AVAILABLE_METHODS.len()..=MAX_METHOD_ROWS).contains(&method_rows)
        && rows == Some(method_rows as u64)
        && available == Some(AVAILABLE_METHODS.len() as u64)
        && unavailable == Some((method_rows - AVAILABLE_METHODS.len()) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_rows() -> Vec<(Option<&'static str>, Option<bool>)> {
        AVAILABLE_METHODS.iter().copied().map(|name| (Some(name), Some(true))).collect()
    }

    #[test]
    fn exact_and_reordered_seven_are_available_data_only() {
        assert_eq!(AVAILABLE_METHODS, [
            "capabilities", "catalog", "project.snapshot", "config.validate",
            "config.suggest", "config.preview", "credentials.assess",
        ]);
        assert!(available_method_set(exact_rows()));
        let mut rows = exact_rows(); rows.reverse();
        assert!(available_method_set(rows));
        // Actual per-case invocation/verification credit is intentionally absent
        // from this module; the observer retains its separate6/1/0 facts.
    }

    #[test]
    fn every_missing_or_disabled_member_is_refused() {
        for index in 0..AVAILABLE_METHODS.len() {
            let mut missing = exact_rows(); missing.remove(index);
            assert!(!available_method_set(missing.clone()));
            missing.push((Some("unrelated.description"), Some(false)));
            assert!(!available_method_set(missing));
            let mut disabled = exact_rows(); disabled[index].1 = Some(false);
            assert!(!available_method_set(disabled));
        }
        assert!(!available_method_set(exact_rows().into_iter().take(6)));
    }

    #[test]
    fn duplicates_and_unexpected_true_names_are_refused() {
        for index in 0..AVAILABLE_METHODS.len() {
            let mut duplicate = exact_rows();
            duplicate[index].0 = Some(AVAILABLE_METHODS[(index + 1) % AVAILABLE_METHODS.len()]);
            assert!(!available_method_set(duplicate));
        }
        let mut duplicate_extra = exact_rows(); duplicate_extra.push((Some("credentials.assess"), Some(true)));
        assert!(!available_method_set(duplicate_extra));
        let mut unknown_extra = exact_rows(); unknown_extra.push((Some("unexpected.available"), Some(true)));
        assert!(!available_method_set(unknown_extra));
        let mut substitution = exact_rows(); substitution[6].0 = Some("unexpected.available");
        assert!(!available_method_set(substitution));
    }

    #[test]
    fn missing_boolean_and_malformed_true_names_are_refused() {
        for index in 0..AVAILABLE_METHODS.len() {
            let mut no_boolean = exact_rows(); no_boolean[index].1 = None;
            assert!(!available_method_set(no_boolean));
            let mut no_name = exact_rows(); no_name[index].0 = None;
            assert!(!available_method_set(no_name));
        }
        let mut extra = exact_rows(); extra.push((None, None));
        assert!(!available_method_set(extra));
        let mut wrong_case = exact_rows(); wrong_case[6].0 = Some("Credentials.Assess");
        assert!(!available_method_set(wrong_case));
        let mut empty_name = exact_rows(); empty_name[6].0 = Some("");
        assert!(!available_method_set(empty_name));
    }

    #[test]
    fn false_rows_are_non_authoritative_and_totals_are_bounded() {
        let mut rows = exact_rows();
        rows.extend([(Some("not.in.the.available.set"), Some(false)),
            (None, Some(false)), (Some("credentials.assess"), Some(false))]);
        assert!(available_method_set(rows.clone()));
        rows.resize(MAX_METHOD_ROWS, (None, Some(false)));
        assert!(available_method_set(rows.clone()));
        rows.push((None, Some(false)));
        assert!(!available_method_set(rows));
        assert!(!available_method_set(std::iter::empty::<(Option<&str>, Option<bool>)>()));
    }

    #[test]
    fn infinite_false_tail_stops_at_the_first_forbidden_row() {
        let observed_tail = std::cell::Cell::new(0usize);
        let tail = std::iter::repeat((None, Some(false))).inspect(|_| {
            observed_tail.set(observed_tail.get() + 1);
        });
        assert!(!available_method_set(exact_rows().into_iter().chain(tail)));
        assert_eq!(observed_tail.get(), MAX_METHOD_ROWS + 1 - AVAILABLE_METHODS.len());
    }

    #[test]
    fn environment_uses_seven_available_not_six_executed() {
        for total in AVAILABLE_METHODS.len()..=MAX_METHOD_ROWS {
            let total = total as u64;
            assert!(environment_counts_match(total as usize, Some(total), Some(7), Some(total - 7)));
            assert!(!environment_counts_match(total as usize, Some(total), Some(6), Some(total - 6)));
            assert!(!environment_counts_match(total as usize, Some(total + 1), Some(7), Some(total - 7)));
            assert!(!environment_counts_match(total as usize, Some(total), Some(7), Some(total - 6)));
        }
        assert!(environment_counts_match(14, Some(14), Some(7), Some(7)));
    }

    #[test]
    fn environment_refuses_missing_and_out_of_range_counts_without_underflow() {
        for total in [0, 6, 65, usize::MAX] {
            assert!(!environment_counts_match(total, Some(14), Some(7), Some(7)));
        }
        assert!(!environment_counts_match(14, None, Some(7), Some(7)));
        assert!(!environment_counts_match(14, Some(14), None, Some(7)));
        assert!(!environment_counts_match(14, Some(14), Some(7), None));
        assert!(!environment_counts_match(14, Some(u64::MAX), Some(7), Some(7)));
        assert!(!environment_counts_match(14, Some(14), Some(u64::MAX), Some(7)));
        assert!(!environment_counts_match(14, Some(14), Some(7), Some(u64::MAX)));
    }
}
