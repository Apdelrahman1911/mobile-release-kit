//! Startup refusal categories, not environment-origin or authentication proof.
//! This DATA seam neither reads nor mutates the ambient process environment.
use std::ffi::OsString;

pub(crate) fn refusal<F, I>(argc: usize, environment_names: F) -> Option<i32>
where
    F: FnOnce() -> I,
    I: IntoIterator<Item = OsString>,
{
    // Preserve the original short circuit: bad argc never reads environment.
    if argc != 1 {
        return Some(64);
    }
    let mut names = environment_names().into_iter();
    match names.next() {
        None => None,
        Some(name) if name == "__CF_USER_TEXT_ENCODING" && names.next().is_none() => Some(65),
        Some(_) => Some(66),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argc_refusal_does_not_observe_environment() {
        for argc in [0, 2, usize::MAX] {
            assert_eq!(refusal(argc, || -> std::iter::Empty<OsString> {
                panic!("environment must stay unobserved")
            }), Some(64));
        }
    }

    #[test]
    fn only_empty_environment_keeps_the_existing_work_admission() {
        assert_eq!(refusal(1, std::iter::empty::<OsString>), None);
        assert_eq!(refusal(1, || [OsString::from("__CF_USER_TEXT_ENCODING")]), Some(65));
        for names in [vec!["OTHER"], vec!["__CF_USER_TEXT_ENCODING", "OTHER"],
            vec!["OTHER", "__CF_USER_TEXT_ENCODING"],
            vec!["__CF_USER_TEXT_ENCODING", "__CF_USER_TEXT_ENCODING"],
            vec!["__cf_user_text_encoding"], vec!["__CF_USER_TEXT_ENCODING_EXTRA"], vec![""]]
        {
            assert_eq!(refusal(1, || names.into_iter().map(OsString::from)), Some(66));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_name_is_refused_without_string_conversion() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(refusal(1, || [OsString::from_vec(vec![0xff])]), Some(66));
    }
}
