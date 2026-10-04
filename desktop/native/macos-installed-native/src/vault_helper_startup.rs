//! Parsed startup-input hygiene, not environment-origin or authentication proof.
//! This DATA seam neither reads nor mutates the ambient process environment.
use std::ffi::{OsStr, OsString};

/// Parsed scalars only. This is not descriptor ownership or parent identity.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct GateHandoff{pub(crate) descriptor:i32,pub(crate) parent_pid:i32}
fn decimal(value:&OsStr,minimum:i32)->Option<i32>{
    let text=value.to_str()?;
    if text.is_empty() || text.len()>10 || text.starts_with('0') || !text.bytes().all(|b|b.is_ascii_digit()){return None;}
    text.parse::<i32>().ok().filter(|value|*value>=minimum)
}
pub(crate) fn gate_handoff(arguments:impl IntoIterator<Item=OsString>)->Option<GateHandoff>{
    let mut arguments=arguments.into_iter();
    arguments.next()?;
    if arguments.next()?.as_os_str()!=OsStr::new("--mrk-vault-worker-gate-v1"){return None;}
    let descriptor=decimal(&arguments.next()?,3)?;
    let parent_pid=decimal(&arguments.next()?,2)?;
    if arguments.next().is_some(){return None;}
    Some(GateHandoff{descriptor,parent_pid})
}

// Canonical historical CF writer representation only, not permissive strtol.
fn canonical_hex(value: &[u8]) -> Option<u32> {
    let digits = value.strip_prefix(b"0x")?;
    if digits.is_empty() || digits.len() > 8 || (digits.len() > 1 && digits[0] == b'0') {
        return None;
    }
    let mut number = 0u32;
    for &digit in digits {
        let digit = match digit {
            b'0'..=b'9' => digit - b'0',
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        number = number.checked_mul(16)?.checked_add(u32::from(digit))?;
    }
    Some(number)
}

fn valid_cf_value(value: &OsStr, uid: u32) -> bool {
    let bytes = value.as_encoded_bytes();
    if uid == 0 || bytes.len() > 32 {
        return false;
    }
    let mut parts = bytes.split(|byte| *byte == b':');
    let Some(encoded_uid) = parts.next().and_then(canonical_hex) else { return false; };
    let Some(script) = parts.next() else { return false; };
    let Some(region) = parts.next() else { return false; };
    if parts.next().is_some() || encoded_uid != uid {
        return false;
    }
    // Missing-file fallback, or the two-UInt32 CF preference writer form.
    (script == b"0" && region == b"0")
        || (canonical_hex(script).is_some() && canonical_hex(region).is_some())
}

pub(crate) fn refusal<F, I, U>(argc: usize, environment: F, current_uid: U) -> Option<i32>
where
    F: FnOnce() -> I,
    I: IntoIterator<Item = (OsString, OsString)>,
    U: FnOnce() -> u32,
{
    // Preserve the original short circuit: bad argc observes neither input.
    if argc != 4 {
        return Some(64);
    }
    let mut entries = environment().into_iter();
    let Some((name, value)) = entries.next() else { return None; };
    // Set membership/cardinality precede value interpretation and UID lookup.
    if name != "__CF_USER_TEXT_ENCODING" || entries.next().is_some() {
        return Some(66);
    }
    if valid_cf_value(&value, current_uid()) { None } else { Some(65) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_private_gate_handoff_is_required_before_environment_admission(){
        let valid=["helper","--mrk-vault-worker-gate-v1","3","2"].map(OsString::from);
        assert_eq!(gate_handoff(valid.clone()),Some(GateHandoff{descriptor:3,parent_pid:2}));
        for end in 0..4{assert!(gate_handoff(valid[..end].to_vec()).is_none());}
        let mut extra=valid.to_vec();extra.push(OsString::from("extra"));assert!(gate_handoff(extra).is_none());
        let mut wrong=valid.clone();wrong[1]=OsString::from("--mrk-installed-entry-v1");assert!(gate_handoff(wrong).is_none());
        for (index,minimum) in [(2,3),(3,2)]{
            for bad in ["","0","01","+3","-3"," 3","3 ","3\n","2147483648","99999999999","é"]{
                let mut args=valid.clone();args[index]=OsString::from(bad);assert!(gate_handoff(args).is_none());
            }
            let mut args=valid.clone();args[index]=OsString::from((minimum-1).to_string());assert!(gate_handoff(args).is_none());
        }
    }
    #[cfg(unix)]
    #[test]
    fn non_utf8_gate_arguments_are_not_converted_or_owned(){
        use std::os::unix::ffi::OsStringExt;
        for index in 1..4{
            let mut args=["helper","--mrk-vault-worker-gate-v1","3","2"].map(OsString::from);
            args[index]=OsString::from_vec(vec![0xff]);assert!(gate_handoff(args).is_none());
        }
    }

    fn cf(value: &str) -> [(OsString, OsString); 1] {
        [(OsString::from("__CF_USER_TEXT_ENCODING"), OsString::from(value))]
    }

    #[test]
    fn argc_refusal_does_not_observe_environment_or_uid() {
        for argc in [0, 1, 2, 3, 5, usize::MAX] {
            assert_eq!(refusal(argc, || -> std::iter::Empty<(OsString, OsString)> {
                panic!("environment must stay unobserved")
            }, || panic!("UID must stay unobserved")), Some(64));
        }
    }

    #[test]
    fn empty_environment_keeps_existing_admission_without_uid() {
        assert_eq!(refusal(4, std::iter::empty::<(OsString, OsString)>,
                          || panic!("UID must stay unobserved")), None);
    }

    #[test]
    fn only_sole_exact_cf_name_can_observe_uid() {
        for entries in [vec![("OTHER", "synthetic")],
            vec![("__CF_USER_TEXT_ENCODING", "invalid"), ("OTHER", "synthetic")],
            vec![("OTHER", "synthetic"), ("__CF_USER_TEXT_ENCODING", "0x1F5:0:0")],
            vec![("__CF_USER_TEXT_ENCODING", "0x1F5:0:0"), ("__CF_USER_TEXT_ENCODING", "0x1F5:0:0")],
            vec![("__cf_user_text_encoding", "0x1F5:0:0")],
            vec![("__CF_USER_TEXT_ENCODING_EXTRA", "0x1F5:0:0")], vec![("", "")]]
        {
            assert_eq!(refusal(4, || entries.into_iter().map(|(name, value)|
                (OsString::from(name), OsString::from(value))),
                || panic!("UID must stay unobserved")), Some(66));
        }
    }

    #[test]
    fn canonical_fallback_and_writer_accept_matching_uid_and_u32_preferences() {
        let maximum = "0xFFFFFFFF:0xFFFFFFFF:0xFFFFFFFF";
        assert_eq!(maximum.len(), 32);
        for (value, uid) in [("0x1F5:0:0", 501), ("0x1F5:0x0:0x0", 501),
            ("0x1F5:0x19:0xAB", 501), ("0x1:0xFFFFFFFF:0xFFFFFFFF", 1),
            (maximum, u32::MAX)]
        {
            assert_eq!(refusal(4, || cf(value), || uid), None);
        }
    }

    #[test]
    fn malformed_noncanonical_or_oversized_values_are_refused() {
        for value in ["", "0x1F5", "0x1F5:0", "0x1F5:0:0:0", "0x1F5:0:0suffix",
            "0x1F5:0x0:0", "0x1F5:0:0x0", "0x1F5:1:1", "501:0:0", "0X1F5:0:0",
            "0x1f5:0:0", "0x01F5:0:0", "0x1F5:0x00:0x0", "0x1F5:0x0:0x01",
            "0x:0:0", "0x1F5:0x:0x0", "0x1F5:0x0:0x", "0x1F5:0xG:0x0",
            "0x1F5:0x0:0xa", "+0x1F5:0:0", "0x1F5:-1:0", " 0x1F5:0:0",
            "0x1F5:0:0 ", "0x1F5:0:0\n", "0x1F5:0:0\0", "0x1F5:0x0:0xé",
            "0x100000000:0:0", "0x1F5:0x100000000:0x0", "0x1F5:0x0:0x100000000",
            "0xFFFFFFFF:0xFFFFFFFF:0xFFFFFFFF0"]
        {
            assert_eq!(refusal(4, || cf(value), || 501), Some(65));
        }
    }

    #[test]
    fn uid_must_be_matching_and_nonzero() {
        for (value, uid) in [("0x0:0:0", 0), ("0x1F5:0:0", 0),
            ("0x1F6:0:0", 501), ("0x0:0x0:0x0", 501)]
        {
            assert_eq!(refusal(4, || cf(value), || uid), Some(65));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_and_values_are_refused_without_conversion() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(refusal(4, || [(OsString::from_vec(vec![0xff]), OsString::from("synthetic"))],
            || panic!("UID must stay unobserved")), Some(66));
        assert_eq!(refusal(4, || [(OsString::from("__CF_USER_TEXT_ENCODING"),
            OsString::from_vec(b"0x1F5:0x0:0x\xff".to_vec()))], || 501), Some(65));
    }
}
