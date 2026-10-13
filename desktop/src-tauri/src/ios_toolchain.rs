//! Fixed full-Xcode selection DATA only. Native custody lives in the original
//! Darwin Book; no PATH discovery, download, xcode-select or renderer tool path.
pub(crate) const APPLICATIONS: &str = "/Applications";
pub(crate) const STANDARD_APP: &str = "Xcode.app";
pub(crate) const SDK_COMPONENTS: [&str; 5] = ["Platforms", "iPhoneOS.platform", "Developer", "SDKs", "iPhoneOS.sdk"];

/// The exact alias is only selection data. Concrete originals still require
/// root ownership and independent native custody; an alias lends no authority.
pub(crate) fn selection_alias_owner(owner: u32, account: u32) -> bool {
    account != 0 && (owner == 0 || owner == account)
}

/// Accept only one direct sibling target. The original native link and named
/// sibling are independently retained/rechecked; this parser grants no IO.
pub(crate) fn sibling_target(value: &str) -> Option<&str> {
    let name = value.strip_prefix("/Applications/").unwrap_or(value);
    (name != STANDARD_APP && name.len() <= 255 && name.starts_with("Xcode") && name.ends_with(".app")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)))
        .then_some(name)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) use crate::installed_runtime::IOSXcodeSlots;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_alias_is_only_one_sibling_not_a_path_traversal_or_second_lookup() {
        assert!(selection_alias_owner(0, 501));
        assert!(selection_alias_owner(501, 501));
        assert!(!selection_alias_owner(502, 501));
        assert!(!selection_alias_owner(0, 0));
        assert!(!selection_alias_owner(501, 0));
        assert_eq!(sibling_target("Xcode_26.0.app"), Some("Xcode_26.0.app"));
        assert_eq!(sibling_target("/Applications/Xcode-beta.app"), Some("Xcode-beta.app"));
        for bad in ["Xcode.app", "/Applications/Xcode.app", "../Xcode_26.app", "./Xcode_26.app",
            "/tmp/Xcode_26.app", "/Applications/../Xcode_26.app", "Xcode_26.app/Contents", "Other.app", "Xcode_26.app\0"] {
            assert_eq!(sibling_target(bad), None, "{bad:?}");
        }
    }
}
