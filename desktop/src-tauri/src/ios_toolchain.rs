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

/// Only a concrete decimal-version sibling of the fixed iPhoneOS.sdk alias.
/// This is link DATA, not path following or SDK/tool execution authority.
pub(crate) fn sdk_sibling_target(value: &str) -> Option<&str> {
    if value.len() > 255 { return None; }
    let version = value.strip_prefix("iPhoneOS")?.strip_suffix(".sdk")?;
    for (index, part) in version.split('.').enumerate() {
        if index >= 3 || part.is_empty() || part.len() > 3
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0')) || (index == 0 && part == "0") {
            return None;
        }
    }
    Some(value)
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
        for good in ["iPhoneOS1.sdk", "iPhoneOS26.0.sdk", "iPhoneOS26.2.sdk", "iPhoneOS26.0.1.sdk", "iPhoneOS999.999.999.sdk"] {
            assert_eq!(sdk_sibling_target(good), Some(good));
        }
        for bad in ["iPhoneOS.sdk", "/Applications/iPhoneOS26.0.sdk", "../iPhoneOS26.0.sdk", "./iPhoneOS26.0.sdk",
            "iPhoneOS26.0.sdk/Other.sdk", "iPhoneOS26.0.sdk/iPhoneOS.sdk", "iPhoneOS26.0\\.sdk",
            "iPhoneSimulator26.0.sdk", "MacOSX26.0.sdk", "iPhoneOS0.sdk", "iPhoneOS026.0.sdk", "iPhoneOS26.00.sdk",
            "iPhoneOS26..sdk", "iPhoneOS26.0.0.1.sdk", "iPhoneOS1000.sdk", "iPhoneOS26-beta.sdk", "iPhoneOS٢٦.sdk",
            "iPhoneOS26.0.sdk\0", "iPhoneOS26.0.sdk\n"] {
            assert_eq!(sdk_sibling_target(bad), None, "{bad:?}");
        }
    }
}
