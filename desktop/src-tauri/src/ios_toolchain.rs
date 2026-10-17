//! Fixed full-Xcode selection DATA only. Native custody lives in the original
//! Darwin Book; no PATH discovery, download, xcode-select or renderer tool path.
pub(crate) const APPLICATIONS: &str = "/Applications";
pub(crate) const MANAGED_PARENT: &str = "/Library";
pub(crate) const MANAGED_NAMESPACE: &str = "MobileReleaseKitDeveloper";
pub(crate) const MANAGED_DEVELOPER: &str = "/Library/MobileReleaseKitDeveloper/Xcode.app/Contents/Developer";
pub(crate) const MANAGED_PENDING: &str = ".pending";
pub(crate) const MANAGED_ATTEMPT: &str = "attempt.json";
pub(crate) const STANDARD_APP: &str = "Xcode.app";
#[path = "../../native/macos-installed-native/src/ios_sdk_selection.rs"]
mod sdk_selection;
pub(crate) use sdk_selection::{SDK_COMPONENTS, sdk_sibling_target};

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

/// Exact native upload projection only. Its managed spelling grants no IO or
/// completion; IOSXcodeSlots requires current originals and absence of pending.
pub(crate) fn upload_developer(value: &str) -> bool {
    if value == MANAGED_DEVELOPER { return true; }
    let Some(name) = value.strip_prefix("/Applications/").and_then(|p| p.strip_suffix("/Contents/Developer")) else { return false; };
    name == STANDARD_APP || sibling_target(name) == Some(name)
}

#[cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) use crate::installed_runtime::IOSXcodeSlots;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_developer_is_exact_without_relaxing_legacy_selection() {
        assert!(upload_developer(MANAGED_DEVELOPER));
        assert_eq!(format!("{MANAGED_PARENT}/{MANAGED_NAMESPACE}/{STANDARD_APP}/Contents/Developer"),MANAGED_DEVELOPER);
        for good in ["/Applications/Xcode.app/Contents/Developer", "/Applications/Xcode_26.6.app/Contents/Developer"] { assert!(upload_developer(good)); }
        for bad in [MANAGED_DEVELOPER.to_lowercase(), format!("{MANAGED_DEVELOPER}/"),
            MANAGED_DEVELOPER.replace("Xcode.app", "Other.app"), MANAGED_DEVELOPER.replace("Xcode.app", ".pending/Xcode.app"),
            MANAGED_DEVELOPER.replace("Xcode.app", "../Xcode.app"), MANAGED_DEVELOPER.replace("MobileReleaseKitDeveloper", "MobileReleaseKitDeveloperOther"),
            "/Applications/A/Xcode.app/Contents/Developer".into(), "/tmp/Xcode.app/Contents/Developer".into()] { assert!(!upload_developer(&bad),"{bad}"); }
    }
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
