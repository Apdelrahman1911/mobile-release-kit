//! Fixed full-Xcode selection DATA only. Native custody lives in the original
//! Darwin Book; no PATH discovery, download, xcode-select or renderer tool path.
pub(crate) const APPLICATIONS: &str = "/Applications";
pub(crate) const STANDARD_APP: &str = "Xcode.app";
pub(crate) const SDK_COMPONENTS: [&str; 5] = ["Platforms", "iPhoneOS.platform", "Developer", "SDKs", "iPhoneOS.sdk"];

/// Accept only one direct sibling target. The original native link and named
/// sibling are independently retained/rechecked; this parser grants no IO.
pub(crate) fn sibling_target(value: &str) -> Option<&str> {
    let name = value.strip_prefix("/Applications/").unwrap_or(value);
    (name != STANDARD_APP && name.len() <= 255 && name.starts_with("Xcode") && name.ends_with(".app")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)))
        .then_some(name)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use crate::installed_runtime::IOSXcodeSlots;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_alias_is_only_one_sibling_not_a_path_traversal_or_second_lookup() {
        assert_eq!(sibling_target("Xcode_26.0.app"), Some("Xcode_26.0.app"));
        assert_eq!(sibling_target("/Applications/Xcode-beta.app"), Some("Xcode-beta.app"));
        for bad in ["Xcode.app", "/Applications/Xcode.app", "../Xcode_26.app", "./Xcode_26.app",
            "/tmp/Xcode_26.app", "/Applications/../Xcode_26.app", "Xcode_26.app/Contents", "Other.app", "Xcode_26.app\0"] {
            assert_eq!(sibling_target(bad), None, "{bad:?}");
        }
    }
}
