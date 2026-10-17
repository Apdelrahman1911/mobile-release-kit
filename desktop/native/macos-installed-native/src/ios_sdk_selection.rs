//! Pure SDK selection DATA shared by the desktop and its native setup.
#![forbid(unsafe_code)]
pub(crate) const SDK_COMPONENTS: [&str; 5] = ["Platforms", "iPhoneOS.platform", "Developer", "SDKs", "iPhoneOS.sdk"];

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
