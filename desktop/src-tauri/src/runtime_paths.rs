const TREE_DEPTH: usize = 16;

pub fn safe_payload_path(path: &str) -> bool { safe_payload_path_in(path, None) }

/// Mac Store DATA paths retain upstream templates and notices. Only this fixed
/// owned prefix admits internal spaces/percent; all other payload paths retain
/// the cross-platform grammar and depth. This is not source authentication.
pub fn safe_macos_runtime_path(path: &str) -> bool { safe_payload_path_in(path, Some("store/")) }
pub fn safe_macos_install_path(path: &str) -> bool { safe_payload_path_in(path, Some("runtime/store/")) }

fn safe_payload_path_in(path: &str, store_prefix: Option<&str>) -> bool {
    if path.is_empty() || path.len() > 512 || !path.is_ascii() { return false; }
    let prefix_depth = store_prefix.filter(|prefix| path.starts_with(prefix))
        .map_or(0, |prefix| prefix.bytes().filter(|byte| *byte == b'/').count());
    let mut depth = 0;
    for part in path.split('/') {
        depth += 1;
        let store = prefix_depth > 0 && depth > prefix_depth;
        if depth > TREE_DEPTH + prefix_depth || part.is_empty() || part == "." || part == ".."
            || part.starts_with(' ') || part.ends_with(['.', ' '])
            || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b)
                || store && b"% ".contains(&b)) { return false; }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes().get(3), Some(b'1'..=b'9'))) { return false; }
    }
    true
}
