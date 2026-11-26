//! Exact pure future-tag reference predicates; no Request/state port/native jobs.
pub(crate) mod future_tag {
use crate::github_preflight_protocol::branch;
fn full_ref(value: &str) -> bool {
    value.len() <= 220 && value.strip_prefix("refs/heads/").or_else(|| value.strip_prefix("refs/tags/"))
        .is_some_and(branch)
}
pub(crate) fn reference(value: &str) -> bool {
    value.starts_with("refs/tags/") && full_ref(value)
}
}
