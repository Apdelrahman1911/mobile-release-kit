/// PRIVATE native preference binding, never accepted by the service protocol.
/// Actual RegisteredRoot/held native descriptors remain operation authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectBinding {
    pub(crate) project_id: Id,
    pub(crate) canonical_root: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}
