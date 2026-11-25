#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) schema_version: u32, pub(crate) protocol: u32, pub(crate) core_version: String, pub(crate) target: String,
    pub(crate) core_sha256: String, pub(crate) protocol_sha256: String, pub(crate) inventory_sha256: String,
    pub(crate) files: Vec<PayloadFile>,
}

// Field order is intentional: compact serde JSON == Python sorted-key JSON.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadFile { pub(crate) path: String, pub(crate) sha256: String, pub(crate) size: u64 }

fn unavailable() -> BridgeError { BridgeError::unavailable("The packaged runtime is absent, incompatible, or fails its trusted inventory.") }
