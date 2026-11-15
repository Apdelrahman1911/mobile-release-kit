// Exact pure shared DATA and actual fixed publisher; no application consumer graph.
pub mod protocol {
    use serde::de::DeserializeSeed;
    use serde_json::Value;
    use crate::error::BridgeError;
    include!("protocol_version.rs");
    include!("protocol_json_common.rs");
}
pub mod runtime {
    use std::{collections::BTreeSet, path::PathBuf, time::Instant};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use crate::{error::BridgeError, protocol::{strict_json, PROTOCOL}};
    include!("runtime_publication_inputs.rs");
    const MANIFEST_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256");
    const PROTOCOL_ANCHOR: Option<&str> = option_env!("MRK_BUNDLED_PROTOCOL_SHA256");
    const MANIFEST_LIMIT: u64 = 1024 * 1024;
    const FILE_LIMIT: u64 = 512 * 1024 * 1024;
    const TOTAL_LIMIT: u64 = 1024 * 1024 * 1024;
    const FILE_COUNT: usize = 2048;
    const ENTRY_COUNT: usize = 8192;
    fn manifest_json(bytes: &[u8]) -> Result<serde_json::Value, BridgeError> { strict_json(bytes) }
    include!("runtime_manifest_data.rs");
    include!("runtime_hash_data.rs");
    include!("runtime_paths.rs");
    include!("runtime_windows_version.rs");
}
pub mod runtime_publication_windows;
