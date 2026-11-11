// Exact shared DATA and fixed publisher only. No application consumer graph.
pub mod protocol {
    use serde::de::DeserializeSeed;
    use serde_json::Value;
    use crate::error::BridgeError;
    include!("protocol_version.rs");
    include!("protocol_json.rs");
}
pub mod runtime {
    include!("runtime_publication_inputs.rs");
    include!("runtime_paths.rs");
}
mod installed_runtime {
    #![forbid(unsafe_code)]
    use std::collections::BTreeSet;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use rustix::fs::{FileType, Mode, Stat};
    use mrk_linux_mount_observation as mount;
    use crate::{protocol::{strict_json, PROTOCOL},
        runtime::{safe_payload_path, COMPILED_TARGET, CORE_VERSION, GITHUB_CA_LIMIT, REQUIRED_RUNTIME_RESOURCES}};
    include!("installed_runtime_data.rs");
}
pub mod runtime_publication;
