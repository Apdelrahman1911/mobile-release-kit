// Narrow library surface for the existing standalone packaging binaries/examples.
// All DATA definitions are sourced once and retain their original module paths.
pub mod protocol {
    use serde::de::DeserializeSeed;
    use serde_json::Value;
    use crate::error::BridgeError;
    include!("protocol_json.rs");
    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        include!("protocol_json_tests.rs");
    }
}
pub mod runtime {
    include!("runtime_paths.rs");
    #[cfg(test)]
    mod tests {
        use super::*;
        include!("runtime_path_tests.rs");
    }
}
