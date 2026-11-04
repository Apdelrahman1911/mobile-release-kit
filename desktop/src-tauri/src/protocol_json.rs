pub const DEPTH_LIMIT: usize = 32;
pub const NODE_LIMIT: usize = 20_000;

use crate::bounded_json_seed::Seed;

pub(crate) fn strict_json_with_limits(bytes: &[u8], node_limit: usize, depth_limit: usize) -> Result<Value, BridgeError> {
    std::str::from_utf8(bytes).map_err(|_| BridgeError::protocol())?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0usize;
    let value = Seed { nodes: &mut nodes, depth: 0, node_limit, depth_limit }
        .deserialize(&mut decoder).map_err(|_| BridgeError::protocol())?;
    decoder.end().map_err(|_| BridgeError::protocol())?;
    Ok(value)
}

pub fn strict_json(bytes: &[u8]) -> Result<Value, BridgeError> {
    strict_json_with_limits(bytes, NODE_LIMIT, DEPTH_LIMIT)
}

// Signed Mac inventory DATA only. Seven nodes/runtime row and nine/install
// row, including keys: 16,384 rows fit these fixed bounds. No renderer caller.
pub(crate) fn strict_macos_runtime_manifest_json(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.len() > crate::macos_install_record::MANIFEST_LIMIT { return Err(BridgeError::protocol()); }
    strict_json_with_limits(bytes, 120_000, 16)
}
pub(crate) fn strict_macos_inventory_json(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.len() > crate::macos_install_record::INVENTORY_LIMIT { return Err(BridgeError::protocol()); }
    strict_json_with_limits(bytes, 150_000, 16)
}
