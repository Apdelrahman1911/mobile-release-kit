include!("protocol_json_common.rs");

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
