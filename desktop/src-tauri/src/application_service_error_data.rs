pub(crate) fn public_error(error: ServiceError) -> BridgeError {
    let code = match error {
        ServiceError::InvalidRequest => "cli_access_invalid_request",
        ServiceError::Unavailable | ServiceError::UnsupportedPlatform => "cli_access_unavailable",
        ServiceError::AccessDenied | ServiceError::Expired => "cli_access_denied",
        ServiceError::Busy => "cli_access_busy",
        ServiceError::Conflict => "cli_access_changed",
        ServiceError::RecoveryRequired => "cli_access_recovery_required",
        ServiceError::StateUnknown => "cli_access_unknown",
    };
    BridgeError::new(code, error.message())
}

pub(crate) fn empty_request(value: &Value) -> Result<(), BridgeError> {
    if value.as_object().is_some_and(|object| object.is_empty()) { Ok(()) }
    else { Err(BridgeError::invalid()) }
}

