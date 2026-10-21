//! Closed PRE-ADMISSION hints. These never describe an entered Prepare/Start,
//! an uncertain original, a tool lease, or permission to retry automatically.
use crate::error::BridgeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Required {
    Catalogue,
    SavedInputs,
}

impl Required {
    pub(crate) fn error(self) -> BridgeError {
        match self {
            Self::Catalogue => BridgeError::new(
                "tool_acquisition_catalog_required",
                "Check the protected tool catalogue, then use its Recover or Choose controls if needed. No tool preparation was admitted.",
            ),
            Self::SavedInputs => BridgeError::new(
                "tool_acquisition_saved_inputs_required",
                "Read the saved project inputs after choosing tools, then check required tools again. No tool preparation was admitted.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prerequisite_errors_are_closed_nonretryable_hints_not_generic_failures() {
        let catalogue = Required::Catalogue.error();
        let saved = Required::SavedInputs.error();
        assert_eq!(catalogue.code, "tool_acquisition_catalog_required");
        assert_eq!(saved.code, "tool_acquisition_saved_inputs_required");
        assert!(!catalogue.retryable && !saved.retryable);
        for error in [BridgeError::invalid(), BridgeError::cleanup_unknown(), BridgeError::shutdown()] {
            assert_ne!(error.code, catalogue.code);
            assert_ne!(error.code, saved.code);
        }
    }
}
