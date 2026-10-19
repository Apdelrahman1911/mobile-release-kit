//! Stock USER gh SOURCE pins, deliberately separate from the custom History
//! provider. A nomination is not a native source or execution capability.
//! Installed builds without independently reviewed stock-provider bindings
//! cannot register/launch it. No PATH/version-text/ad-hoc hash fallback exists.
use crate::github_auth_capture_wire as wire;

pub(crate) struct StockGhNomination {
    executable_sha256: &'static str,
    source_sha256: &'static str,
}
impl StockGhNomination {
    pub(crate) const VERSION: &'static str = "2.88.1";
    pub(crate) fn compiled() -> Option<Self> {
        // Root's existing protected build/installation owner must supply these
        // reviewed stock-release bindings. Runtime/renderer env is not read.
        let source_sha256 = option_env!("MRK_STOCK_GH_AUTH_2_88_1_SOURCE_SHA256")?;
        let executable_sha256 = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            option_env!("MRK_STOCK_GH_AUTH_2_88_1_ARM64_SHA256")?
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            option_env!("MRK_STOCK_GH_AUTH_2_88_1_X86_64_SHA256")?
        } else {
            return None;
        };
        if !wire::hex(source_sha256)
            || !wire::hex(executable_sha256)
            || source_sha256 == executable_sha256
        {
            return None;
        }
        Some(Self {
            executable_sha256,
            source_sha256,
        })
    }
    pub(crate) fn matches_actual_sha256(&self, value: &str) -> bool {
        value == self.executable_sha256
    }
    pub(crate) fn source_sha256(&self) -> &'static str {
        self.source_sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_or_history_nomination_is_not_a_stock_provider_binding() {
        assert_eq!(StockGhNomination::VERSION, "2.88.1");
        assert_ne!(StockGhNomination::VERSION, "2.88.1-mrk-history.1");
        // Never opens a candidate, calls gh, reads the process environment or
        // fabricates a successful source/executable qualification.
        if let Some(value) = StockGhNomination::compiled() {
            assert!(wire::hex(value.source_sha256()));
        }
    }
}
