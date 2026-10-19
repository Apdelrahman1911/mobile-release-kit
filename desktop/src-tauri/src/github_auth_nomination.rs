//! Stock USER gh SOURCE pins, deliberately separate from the custom History
//! provider. A nomination is not a native source or execution capability.
//! Only the reviewed upstream release members below may be nominated. Native
//! source, account and execution checks remain mandatory; these constants do
//! not qualify a provider. No PATH/version-text/ad-hoc hash fallback exists.
use crate::github_auth_capture_wire as wire;

// Official cli/cli v2.88.1, revision 37800dd56a536e69b20d682b770e983c3829c164.
// SOURCE hashes the exact-revision codeload tar.gz bytes, not the Git revision.
// Executable hashes cover bin/gh inside the official macOS release ZIPs, NOT
// the ZIP bytes. Homebrew, locally rebuilt/re-signed and History providers are
// deliberately not interchangeable with these stock release members.
const SOURCE_SHA256: &str = "910e15ecdd2712282d5ffac5ead0a149a6c7adc00f3c97e62f04f9cd03640245";
const MACOS_ARM64_SHA256: &str = "60c6856cd1fbfffaff60c333a1537befed5a9fb35fe42baa193f1cf4db5a5cf3";
const MACOS_X86_64_SHA256: &str =
    "1be4c75421fac469ee08e07cc81749425b645196f8ef62aa302a93ea2fa68a50";

pub(crate) struct StockGhNomination {
    executable_sha256: &'static str,
    source_sha256: &'static str,
}
impl StockGhNomination {
    pub(crate) const VERSION: &'static str = "2.88.1";
    pub(crate) fn compiled() -> Option<Self> {
        // Source-controlled release bindings; neither build nor runtime input
        // can replace them. Registration still proves the actual native source.
        let source_sha256 = SOURCE_SHA256;
        let executable_sha256 = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            MACOS_ARM64_SHA256
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            MACOS_X86_64_SHA256
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
        for executable_sha256 in [MACOS_ARM64_SHA256, MACOS_X86_64_SHA256] {
            assert!(wire::hex(executable_sha256));
            let value = StockGhNomination {
                executable_sha256,
                source_sha256: SOURCE_SHA256,
            };
            assert!(wire::hex(value.source_sha256()));
            assert!(value.matches_actual_sha256(executable_sha256));
            assert!(!value.matches_actual_sha256(SOURCE_SHA256));
            assert!(!value.matches_actual_sha256(StockGhNomination::VERSION));
            assert!(!value.matches_actual_sha256("2.88.1-mrk-history.1"));
            let other_architecture = if executable_sha256 == MACOS_ARM64_SHA256 {
                MACOS_X86_64_SHA256
            } else {
                MACOS_ARM64_SHA256
            };
            assert!(!value.matches_actual_sha256(other_architecture));
        }
        // Never opens a candidate, calls gh, reads the process environment or
        // fabricates a successful source/executable qualification.
        if let Some(value) = StockGhNomination::compiled() {
            assert!(wire::hex(value.source_sha256()));
            assert!(cfg!(all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )));
            assert!(
                value.matches_actual_sha256(if cfg!(target_arch = "aarch64") {
                    MACOS_ARM64_SHA256
                } else {
                    MACOS_X86_64_SHA256
                })
            );
        } else {
            assert!(!cfg!(all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )));
        }
    }
}
