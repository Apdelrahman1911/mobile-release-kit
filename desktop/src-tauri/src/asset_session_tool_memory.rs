//! Borrowed admission for the fixed public tool-acquisition buffers.
//! This is not a process-RSS limit or credit borrowed from the signing vault.
use super::*;
use crate::saved_command_owner::ToolAcquisitionCensus;

// Shared Document backing is separate from the fixed public download/parser
// buffers. Keep those at 96MiB and installed code at 128MiB: at most 288MiB
// accounted representations, not RSS or extra private credential capacity.
const DOCUMENT_BACKING: usize = SESSION_BYTES;

pub(crate) struct ToolAcquisitionMemoryAdmission<'a> {
    remaining: usize,
    census: &'a ToolAcquisitionCensus,
    _state: &'a DocumentState,
}
impl ToolAcquisitionMemoryAdmission<'_> {
    pub(crate) fn accepts(&self, census: &ToolAcquisitionCensus, actual: usize) -> bool {
        std::ptr::eq(self.census, census)
            && actual >= census.future_public_bytes()
            && actual <= self.remaining
    }
}

fn remaining(document: usize, retained: usize, admission: usize, public: usize,
    future: usize, code: usize) -> Option<usize> {
    if document > DOCUMENT_BACKING { return None; }
    let live = retained.checked_add(admission)?;
    // The installed-code reservation is charged once, separately. It cannot
    // increase the public partition or conceal overflow in the combined bound.
    let total = document.checked_add(live)?.checked_add(future)?.checked_add(code)?;
    let limit = DOCUMENT_BACKING.checked_add(public)?.checked_add(code)?;
    if total > limit { return None; }
    let available = public.checked_sub(live)?;
    (future <= available).then_some(available)
}

impl DocumentBinding {
    pub(super) fn tool_acquisition_budget<'a>(&self, state: &'a DocumentState,
        census: &'a ToolAcquisitionCensus) -> Result<ToolAcquisitionMemoryAdmission<'a>, BridgeError> {
        if !census.same_document(&self.inner.session_identity) {
            return Err(crate::tool_acquisition_protocol::invalid());
        }
        #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        {
            let document = lookup_memory::tool_acquisition_document_bytes(&self.inner, state, census).map_err(|error| {
                if error == keyring::Problem::CleanupUnknown { BridgeError::cleanup_unknown() }
                else { crate::tool_acquisition_protocol::invalid() }
            })?;
            let extras = installation_memory::additional_document_bytes(self, state)
                .map_err(|_| crate::tool_acquisition_protocol::invalid())?;
            let document = document.checked_add(extras).ok_or_else(crate::tool_acquisition_protocol::invalid)?;
            let remaining = remaining(document, census.retained_bytes(), std::mem::size_of::<ToolAcquisitionMemoryAdmission<'_>>(),
                census.public_work_limit(), census.future_public_bytes(), census.installed_code_limit())
                .ok_or_else(crate::tool_acquisition_protocol::invalid)?;
            Ok(ToolAcquisitionMemoryAdmission { remaining, census, _state: state })
        }
        #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"), all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
        { let _ = state; Err(crate::tool_acquisition_protocol::invalid()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_partition_preserves_document_cap_future_reserve_and_checked_totals() {
        const M: usize = 1024 * 1024;
        assert_eq!(remaining(M, 2*M, 64, 96*M, 82*M, 128*M), Some(94*M-64));
        assert_eq!(remaining(64*M, 14*M, 0, 96*M, 82*M, 128*M), Some(82*M));
        assert_eq!(remaining(64*M, 14*M, 1, 96*M, 82*M, 128*M), None);
        assert_eq!(remaining(64*M+1, 0, 0, 96*M, 0, 128*M), None);
        assert_eq!(remaining(0, 0, 0, 96*M, 96*M+1, 128*M), None);
        assert_eq!(remaining(1, usize::MAX, 0, 96*M, 82*M, 128*M), None);
        assert_eq!(remaining(0, 0, 0, 96*M, 82*M, usize::MAX), None);
        assert_eq!(remaining(0, 0, 0, usize::MAX, 82*M, 128*M), None);
    }
}
