//! Closed generation profile's borrowed audits of the SAME installed Book.
//! Existing slots! inspection/prepare/claim/settle remains the sole lifecycle.
use super::*;
impl UploadKeyRuntimeSlots {
    pub(crate) fn upload_key_inspection_peak() -> Option<usize> {
        crate::macos_history_inventory::code_storage_bytes(
            std::mem::size_of::<Record>(),
            native::vault_filesystem::SNAPSHOT_FRAME_BYTES,
        )?
        .checked_add(std::mem::size_of::<Self>())?
        // The fixed selection can be retained in both slot and worker. Each
        // of its four installed paths is independently bounded by4096 bytes.
        .checked_add(8 * 4096)
    }
    pub(crate) fn bind_upload_key_inspection(&mut self) -> Result<()> {
        if !self.never_started() || Self::upload_key_inspection_peak().is_none() {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let original = self.inspection.as_mut().ok_or(AdmissionFailure::Unknown)?;
        if original.upload_key_inspection {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        // Only this closed role opts in to the already-existing pure indexed
        // inventory planner. Other installed slot profiles are unchanged.
        original.upload_key_inspection = true;
        Ok(())
    }
}

impl UploadKeyInstalledRuntime {
    pub(crate) fn check_before_or_after_use(
        &self,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        self.original.point(end, stop)?;
        if !self.claimed
            || self.no_effect
            || !self.original.inspected
            || !self.original.prepared
            || self
                .original
                .retained_original_count()
                .is_none_or(|n| n == 0)
        {
            return Err(AdmissionFailure::AlreadyUsed);
        }
        let result = (|| {
            for (index, record) in self.original.records.iter().enumerate() {
                if record.state == State::Owned {
                    self.original.check_name(index, end, stop)?;
                }
            }
            self.original.point(end, stop)
        })();
        if let Err(failure) = result {
            self.original.note_acl(failure, Instant::now());
        }
        result
    }
    pub(crate) fn check_before_settlement(
        &self,
        expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool,
    ) -> Result<()> {
        let result = (|| {
            if !self.claimed
                || self.no_effect
                || !self.original.inspected
                || !self.original.prepared
                || self
                    .original
                    .retained_original_count()
                    .is_none_or(|n| n == 0)
            {
                return Err(AdmissionFailure::AlreadyUsed);
            }
            for (index, record) in self.original.records.iter().enumerate() {
                if expired(self.original.first_failure()) {
                    return Err(AdmissionFailure::Deadline);
                }
                if record.state == State::Owned {
                    self.original.check_name_with(index, &mut || {
                        if expired(self.original.first_failure()) {
                            Err(AdmissionFailure::Deadline)
                        } else {
                            Ok(())
                        }
                    })?;
                }
            }
            Ok(())
        })();
        if let Err(failure) = result {
            self.original.note_acl(failure, Instant::now());
        }
        result
    }
}
