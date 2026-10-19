//! GitHubAuth-only extension of the existing slots!/Book implementation.
//! Included after its distinct slots! invocation in installed_runtime_macos.
//! This checks the SAME held Python/core/bootstrap originals; it does not lend
//! History's gh nomination or create an alternative runtime/process stack.
use super::*;

impl GitHubAuthInstalledRuntime {
    pub(crate) fn post_original(
        &mut self,
        end: Instant,
        stop: &watch::Receiver<bool>,
        publish: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>),
    ) -> Result<()> {
        let result = (|| {
            if !self.original.inspected
                || !self.original.prepared
                || !self.original.admission_custody_ready()
            {
                return Err(AdmissionFailure::AlreadyUsed);
            }
            self.original.point(end, stop)?;
            native::real_user().map_err(native_error)?;
            for (index, record) in self.original.records.iter().enumerate() {
                if record.state == State::Owned {
                    self.original.check_name(index, end, stop)?;
                }
            }
            self.original.point(end, stop)
        })();
        if let Err(failure) = result.as_ref() {
            self.original.note_acl(*failure, Instant::now());
        }
        publish(self.original.first_failure());
        result
    }
}
