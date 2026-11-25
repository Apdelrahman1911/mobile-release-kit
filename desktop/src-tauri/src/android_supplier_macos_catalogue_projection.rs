// Address-only views of the two dependency-owned static catalogues.
// No foreign static field is read or projected during application const evaluation.
const REFERENCES: &[Reference] = std::slice::from_ref(&mrk_android_catalogue_arm64::CATALOGUE);
mod intel_catalogue {
    use super::*;
    pub(super) const REFERENCES: &[Reference] = std::slice::from_ref(&mrk_android_catalogue_x86_64::CATALOGUE);
}
