//! Read-only Windows project registration, not a credential/write backend.
use super::*;
use mrk_windows_installed_native as native;

// The existing operation owns this book outside its blocking worker. Native
// output cells/handles survive a worker panic or uncertain completion here.
pub(crate) struct SourceBook { project: native::ProjectBook }
impl SourceBook {
    pub(crate) fn new() -> Self { Self { project: native::ProjectBook::new() } }
    pub(crate) fn settled(&self) -> bool { self.project.settled() }
    pub(crate) fn not_started(&self) -> bool { self.project.never_started() }
}
fn reason(error: native::Error) -> Reason {
    match error {
        native::Error::Unknown | native::Error::State => Reason::CleanupUnknown,
        native::Error::Bounds => Reason::Capacity,
        native::Error::Unavailable | native::Error::Unsafe => Reason::SourceRefused,
    }
}
pub(crate) fn path_hint(path: &Path) -> Result<(), Reason> {
    let path = path.to_str().ok_or(Reason::SourceRefused)?;
    native::project_path_hint(path).map_err(reason)
}
pub(crate) fn probe_project(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>],
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
    // No Windows capture backend exists. Never omit an origin's exclusion
    // obligations merely because the new project picker is supported.
    if !origins.is_empty() { return Err(Reason::UnsupportedPlatform); }
    let spelling = path.to_str().ok_or(Reason::SourceRefused)?;
    let mut cancelled = false;
    let result = book.project.probe_once(spelling, &mut || {
        let stopped = stop(); cancelled |= stopped; stopped
    });
    if let Err(native::Error::Unknown | native::Error::State) = result { return Err(Reason::CleanupUnknown); }
    if cancelled { return Err(Reason::UserCancelled); }
    let identity = result.map_err(reason)?;
    Ok(ProjectProbe { path, identity: ProjectIdentity::Windows { volume: identity.volume_serial, file_id: identity.file_id } })
}

// Project selection does not widen any credential, descendant-path or evidence
// authority. These original routes continue refusing before native acquisition.
pub(crate) fn suffix(_: FileKind, _: &Path) -> Result<(), Reason> { Err(Reason::UnsupportedPlatform) }
pub(crate) fn capture(_: &mut SourceBook, _: PathBuf, _: &[RegisteredRoot], _: FileKind,
    _: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> { Err(Reason::UnsupportedPlatform) }
pub(crate) fn probe_project_path(_: &mut SourceBook, _: &RegisteredRoot, _: PathBuf, _: ProjectPathField,
    _: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> { Err(Reason::UnsupportedPlatform) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_project_registration_never_grants_capture_or_descendant_authority() {
        let mut source = SourceBook::new();
        let path = PathBuf::from(r"C:\project");
        let root = RegisteredRoot { path: path.clone(), identity: ProjectIdentity::Windows { volume: 1, file_id: [1; 16] } };
        assert!(capture(&mut source, path.clone(), &[root.clone()], FileKind::AndroidFirebase, &mut || false).is_err());
        assert!(probe_project_path(&mut source, &root, path, ProjectPathField::VersionSource, &mut || false).is_err());
        assert!(source.not_started());
        assert!(!source.settled());
    }
}
