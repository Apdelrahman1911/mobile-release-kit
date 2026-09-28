//! Read-only Windows project and credential-source custody, not a write backend.
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
fn source_reason(error: native::CredentialError) -> Reason {
    match error {
        native::CredentialError::Native(error) => reason(error),
        native::CredentialError::SourceChanged => Reason::SourceChanged,
        native::CredentialError::ProjectOverlap => Reason::ProjectOverlap,
        native::CredentialError::ExclusionUnconfirmed => Reason::ExclusionUnconfirmed,
        native::CredentialError::MaterialLimit => Reason::MaterialLimit,
    }
}
fn completed<T>(result: Result<T, native::CredentialError>, cancelled: bool) -> Result<T, Reason> {
    // Definite cancellation is not proof that an uncertain original retired.
    if matches!(result, Err(native::CredentialError::Native(native::Error::Unknown | native::Error::State))) {
        return Err(Reason::CleanupUnknown);
    }
    if cancelled { return Err(Reason::UserCancelled); }
    result.map_err(source_reason)
}
pub(crate) fn path_hint(path: &Path) -> Result<(), Reason> {
    let path = path.to_str().ok_or(Reason::SourceRefused)?;
    native::project_path_hint(path).map_err(reason)
}
pub(crate) fn probe_project(book: &mut SourceBook, path: PathBuf, origins: &[Arc<OriginWitness>],
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectProbe, Reason> {
    if origins.len() > 32 { return Err(Reason::Capacity); }
    let spelling = path.to_str().ok_or(Reason::SourceRefused)?;
    let mut borrowed = Vec::new(); borrowed.try_reserve_exact(origins.len()).map_err(|_| Reason::Capacity)?;
    for origin in origins { borrowed.push(origin.as_ref()); }
    let mut cancelled = false;
    let result = book.project.probe_excluding_credentials_once(spelling, &borrowed, &mut || {
        let stopped = stop(); cancelled |= stopped; stopped
    });
    let identity = completed(result, cancelled)?;
    Ok(ProjectProbe { path, identity: ProjectIdentity::Windows { volume: identity.volume_serial, file_id: identity.file_id } })
}

/// Only the three already-enabled Windows file kinds. This does not open the
/// separate native dialog/session/profile gates or grant signing qualification.
pub(crate) fn suffix(kind: FileKind, path: &Path) -> Result<(), Reason> {
    let allowed: &[&str] = match kind {
        FileKind::AndroidKeystore => &["jks", "keystore"],
        FileKind::AndroidFirebase => &["json"],
        FileKind::IosFirebase => &["plist"],
        FileKind::AppleP12 | FileKind::AppleProfile | FileKind::AscP8 => return Err(Reason::UnsupportedPlatform),
    };
    let extension = path.extension().and_then(|extension| extension.to_str()).ok_or(Reason::UnsupportedFormat)?;
    if !allowed.iter().any(|allowed| extension.eq_ignore_ascii_case(allowed)) { return Err(Reason::UnsupportedFormat); }
    path_hint(path)
}
pub(crate) fn capture(book: &mut SourceBook, path: PathBuf, roots: &[RegisteredRoot], kind: FileKind,
    stop: &mut dyn FnMut() -> bool) -> Result<CapturedSource, Reason> {
    suffix(kind, &path)?;
    if roots.len() > 64 { return Err(Reason::Capacity); }
    let spelling = path.to_str().ok_or(Reason::SourceRefused)?;
    let mut projects = Vec::new(); projects.try_reserve_exact(roots.len()).map_err(|_| Reason::Capacity)?;
    for root in roots {
        let identity = match root.identity {
            ProjectIdentity::Windows { volume, file_id } => native::FileIdentity { volume_serial: volume, file_id },
            ProjectIdentity::Posix(_) => return Err(Reason::UnsupportedPlatform),
        };
        projects.push(native::RegisteredProject { path: root.path.to_str().ok_or(Reason::SourceRefused)?, identity });
    }
    let mut cancelled = false;
    let result = book.project.capture_credential_once(spelling, &projects, material_limit(kind), &mut || {
        let stopped = stop(); cancelled |= stopped; stopped
    });
    let captured = completed(result, cancelled)?;
    Ok(CapturedSource { bytes: captured.bytes, origin: Arc::new(captured.origin) })
}

// A credential source is not a metadata descendant-selector or a write lease.
// That separate picker route remains refused before native acquisition.
pub(crate) fn probe_project_path(_: &mut SourceBook, _: &RegisteredRoot, _: PathBuf, _: ProjectPathField,
    _: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> { Err(Reason::UnsupportedPlatform) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_source_suffixes_are_scoped_and_never_normalize_a_path() {
        for (kind, path) in [
            (FileKind::AndroidKeystore, r"C:\private\release.JKS"),
            (FileKind::AndroidKeystore, r"C:\private\release.keystore"),
            (FileKind::AndroidFirebase, r"C:\private\google-services.json"),
            (FileKind::IosFirebase, r"C:\private\GoogleService-Info.plist"),
        ] { assert!(suffix(kind, Path::new(path)).is_ok()); }
        for path in [r"C:\private\release.p12", r"C:\private\release.jks.", r"C:\private\..\release.jks",
            r"\\server\private\release.jks", r"C:\private\release.jks:stream", r"C:\private\\release.jks"] {
            assert!(suffix(FileKind::AndroidKeystore, Path::new(path)).is_err());
        }
        assert_eq!(suffix(FileKind::AscP8, Path::new(r"C:\private\AuthKey.p8")), Err(Reason::UnsupportedPlatform));
    }
    #[test]
    fn windows_source_refusals_preserve_no_acquisition_and_descendant_scope() {
        let mut source = SourceBook::new();
        let path = PathBuf::from(r"C:\project");
        let root = RegisteredRoot { path: path.clone(), identity: ProjectIdentity::Windows { volume: 1, file_id: [1; 16] } };
        assert!(capture(&mut source, path.clone(), &[root.clone()], FileKind::AndroidFirebase, &mut || false).is_err());
        assert!(probe_project_path(&mut source, &root, path, ProjectPathField::VersionSource, &mut || false).is_err());
        assert!(source.not_started()); assert!(!source.settled());
    }
    #[test]
    fn windows_source_unknown_dominates_stop_and_errors_remain_specific() {
        for error in [native::Error::Unknown, native::Error::State] {
            assert_eq!(completed::<()>(Err(native::CredentialError::Native(error)), true), Err(Reason::CleanupUnknown));
        }
        assert_eq!(completed(Ok(()), true), Err(Reason::UserCancelled));
        assert_eq!(completed::<()>(Err(native::CredentialError::Native(native::Error::Unsafe)), false), Err(Reason::SourceRefused));
        assert_eq!(completed::<()>(Err(native::CredentialError::ProjectOverlap), false), Err(Reason::ProjectOverlap));
        assert_eq!(completed::<()>(Err(native::CredentialError::ExclusionUnconfirmed), false), Err(Reason::ExclusionUnconfirmed));
        assert_eq!(completed::<()>(Err(native::CredentialError::MaterialLimit), false), Err(Reason::MaterialLimit));
    }
}
