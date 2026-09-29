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
        FileKind::AndroidKeystore => &["jks", "keystore", "p12", "pfx"],
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

// Only MetadataRoot's strict-descendant directory source proof is implemented.
// This does not enable its native picker/profile, capture public images, widen
// credential kinds or grant any file/write authority.
pub(crate) fn probe_project_path(book: &mut SourceBook, root: &RegisteredRoot, path: PathBuf, field: ProjectPathField,
    stop: &mut dyn FnMut() -> bool) -> Result<ProjectPathProbe, Reason> {
    // Re-entry cannot hide an uncertain/consumed original behind bad arguments
    // or cancellation. Fresh unsupported routes still refuse without starting.
    if !book.not_started() { return Err(Reason::CleanupUnknown); }
    if field != ProjectPathField::MetadataRoot { return Err(Reason::UnsupportedPlatform); }
    let identity = match root.identity {
        ProjectIdentity::Windows { volume, file_id } => native::FileIdentity { volume_serial: volume, file_id },
        ProjectIdentity::Posix(_) => return Err(Reason::UnsupportedPlatform),
    };
    let root_spelling = root.path.to_str().ok_or(Reason::SourceRefused)?;
    let spelling = path.to_str().ok_or(Reason::SourceRefused)?;
    let relative_path = native::ProjectBook::metadata_root_relative_hint(root_spelling, spelling).map_err(reason)?;
    if !crate::release_version_protocol::relative_display_path(&relative_path) { return Err(Reason::SourceRefused); }
    let mut cancelled = false;
    let result = book.project.probe_metadata_root_once(root_spelling, identity, spelling, &mut || {
        let stopped = stop(); cancelled |= stopped; stopped
    });
    completed(result.map_err(native::CredentialError::Native), cancelled)?;
    Ok(ProjectPathProbe { relative_path })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_metadata_root_scope_refuses_before_acquisition() {
        let root = RegisteredRoot { path: PathBuf::from(r"C:\project"),
            identity: ProjectIdentity::Windows { volume: u64::MAX, file_id: [0xff; 16] } };
        let mut source = SourceBook::new();
        let mut checkpoints = 0;
        for field in [ProjectPathField::VersionSource, ProjectPathField::IosProject, ProjectPathField::IosWorkspace] {
            assert_eq!(probe_project_path(&mut source, &root, PathBuf::from(r"C:\project\metadata"), field, &mut || {
                checkpoints += 1; true
            }).err(), Some(Reason::UnsupportedPlatform));
        }
        let posix = RegisteredRoot { path: root.path.clone(),
            identity: ProjectIdentity::Posix(DirectoryIdentity::synthetic_evidence_identity()) };
        assert_eq!(probe_project_path(&mut source, &posix, PathBuf::from(r"C:\project\metadata"),
            ProjectPathField::MetadataRoot, &mut || { checkpoints += 1; true }).err(), Some(Reason::UnsupportedPlatform));
        assert_eq!(checkpoints, 0); assert!(source.not_started()); assert!(!source.settled());
    }
    #[test]
    fn windows_metadata_root_spelling_and_display_refuse_before_acquisition() {
        let root = RegisteredRoot { path: PathBuf::from(r"C:\project"),
            identity: ProjectIdentity::Windows { volume: 1, file_id: [1; 16] } };
        let mut source = SourceBook::new();
        let mut checkpoints = 0;
        for path in [r"C:\project", r"C:\project2\metadata", r"C:\other\metadata", r"D:\project\metadata",
            r"C:\PROJECT\metadata", r"C:\project\..\metadata", r"C:\project\.\metadata", r"C:\project\\metadata",
            r"C:\project\metadata\", r"C:\project\metadata:stream", r"C:\project\.hidden",
            r"C:\project\PrIvAtE\metadata", r"C:\project\secrets\metadata", r"C:\project\metadata\NUL.txt",
            r"C:\project\metadata\name.", r"C:\project\metadata\name ", "C:\\project\\metadata\\a\nb", "relative"] {
            assert_eq!(probe_project_path(&mut source, &root, PathBuf::from(path), ProjectPathField::MetadataRoot,
                &mut || { checkpoints += 1; true }).err(), Some(Reason::SourceRefused));
        }
        for suffix in [vec!["a"; 13].join("\\"), vec!["a".repeat(171); 3].join("\\")] {
            let path = PathBuf::from(format!("C:\\project\\{suffix}"));
            assert_eq!(probe_project_path(&mut source, &root, path, ProjectPathField::MetadataRoot,
                &mut || { checkpoints += 1; true }).err(), Some(Reason::SourceRefused));
        }
        for spelling in ["relative", r"C:\project\", r"C:\project\."] {
            let bad_root = RegisteredRoot { path: PathBuf::from(spelling), identity: root.identity };
            assert_eq!(probe_project_path(&mut source, &bad_root, PathBuf::from(r"C:\project\metadata"),
                ProjectPathField::MetadataRoot, &mut || { checkpoints += 1; true }).err(), Some(Reason::SourceRefused));
        }
        assert_eq!(checkpoints, 0); assert!(source.not_started()); assert!(!source.settled());
    }
    #[test]
    fn windows_metadata_root_invalid_utf16_refuses_before_acquisition() {
        use std::os::windows::ffi::OsStringExt;
        let mut units: Vec<u16> = "C:\\project\\".encode_utf16().collect();
        units.push(0xd800); // Unpaired surrogate; this is pathname DATA, not a file.
        let invalid = PathBuf::from(std::ffi::OsString::from_wide(&units));
        let root = RegisteredRoot { path: PathBuf::from(r"C:\project"),
            identity: ProjectIdentity::Windows { volume: 1, file_id: [1; 16] } };
        let mut source = SourceBook::new();
        let mut checkpoints = 0;
        assert_eq!(probe_project_path(&mut source, &root, invalid.clone(), ProjectPathField::MetadataRoot,
            &mut || { checkpoints += 1; true }).err(), Some(Reason::SourceRefused));
        let bad_root = RegisteredRoot { path: invalid, identity: root.identity };
        assert_eq!(probe_project_path(&mut source, &bad_root, PathBuf::from(r"C:\project\metadata"), ProjectPathField::MetadataRoot,
            &mut || { checkpoints += 1; true }).err(), Some(Reason::SourceRefused));
        assert_eq!(checkpoints, 0); assert!(source.not_started()); assert!(!source.settled());
    }
    #[test]
    fn windows_metadata_root_stop_consumes_original_without_native_acquisition() {
        let root = RegisteredRoot { path: PathBuf::from(r"C:\project"),
            identity: ProjectIdentity::Windows { volume: u64::MAX, file_id: [0xff; 16] } };
        let mut source = SourceBook::new();
        assert_eq!(probe_project_path(&mut source, &root, PathBuf::from(r"C:\project\metadata\en-US"),
            ProjectPathField::MetadataRoot, &mut || true).err(), Some(Reason::UserCancelled));
        assert!(source.settled()); assert!(!source.not_started());
        let mut checkpoints = 0;
        // Even a different field/bad spelling cannot renew this original book.
        assert_eq!(probe_project_path(&mut source, &root, PathBuf::from("invalid"), ProjectPathField::VersionSource,
            &mut || { checkpoints += 1; true }).err(), Some(Reason::CleanupUnknown));
        assert_eq!(checkpoints, 0); assert!(source.settled());
    }
    #[test]
    fn windows_source_suffixes_are_scoped_and_never_normalize_a_path() {
        for (kind, path) in [
            (FileKind::AndroidKeystore, r"C:\private\release.JKS"),
            (FileKind::AndroidKeystore, r"C:\private\release.keystore"),
            (FileKind::AndroidKeystore, r"C:\private\release.P12"),
            (FileKind::AndroidKeystore, r"C:\private\release.pfx"),
            (FileKind::AndroidFirebase, r"C:\private\google-services.json"),
            (FileKind::IosFirebase, r"C:\private\GoogleService-Info.plist"),
        ] { assert!(suffix(kind, Path::new(path)).is_ok()); }
        for path in [r"C:\private\release.p12.bak", r"C:\private\release.jks.", r"C:\private\..\release.jks",
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

// A separate ordinary-public read purpose in the SAME original SourceBook.
// MetadataRoot above remains a directory proof, never a public capture or writer.
struct PreparedPublicImage { item_id: String, display_name: String, sha256: String }
fn public_image_name(path: &Path, ordinal: usize) -> Result<String, Reason> {
    path_hint(path)?;
    let name = path.file_name().and_then(|value| value.to_str()).ok_or(Reason::SourceRefused)?;
    let (stem, extension) = name.rsplit_once('.').ok_or(Reason::UnsupportedFormat)?;
    let extension = if extension.eq_ignore_ascii_case("png") { "png" }
        else if extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg") { "jpg" }
        else { return Err(Reason::UnsupportedFormat); };
    if stem.is_empty() { return Err(Reason::UnsupportedFormat); }
    if name.len() <= 255 && !name.contains(['/', '\\'])
        && !name.chars().any(|ch| ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        return Ok(name.to_owned());
    }
    Ok(format!("selected-image-{:02}.{extension}", ordinal + 1))
}
fn public_image_reason(error: native::PublicImageError, cancelled: bool) -> Reason {
    match error {
        native::PublicImageError::Native(native::Error::Unknown | native::Error::State) => Reason::CleanupUnknown,
        _ if cancelled => Reason::UserCancelled,
        native::PublicImageError::Native(error) => reason(error),
        native::PublicImageError::SourceChanged => Reason::SourceChanged,
        native::PublicImageError::MaterialLimit => Reason::MaterialLimit,
    }
}
pub(crate) fn capture_public_images(book: &mut SourceBook, paths: Vec<PathBuf>, root: &RegisteredRoot,
    budget: PublicImageBudget, stop: &mut dyn FnMut() -> bool,
    failed: &mut dyn FnMut(Reason)) -> Result<CapturedPublicImageBatch, Reason> {
    use sha2::{Digest, Sha256};
    use std::{cell::Cell, fmt::Write, mem::size_of};
    let reported = Cell::new(false);
    let result = (|| {
        // Re-entry cannot turn unknown/consumed originals into an argument error.
        if !book.not_started() { return Err(Reason::CleanupUnknown); }
        if !budget.valid() || !(1..=PUBLIC_IMAGE_FILES).contains(&paths.len()) || paths.capacity() > PUBLIC_IMAGE_FILES
            || paths.iter().any(|path| path.capacity() > PATH_LIMIT) { return Err(Reason::MaterialLimit); }
        let identity = match root.identity {
            ProjectIdentity::Windows { volume, file_id } => native::FileIdentity { volume_serial: volume, file_id },
            ProjectIdentity::Posix(_) => return Err(Reason::UnsupportedPlatform),
        };
        let root_path = root.path.to_str().ok_or(Reason::SourceRefused)?;
        native::project_path_hint(root_path).map_err(reason)?;
        let mut spellings = Vec::new(); spellings.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        let mut prepared = Vec::new(); prepared.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        let mut images = Vec::new(); images.try_reserve_exact(paths.len()).map_err(|_| Reason::Capacity)?;
        for (ordinal, path) in paths.iter().enumerate() {
            let display_name = public_image_name(path, ordinal)?;
            let item_id = public_image_token(stop)?;
            if prepared.iter().any(|prior: &PreparedPublicImage| prior.item_id == item_id) { return Err(Reason::SourceRefused); }
            let mut sha256 = String::new(); sha256.try_reserve_exact(64).map_err(|_| Reason::Capacity)?;
            prepared.push(PreparedPublicImage { item_id, display_name, sha256 });
            spellings.push(path.to_str().ok_or(Reason::SourceRefused)?);
        }
        let mut application = size_of::<CapturedPublicImageBatch>()
            .checked_add(paths.capacity().checked_mul(size_of::<PathBuf>()).ok_or(Reason::Capacity)?)
            .and_then(|n| n.checked_add(spellings.capacity().checked_mul(size_of::<&str>())?))
            .and_then(|n| n.checked_add(prepared.capacity().checked_mul(size_of::<PreparedPublicImage>())?))
            .and_then(|n| n.checked_add(images.capacity().checked_mul(size_of::<CapturedPublicImage>())?))
            .and_then(|n| n.checked_add(root.path.capacity())).ok_or(Reason::Capacity)?;
        for path in &paths { application = application.checked_add(path.capacity()).ok_or(Reason::Capacity)?; }
        for image in &prepared {
            application = application.checked_add(image.item_id.capacity()).and_then(|n| n.checked_add(image.display_name.capacity()))
                .and_then(|n| n.checked_add(image.sha256.capacity())).ok_or(Reason::Capacity)?;
        }
        budget.admit(Some(application))?;
        let retained = budget.retained_bytes.checked_sub(application).ok_or(Reason::MaterialLimit)?;
        let cancelled = Cell::new(false);
        let native_result = book.project.capture_public_images_once(native::RegisteredProject { path: root_path, identity },
            &spellings, budget.payload_bytes, retained,
            &mut || { let stopped = stop(); cancelled.set(cancelled.get() || stopped); stopped },
            &mut |error| { reported.set(true); failed(public_image_reason(error, cancelled.get())); });
        let captured = native_result.map_err(|error| public_image_reason(error, cancelled.get()))?;
        if !book.settled() { return Err(Reason::CleanupUnknown); }
        // Count both live container capacities and this same retained native book
        // before moving any original bytes. No whole-batch or per-file byte clone.
        budget.admit(book.project.public_image_retained_bytes()
            .and_then(|n| n.checked_add(captured.retained_bytes()?)).and_then(|n| n.checked_add(application)))?;
        if captured.images.len() != prepared.len() { return Err(Reason::CleanupUnknown); }
        let native::PublicImageBatchSnapshot { images: captured, protected_sources } = captured;
        for (snapshot, mut control) in captured.into_iter().zip(prepared) {
            if stop() { return Err(Reason::UserCancelled); }
            write!(&mut control.sha256, "{:x}", Sha256::digest(&snapshot.bytes)).map_err(|_| Reason::Capacity)?;
            images.push(CapturedPublicImage { item_id: control.item_id, display_name: control.display_name,
                bytes: snapshot.bytes, sha256: control.sha256, origin: PublicImageOriginWitness::Windows(snapshot.origin) });
        }
        drop(spellings); drop(paths);
        let batch = CapturedPublicImageBatch { images, protected_sources };
        budget.admit(book.project.public_image_retained_bytes().and_then(|n| n.checked_add(batch.retained_bytes()?)))?;
        if stop() { return Err(Reason::UserCancelled); }
        Ok(batch)
    })();
    if let Err(reason) = &result { if !reported.get() { failed(*reason); } }
    result
}

#[cfg(test)]
mod public_image_adapter_data_tests {
    use super::*;
    #[test]
    fn public_image_display_and_extensions_are_not_credential_policy() {
        for path in [r"C:\shared\screen.PNG", r"\\?\C:\shared\screen.jpeg", r"D:\images\screen.jpg"] {
            assert!(public_image_name(Path::new(path), 0).is_ok());
        }
        for path in [r"C:\shared\screen.p12", r"C:\shared\screen.png:secret", r"C:\shared\..\screen.png",
            r"\\server\share\screen.png", r"C:\shared\.png"] {
            assert!(public_image_name(Path::new(path), 0).is_err());
        }
        assert_eq!(public_image_name(Path::new("C:\\shared\\a\u{202e}b.png"), 1).unwrap(), "selected-image-02.png");
    }
    #[test]
    fn public_image_admission_and_failure_categories_are_pure_data() {
        let mut book = SourceBook::new();
        let root = RegisteredRoot { path: r"C:\project".into(), identity: ProjectIdentity::Windows { volume: 1, file_id: [1; 16] } };
        let mut reports = Vec::new();
        assert!(capture_public_images(&mut book, Vec::new(), &root,
            PublicImageBudget { payload_bytes: 10, retained_bytes: 20 }, &mut || panic!("no native work"),
            &mut |reason| reports.push(reason)).is_err());
        assert!(book.not_started()); assert_eq!(reports, [Reason::MaterialLimit]);
        assert_eq!(public_image_reason(native::PublicImageError::Native(native::Error::Unknown), true), Reason::CleanupUnknown);
        assert_eq!(public_image_reason(native::PublicImageError::Native(native::Error::State), true), Reason::CleanupUnknown);
        assert_eq!(public_image_reason(native::PublicImageError::SourceChanged, false), Reason::SourceChanged);
        assert_eq!(public_image_reason(native::PublicImageError::MaterialLimit, false), Reason::MaterialLimit);
        assert_eq!(public_image_reason(native::PublicImageError::Native(native::Error::Unavailable), true), Reason::UserCancelled);
    }
}
