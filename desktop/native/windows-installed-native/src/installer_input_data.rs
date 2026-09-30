//! Fixed installer mapping/capacity DATA, not native or execution authority.

/// Literal DATA roster, not caller-selected destinations or executable authority.
pub const PUBLICATION_PAYLOADS: [&str; 47] = [
    "android_build_bootstrap.py",
    "config_edit_bootstrap.py",
    "core.zip",
    "engine_bootstrap.py",
    "environment_bootstrap.py",
    "github-ca.pem",
    "github_connection_bootstrap.py",
    "manifest.json",
    "offline_preflight_bootstrap.py",
    "python/LICENSE.txt",
    "python/MRK-EMBEDDED-NOTICES.txt",
    "python/_asyncio.pyd",
    "python/_bz2.pyd",
    "python/_ctypes.pyd",
    "python/_decimal.pyd",
    "python/_elementtree.pyd",
    "python/_hashlib.pyd",
    "python/_lzma.pyd",
    "python/_multiprocessing.pyd",
    "python/_overlapped.pyd",
    "python/_queue.pyd",
    "python/_remote_debugging.pyd",
    "python/_socket.pyd",
    "python/_sqlite3.pyd",
    "python/_ssl.pyd",
    "python/_uuid.pyd",
    "python/_wmi.pyd",
    "python/_zoneinfo.pyd",
    "python/_zstd.pyd",
    "python/libcrypto-3.dll",
    "python/libffi-8.dll",
    "python/libssl-3.dll",
    "python/libtommath.dll",
    "python/pyexpat.pyd",
    "python/python.cat",
    "python/python.exe",
    "python/python3.dll",
    "python/python314._pth",
    "python/python314.dll",
    "python/python314.zip",
    "python/pythonw.exe",
    "python/select.pyd",
    "python/sqlite3.dll",
    "python/unicodedata.pyd",
    "python/vcruntime140.dll",
    "python/vcruntime140_1.dll",
    "python/winsound.pyd",
];

pub(super) fn digest_name(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(feature = "installer-acquisition")]
pub(super) const TARGET: &str = "x86_64-pc-windows-msvc";
#[cfg(feature = "installer-acquisition")]
pub(super) const INPUTS: usize = 54;
#[cfg(feature = "installer-acquisition")]
pub(super) const PAYLOADS: usize = 52;
#[cfg(feature = "installer-acquisition")]
pub(super) const CONTROLS: [usize; 2] = [52, 53];
#[cfg(feature = "installer-acquisition")]
pub(super) const CONTROL_LIMITS: [usize; 2] = [16 * 1024, 1024 * 1024];
#[cfg(feature = "installer-acquisition")]
pub(super) const PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(feature = "installer-acquisition")]
pub(super) const ACQUISITION_TOTAL_BYTES: u64 = PAYLOAD_BYTES + 1024 * 1024 + 16 * 1024;
#[cfg(feature = "installer-acquisition")]
pub(super) const OUTPUT_RECORDS: usize = 131072;
#[cfg(feature = "installer-acquisition")]
pub(super) const SOURCE_COMPONENTS: usize = 16;
#[cfg(feature = "installer-acquisition")]
pub(super) const DIRECTORY_INTENTS: usize = 12;
#[cfg(feature = "installer-acquisition")]
pub(super) const CHUNK_BYTES: usize = 64 * 1024;
// Actual fixed recheck call sites: admit, create, each new directory, each
// start/finish-copy, and final pre/post inventory. Only nonempty copied chunks
// use the separate variable term below. There is no readback-token reset loop.
#[cfg(feature = "installer-acquisition")]
pub(super) const FIXED_RECHECKS: usize = 1 + 1 + DIRECTORY_INTENTS + 2 * INPUTS + 2;
#[cfg(feature = "installer-acquisition")]
pub(super) const FULL_REQUEST_CHUNKS: usize =
    ACQUISITION_TOTAL_BYTES.div_ceil(CHUNK_BYTES as u64) as usize + INPUTS - 1;
#[cfg(feature = "installer-acquisition")]
pub(super) const FULL_REQUEST_TOKEN_RECORDS: usize = FULL_REQUEST_CHUNKS * 6;
// Initial token + two probes, fixed rechecks, both books' maximum retained
// directory rosters, and every source/writer/readback original. This is an
// intentionally conservative fixed control-flow bound, not arbitrary short I/O.
#[cfg(feature = "installer-acquisition")]
pub(super) const FIXED_RECORDS: usize = 3 + FIXED_RECHECKS * 6 + 2 * 48 + 3 * INPUTS;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "installer-acquisition")]
pub(super) struct InputPath {
    pub(super) source: String,
    pub(super) output: String,
}
#[cfg(feature = "installer-acquisition")]
impl InputPath {
    pub(super) fn image(&self) -> bool {
        self.source.ends_with(".exe") || self.source.ends_with(".dll") || self.source.ends_with(".pyd")
    }
}

#[derive(Clone, Debug)]
#[cfg(feature = "installer-acquisition")]
pub(super) struct InputLayout {
    pub(super) paths: [InputPath; INPUTS],
    // Relative to the admitted strict source root / OS-discovered MRK root.
    // Empty denotes that root, not a caller-supplied filesystem path.
    pub(super) source_directories: Vec<String>,
    pub(super) output_directories: Vec<String>,
}
#[cfg(feature = "installer-acquisition")]
fn directories(paths: impl Iterator<Item = String>) -> Vec<String> {
    let mut result = std::collections::BTreeSet::from([String::new()]);
    for path in paths {
        let mut current = path.as_str();
        while let Some((parent, _)) = current.rsplit_once('/') {
            result.insert(parent.to_owned()); current = parent;
        }
    }
    let mut result: Vec<_> = result.into_iter().collect();
    result.sort_by_key(|path| (path.split('/').filter(|s| !s.is_empty()).count(), path.clone()));
    result
}
#[cfg(feature = "installer-acquisition")]
impl InputLayout {
    pub(super) fn new(digest: &str, helper: &str, image: &str) -> Option<Self> {
        if !digest_name(digest) || !digest_name(helper) || !digest_name(image) { return None; }
        // D authenticates runtime bytes; I independently binds the complete
        // finalized application profile. Same-D shell upgrades get a new I.
        let source = format!("runtime-input/{TARGET}/{digest}");
        let output = format!("runtime-input/{TARGET}/{image}");
        let installer = format!("installer-input/{TARGET}/{image}");
        let mut paths: Vec<_> = PUBLICATION_PAYLOADS.iter().map(|leaf| {
            InputPath { source: format!("{source}/{leaf}"), output: format!("{output}/{leaf}") }
        }).collect();
        for (source, output) in [
            ("publisher/mrk-windows-runtime-publish.exe", format!("{helper}/mrk-windows-runtime-publish.exe")),
            ("shell/mobile-release-kit-desktop.exe", "shell/mobile-release-kit-desktop.exe".to_owned()),
            ("prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe", "prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe".to_owned()),
            ("licenses/application-notices.txt", "licenses/application-notices.txt".to_owned()),
            ("licenses/webview2-notices.txt", "licenses/webview2-notices.txt".to_owned()),
            ("admission.json", "admission.json".to_owned()),
            ("inventory.json", "inventory.json".to_owned()),
        ] {
            paths.push(InputPath { source: source.to_owned(), output: format!("{installer}/{output}") });
        }
        let source_directories = directories(paths.iter().map(|p| p.source.clone()));
        let output_directories = directories(paths.iter().map(|p| p.output.clone()));
        Some(Self { paths: paths.try_into().ok()?, source_directories, output_directories })
    }
}

// These are expected authenticated DATA3 lengths. DirectoryEntry has no actual
// size: each original file must additionally prove equality before its writer.
#[cfg(feature = "installer-acquisition")]
pub(super) fn expected_sizes(sizes: &[u64; INPUTS]) -> Option<u64> {
    for (index, size) in sizes.iter().copied().enumerate() {
        let limit = match index {
            7 => 1024 * 1024, // original runtime manifest
            47 | 48 => 256 * 1024 * 1024,
            50 | 51 => 4 * 1024 * 1024,
            52 => CONTROL_LIMITS[0] as u64,
            53 => CONTROL_LIMITS[1] as u64,
            _ => 512 * 1024 * 1024,
        };
        if size == 0 || size > limit { return None; }
    }
    let payload = sizes[..PAYLOADS].iter().try_fold(0u64, |sum, n| sum.checked_add(*n))?;
    if payload > PAYLOAD_BYTES { return None; }
    let total = sizes.iter().try_fold(0u64, |sum, n| sum.checked_add(*n))?;
    (total <= ACQUISITION_TOTAL_BYTES).then_some(total)
}

#[cfg(feature = "installer-acquisition")]
pub(super) fn control_window(expected: u64, original_read: u64, original_eof: bool,
    cache_length: usize, copied: u64) -> Option<std::ops::Range<usize>> {
    if !original_eof || original_read != expected || cache_length as u64 != expected || copied > expected {
        return None;
    }
    let start = usize::try_from(copied).ok()?;
    Some(start..start.checked_add(CHUNK_BYTES)?.min(cache_length))
}

// Canonical component DATA only. Callers also require separately observed
// mappings, original identities and security before using a common ancestor.
#[cfg(feature = "installer-acquisition")]
pub(super) fn prefix_components(prefix: &[String], path: &[String]) -> bool {
    prefix.len() <= path.len() && prefix.iter().zip(path).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

#[cfg(all(test, feature = "installer-acquisition"))]
mod tests {
    use super::*;
    #[test]
    fn fixed_roster_mapping_and_per_release_helpers() -> Result<(), &'static str> {
        let d = "a".repeat(64); let h = "b".repeat(64); let image = "c".repeat(64);
        let layout = InputLayout::new(&d, &h, &image).ok_or("layout")?;
        assert_eq!(PUBLICATION_PAYLOADS.len(), 47);
        assert!(PUBLICATION_PAYLOADS.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(PUBLICATION_PAYLOADS.iter().filter(|p| p.starts_with("python/")).count(), 38);
        assert_eq!(layout.source_directories.len(), 9);
        assert_eq!(layout.output_directories.len(), DIRECTORY_INTENTS);
        assert_eq!(layout.paths.len(), INPUTS);
        for (i, leaf) in PUBLICATION_PAYLOADS.iter().enumerate() {
            assert_eq!(layout.paths[i].source, format!("runtime-input/{TARGET}/{d}/{leaf}"));
            assert_eq!(layout.paths[i].output, format!("runtime-input/{TARGET}/{image}/{leaf}"));
        }
        assert_eq!(layout.paths[47].output, format!("installer-input/{TARGET}/{image}/{h}/mrk-windows-runtime-publish.exe"));
        assert_eq!(layout.paths[52].source, "admission.json");
        assert_eq!(layout.paths[53].source, "inventory.json");
        // Same D, changed finalized shell/profile I: no output collision.
        let next = InputLayout::new(&d, &h, &"e".repeat(64)).ok_or("next")?;
        assert_eq!(layout.paths[0].source, next.paths[0].source);
        for row in &layout.paths {
            assert!(!next.paths.iter().any(|n| n.output == row.output));
            assert!(!row.output.starts_with("versions/") && !row.output.starts_with("desktop/"));
        }
        assert!(InputLayout::new(&"A".repeat(64), &h, &image).is_none());
        assert!(InputLayout::new(&d, "../helper", &image).is_none());
        assert!(InputLayout::new(&d, &h, "../image").is_none());
        Ok(())
    }
    #[test]
    fn finite_capacity_is_not_an_arbitrary_short_read_promise() {
        assert_eq!(FULL_REQUEST_CHUNKS, 16454);
        assert_eq!(FULL_REQUEST_TOKEN_RECORDS, 98724);
        assert_eq!(OUTPUT_RECORDS - FULL_REQUEST_TOKEN_RECORDS, 32348);
        assert!(FIXED_RECORDS < OUTPUT_RECORDS - FULL_REQUEST_TOKEN_RECORDS);
        // One-byte native reads still each require six originals. They exhaust
        // the unchanged fixed record capacity; they cannot promise success.
        assert!(ACQUISITION_TOTAL_BYTES * 6 > OUTPUT_RECORDS as u64);
        let mut sizes = [1; INPUTS];
        assert_eq!(expected_sizes(&sizes), Some(INPUTS as u64));
        sizes[52] = CONTROL_LIMITS[0] as u64 + 1;
        assert!(expected_sizes(&sizes).is_none()); sizes[52] = 1;
        sizes[53] = 0; assert!(expected_sizes(&sizes).is_none()); sizes[53] = 1;
        sizes[0] = 512 * 1024 * 1024; sizes[1] = 512 * 1024 * 1024;
        assert!(expected_sizes(&sizes).is_none());
    }
    #[test]
    fn control_cache_never_supplies_an_original_eof_or_second_read() {
        assert!(control_window(17, 17, false, 17, 0).is_none());
        assert!(control_window(17, 16, true, 17, 0).is_none());
        assert!(control_window(17, 17, true, 18, 0).is_none());
        assert!(control_window(17, 17, true, 17, 18).is_none());
        assert_eq!(control_window(17, 17, true, 17, 0), Some(0..17));
        assert_eq!(control_window(17, 17, true, 17, 17), Some(17..17));
    }
    #[test]
    fn component_overlap_is_not_a_text_prefix() {
        let values = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(prefix_components(&values(&["Program Files", "Mobile Release Kit"]),
            &values(&["Program Files", "mobile release kit", "source"])));
        assert!(!prefix_components(&values(&["Program Files", "Mobile Release Kit"]),
            &values(&["Program Files", "Mobile Release Kit backup"])));
    }
}
