// Inert DATA only: original installer methods, abstract snapshots and FD returns.
// No filesystem, OS attributes, grants, installation or native admission.
#![allow(dead_code)]
use std::cell::Cell;
type Result<T> = std::result::Result<T, &'static str>;
fn check(ok: bool, reason: &'static str) -> Result<()> { if ok { Ok(()) } else { Err(reason) } }
mod mobile_release_desktop {
    pub mod macos_applications_launcher { pub const BUNDLE: &str = "app/Contents/Helpers/Mobile Release Kit.app"; }
    pub mod macos_existing_app_metadata {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct SnapshotData(pub u8);
        impl SnapshotData {
            pub fn from_observed_bytes_data(bytes: &[u8]) -> Option<Self> { Some(Self(bytes.first().copied().unwrap_or(0))) }
            pub fn conserve_data(prior: Option<Self>, observed: Self) -> Option<Self> {
                match prior { Some(first) if first != observed => None, Some(first) => Some(first), None => Some(observed) }
            }
        }
    }
}
use mobile_release_desktop::macos_existing_app_metadata::SnapshotData;
#[derive(Clone, Copy)] struct Identity(u8);
impl Identity { fn same_object(self, other: Self) -> bool { self.0 == other.0 } }
struct Original { identity: Option<Identity>, existing_app_metadata: Option<SnapshotData>, actual: Cell<SnapshotData> }
struct Creation { identity: Option<Identity> }
struct Install { originals: Vec<Original>, creations: Vec<Creation>, reader_failed: Cell<bool>, post_failed: Cell<bool> }
#[derive(Clone, Copy)] struct Fd<'a>(&'a Cell<SnapshotData>);
impl<'a> Fd<'a> { fn as_fd(self) -> Self { self } }
mod native {
    pub fn no_xattrs(fd: super::Fd<'_>) -> std::result::Result<(), ()> {
        if fd.0.get().0 == 0 { Ok(()) } else { Err(()) }
    }
}
impl Install {
    fn identity(&self, n: usize) -> Result<Identity> { self.originals[n].identity.ok_or("identity") }
    fn fd(&self, n: usize) -> Result<Fd<'_>> { Ok(Fd(&self.originals[n].actual)) }
    fn clock(&self) -> Result<()> { Ok(()) }
    fn check_name(&self, n: usize, _exact: bool) -> Result<()> {
        check(!self.post_failed.get(), "original-correspondence")?;
        self.existing_app_metadata_post(n, "maintenance-app-attributes")
    }
    fn read_existing_app_metadata(&self, n: usize, reason: &'static str) -> Result<SnapshotData> {
        check(!self.reader_failed.get(), reason)?;
        Ok(self.originals[n].actual.get())
    }
    /* MRK_EXISTING_METADATA_POST_ORIGINAL */
    /* MRK_EXISTING_METADATA_CAPTURE_ORIGINAL */
    /* MRK_APP_ATTRIBUTES_ORIGINAL */
}
fn launcher_inventory_depth_data() -> usize {
    mobile_release_desktop::macos_applications_launcher::BUNDLE.bytes().filter(|b| *b == b'/').count()
}
fn root_check(book: &Install, root: usize, prefix: &str, depth: usize) -> Result<()> {
    /* MRK_TREE_ROOT_ATTRIBUTES_ORIGINAL */
    Ok(())
}
fn book(value: u8) -> Install {
    Install { originals: vec![Original { identity: Some(Identity(3)), existing_app_metadata: None,
        actual: Cell::new(SnapshotData(value)) }], creations: vec![], reader_failed: Cell::new(false), post_failed: Cell::new(false) }
}
fn main() {
    let reason = "maintenance-payload-attributes";
    let prefix = mobile_release_desktop::macos_applications_launcher::BUNDLE;
    let depth = launcher_inventory_depth_data();
    let mut existing = book(7);
    assert_eq!(existing.capture_existing_app_metadata(0, true, reason), Ok(()));
    // This fails with the old original root gate even after enrollment.
    assert_eq!(root_check(&existing, 0, prefix, depth), Ok(()));
    assert_eq!(root_check(&existing, 0, "app", 0), Ok(()));
    for (p, d) in [(prefix, depth+1), ("runtime", 0), ("app/Contents", 1)] {
        assert_eq!(root_check(&existing, 0, p, d), Err(reason));
    }
    for allow in [false, true] {
        let mut fresh = book(7);
        if allow { fresh.creations.push(Creation { identity: Some(Identity(3)) }); }
        assert_eq!(fresh.capture_existing_app_metadata(0, allow, reason), Err(reason));
        assert_eq!(fresh.originals[0].existing_app_metadata, None);
    }
    let mut new_empty = book(0);
    assert_eq!(new_empty.capture_existing_app_metadata(0, false, reason), Ok(()));
    new_empty.originals[0].actual.set(SnapshotData(7));
    assert_eq!(root_check(&new_empty, 0, prefix, depth), Err(reason));
    for changed in [0, 8] {
        existing.originals[0].actual.set(SnapshotData(changed));
        assert_eq!(root_check(&existing, 0, prefix, depth), Err(reason));
        existing.originals.push(Original { identity: Some(Identity(3)), existing_app_metadata: None,
            actual: Cell::new(SnapshotData(changed)) });
        let n = existing.originals.len()-1;
        assert_eq!(existing.capture_existing_app_metadata(n, true, reason), Err(reason));
        assert_eq!(existing.originals[n].existing_app_metadata, None);
    }
    existing.originals[0].actual.set(SnapshotData(7));
    existing.originals.push(Original { identity: Some(Identity(3)), existing_app_metadata: None,
        actual: Cell::new(SnapshotData(7)) });
    let n = existing.originals.len()-1;
    assert_eq!(existing.capture_existing_app_metadata(n, true, reason), Ok(()));
    let mut refused = book(7); refused.reader_failed.set(true);
    assert_eq!(refused.capture_existing_app_metadata(0, true, reason), Err(reason));
    refused.reader_failed.set(false); refused.post_failed.set(true);
    assert_eq!(refused.capture_existing_app_metadata(0, true, reason), Err("original-correspondence"));
    assert_eq!(refused.originals[0].existing_app_metadata, None);
    println!("MRK_EXISTING_LAUNCHER_METADATA_DATA=PASS");
}
