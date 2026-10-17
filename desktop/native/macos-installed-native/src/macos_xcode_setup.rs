//! Fixed protected-Xcode setup DATA, not a root grant or installed tool receipt.
//!
//! The separate Installer Parent/copier must supply its actual original facts.
//! This module performs no filesystem access, package launch, or publication.
//! It is deliberately not registered in the product until that caller is joined.

pub(crate) const ROOT: &str = "/Library/MobileReleaseKitDeveloper";
pub(crate) const APP: &str = "Xcode.app";
pub(crate) const DEVELOPER: &str =
    "/Library/MobileReleaseKitDeveloper/Xcode.app/Contents/Developer";
pub(crate) const PENDING: &str = ".pending";
pub(crate) const LOCK: &str = "setup.lock";
pub(crate) const ATTEMPT: &str = "attempt.json";
pub(crate) const APPLE_REQUIREMENT: &str = "identifier \"com.apple.dt.Xcode\" and anchor apple";

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
pub(crate) const ENTRY_LIMIT: u64 = 1_000_000;
pub(crate) const DATA_LIMIT: u64 = 128 * GIB;
pub(crate) const FILE_LIMIT: u64 = 16 * GIB;
pub(crate) const ATTRIBUTE_LIMIT: u64 = MIB;
pub(crate) const ALL_ATTRIBUTES_LIMIT: u64 = 256 * MIB;
pub(crate) const NAME_CONTROL_LIMIT: u64 = 32 * MIB;
pub(crate) const DEPTH_LIMIT: usize = 64;
pub(crate) const PATH_LIMIT: usize = 4096;
pub(crate) const LINK_LIMIT: usize = 1024;
pub(crate) const OWNED_MEMORY_LIMIT: usize = 96 * 1024 * 1024;
pub(crate) const ORIGINAL_LIMIT: usize = 256;
pub(crate) const PARENT_ORIGINAL_LIMIT: usize = 32;
pub(crate) const COPIER_ORIGINAL_LIMIT: usize = 192;
pub(crate) const TRANSIENT_ORIGINAL_LIMIT: usize = 16;
const SECOND: u64 = 1_000_000_000;
const WORK: u64 = 3600 * SECOND;
const FINISH: u64 = 3720 * SECOND;
const HARD: u64 = 3730 * SECOND;
const FAILURE_CLEANUP: u64 = 120 * SECOND;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Kind,
    PublicAccess,
    SpecialMode,
    Links,
    Bounds,
    Space,
    Clock,
}
type Result<T> = std::result::Result<T, Refusal>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Directory,
    Regular,
    Symlink,
}

/// A regular source may have multiple names. The copier must make independent
/// destination inodes; this policy does NOT permit target hardlinks.
/// Empty ACL and actual original/named equality remain separate native checks.
pub(crate) fn copied_mode(kind: Kind, original_mode: u32, links: u64) -> Result<Option<u32>> {
    let expected = match kind {
        Kind::Directory => 0o040000,
        Kind::Regular => 0o100000,
        Kind::Symlink => 0o120000,
    };
    if original_mode & 0o170000 != expected {
        return Err(Refusal::Kind);
    }
    if original_mode & 0o7000 != 0 {
        return Err(Refusal::SpecialMode);
    }
    if links == 0 || (kind == Kind::Symlink && links != 1) {
        return Err(Refusal::Links);
    }
    match kind {
        Kind::Directory if original_mode & 0o005 == 0o005 => Ok(Some(0o555)),
        Kind::Regular if original_mode & 0o004 != 0 => {
            if original_mode & 0o111 == 0 {
                Ok(Some(0o444))
            } else if original_mode & 0o001 != 0 {
                Ok(Some(0o555))
            } else {
                Err(Refusal::PublicAccess)
            }
        }
        Kind::Symlink => Ok(None), // Preserve link bytes; never chmod/follow it.
        _ => Err(Refusal::PublicAccess),
    }
}

/// Reserve the actual live totals before an open/allocation. Unknown originals
/// remain in these caller-owned totals; future closes never earn headroom.
pub(crate) fn originals_fit(
    parent: usize,
    copier: usize,
    transient: usize,
    owned_bytes: usize,
) -> bool {
    parent <= PARENT_ORIGINAL_LIMIT
        && copier <= COPIER_ORIGINAL_LIMIT
        && transient <= TRANSIENT_ORIGINAL_LIMIT
        && owned_bytes <= OWNED_MEMORY_LIMIT
        && parent
            .checked_add(copier)
            .and_then(|n| n.checked_add(transient))
            .is_some_and(|n| n <= ORIGINAL_LIMIT)
}

/// One actual physical node's source stat/xattr observation. No path, fd or
/// identity is admitted by this value. Quote BEFORE allocating/copying it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NodeSize {
    pub(crate) kind: Kind,
    pub(crate) data_bytes: u64,
    pub(crate) attribute_bytes: u64,
    pub(crate) depth: usize,
    pub(crate) path_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CopyQuote {
    entries: u64,
    data_bytes: u64,
    attribute_bytes: u64,
    allocation_bytes: u64,
    allocation_unit: u64,
}
impl CopyQuote {
    pub(crate) fn new(allocation_unit: u64) -> Result<Self> {
        // Actual fstatfs unit, not a renderer-provided disk-space estimate.
        if !(512..=MIB).contains(&allocation_unit) || !allocation_unit.is_power_of_two() {
            return Err(Refusal::Bounds);
        }
        Ok(Self {
            entries: 0,
            data_bytes: 0,
            attribute_bytes: 0,
            allocation_bytes: 0,
            allocation_unit,
        })
    }
    fn allocated(&self, bytes: u64) -> Result<u64> {
        let blocks = bytes
            .max(1)
            .checked_add(self.allocation_unit - 1)
            .ok_or(Refusal::Bounds)?
            / self.allocation_unit;
        blocks
            .checked_mul(self.allocation_unit)
            .ok_or(Refusal::Bounds)
    }
    pub(crate) fn add(&mut self, node: NodeSize) -> Result<()> {
        if node.depth > DEPTH_LIMIT
            || node.path_bytes == 0
            || node.path_bytes > PATH_LIMIT
            || node.attribute_bytes > ATTRIBUTE_LIMIT
            || (node.kind == Kind::Directory && node.data_bytes != 0)
            || (node.kind == Kind::Regular && node.data_bytes > FILE_LIMIT)
            || (node.kind == Kind::Symlink && !(1..=LINK_LIMIT as u64).contains(&node.data_bytes))
        {
            return Err(Refusal::Bounds);
        }
        let entries = self.entries.checked_add(1).ok_or(Refusal::Bounds)?;
        let data = self
            .data_bytes
            .checked_add(node.data_bytes)
            .ok_or(Refusal::Bounds)?;
        let attributes = self
            .attribute_bytes
            .checked_add(node.attribute_bytes)
            .ok_or(Refusal::Bounds)?;
        // Include one allocation unit per node for metadata, independently of
        // rounded data/xattrs. This is conservative admission, not a promise
        // about future APFS metadata allocation or concurrent free-space use.
        let allocation = self
            .allocation_bytes
            .checked_add(self.allocation_unit)
            .ok_or(Refusal::Bounds)?
            .checked_add(if node.data_bytes == 0 {
                0
            } else {
                self.allocated(node.data_bytes)?
            })
            .ok_or(Refusal::Bounds)?
            .checked_add(if node.attribute_bytes == 0 {
                0
            } else {
                self.allocated(node.attribute_bytes)?
            })
            .ok_or(Refusal::Bounds)?;
        if entries > ENTRY_LIMIT || data > DATA_LIMIT || attributes > ALL_ATTRIBUTES_LIMIT {
            return Err(Refusal::Bounds);
        }
        // An unsuccessful reservation cannot leave a partially advanced quote.
        self.entries = entries;
        self.data_bytes = data;
        self.attribute_bytes = attributes;
        self.allocation_bytes = allocation;
        Ok(())
    }
    pub(crate) fn allocation_unit(&self) -> u64 {
        self.allocation_unit
    }
    pub(crate) fn entries(&self) -> u64 {
        self.entries
    }
    pub(crate) fn logical_bytes(&self) -> u64 {
        self.data_bytes
    }
    pub(crate) fn required_free_bytes(&self) -> Result<u64> {
        // Full copy, never assumed CoW savings; ceil10% plus a minimum2GiB.
        let tenth = self
            .allocation_bytes
            .checked_add(9)
            .ok_or(Refusal::Bounds)?
            / 10;
        self.allocation_bytes
            .checked_add((2 * GIB).max(tenth))
            .ok_or(Refusal::Bounds)
    }
    pub(crate) fn admit_space(&self, available_bytes: u64) -> Result<()> {
        if available_bytes < self.required_free_bytes()? {
            Err(Refusal::Space)
        } else {
            Ok(())
        }
    }
}

/// Caller charges aggregate names across ALL simultaneously retained directory
/// frames, including vector/cell overhead before insertion. Not bytes alone.
pub(crate) fn name_control_fit(current: u64, next_allocation: u64) -> bool {
    current
        .checked_add(next_allocation)
        .is_some_and(|n| n <= NAME_CONTROL_LIMIT)
}

/// Raw directory-entry component, not a path parser or symlink resolver.
pub(crate) fn component(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != b"."
        && name != b".."
        && !name.iter().any(|b| matches!(b, 0 | b'/'))
}

/// A fixed shape only. Complete in-order symlink expansion and original
/// filesystem joins MUST be performed by the actual copier; lexical reduction
/// here would hide `alias/..` traversal and is intentionally not provided.
pub(crate) fn relative_link_shape(target: &[u8]) -> bool {
    !target.is_empty()
        && target.len() <= LINK_LIMIT
        && target[0] != b'/'
        && !target.contains(&0)
        && target
            .split(|b| *b == b'/')
            .all(|part| !part.is_empty() && part.len() <= 255)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Deadline {
    start: u64,
    work: u64,
    finish: u64,
    hard: u64,
}
impl Deadline {
    pub(crate) fn from_original_start(start: u64) -> Result<Self> {
        if start == 0 {
            return Err(Refusal::Clock);
        }
        Ok(Self {
            start,
            work: start.checked_add(WORK).ok_or(Refusal::Clock)?,
            finish: start.checked_add(FINISH).ok_or(Refusal::Clock)?,
            hard: start.checked_add(HARD).ok_or(Refusal::Clock)?,
        })
    }
    pub(crate) fn work(&self, now: u64) -> Result<()> {
        if self.start <= now && now < self.work {
            Ok(())
        } else {
            Err(Refusal::Clock)
        }
    }
    pub(crate) fn cleanup_end(&self, first_failure: Option<u64>) -> Result<u64> {
        match first_failure {
            None => Ok(self.finish),
            Some(first) if self.start <= first && first < self.hard => Ok(self
                .finish
                .min(first.checked_add(FAILURE_CLEANUP).ok_or(Refusal::Clock)?)),
            _ => Err(Refusal::Clock),
        }
    }
    pub(crate) fn hard(&self) -> u64 {
        self.hard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_vendor_copy_never_promotes_private_access_or_shared_inodes() {
        for mode in 0..=0o7777 {
            let file = copied_mode(Kind::Regular, 0o100000 | mode, 2);
            let public =
                mode & 0o7000 == 0 && mode & 4 != 0 && (mode & 0o111 == 0 || mode & 1 != 0);
            assert_eq!(file.is_ok(), public, "{mode:o}");
            if let Ok(Some(target)) = file {
                assert_eq!(target & 0o222, 0);
                assert!(matches!(target, 0o444 | 0o555));
            }
            assert_eq!(
                copied_mode(Kind::Directory, 0o040000 | mode, 2).is_ok(),
                mode & 0o7000 == 0 && mode & 5 == 5
            );
        }
        assert_eq!(
            copied_mode(Kind::Regular, 0o100600, 1),
            Err(Refusal::PublicAccess)
        );
        assert_eq!(
            copied_mode(Kind::Directory, 0o040700, 2),
            Err(Refusal::PublicAccess)
        );
        assert_eq!(copied_mode(Kind::Symlink, 0o120755, 1), Ok(None));
        assert_eq!(copied_mode(Kind::Symlink, 0o120755, 2), Err(Refusal::Links));
        assert_eq!(copied_mode(Kind::Regular, 0o120755, 1), Err(Refusal::Kind));
        assert_eq!(copied_mode(Kind::Regular, 0o100644, 0), Err(Refusal::Links));
    }
    #[test]
    fn full_copy_quote_refuses_before_effect_and_does_not_assume_clone_savings() {
        let file = NodeSize {
            kind: Kind::Regular,
            data_bytes: 169152,
            attribute_bytes: 32,
            depth: 4,
            path_bytes: 160,
        };
        let mut q = CopyQuote::new(4096).unwrap();
        q.add(file).unwrap();
        assert_eq!(q.logical_bytes(), 169152);
        assert_eq!(q.entries(), 1);
        assert_eq!(q.required_free_bytes().unwrap(), 44 * 4096 + 2 * GIB);
        let bound = q.required_free_bytes().unwrap();
        assert_eq!(q.admit_space(bound - 1), Err(Refusal::Space));
        assert_eq!(q.admit_space(bound), Ok(()));
        for bad in [
            NodeSize { depth: 65, ..file },
            NodeSize {
                data_bytes: FILE_LIMIT + 1,
                ..file
            },
            NodeSize {
                path_bytes: 4097,
                ..file
            },
            NodeSize {
                attribute_bytes: ATTRIBUTE_LIMIT + 1,
                ..file
            },
            NodeSize {
                kind: Kind::Directory,
                ..file
            },
        ] {
            let original = q;
            assert_eq!(q.add(bad), Err(Refusal::Bounds));
            assert_eq!(q, original);
        }
        let mut maximum = CopyQuote::new(4096).unwrap();
        for _ in 0..8 {
            maximum
                .add(NodeSize {
                    data_bytes: FILE_LIMIT,
                    attribute_bytes: 0,
                    ..file
                })
                .unwrap();
        }
        let original = maximum;
        assert_eq!(maximum.logical_bytes(), DATA_LIMIT);
        assert_eq!(
            maximum.add(NodeSize {
                data_bytes: 1,
                attribute_bytes: 0,
                ..file
            }),
            Err(Refusal::Bounds)
        );
        assert_eq!(maximum, original);
        assert_eq!(CopyQuote::new(0), Err(Refusal::Bounds));
        assert_eq!(CopyQuote::new(4097), Err(Refusal::Bounds));
    }
    #[test]
    fn aggregate_live_originals_names_and_absolute_deadlines_never_renew() {
        assert!(originals_fit(32, 192, 16, OWNED_MEMORY_LIMIT));
        for (p, c, t, m) in [
            (33, 192, 16, 1),
            (32, 193, 16, 1),
            (32, 192, 17, 1),
            (1, 1, 1, OWNED_MEMORY_LIMIT + 1),
            (usize::MAX, 1, 1, 1),
        ] {
            assert!(!originals_fit(p, c, t, m));
        }
        assert!(name_control_fit(NAME_CONTROL_LIMIT - 1, 1));
        assert!(!name_control_fit(NAME_CONTROL_LIMIT, 1));
        assert!(!name_control_fit(u64::MAX, 1));
        let d = Deadline::from_original_start(10).unwrap();
        assert_eq!(d.work(9), Err(Refusal::Clock));
        assert_eq!(d.work(10 + WORK - 1), Ok(()));
        assert_eq!(d.work(10 + WORK), Err(Refusal::Clock));
        assert_eq!(d.cleanup_end(Some(10 + SECOND)), Ok(10 + 121 * SECOND));
        assert_eq!(
            d.cleanup_end(Some(10 + WORK - 1)),
            Ok(10 + WORK - 1 + FAILURE_CLEANUP)
        );
        assert_eq!(d.cleanup_end(Some(d.hard())), Err(Refusal::Clock));
        assert_eq!(d.cleanup_end(None), Ok(10 + FINISH));
        assert_eq!(Deadline::from_original_start(u64::MAX), Err(Refusal::Clock));
    }
    #[test]
    fn fixed_names_and_relative_link_shape_do_not_pretend_to_resolve_links() {
        assert_eq!(format!("{ROOT}/{APP}/Contents/Developer"), DEVELOPER);
        for name in [APP, PENDING, LOCK, ATTEMPT] {
            assert!(component(name.as_bytes()));
        }
        assert!(APPLE_REQUIREMENT.contains("anchor apple"));
        for bad in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert!(!component(bad));
        }
        assert!(!component(&vec![b'x'; 256]));
        assert!(relative_link_shape(b"../../Versions/A/Resources"));
        assert!(relative_link_shape(b"alias/../actual")); // Shape only; actual ordered resolver is required.
        for bad in [b"".as_slice(), b"/Applications/Xcode.app", b"a//b", b"a\0b"] {
            assert!(!relative_link_shape(bad));
        }
        assert!(!relative_link_shape(&vec![b'x'; LINK_LIMIT + 1]));
    }
}
