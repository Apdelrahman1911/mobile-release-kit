//! Darwin flags for the fixed Git provider and its held source ancestors.
//! This does not relax owner/mode/link/ACL/content or named-original checks.
use super::Reason;

#[derive(Clone, Copy)]
pub(super) enum Kind { SystemGit, Directory, RepositoryFile }

// Apple sys/stat.h. Compression is an ordinary representation of the fixed
// root-owned CLT executable. System directories may carry SF_RESTRICTED,
// SF_NOUNLINK, SF_FIRMLINK and UF_HIDDEN (the real /private Finder flag).
const COMPRESSED: u32 = 0x00000020;
const ANCESTOR_FLAGS: u32 = 0x00080000 | 0x00100000 | 0x00800000 | 0x00008000;

pub(super) fn permits(flags: u32, owner: u32, kind: Kind) -> bool {
    let allowed = match (owner, kind) {
        (0, Kind::SystemGit) => COMPRESSED,
        (0, Kind::Directory) => ANCESTOR_FLAGS,
        _ => 0,
    };
    flags & !allowed == 0
}

pub(super) struct Snapshots<const N: usize>([Option<u32>; N]);
impl<const N: usize> Snapshots<N> {
    pub(super) fn new() -> Self { Self([None; N]) }

    pub(super) fn observe(&mut self, index: usize, held: u32, named: u32,
        owner: u32, kind: Kind) -> Result<(), Reason> {
        let original = self.0.get_mut(index).ok_or(Reason::Capacity)?;
        if held != named || !permits(held, owner, kind) || original.is_some_and(|flags| flags != held) {
            return Err(Reason::SourceChanged);
        }
        *original = Some(held);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compression_only_belongs_to_fixed_root_owned_git() {
        assert!(permits(COMPRESSED, 0, Kind::SystemGit));
        for (owner, kind) in [(501, Kind::SystemGit), (0, Kind::Directory),
            (0, Kind::RepositoryFile), (501, Kind::RepositoryFile)] {
            assert!(!permits(COMPRESSED, owner, kind));
        }
    }
    #[test]
    fn protection_and_hidden_flags_only_belong_to_root_owned_directories() {
        assert!(permits(ANCESTOR_FLAGS, 0, Kind::Directory));
        for (owner, kind) in [(501, Kind::Directory), (0, Kind::SystemGit), (0, Kind::RepositoryFile)] {
            assert!(!permits(ANCESTOR_FLAGS, owner, kind));
        }
        for bit in 0..32 {
            let flags = 1 << bit;
            if flags & ANCESTOR_FLAGS == 0 { assert!(!permits(flags, 0, Kind::Directory)); }
            if flags != COMPRESSED { assert!(!permits(flags, 0, Kind::SystemGit)); }
        }
    }
    #[test]
    fn held_named_and_later_original_flags_must_match() {
        let mut snapshots = Snapshots::<2>::new();
        assert_eq!(snapshots.observe(0, COMPRESSED, 0, 0, Kind::SystemGit), Err(Reason::SourceChanged));
        assert_eq!(snapshots.observe(0, COMPRESSED, COMPRESSED, 0, Kind::SystemGit), Ok(()));
        assert_eq!(snapshots.observe(0, 0, 0, 0, Kind::SystemGit), Err(Reason::SourceChanged));
        assert_eq!(snapshots.observe(0, COMPRESSED, COMPRESSED, 0, Kind::SystemGit), Ok(()));
        assert_eq!(snapshots.observe(1, 0, 0, 501, Kind::RepositoryFile), Ok(()));
        assert_eq!(snapshots.observe(1, COMPRESSED, COMPRESSED, 501, Kind::RepositoryFile), Err(Reason::SourceChanged));
        assert_eq!(snapshots.observe(2, 0, 0, 0, Kind::Directory), Err(Reason::Capacity));
    }
}
