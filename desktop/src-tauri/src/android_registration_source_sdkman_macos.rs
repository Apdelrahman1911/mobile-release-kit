//! One fallback on the SAME acquisition SourceSlots, not an SDKMAN runner.
//! The ordinary fixed Gradle absence remains retained and is rechecked before
//! this lookup and at source POST. No current symlink, PATH or version scan.
use super::*;

pub(super) const SLOT: usize = 3;
pub(super) const SUFFIX: &str = "/.sdkman/candidates/gradle/8.14.5";

impl DiscoveryWork {
    fn sdkman_pending(&self) -> bool {
        self.searched & 4 != 0
            && self.present & 4 == 0
            && self.paths[2].as_deref() == Some(Path::new(data::GRADLE))
            && self.absent[2].is_some()
            && self.paths[SLOT].is_none()
            && self.absent[SLOT].is_none()
    }
}

impl SourceSlots {
    pub(super) fn discovery_sdkman_gradle(
        &mut self,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<Option<usize>> {
        self.point(end, stop)?;
        if self.roots[2].is_some()
            || !self
                .acquisition
                .as_ref()
                .ok_or(AdmissionFailure::Unknown)?
                .discovery
                .sdkman_pending()
        {
            return Err(AdmissionFailure::Inventory);
        }
        // A recorded missing edge is not enough: require this SAME held parent
        // and its current negative edge before Account/path/native entry. A
        // failure never becomes None or authorizes another location/retry.
        self.discovery_check_absent(2, end, stop)?;
        self.discovery_path(SLOT, end, stop)?;
        self.discovery_location(SLOT, end, stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdkman_path_is_fixed_native_home_version_not_current_or_environment() {
        let path = fixed_path(SLOT, Some("/Users/inert-fixture")).unwrap();
        assert_eq!(
            path,
            Path::new("/Users/inert-fixture/.sdkman/candidates/gradle/8.14.5")
        );
        assert!(!path.to_str().unwrap().contains("current"));
        for home in [
            None,
            Some("/"),
            Some("relative"),
            Some("/Users/../other"),
            Some("/Users/name/"),
            Some("/Users/a\\b"),
            Some("/Users/a\nname"),
        ] {
            assert!(fixed_path(SLOT, home).is_err());
        }
        assert!(fixed_path(SLOT + 1, Some("/Users/inert-fixture")).is_err());
        assert_eq!(fixed_path(2, None).unwrap(), Path::new(data::GRADLE));
        let work = DiscoveryWork::new();
        assert!(!work.account_entered);
        assert!(work.call_settled()); // Unentered Account only; no native lookup.
    }

    #[test]
    fn sdkman_needs_exact_primary_negative_not_present_failed_or_a_second_lookup() {
        use nix::errno::Errno;
        let mut work = DiscoveryWork::new();
        work.paths[2] = Some(fixed_path(2, None).unwrap());
        work.searched = 4;
        assert!(!work.sdkman_pending());
        // Exercise the production errno classifier, not error -> absence.
        for result in [
            Ok(()),
            Err(Errno::EACCES),
            Err(Errno::EPERM),
            Err(Errno::ENOTDIR),
            Err(Errno::ELOOP),
            Err(Errno::EINTR),
            Err(Errno::EIO),
        ] {
            assert_ne!(absent_entry(result), Ok(true));
            assert!(!work.sdkman_pending());
        }
        assert_eq!(absent_entry(Err(Errno::ENOENT)), Ok(true));
        // Inert bookkeeping only. This does NOT supply the native held parent
        // required by discovery_check_absent before the actual fallback call.
        work.absent[2] = Some(Absent {
            parent: 7,
            name: "gradle-8.14.5".to_owned(),
        });
        assert!(work.sdkman_pending());
        work.present = 4;
        assert!(!work.sdkman_pending());
        work.present = 0;
        work.paths[SLOT] = Some(fixed_path(SLOT, Some("/Users/inert-fixture")).unwrap());
        work.absent[SLOT] = Some(Absent {
            parent: 11,
            name: "8.14.5".to_owned(),
        });
        assert!(!work.sdkman_pending());
        assert_eq!(work.absent[2].as_ref().unwrap().parent, 7);
        assert_eq!(work.absent[SLOT].as_ref().unwrap().parent, 11);
        assert_eq!(work.paths[2].as_deref(), Some(Path::new(data::GRADLE)));
        assert!(work.finding.is_none()); // No result or source authority minted.
    }

    #[test]
    fn sdkman_paths_and_both_rosters_fit_unchanged_heap_spill_and_fd_limits() {
        use crate::android_build_protocol::Profile;
        assert_eq!(LIVE_FDS, 64);
        assert_eq!(HEAP_BOUND, 3 * (4096 + 255));
        // Two home-based paths, two short literal paths, four negative names.
        // Exact-capacity paths + their original component names fit the OLD
        // three-path charges; the additional inline slots use size_of<SourceSlots>.
        let path_heap = data::JDK.len() + data::GRADLE.len() + 2 * 4096;
        assert!(path_heap <= 3 * 4096);
        assert!(path_heap + 4 * 255 <= HEAP_BOUND);
        let mut work = DiscoveryWork::new();
        for slot in 0..4 {
            work.paths[slot] = Some(fixed_path(slot, Some("/Users/inert-fixture")).unwrap());
            work.absent[slot] = Some(Absent {
                parent: slot,
                name: "x".repeat(255),
            });
        }
        assert!(work.heap_bytes().is_some_and(|bytes| bytes <= HEAP_BOUND));
        let chains = |slot: usize| {
            work.paths[slot].as_ref().unwrap().to_str().unwrap()[1..]
                .split('/')
                .count()
                + 1
        };
        let retained_ancestors = chains(0) + chains(1) + (chains(2) - 1) + chains(SLOT);
        assert_eq!(retained_ancestors, 21);
        // Fixed native-home shape, worst16 directory walk + one file, retained
        // JDK Contents/Home/release and both SDK prefixes. Deep arbitrary homes
        // still hit the SAME reserve()->LIVE_FDS refusal, never another quota.
        assert_eq!(retained_ancestors + 3 + 4 + 16 + 1, 45);
        assert!(retained_ancestors + 3 + 4 + 16 + 1 <= LIVE_FDS);
        assert!(3 * ANCESTORS + 3 + 3 + 4 + 2 <= SOURCE_ORIGINAL_SPILL);
        for profile in [Profile::MacArm64, Profile::MacX64] {
            let checked = supplier::acquisition::picked_roster_data(profile).unwrap();
            assert!(checked
                .roster
                .members
                .iter()
                .all(|member| member.relative.split('/').count() <= 16));
            let reserved = super::super::super::reservation(checked).unwrap();
            assert_eq!(
                reserved.storage.originals,
                reserved.storage.members - reserved.storage.aliases + SOURCE_ORIGINAL_SPILL
            );
            let retained = reserved.acquisition_retained_bytes().unwrap();
            assert_eq!(
                reserved.bytes,
                retained + super::super::super::READ_WORKSPACE
            );
            assert!(82 * 1024 * 1024 + 2 * retained < 96 * 1024 * 1024);
        }
    }
}
