//! Fixed conventional lookup DATA, not selected-source or executable authority.
//! Only the existing SourceSlots read/POST/close and original owner joins may
//! attach this to a current project inspection. No path enters the public view.
use super::components::Partition;
use serde_json::{json, Value};

pub(crate) const SCOPE: &str = "fixed-macos-locations-v1";
pub(crate) const ROLES: [&str; 3] = ["jdk", "sdk", "gradle"];
pub(crate) const JDK: &str = "/Library/Java/JavaVirtualMachines/temurin-17.jdk";
pub(crate) const GRADLE: &str = "/opt/gradle/gradle-8.14.5";
pub(crate) const SDK_SUFFIX: &str = "/Library/Android/sdk";
const COMPONENT_ROLES: [u8; 4] = [1, 2, 2, 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Discovery {
    searched: u8,
    present: u8,
    compatible: u8,
}
impl Discovery {
    /// The caller supplies actual successful original observations. Unknown or
    /// failed checks have NO representation here and cannot become absence.
    pub(crate) fn observed(searched: u8, present: u8, parts: Partition) -> Option<Self> {
        if searched & !7 != 0 || present & !searched != 0 {
            return None;
        }
        let mut compatible = 0;
        for (index, role) in COMPONENT_ROLES.into_iter().enumerate() {
            if searched & role != 0 && parts.is_compatible(index) {
                if present & role == 0 {
                    return None;
                }
                compatible |= 1 << index;
            }
        }
        Some(Self {
            searched,
            present,
            compatible,
        })
    }
    pub(crate) fn searched(&self) -> bool {
        self.searched != 0
    }
    pub(crate) fn candidate_roles(&self) -> u8 {
        COMPONENT_ROLES
            .into_iter()
            .enumerate()
            .fold(0, |roles, (index, role)| {
                roles
                    | if self.compatible & (1 << index) != 0 {
                        role
                    } else {
                        0
                    }
            })
    }
    pub(crate) fn needs_selection(&self) -> bool {
        self.candidate_roles() != 0
    }
    pub(crate) fn matches(&self, parts: Partition) -> bool {
        Self::observed(self.searched, self.present, parts) == Some(*self)
    }
    pub(crate) fn data(&self) -> Value {
        let roles = |mask: u8| {
            ROLES
                .into_iter()
                .enumerate()
                .filter_map(move |(i, role)| (mask & (1 << i) != 0).then_some(role))
                .collect::<Vec<_>>()
        };
        json!({"scope":SCOPE,"searched":roles(self.searched),"present":roles(self.present),
            "compatibleComponents":super::components::ALL.into_iter().enumerate().filter_map(|(i, component)|
                (self.compatible & (1 << i) != 0).then_some(component)).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_scope_distinguishes_absent_present_and_compatible_without_paths() {
        let parts =
            Partition::observed([Some(true), Some(true), Some(false), Some(false)]).unwrap();
        let found = Discovery::observed(7, 3, parts).unwrap();
        assert!(found.needs_selection());
        assert_eq!(found.candidate_roles(), 3);
        assert_eq!(
            found.data(),
            json!({"scope":SCOPE,"searched":["jdk","sdk","gradle"],
            "present":["jdk","sdk"],"compatibleComponents":["jdk","sdk-platform"]})
        );
        assert!(!found.data().to_string().contains('/'));
        // An existing SDK with neither exact package is present, not absent.
        assert!(!Discovery::observed(2, 2, Partition::missing_all())
            .unwrap()
            .needs_selection());
        assert_eq!(
            Discovery::observed(2, 0, Partition::missing_all())
                .unwrap()
                .data()["present"],
            json!([])
        );
        assert!(Discovery::observed(7, 1, parts).is_none());
        assert!(Discovery::observed(8, 0, parts).is_none());
        assert!(Discovery::observed(1, 3, parts).is_none());
    }
    #[test]
    fn explicit_picks_are_not_rediscovered_or_reported_as_unchosen_candidates() {
        let parts = Partition::compatible_all();
        assert!(!Discovery::observed(0, 0, parts).unwrap().searched());
        assert!(!Discovery::observed(0, 0, parts).unwrap().needs_selection());
        let only_gradle = Discovery::observed(4, 4, parts).unwrap();
        assert_eq!(only_gradle.candidate_roles(), 4);
        assert!(!only_gradle.matches(Partition::missing_all()));
        assert_eq!(
            only_gradle.data()["compatibleComponents"],
            json!(["gradle"])
        );
    }
}
