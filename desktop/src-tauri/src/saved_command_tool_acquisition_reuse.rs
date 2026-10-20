//! Read-only reuse of the SAME protected catalogue publication. This is not a
//! tool lease, a component-repair path, or permission to start an installation.
use super::*;

pub(super) enum CatalogLoan {
    Empty(android_catalog::EmptyLoan),
    Selected(Arc<android_catalog::Selection>),
}
impl CatalogLoan {
    pub(super) fn capture(catalog: &android_catalog::Catalog, owner: &Inner) -> Option<Self> {
        if let Some(selected) = catalog.tool_acquisition_selection(owner) {
            return Some(Self::Selected(selected));
        }
        let empty = catalog.empty_acquisition_loan()?;
        empty.joined_for(owner).then_some(Self::Empty(empty))
    }
    pub(super) fn joined_for(&self, owner: &Inner) -> bool {
        match self {
            Self::Empty(original) => original.joined_for(owner),
            Self::Selected(original) => original.matches_owner(owner),
        }
    }
    pub(super) fn current(&self, catalog: &android_catalog::Catalog, owner: &Inner) -> bool {
        self.joined_for(owner)
            && match self {
                Self::Empty(original) => catalog.same_empty_acquisition_loan(original),
                Self::Selected(original) => {
                    catalog.same_tool_acquisition_selection(original, owner)
                }
            }
    }
    pub(super) fn generation(&self) -> u32 {
        match self {
            Self::Empty(original) => original.generation(),
            Self::Selected(original) => original.data().catalog_generation,
        }
    }
    pub(super) fn empty(&self) -> Option<&android_catalog::EmptyLoan> {
        match self {
            Self::Empty(original) => Some(original),
            Self::Selected(_) => None,
        }
    }
    pub(super) fn permits_action(&self, action: wire::Action) -> bool {
        permits_action(self.empty().is_some(), action)
    }
    pub(super) fn finding(
        &self,
        owner: &Inner,
        profile: wire::Profile,
        terminal: &wire::Terminal,
    ) -> wire::ProtectedTools {
        let versions = match self {
            Self::Empty(_) => None,
            Self::Selected(original) => match original.tool_preparation_versions(owner) {
                Some(versions) => Some(versions),
                None => return wire::ProtectedTools::ManualCheckRequired,
            },
        };
        let Some(requirements) = requirements(terminal) else {
            return wire::ProtectedTools::ManualCheckRequired;
        };
        #[cfg(any(
            test,
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        ))]
        {
            // Already-warm checked supplier DATA only. No catalogue startup,
            // filesystem, service or provider call occurs under the Registry.
            let Some(policies) =
                crate::android_supplier_macos::preparation_policies_for(profile.android())
            else {
                return wire::ProtectedTools::ManualCheckRequired;
            };
            if policies.len() != 1 {
                return wire::ProtectedTools::ManualCheckRequired;
            }
            let p = &policies[0];
            let policy = crate::tool_preparation::Policy {
                host: match profile {
                    wire::Profile::MacArm64 => crate::tool_preparation::Host::MacArm64,
                    wire::Profile::MacX64 => crate::tool_preparation::Host::MacX64,
                },
                versions: version_data(&p.versions),
                distribution: crate::tool_preparation::Distribution {
                    url: p.distribution_url.into(),
                    sha256: p.distribution_sha256.into(),
                },
            };
            return finding(&policy, versions, &requirements);
        }
        #[cfg(not(any(
            test,
            all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        {
            let _ = (profile, versions, requirements);
            wire::ProtectedTools::ManualCheckRequired
        }
    }
}

// Even a changed/unsupported project must not turn a known protected selection
// into download permission. Use the ordinary Recover/Choose/manual path instead.
fn permits_action(empty: bool, action: wire::Action) -> bool {
    empty || action == wire::Action::Inspect
}
fn requirements(terminal: &wire::Terminal) -> Option<crate::tool_preparation::Requirements> {
    let raw = crate::edit_protocol::bounded(
        &terminal.result.as_ref()?["requirements"],
        wire::CONTROL_LIMIT,
    )
    .ok()?;
    crate::tool_preparation_protocol::requirements(&raw)
        .ok()
        .map(|(_, value)| value)
}
fn version_data(
    value: &crate::android_toolchain_catalog::Versions,
) -> crate::tool_preparation::Versions {
    crate::tool_preparation::Versions {
        jdk_vendor: value.jdk_vendor.clone(),
        jdk: value.jdk_version.clone(),
        gradle: value.gradle_version.clone(),
        agp: value.agp_version.clone(),
        sdk_platform: value.sdk_platform.clone(),
        sdk_build_tools: value.sdk_build_tools_version.clone(),
    }
}
fn finding(
    policy: &crate::tool_preparation::Policy,
    selected: Option<&crate::android_toolchain_catalog::Versions>,
    requirements: &crate::tool_preparation::Requirements,
) -> wire::ProtectedTools {
    if !policy.permits(requirements)
        || selected.is_some_and(|versions| version_data(versions) != policy.versions)
    {
        wire::ProtectedTools::ManualCheckRequired
    } else if selected.is_some() {
        wire::ProtectedTools::ReuseSelected
    } else {
        wire::ProtectedTools::NoneInSupportedCatalogue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_preparation::{Constraint as C, *};
    fn data() -> (
        Policy,
        crate::android_toolchain_catalog::Versions,
        Requirements,
    ) {
        let selected = crate::android_toolchain_catalog::Versions {
            jdk_vendor: "temurin".into(),
            jdk_version: "17.0.20.1".into(),
            gradle_version: "8.14.5".into(),
            agp_version: "8.9.2".into(),
            sdk_platform: "android-35".into(),
            sdk_build_tools_version: "35.0.0".into(),
        };
        let distribution = Distribution {
            url: "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip".into(),
            sha256: "a".repeat(64),
        };
        let policy = Policy {
            host: Host::MacArm64,
            versions: version_data(&selected),
            distribution: distribution.clone(),
        };
        let requirements = Requirements {
            platform: Platform::Android,
            complete: true,
            xcode: XcodePin {
                version: "26.3".into(),
                build: "17C529".into(),
            },
            android: Some(AndroidRequirements {
                jdk: C::Literal("17".into()),
                gradle: C::Literal("8.14.5".into()),
                agp: C::Literal("8.9.2".into()),
                sdk_platform: C::Literal("android-35".into()),
                sdk_build_tools: C::Unspecified,
                distribution: Some(distribution),
            }),
        };
        (policy, selected, requirements)
    }
    #[test]
    fn selected_full_tuple_is_read_only_even_when_project_pins_do_not_match() {
        // Pure action/policy DATA: no original selection or native join exists.
        assert!(permits_action(false, wire::Action::Inspect));
        assert!(!permits_action(false, wire::Action::Acquire));
        assert!(permits_action(true, wire::Action::Acquire));
        let (policy, selected, mut requirements) = data();
        assert_eq!(
            finding(&policy, Some(&selected), &requirements),
            wire::ProtectedTools::ReuseSelected
        );
        assert_eq!(
            finding(&policy, None, &requirements),
            wire::ProtectedTools::NoneInSupportedCatalogue
        );
        requirements.android.as_mut().unwrap().jdk = C::Literal("21".into());
        assert_eq!(
            finding(&policy, Some(&selected), &requirements),
            wire::ProtectedTools::ManualCheckRequired
        );
        assert!(!permits_action(false, wire::Action::Acquire));
    }
    #[test]
    fn every_registered_component_and_exact_project_distribution_must_match() {
        let (policy, selected, requirements) = data();
        for part in 0..6 {
            let mut changed = selected.clone();
            match part {
                0 => changed.jdk_vendor.push('x'),
                1 => changed.jdk_version.push('x'),
                2 => changed.gradle_version.push('x'),
                3 => changed.agp_version.push('x'),
                4 => changed.sdk_platform.push('x'),
                _ => changed.sdk_build_tools_version.push('x'),
            }
            assert_eq!(
                finding(&policy, Some(&changed), &requirements),
                wire::ProtectedTools::ManualCheckRequired
            );
        }
        for change in 0..3 {
            let mut changed = requirements.clone();
            match change {
                0 => changed.android.as_mut().unwrap().gradle = C::Unknown,
                1 => {
                    changed
                        .android
                        .as_mut()
                        .unwrap()
                        .distribution
                        .as_mut()
                        .unwrap()
                        .sha256 = "b".repeat(64)
                }
                _ => changed.complete = false,
            }
            assert_eq!(
                finding(&policy, Some(&selected), &changed),
                wire::ProtectedTools::ManualCheckRequired
            );
        }
    }
}
