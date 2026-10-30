//! Store runtime inventory DATA. A complete signed inventory, not this shape
//! check, binds actual bytes. This does not authorize a Store operation.
use std::collections::BTreeSet;

pub const RUBY: &str = "store/bin/ruby";
pub const BUNDLE: &str = "store/bin/bundle";
pub const BUNDLE_ENTRY: &str = "store/lib/ruby/gems/3.3.0/gems/bundler-4.0.16/exe/bundle";
pub const CA: &str = "store/ca.pem";
pub const TOOLING: &str = "store/tooling";
pub const REQUIRED: &[&str] = &[
    RUBY, BUNDLE, BUNDLE_ENTRY, CA, "store/bin/mrk_bundle_setup.rb",
    "store/bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane.rb",
    "store/tooling/Gemfile", "store/tooling/Gemfile.lock", "store/tooling/fastlane/Fastfile",
    "store/tooling/fastlane/run_lane.rb", "store/tooling/fastlane/native_process_spawn.rb",
    "store/tooling/fastlane/apple_provisioning.rb", "store/tooling/fastlane/apple_provisioning_bundle_read.rb",
    "store/tooling/fastlane/apple_provisioning_profile_read.rb",
    "store/tooling/fastlane/apple_provisioning_p12.rb",
    "store/tooling/fastlane/apple_provisioning_p12_assemble.rb",
    "store/tooling/fastlane/apple_provisioning_signing.rb",
    "store/tooling/fastlane/apple_provisioning_bundle_registration.rb",
    "store/tooling/fastlane/apple_distribution_key.rb",
    "store/tooling/fastlane/apple_distribution_key_verify.rb",
    "store/tooling/fastlane/apple_distribution_certificate_policy.rb",
    "store/tooling/fastlane/apple_distribution_certificate_prepare.rb",
    "store/tooling/fastlane/apple_distribution_certificate_verify.rb",
    "store/tooling/fastlane/apple_provisioning_certificate_issuance.rb",
    "store/tooling/fastlane/apple_store_versions.rb",
    "store/licenses/Ruby-COPYING", "store/licenses/Ruby-BSDL", "store/licenses/Ruby-LEGAL",
    "store/licenses/OpenSSL-LICENSE.txt", "store/licenses/LibYAML-License",
    "store/licenses/locked-gem-licenses.txt",
];

// Exact roster from the approved bf9d397 release's original source. Later
// tooling additions are required by current inventories, not by that frozen
// predecessor. The caller must first bind its original inventory bytes to the
// independently selected, authenticated release tuple.
const DESKTOP_02_REQUIRED: &[&str] = &[
    RUBY, BUNDLE, BUNDLE_ENTRY, CA, "store/bin/mrk_bundle_setup.rb",
    "store/bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane.rb",
    "store/tooling/Gemfile", "store/tooling/Gemfile.lock", "store/tooling/fastlane/Fastfile",
    "store/tooling/fastlane/run_lane.rb", "store/tooling/fastlane/native_process_spawn.rb",
    "store/licenses/Ruby-COPYING", "store/licenses/Ruby-BSDL", "store/licenses/Ruby-LEGAL",
    "store/licenses/OpenSSL-LICENSE.txt", "store/licenses/LibYAML-License",
    "store/licenses/locked-gem-licenses.txt",
];

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) enum InventoryContract {
    #[default]
    Current,
    ApprovedArm64Desktop02,
}

pub(crate) fn selected_inventory_contract(
    b: crate::macos_install_maintenance::ReleaseBindingData<'_>,
) -> InventoryContract {
    // Every field is pinned. Version labels, destination DATA, and an
    // inventory's own claims never select historical compatibility.
    if b.profile == "fixed-macos26-arm64-maintenance-v2"
        && b.package_identifier == "dev.mobile-release-kit.desktop.installed"
        && b.bundle_identifier == "dev.mobile-release-kit.desktop"
        && b.package_version == "0.1.2" && b.release == "macos26-arm64-desktop-02"
        && b.source_commit == "bf9d397bde641aae4b4cd205f3c962e899557650"
        && b.protocol_sha256 == "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5"
        && b.runtime_manifest_sha256 == "4b45dc85aac03b7b5883045d89e8bd6f8ea642d5368d715a45ec84e807509c1c"
        && b.inventory_sha256 == "9ba42c36e3b4f332e64300ce6de881b220886b5454335065813c3c40add4d586"
        && b.signing_policy_sha256 == "c33cb173b7cb29c3ee82d6265e2c2eb720e3b9e2de0e4da0c173150734fedacb"
        && b.package_sha256 == "98edbc4f965800be699972db523e6a25c9b47a6051068b2bcf02a5c173a7720a"
    { InventoryContract::ApprovedArm64Desktop02 } else { InventoryContract::Current }
}

pub fn executable(path: &str) -> bool { matches!(path, RUBY | BUNDLE) }

/// Other Store files are still covered by the caller's complete signed
/// inventory. No executable mode is inferred from a suffix or publisher mode.
pub fn validate<'a>(files: impl IntoIterator<Item = (&'a str, u64)>) -> Result<bool, &'static str> {
    validate_inventory_contract(files, InventoryContract::Current)
}

pub(crate) fn validate_inventory_contract<'a>(files: impl IntoIterator<Item = (&'a str, u64)>,
    contract: InventoryContract) -> Result<bool, &'static str> {
    let expected = match contract { InventoryContract::Current => REQUIRED,
        InventoryContract::ApprovedArm64Desktop02 => DESKTOP_02_REQUIRED };
    let mut present = false;
    let mut required = BTreeSet::new();
    for (path, size) in files {
        if path.starts_with("store/") {
            present = true;
            if expected.contains(&path) && (size == 0 || !required.insert(path)) {
                return Err("store-required-input");
            }
        }
    }
    if present && required.len() != expected.len() { return Err("store-incomplete-runtime"); }
    Ok(present)
}

#[cfg(test)]
pub(crate) fn assert_approved_predecessor_store_contract_data() {
    use crate::macos_install_maintenance::ReleaseBindingData;
    let binding = ReleaseBindingData {
        profile: "fixed-macos26-arm64-maintenance-v2",
        package_identifier: "dev.mobile-release-kit.desktop.installed",
        bundle_identifier: "dev.mobile-release-kit.desktop", package_version: "0.1.2",
        release: "macos26-arm64-desktop-02", source_commit: "bf9d397bde641aae4b4cd205f3c962e899557650",
        protocol_sha256: "083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5",
        runtime_manifest_sha256: "4b45dc85aac03b7b5883045d89e8bd6f8ea642d5368d715a45ec84e807509c1c",
        inventory_sha256: "9ba42c36e3b4f332e64300ce6de881b220886b5454335065813c3c40add4d586",
        signing_policy_sha256: "c33cb173b7cb29c3ee82d6265e2c2eb720e3b9e2de0e4da0c173150734fedacb",
        package_sha256: "98edbc4f965800be699972db523e6a25c9b47a6051068b2bcf02a5c173a7720a",
    };
    assert_eq!(selected_inventory_contract(binding), InventoryContract::ApprovedArm64Desktop02);
    for changed in [
        ReleaseBindingData { profile: "other", ..binding },
        ReleaseBindingData { package_identifier: "other", ..binding },
        ReleaseBindingData { bundle_identifier: "other", ..binding },
        ReleaseBindingData { package_version: "0.1.3", ..binding },
        ReleaseBindingData { release: "macos26-arm64-desktop-03", ..binding },
        ReleaseBindingData { source_commit: "other", ..binding },
        ReleaseBindingData { protocol_sha256: "other", ..binding },
        ReleaseBindingData { runtime_manifest_sha256: "other", ..binding },
        ReleaseBindingData { inventory_sha256: "other", ..binding },
        ReleaseBindingData { signing_policy_sha256: "other", ..binding },
        ReleaseBindingData { package_sha256: "other", ..binding },
    ] { assert_eq!(selected_inventory_contract(changed), InventoryContract::Current); }
    assert_eq!(DESKTOP_02_REQUIRED.len(), 17);
    assert_eq!(REQUIRED.len(), 31);
    assert_eq!(validate(DESKTOP_02_REQUIRED.iter().map(|path| (*path, 1))), Err("store-incomplete-runtime"));
    for (contract, roster) in [(InventoryContract::Current, REQUIRED),
        (InventoryContract::ApprovedArm64Desktop02, DESKTOP_02_REQUIRED)] {
        assert_eq!(validate_inventory_contract(roster.iter().map(|path| (*path, 1)), contract), Ok(true));
        for omitted in 0..roster.len() {
            assert_eq!(validate_inventory_contract(roster.iter().enumerate()
                .filter(|(i, _)| *i != omitted).map(|(_, path)| (*path, 1)), contract), Err("store-incomplete-runtime"));
            assert_eq!(validate_inventory_contract(roster.iter().enumerate()
                .map(|(i, path)| (*path, if i == omitted { 0 } else { 1 })), contract), Err("store-required-input"));
            let mut repeated: Vec<_> = roster.iter().map(|path| (*path, 1)).collect();
            repeated.push((roster[omitted], 1));
            assert_eq!(validate_inventory_contract(repeated, contract), Err("store-required-input"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approved_predecessor_keeps_its_complete_original_contract() {
        assert_approved_predecessor_store_contract_data();
    }
    #[test]
    fn optional_store_runtime_is_complete_and_has_only_two_executable_roles() {
        assert_eq!(validate([("python/bin/python3", 1)]), Ok(false));
        assert_eq!(validate(REQUIRED.iter().map(|path| (*path, 1))), Ok(true));
        // The upstream gem's real monorepo layout is independent of REQUIRED.
        // Synthesizing every fixture from REQUIRED previously hid a shared typo.
        let mut upstream: Vec<_> = REQUIRED.iter().filter(|p| !p.contains("/gems/fastlane-"))
            .map(|path| (*path, 1)).collect();
        let entry = "store/bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane.rb";
        upstream.push((entry, 1));
        assert_eq!(validate(upstream.iter().copied()), Ok(true));
        upstream.pop();
        upstream.push(("store/bundle/ruby/3.3.0/gems/fastlane-2.235.0/lib/fastlane.rb", 1));
        assert!(validate(upstream).is_err());
        for omitted in 0..REQUIRED.len() {
            assert!(validate(REQUIRED.iter().enumerate().filter(|(i, _)| *i != omitted)
                .map(|(_, path)| (*path, 1))).is_err());
        }
        for invalid in [[("store/extra", 1)], [(RUBY, 0)], [(BUNDLE, 1)]] {
            assert!(validate(invalid).is_err());
        }
        let mut repeated: Vec<_> = REQUIRED.iter().map(|path| (*path, 1)).collect();
        repeated.push((RUBY, 1));
        assert!(validate(repeated).is_err());
        assert!(executable(RUBY) && executable(BUNDLE));
        for path in [BUNDLE_ENTRY, "store/bin/gem", "store/x.bundle", "other/bin/ruby", CA] {
            assert!(!executable(path));
        }
    }
}
