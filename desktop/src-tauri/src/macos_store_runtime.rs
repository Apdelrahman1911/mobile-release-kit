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
    "store/tooling/fastlane/apple_distribution_key.rb",
    "store/tooling/fastlane/apple_distribution_key_verify.rb",
    "store/tooling/fastlane/apple_provisioning_certificate_issuance.rb",
    "store/tooling/fastlane/apple_store_versions.rb",
    "store/licenses/Ruby-COPYING", "store/licenses/Ruby-BSDL", "store/licenses/Ruby-LEGAL",
    "store/licenses/OpenSSL-LICENSE.txt", "store/licenses/LibYAML-License",
    "store/licenses/locked-gem-licenses.txt",
];

pub fn executable(path: &str) -> bool { matches!(path, RUBY | BUNDLE) }

/// Other Store files are still covered by the caller's complete signed
/// inventory. No executable mode is inferred from a suffix or publisher mode.
pub fn validate<'a>(files: impl IntoIterator<Item = (&'a str, u64)>) -> Result<bool, &'static str> {
    let mut present = false;
    let mut required = BTreeSet::new();
    for (path, size) in files {
        if path.starts_with("store/") {
            present = true;
            if REQUIRED.contains(&path) && (size == 0 || !required.insert(path)) {
                return Err("store-required-input");
            }
        }
    }
    if present && required.len() != REQUIRED.len() { return Err("store-incomplete-runtime"); }
    Ok(present)
}

#[cfg(test)]
mod tests {
    use super::*;
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
