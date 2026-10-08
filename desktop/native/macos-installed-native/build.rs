#[path = "../../src-tauri/src/macos_install_fixed_paths.rs"]
mod installed_paths;
#[path = "build_support/producer_selection.rs"]
mod producer_selection;

// Full SOURCE proof: both pinned releases use the identical Apple
// Instant -> CLOCK_UPTIME_RAW -> clock_gettime implementation. Keep the
// original 1.98.1 route on BOTH supported targets; add 1.98.0 only for Intel.
const CLOCK_TOOLCHAINS: [(&str, &str, &str); 3] = [
    ("aarch64-apple-darwin", "release: 1.98.1", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
    ("x86_64-apple-darwin", "release: 1.98.1", "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
    ("x86_64-apple-darwin", "release: 1.98.0", "commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea"),
];

// Only reviewed source inputs can select the shipping identity. This is not a
// renderer/environment requirement string, same-team wildcard or ad-hoc path.
// The deliberately unconfigured profile builds an unavailable engineering app.
fn android_requirements() -> Option<(String, String)> {
    let profile = include_str!("../../packaging/macos-android-service-signing.profile");
    let rows: Vec<_> = profile.lines().collect();
    assert!(profile.len() <= 1024 && rows.len() == 5 && rows[0] == "schema=1"
        && rows[1] == "app-identifier=dev.mobile-release-kit.desktop"
        && rows[2] == "helper-identifier=dev.mobile-release-kit.desktop.android-register",
        "fixed Android service signing profile shape");
    let team = rows[3].strip_prefix("team-identifier=").expect("fixed Team ID profile field");
    let certificate = rows[4].strip_prefix("developer-id-certificate-sha1=").expect("fixed Developer ID certificate profile field");
    if team == "unconfigured" && certificate == "unconfigured" { return None; }
    assert!(team.len() == 10 && team.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && certificate.len() == 40 && certificate.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && certificate.bytes().any(|b| b != b'0'), "complete genuine Developer ID signing profile required");
    let requirement = |identifier: &str| format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\" and certificate leaf = H\"{certificate}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists");
    Some((requirement(installed_paths::BUNDLE_ID), requirement("dev.mobile-release-kit.desktop.android-register")))
}

// These are fixed public SOURCE inputs inside the already admitted read-only
// build projection. No certificate path is supplied by a package or environment.
fn producer_certificate(path: &str) -> Vec<u8> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let before = std::fs::symlink_metadata(path).expect("fixed public producer certificate SOURCE");
    assert!(before.is_file() && before.len() > 0
        && before.len() <= producer_selection::CERTIFICATE_LIMIT as u64,
        "bounded regular public producer certificate SOURCE");
    let same = |actual: &std::fs::Metadata| actual.dev() == before.dev()
        && actual.ino() == before.ino() && actual.mode() == before.mode()
        && actual.uid() == before.uid() && actual.gid() == before.gid()
        && actual.nlink() == before.nlink() && actual.size() == before.size()
        && actual.mtime() == before.mtime() && actual.mtime_nsec() == before.mtime_nsec()
        && actual.ctime() == before.ctime() && actual.ctime_nsec() == before.ctime_nsec();
    let mut input = std::fs::File::open(path).expect("open original public producer certificate");
    assert!(same(&input.metadata().expect("original producer certificate metadata")),
        "original named/held producer certificate SOURCE");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut input).take(producer_selection::CERTIFICATE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes).expect("read bounded original public producer certificate");
    assert!(bytes.len() == before.len() as usize
        && same(&input.metadata().expect("producer certificate held POST"))
        && same(&std::fs::symlink_metadata(path).expect("producer certificate named POST")),
        "complete unchanged producer certificate SOURCE");
    bytes
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(mrk_e2_native_fixture_native)");
    assert!(std::env::var_os("CARGO_CFG_MRK_E2_NATIVE_FIXTURE_NATIVE").is_none(),
        "E2 fixture native handshake is build-script output only");
    println!("cargo:rustc-check-cfg=cfg(mrk_wrapping_keychain_qualification)");
    println!("cargo:rustc-check-cfg=cfg(mrk_wrapping_keychain_qualification_native)");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_MRK_WRAPPING_KEYCHAIN_QUALIFICATION");
    let target = std::env::var("TARGET").expect("Cargo native target binding required");
    assert!(matches!(target.as_str(), "aarch64-apple-darwin" | "x86_64-apple-darwin"),
        "fixed supported macOS native target required");
    assert_eq!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("macos"), "native target must be macOS");
    assert_eq!(std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").as_deref(), Ok("64"), "native target must be LP64");
    assert_eq!(std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref(), Ok("apple"), "native clock requires Apple target vendor");
    assert_eq!(std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref(), Ok("unix"), "native clock requires Unix target family");
    // Only a flag cfg supplied to this owned Cargo build enables the source
    // seam. Neither an environment fixture path nor a runtime switch exists.
    let qualification = match std::env::var_os("CARGO_CFG_MRK_WRAPPING_KEYCHAIN_QUALIFICATION") {
        None => false,
        Some(value) if value.is_empty() => true,
        Some(_) => panic!("wrapping qualification cfg must be a flag, not a value"),
    };
    assert!(std::env::var_os("CARGO_CFG_MRK_WRAPPING_KEYCHAIN_QUALIFICATION_NATIVE").is_none(),
        "native qualification handshake cfg is build-script output only");
    let observation = std::env::var_os("CARGO_FEATURE_INSTALLED_OBSERVATION").is_some();
    let helper = std::env::var_os("CARGO_FEATURE_VAULT_HELPER").is_some();
    let android_helper = std::env::var_os("CARGO_FEATURE_ANDROID_REGISTRATION_HELPER").is_some();
    let desktop_image = std::env::var_os("CARGO_FEATURE_DESKTOP_IMAGE").is_some();
    let resident_image = std::env::var_os("CARGO_FEATURE_RESIDENT_IMAGE").is_some();
    let e2_fixture = std::env::var_os("CARGO_FEATURE_E2_NATIVE_FIXTURE").is_some();
    let producer_signing = std::env::var_os("CARGO_FEATURE_PACKAGE_PRODUCER_SIGNING").is_some();
    assert!(!producer_signing || !helper && !android_helper && !desktop_image && !resident_image
        && !observation && !e2_fixture && !qualification,
        "package signing requires the isolated nonshipping native graph");
    assert!(!e2_fixture || (desktop_image != resident_image) && !helper && !observation && !qualification,
        "E2 fixture requires exactly one isolated desktop or resident image graph");
    assert!(!resident_image || android_helper && !desktop_image && !helper && !observation && !qualification,
        "resident image requires the isolated helper image graph");
    // The existing package owner validates these projections against complete
    // SOURCE/build-release.json. Native Rust and the facade use the same values.
    println!("cargo:rerun-if-env-changed=MRK_MACOS_INSTALL_SOURCE_COMMIT");
    println!("cargo:rerun-if-env-changed=MRK_IMAGE_RELEASE_ID");
    let projection = std::env::var("MRK_MACOS_INSTALL_SOURCE_COMMIT").ok()
        .zip(std::env::var("MRK_IMAGE_RELEASE_ID").ok());
    if let Some((source, release)) = projection.as_ref() {
        assert!(source.len()==40 && source.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && source.bytes().any(|b|b!=b'0'), "complete lowercase nonzero SOURCE commit");
        assert!(!release.is_empty() && release.len()<64
            && release.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'|b'.')),
            "bounded build-release projection");
        println!("cargo:rustc-env=MRK_IMAGE_SOURCE_COMMIT={source}");
        println!("cargo:rustc-env=MRK_IMAGE_RELEASE_ID={release}");
    }
    assert!(!desktop_image && !resident_image || projection.is_some(),
        "image roles require both authenticated source/release projections");
    assert!(!desktop_image || !helper && !android_helper && !observation && !qualification,
        "ordinary product image cannot contain helper/observation/fixture roles");
    println!("cargo:rustc-check-cfg=cfg(mrk_android_registration_helper_native)");
    assert!(std::env::var_os("CARGO_CFG_MRK_ANDROID_REGISTRATION_HELPER_NATIVE").is_none(),
        "Android helper native handshake is build-script output only");
    assert!(!android_helper || !helper && !observation && !qualification,
        "Android helper cannot contain vault/observation/fixture roles");
    println!("cargo:rustc-check-cfg=cfg(mrk_wrapping_vault_helper_native)");
    assert!(std::env::var_os("CARGO_CFG_MRK_WRAPPING_VAULT_HELPER_NATIVE").is_none(),
        "vault helper native handshake is build-script output only");
    assert!(!helper || !observation && !qualification, "vault helper cannot contain observation/fixture roles");
    // Both app and helper depend on this crate. Do not infer the shared clock
    // from a Cargo cwd/default or from a differently versioned historical run.
    let rustc = std::env::var_os("RUSTC").expect("Cargo compiler binding required");
    let version = std::process::Command::new(rustc).args(["--version", "--verbose"])
        .output().expect("query actual Mac compiler");
    let version_text = std::str::from_utf8(&version.stdout).expect("compiler version is UTF-8");
    assert!(version.status.success() && version.stdout.len() <= 4096
        && CLOCK_TOOLCHAINS.iter().any(|(clock_target, release, commit)| {
            target.as_str() == *clock_target
                && version_text.lines().filter(|line| line.starts_with("release:"))
                    .eq(std::iter::once(*release))
                && version_text.lines().filter(|line| line.starts_with("commit-hash:"))
                    .eq(std::iter::once(*commit))
        }), "Mac app/helper CLOCK_UPTIME_RAW proof requires an exact reviewed target/compiler tuple");
    if qualification {
        assert!(observation, "wrapping qualification requires installed-observation");
        assert_eq!(std::env::var("PROFILE").as_deref(), Ok("debug"), "wrapping qualification is debug-profile only");
        // PROFILE is not proof of target debug_assertions. The sibling Rust
        // compile_error independently checks that target cfg and this handshake.
        println!("cargo:rustc-cfg=mrk_wrapping_keychain_qualification_native");
    }
    println!("cargo:rerun-if-changed=src/native.m");
    println!("cargo:rerun-if-changed=src/android_registration.m");
    println!("cargo:rerun-if-changed=src/android_service_management.m");
    println!("cargo:rerun-if-changed=src/install_producer.m");
    println!("cargo:rerun-if-changed=src/install_producer.h");
    println!("cargo:rerun-if-changed=build_support/producer_selection.rs");
    println!("cargo:rerun-if-changed=build_support/producer_compile_only.h");
    println!("cargo:rerun-if-changed=../../packaging/macos-install-producer-signing.profile");
    println!("cargo:rerun-if-changed=../../packaging/macos-android-service-signing.profile");
    println!("cargo:rerun-if-changed=src/vault_filesystem.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain.m");
    println!("cargo:rerun-if-changed=src/wrapping_interaction_policy.h");
    println!("cargo:rerun-if-changed=src/vault_helper_control.h");
    println!("cargo:rerun-if-changed=src/vault_helper_control.m");
    println!("cargo:rerun-if-changed=src/vault_helper_auth.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain_fixture.m");
    let mut build = cc::Build::new();
    // Rust's feature-only signer and this C branch are selected together. No
    // ordinary app/Installer/helper build contains a Keychain signing route.
    build.define("MRK_INSTALL_PRODUCER_SIGNING", Some(if producer_signing { "1" } else { "0" }));
    if !helper && !android_helper {
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo native output binding"));
        let selection = producer_selection::SourceSelection::parse(
            include_bytes!("../../packaging/macos-install-producer-signing.profile"),
            include_bytes!("../../packaging/macos-android-service-signing.profile"))
            .expect("complete fixed producer SOURCE profile matching current service identity");
        let certificates = if selection.requires_certificates() {
            let paths = [
                "../../packaging/macos-install-producer-certificates/leaf.der",
                "../../packaging/macos-install-producer-certificates/issuer.der",
                "../../packaging/macos-install-producer-certificates/root.der",
            ];
            for path in paths { println!("cargo:rerun-if-changed={path}"); }
            Some(paths.map(producer_certificate))
        } else { None };
        // Shape and SOURCE correspondence only. The native runtime independently
        // checks every declared digest, returned key, full chain and trust policy.
        let header = selection.header(certificates.as_ref().map(|rows|
            [rows[0].as_slice(), rows[1].as_slice(), rows[2].as_slice()]))
            .expect("bounded public producer SOURCE header");
        std::fs::write(out.join("mrk-install-producer-selection.h"), header)
            .expect("write fixed producer source selection");
        build.include(&out).file("src/install_producer.m");

        if e2_fixture {
            // Compile the accepted CONFIGURED1 C branch in this existing native
            // fixture build, WITHOUT selecting it for any Rust/native operation.
            // Invalid empty DER sequences cannot authenticate a certificate.
            // The normal header above and all shipping exports stay unchanged.
            let compile_only = out.join("producer-configured-compile");
            std::fs::create_dir_all(&compile_only).expect("fixed fixture compiler output");
            std::fs::write(compile_only.join("mrk-install-producer-selection.h"),
                include_bytes!("build_support/producer_compile_only.h"))
                .expect("write nonshipping compile-only producer header");
            let mut syntax = cc::Build::new();
            for (from, to) in [
                ("mrk_install_producer_source", "mrk_install_producer_compile_only_source"),
                ("mrk_install_producer_source_leaf_matches", "mrk_install_producer_compile_only_source_leaf_matches"),
                ("mrk_install_producer_new", "mrk_install_producer_compile_only_new"),
                ("mrk_remove_producer_new", "mrk_remove_producer_compile_only_new"),
                ("mrk_remove_producer_code_new", "mrk_remove_producer_compile_only_code_new"),
                ("mrk_remove_producer_sign_new", "mrk_remove_producer_compile_only_sign_new"),
                ("mrk_install_producer_code_new", "mrk_install_producer_compile_only_code_new"),
                ("mrk_install_producer_sign_new", "mrk_install_producer_compile_only_sign_new"),
                ("mrk_install_producer_sign_copy", "mrk_install_producer_compile_only_sign_copy"),
                ("mrk_install_producer_step", "mrk_install_producer_compile_only_step"),
                ("mrk_install_producer_release", "mrk_install_producer_compile_only_release"),
                ("mrk_install_producer_retire", "mrk_install_producer_compile_only_retire"),
            ] { syntax.define(from, Some(to)); }
            // Type/API coverage of configured signing code only: all twelve
            // exports are renamed, and no Rust path can call this translation.
            syntax.define("MRK_INSTALL_PRODUCER_SIGNING", Some("1"));
            syntax.include(&compile_only).file("src/install_producer.m")
                .flag("-fno-objc-arc").flag("-fblocks").flag("-mmacosx-version-min=26.0")
                .warnings(true).compile("mrk_install_producer_compile_only");
        }
    }
    if e2_fixture {
        // Fixed test identity is independently validated at runtime. This
        // compile gate is never an identity-ready or native-finality receipt.
        println!("cargo:rerun-if-changed=src/e2_native_fixture_identity.m");
        println!("cargo:rerun-if-changed=src/e2_native_fixture_identity.h");
        println!("cargo:rerun-if-changed=src/e2_native_fixture_fixed.h");
        build.define("MRK_E2_NATIVE_FIXTURE", Some("1"));
        build.file("src/e2_native_fixture_identity.m");
        println!("cargo:rustc-cfg=mrk_e2_native_fixture_native");
        // The fixed owner passes the client identity to cargo rustc's selected
        // example only. Shared build-script arguments would also reach libtest.
    }
    if let Some((source,release))=projection.as_ref() {
        let source=format!("{source:?}");let release=format!("{release:?}");
        build.define("MRK_IMAGE_SOURCE_COMMIT",Some(source.as_str()));
        build.define("MRK_IMAGE_RELEASE_ID",Some(release.as_str()));
    }
    if resident_image { build.define("MRK_ANDROID_RESIDENT_IMAGE",Some("1")); }
    let app_path = format!("{:?}", installed_paths::PAYLOAD_APP);
    build.define("MRK_ANDROID_APP_PATH", Some(app_path.as_str()));
    if let Some((app, helper)) = android_requirements() {
        let app = format!("{app:?}"); let helper = format!("{helper:?}");
        build.define("MRK_ANDROID_APP_REQUIREMENT", Some(app.as_str()));
        build.define("MRK_ANDROID_HELPER_REQUIREMENT", Some(helper.as_str()));
        println!("cargo:rustc-env=MRK_ANDROID_SIGNING_PROFILE_CONFIGURED=1");
    } else {
        println!("cargo:rustc-env=MRK_ANDROID_SIGNING_PROFILE_CONFIGURED=0");
    }
    if helper {
        build.define("MRK_WRAPPING_VAULT_HELPER", Some("1"));
        let app = format!("{:?}", installed_paths::PAYLOAD_APP);
        build.define("MRK_VAULT_APP_PATH", Some(app.as_str()));
        build.file("src/vault_helper_auth.m");
        println!("cargo:rustc-cfg=mrk_wrapping_vault_helper_native");
    }
    if android_helper {
        build.define("MRK_ANDROID_REGISTRATION_HELPER", Some("1"));
        println!("cargo:rustc-cfg=mrk_android_registration_helper_native");
    }
    if observation {
        build.define("MRK_INSTALLED_OBSERVATION", None);
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
    }
    if qualification {
        build.define("MRK_WRAPPING_KEYCHAIN_QUALIFICATION", Some("1"));
        build.define("MRK_WRAPPING_KEYCHAIN_QUALIFICATION_DEBUG", Some("1"));
    }
    // Shared fixed gate primitives also serve the shipping vault helper and
    // observed app transport. Ordinary entry admission stays Rust-role gated.
    if !android_helper {
        println!("cargo:rerun-if-changed=../macos-installed-entry/gate.c");
        println!("cargo:rerun-if-changed=../macos-installed-entry/gate.h");
        println!("cargo:rerun-if-changed=../macos-installed-entry/fixed_paths.h");
        build.file("../macos-installed-entry/gate.c");
    }
    build.file("src/native.m").file("src/android_registration.m").file("src/android_service_management.m").file("src/wrapping_keychain.m").file("src/vault_filesystem.m").file("src/vault_helper_control.m").flag("-fno-objc-arc").flag("-fblocks")
        .flag("-mmacosx-version-min=26.0").warnings(true).compile("mrk_macos_installed_native");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=ServiceManagement");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
