#[path = "../../src-tauri/src/macos_install_fixed_paths.rs"]
mod installed_paths;

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

fn main() {
    println!("cargo:rustc-check-cfg=cfg(mrk_wrapping_keychain_qualification)");
    println!("cargo:rustc-check-cfg=cfg(mrk_wrapping_keychain_qualification_native)");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_MRK_WRAPPING_KEYCHAIN_QUALIFICATION");
    assert_eq!(std::env::var("TARGET").as_deref(), Ok("aarch64-apple-darwin"), "fixed macOS ARM64 native seam only");
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
        && version_text.lines().any(|l| l == "release: 1.98.1")
        && version_text.lines().any(|l| l == "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985"),
        "Mac app/helper CLOCK_UPTIME_RAW proof requires the pinned Rust1.98.1 compiler");
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
    println!("cargo:rerun-if-changed=../../packaging/macos-android-service-signing.profile");
    println!("cargo:rerun-if-changed=src/vault_filesystem.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain.m");
    println!("cargo:rerun-if-changed=src/wrapping_interaction_policy.h");
    println!("cargo:rerun-if-changed=src/vault_helper_control.h");
    println!("cargo:rerun-if-changed=src/vault_helper_control.m");
    println!("cargo:rerun-if-changed=src/vault_helper_auth.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain_fixture.m");
    let mut build = cc::Build::new();
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
    if !helper && !android_helper && !observation {
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
