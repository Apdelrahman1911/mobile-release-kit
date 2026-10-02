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
    if qualification {
        assert!(observation, "wrapping qualification requires installed-observation");
        assert_eq!(std::env::var("PROFILE").as_deref(), Ok("debug"), "wrapping qualification is debug-profile only");
        // PROFILE is not proof of target debug_assertions. The sibling Rust
        // compile_error independently checks that target cfg and this handshake.
        println!("cargo:rustc-cfg=mrk_wrapping_keychain_qualification_native");
    }
    println!("cargo:rerun-if-changed=src/native.m");
    println!("cargo:rerun-if-changed=src/vault_filesystem.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain.m");
    println!("cargo:rerun-if-changed=src/wrapping_keychain_fixture.m");
    let mut build = cc::Build::new();
    if observation {
        build.define("MRK_INSTALLED_OBSERVATION", None);
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
    }
    if qualification {
        build.define("MRK_WRAPPING_KEYCHAIN_QUALIFICATION", Some("1"));
        build.define("MRK_WRAPPING_KEYCHAIN_QUALIFICATION_DEBUG", Some("1"));
    }
    build.file("src/native.m").file("src/wrapping_keychain.m").file("src/vault_filesystem.m").flag("-fno-objc-arc").flag("-fblocks")
        .flag("-mmacosx-version-min=26.0").warnings(true).compile("mrk_macos_installed_native");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}
