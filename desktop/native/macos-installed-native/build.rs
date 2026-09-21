fn main() {
    assert_eq!(std::env::var("TARGET").as_deref(), Ok("aarch64-apple-darwin"), "fixed macOS ARM64 native seam only");
    println!("cargo:rerun-if-changed=src/native.m");
    cc::Build::new().file("src/native.m").flag("-fno-objc-arc").flag("-fblocks")
        .flag("-mmacosx-version-min=26.0").warnings(true).compile("mrk_macos_installed_native");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
