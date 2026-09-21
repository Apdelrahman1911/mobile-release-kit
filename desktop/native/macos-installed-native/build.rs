fn main() {
    assert_eq!(std::env::var("TARGET").as_deref(), Ok("aarch64-apple-darwin"), "fixed macOS ARM64 native seam only");
    println!("cargo:rerun-if-changed=src/native.m");
    let mut build = cc::Build::new();
    if std::env::var_os("CARGO_FEATURE_INSTALLED_OBSERVATION").is_some() {
        build.define("MRK_INSTALLED_OBSERVATION", None);
    }
    build.file("src/native.m").flag("-fno-objc-arc").flag("-fblocks")
        .flag("-mmacosx-version-min=26.0").warnings(true).compile("mrk_macos_installed_native");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
