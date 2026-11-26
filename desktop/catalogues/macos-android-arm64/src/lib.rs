//! One immutable, complete catalogue compiled in its own crate.
//! These comparison rows confer no runtime or native authority.
use mrk_android_catalogue_schema::*;
use mrk_android_catalogue_schema as policy;
use mrk_android_catalogue_schema::CatalogueData as Reference;
mod android_build_protocol {
    pub(super) use mrk_android_catalogue_schema::{MAC_TOOLCHAIN_PROFILE, MAC_X64_TOOLCHAIN_PROFILE};
}
mod compiled {
    use super::*;
    include!("../../../src-tauri/src/android_supplier_macos_catalogue.rs");
    // Only this named static carrier is exported. Dependent code borrows its
    // existing static row addresses; it does not instantiate the large decoder.
    pub static CATALOGUE: CatalogueData = REFERENCES[0];
}
pub use compiled::CATALOGUE;
