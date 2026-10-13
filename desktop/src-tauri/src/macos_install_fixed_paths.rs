//! Stable protected locations/product names, also consumed by the independent
//! native helper's build script. No app-generated OUT_DIR dependency belongs here.
pub const INSTALL_ROOT: &str = "/Library/Application Support/MobileReleaseKit";
pub const PACKAGE_ID: &str = "dev.mobile-release-kit.desktop.installed";
pub const FIXTURE_PACKAGE_ID: &str = "dev.mobile-release-kit.desktop.installed-fixture";
pub const BUNDLE_ID: &str = "dev.mobile-release-kit.desktop";
pub const APP_NAME: &str = "Mobile Release Kit.app";
pub const APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app";
// APP remains the user-visible entry. BUNDLE_ID continues to identify the real
// executing product, preserving Tauri's application-data/vault namespace.
pub const ENTRY_BUNDLE_ID: &str = "dev.mobile-release-kit.desktop.entry";
pub const ENTRY_BINARY: &str = "Contents/MacOS/mrk-macos-entry";
pub const PAYLOAD_NAME: &str = "MobileReleaseKitPayload.app";
pub const PAYLOAD_RELATIVE: &str = "Contents/Helpers/MobileReleaseKitPayload.app";
pub const PAYLOAD_APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app";
pub const PAYLOAD_EXECUTABLE: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop";
pub const PAYLOAD_BINARY: &str = "Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop";
pub const PAYLOAD_CONTENTS: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents";
pub const VAULT_HELPER_BINARY: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-vault-keychain";
pub const PAYLOAD_HELPERS: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers";
// Inert until the complete image stager/transport integration is verified.
pub const ANDROID_HELPER_BINARY: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-android-register";
pub const DESKTOP_IMAGE: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_desktop_image.dylib";
pub const RESIDENT_IMAGE: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_resident_image.dylib";
pub const DESKTOP_IMAGE_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_desktop_image.dylib";
pub const RESIDENT_IMAGE_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_resident_image.dylib";
pub const REMOVER_NAME: &str = "mrk-macos-remove";
pub const REMOVER_IDENTIFIER: &str = "dev.mobile-release-kit.desktop.remove";
pub const REMOVER_BINARY: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-macos-remove";
pub const REMOVER_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-macos-remove";
pub const MAINTENANCE_GATE_NAME: &str = "maintenance-gate-v1";
pub const MAINTENANCE_GATE: &str = "/Library/Application Support/MobileReleaseKit/maintenance-gate-v1";
pub const MAINTENANCE_GATE_BYTES: &[u8] = b"MRK-MACOS-MAINTENANCE-GATE-v1\n";
pub const REGISTRATION_GATE_NAME: &str = "registration-reservation-v1";
pub const REGISTRATION_GATE_BYTES: &[u8] = b"MRK-MACOS-REGISTRATION-RESERVATION-v1\n";
pub const ENTRY_INVENTORY_PATH: &str = "app/Contents/MacOS/mrk-macos-entry";
pub const PAYLOAD_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop";
pub const PAYLOAD_INFO_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Info.plist";
pub const VAULT_HELPER_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-vault-keychain";
pub const ANDROID_HELPER_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-android-register";
pub const ANDROID_SERVICE_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Library/LaunchDaemons/dev.mobile-release-kit.desktop.android-register.plist";

// Exact optional SOURCE-enrolled executable rows, not arbitrary tool authority.
pub const HISTORY_PROVIDER_INVENTORY_PATH: &str = "runtime/tools/gh";
pub const GITHUB_SEAL_INVENTORY_PATH: &str = "app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-github-seal";
