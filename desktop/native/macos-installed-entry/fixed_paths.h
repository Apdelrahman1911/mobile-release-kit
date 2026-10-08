/* Checked projection of src-tauri/src/macos_install_fixed_paths.rs. Neither
 * argv, environment nor an installed record selects a path or release. */
#ifndef MRK_INSTALLED_ENTRY_FIXED_PATHS_H
#define MRK_INSTALLED_ENTRY_FIXED_PATHS_H
#if defined(MRK_E2_NATIVE_FIXTURE)
#include "../macos-installed-native/src/e2_native_fixture_fixed.h"
#define MRK_INSTALLED_ROOT_LEAF MRK_E2_FIXTURE_ROOT_LEAF
#define MRK_ENTRY_EXECUTABLE MRK_E2_FIXTURE_ENTRY
#define MRK_PAYLOAD_EXECUTABLE MRK_E2_FIXTURE_CLIENT
#define MRK_RESIDENT_EXECUTABLE MRK_E2_FIXTURE_RESIDENT
#define MRK_DESKTOP_IMAGE MRK_E2_FIXTURE_CLIENT_IMAGE
#define MRK_RESIDENT_IMAGE MRK_E2_FIXTURE_RESIDENT_IMAGE
#else
#define MRK_INSTALLED_ROOT_LEAF "MobileReleaseKit"
#define MRK_ENTRY_EXECUTABLE "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mrk-macos-entry"
#define MRK_PAYLOAD_EXECUTABLE "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop"
/* Facade/image layout is not activated until the complete stager/native path
 * is integrated and verified. These names are fixed SOURCE projections. */
#define MRK_RESIDENT_EXECUTABLE "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Helpers/mrk-android-register"
#define MRK_DESKTOP_IMAGE "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_desktop_image.dylib"
#define MRK_RESIDENT_IMAGE "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/Frameworks/libmrk_resident_image.dylib"
#endif
#define MRK_MAINTENANCE_GATE_NAME "maintenance-gate-v1"
#define MRK_MAINTENANCE_GATE_BYTES "MRK-MACOS-MAINTENANCE-GATE-v1\n"
#define MRK_REGISTRATION_GATE_NAME "registration-reservation-v1"
#define MRK_REGISTRATION_GATE_BYTES "MRK-MACOS-REGISTRATION-RESERVATION-v1\n"
#define MRK_INSTALLED_ENTRY_ARGUMENT "--mrk-installed-entry-v1"
#endif
