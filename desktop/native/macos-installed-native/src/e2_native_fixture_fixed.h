/* Fixed nonshipping native E2 fixture projection.
 * No runtime path, requirement, case or service selector exists.
 * The ordinary package must reject this profile/namespace. */
#ifndef MRK_E2_NATIVE_FIXTURE_FIXED_H
#define MRK_E2_NATIVE_FIXTURE_FIXED_H
#if !defined(MRK_E2_NATIVE_FIXTURE) || MRK_E2_NATIVE_FIXTURE != 1
#error E2 fixture constants require the explicit nonshipping native build
#endif
#define MRK_E2_FIXTURE_PROFILE "e2-native-fixture-v1"
#define MRK_E2_FIXTURE_PACKAGE_ID "dev.mobile-release-kit.fixture.e2.pkg.v1"
#define MRK_E2_FIXTURE_ROOT_LEAF "MobileReleaseKit-E2NativeFixture"
#define MRK_E2_FIXTURE_ROOT "/Library/Application Support/" MRK_E2_FIXTURE_ROOT_LEAF
#define MRK_E2_FIXTURE_APP MRK_E2_FIXTURE_ROOT "/MRK E2 Native Fixture.app"
#define MRK_E2_FIXTURE_CLIENT_APP MRK_E2_FIXTURE_APP "/Contents/Helpers/MRK E2 Native Client.app"
#define MRK_E2_FIXTURE_ENTRY MRK_E2_FIXTURE_APP "/Contents/MacOS/mrk-e2-native-entry"
#define MRK_E2_FIXTURE_CLIENT MRK_E2_FIXTURE_CLIENT_APP "/Contents/MacOS/mrk-e2-native-client"
#define MRK_E2_FIXTURE_RESIDENT MRK_E2_FIXTURE_CLIENT_APP "/Contents/Helpers/mrk-e2-native-resident"
#define MRK_E2_FIXTURE_CLIENT_IMAGE MRK_E2_FIXTURE_CLIENT_APP "/Contents/Frameworks/libmrk_e2_native_client.dylib"
#define MRK_E2_FIXTURE_RESIDENT_IMAGE MRK_E2_FIXTURE_CLIENT_APP "/Contents/Frameworks/libmrk_e2_native_resident.dylib"
#define MRK_E2_FIXTURE_APP_ID "dev.mobile-release-kit.fixture.e2"
#define MRK_E2_FIXTURE_CLIENT_ID "dev.mobile-release-kit.fixture.e2.client"
#define MRK_E2_FIXTURE_RESIDENT_ID "dev.mobile-release-kit.fixture.e2.resident"
#define MRK_E2_FIXTURE_SERVICE MRK_E2_FIXTURE_RESIDENT_ID
#define MRK_E2_FIXTURE_PLIST MRK_E2_FIXTURE_RESIDENT_ID ".plist"
#define MRK_E2_FIXTURE_BUNDLE_VERSION "1"
#define MRK_E2_FIXTURE_SHORT_VERSION "0.1.0"
#endif
