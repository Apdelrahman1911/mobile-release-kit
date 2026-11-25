# Disposable unsigned iOS compile fixture

Public synthetic Objective-C/UIKit project, iOS-only MRK configuration and a
saved version file consumed directly as an Xcode base configuration. It has no
team, provisioning profile, account, entitlement, credential or external package.
All targets use Debug and disable code signing. No script build phases exist.

Copy the fixture to a fresh private directory and use a private derived-data and
result-bundle path. On the recorded Mac, Xcode/SDK 27 compiled arm64 with one job:

    xcodebuild -project MRKFixture.xcodeproj -scheme MRKFixture -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath "$MRK_DERIVED_DATA" -jobs 1 CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= DEVELOPMENT_TEAM= ARCHS=arm64 build

An unsigned Debug test archive can use the same arguments with -sdk iphoneos,
-destination generic/platform=iOS, -archivePath "$MRK_TEST_ARCHIVE", and archive
instead of build. These are disposable test binaries, not MRK app releases or
installers. They are never exported, signed, installed or distributed.

The typed-core test edits public/version.xcconfig from 1.0.0 / 1 to 2.3.4 / 8:

    PYTHONPATH=src:tests:tests/desktop python3.11 -m unittest test_macos_ios_journey_fixture

The recorded actual simulator and unsigned archive builds contain those edited
values; the original core archive/Mach-O inspector accepts the test archive.
No simulator was booted and no personal device or Apple account was selected.
Keep build products and generated Xcode user state outside version control.
This does not establish installed app integration or signed export readiness.
