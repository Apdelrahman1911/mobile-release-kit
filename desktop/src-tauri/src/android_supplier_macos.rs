//! Private, compiled macOS Android supplier recipe and canonical proposal.
//! Caller DATA never supplies a reference. This module performs no IO and
//! cannot settle source custody, consent, original deadlines or native work.
use std::{cmp::Ordering, mem::size_of};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::android_toolchain_macos_policy as policy;
use crate::android_toolchain_macos_policy::{Alias, FileSpec, Inventory, Roles, Versions, Distribution};
use crate::android_supplier_macos_source::*;
use crate::android_sdk_metadata_macos as sdk_metadata;
use crate::android_native_macos_profile as native_profile;

const APP_BYTES: usize = 64 * 1024 * 1024;
// Combined six-archive reference: count/hash only, never a retained document.
// Separate from the unchanged 4MiB per-artifact/proposal and 64MiB app limits.
const REFERENCE_STREAM_BYTES: usize = 64 * 1024 * 1024;
const ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const NATIVE_HEADER: usize = 64 * 1024;
const NATIVE_COMMANDS: u32 = 128;
const NATIVE_RPATHS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SupplierFailure { Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure { Unavailable, UnsupportedLayout, Reference, SourceMismatch, Bounds, Metadata }

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
enum Component { Jdk, SdkPlatform, SdkBuildTools, Gradle, Aapt2, Bundletool }
const COMPONENTS: [Component; 6] = [Component::Jdk, Component::SdkPlatform,
    Component::SdkBuildTools, Component::Gradle, Component::Aapt2, Component::Bundletool];
#[derive(Clone, Copy, Serialize)]
enum PublishedChecksum { Sha256(&'static str), Sha1(&'static str) }
#[derive(Clone, Copy, Serialize)]
enum ArchiveKind {
    Directory { mode: u32 },
    File { mode: u32, bytes: u64, sha256: &'static str },
    Alias { mode: u32, target: &'static str },
}
#[derive(Clone, Copy, Serialize)]
enum ArchiveDisposition {
    Picked { source_index: u32 },
    /// Every byte is retained in the sealed support original, not discarded.
    SealedSupport(SupportAsset),
    /// Only an explicit directory wrapping the selected distribution/bundle.
    WrapperDirectory,
}
#[derive(Clone, Copy, Serialize)]
struct OfficialMember {
    name: &'static str,
    kind: ArchiveKind,
    disposition: ArchiveDisposition,
}
#[derive(Clone, Copy, Serialize)]
struct OfficialArchive {
    component: Component,
    official_source: &'static str,
    vendor_release: &'static str,
    archive: ArchivePin<'static>,
    published: PublishedChecksum,
    /// Actual archive-directory count/expansion, not a local selected-file count.
    member_count: u32,
    expanded_bytes: u64,
    members: &'static [OfficialMember],
}
#[derive(Clone, Copy, Serialize)]
enum SourceProvenance {
    Vendor { archive: u8, member: u32 },
    /// A necessary filesystem parent absent from the actual archive headers.
    /// The complete bidirectional prefix closure below binds this exact archive
    /// and prefix; neither a fictional member nor an archival mode is supplied.
    ArchiveParent { archive: u8, prefix: &'static str },
}
#[derive(Clone, Copy, Serialize)]
enum SourceDisposition {
    Payload(u32),
    Alias(u32),
    /// Empty source directories are explicitly observed; canonical installed
    /// directory closure is derived only from regular files/aliases.
    Directory,
}
#[derive(Clone, Copy, Serialize)]
struct SourceBinding {
    provenance: SourceProvenance,
    disposition: SourceDisposition,
}
#[derive(Serialize)]
struct CanonicalAlias {
    path: &'static str, target: &'static str, canonical: &'static str,
    source_index: u32,
}
#[derive(Clone, Copy, Serialize)]
struct NativeHeader {
    /// Actual archived-byte header snapshots reviewed with its complete hash.
    prefix: &'static [u8],
    commands: &'static [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum NativeResourceKind {
    Arm64,
    JdkInstalledCounterpart,
    JdkJpackageTemplate,
    OtherPlatformElf,
    OtherPlatformPe,
    GradleIntelPlatform,
    // Plain Gradle still copies this Intel resource; it is not an ARM64 JNI.
    GradlePlainJansiIntel,
    // Genuine bundletool ARM64 bypasses its Intel/Rosetta-only JNA route.
    BundletoolDarwinI386X64,
}
#[derive(Clone, Copy, Serialize)]
struct NestedNative {
    member: &'static str, bytes: u64, sha256: &'static str, mode: u32,
    kind: NativeResourceKind,
    // None is admitted ONLY by a complete exact compiled resource tuple below.
    // It is not a caller-selected inactive flag or a general DATA downgrade.
    header: Option<NativeHeader>,
}
struct NativeResourcePin {
    member: &'static str, bytes: u64, sha256: &'static str, mode: u32,
    kind: NativeResourceKind,
}
struct NativeArchivePin {
    path: &'static str, bytes: u64, sha256: &'static str,
    members: &'static [NativeResourcePin],
}
#[derive(Serialize)]
enum FileClass {
    Data,
    /// An explicit reviewed textual license/notice whose vendor archive mode
    /// happens to be executable. This is not a general script downgrade.
    LicenseText,
    GradleShell,
    GradleForeignLauncher,
    AndroidTargetElf,
    SdkBash(policy::Sdk35File),
    SdkLegacyIntel(policy::Sdk35File, NativeHeader),
    MachO(NativeHeader),
    JvmArchive { native_members: &'static [NestedNative] },
}

// Inert original DATA pins from Gradle8.14.5 and bundletool1.18.3. Every known
// archive's native roster is complete, including foreign resources. A changed
// archive, member, mode, size, digest, selector class, missing or extra member
// refuses. Required ARM64 members still carry genuine header/load closure.
// Adding another platform/resource is a source-reviewed profile change.
const JDK17_ARCHIVE_SHA: &str = "196d13ba5f10414bef7f6a05a9b3f00edacb18ebacef2b99485db9e2ee18f0e8";
const GRADLE_ARCHIVE_SHA: &str = "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854";
const NATIVE_ARCHIVES: &[NativeArchivePin] = &[
    NativeArchivePin { path: "gradle/lib/gradle-fileevents-0.2.7.jar", bytes: 1433862,
        sha256: "9f8d26b0057ed645af68c8d4139988d69ee884ad8d009e98a793c08cbdd3d2f8", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/aarch64-linux-gnu/libgradle-fileevents.so", bytes: 569592,
                sha256: "e32f36eeb112888078b6edb33e5c9aea764401e2b6719a753b2fe24c32a319d9", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "net/rubygrapefruit/platform/aarch64-linux-musl/libgradle-fileevents.so", bytes: 573080,
                sha256: "ad2564b331076dd6ce4cf71f3b4f30224329cd5fa491f204371d1de26f66cbe8", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "net/rubygrapefruit/platform/aarch64-macos/libgradle-fileevents.dylib", bytes: 534584,
                sha256: "94f6518ba52029073c3fde817647ff8d8a9941b483e028616b9e06eb7235d91b", mode: 0o100755, kind: NativeResourceKind::Arm64 },
            NativeResourcePin { member: "net/rubygrapefruit/platform/aarch64-windows-gnu/gradle-fileevents.dll", bytes: 437760,
                sha256: "d91e361294f1a3673d18e41ee82185cf427004593d98d4972018783d7e3b81d3", mode: 0o100755, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "net/rubygrapefruit/platform/x86_64-linux-gnu/libgradle-fileevents.so", bytes: 571128,
                sha256: "64c77581ccffde085b013ad20f235d5200bac7c34a44ad5ea9241f1a5dd2c8e5", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "net/rubygrapefruit/platform/x86_64-linux-musl/libgradle-fileevents.so", bytes: 573760,
                sha256: "93454d59e9f0380dcf797a93766f05e6da4fee6f2002a92ed329fcae18d4000f", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "net/rubygrapefruit/platform/x86_64-macos/libgradle-fileevents.dylib", bytes: 447852,
                sha256: "a691507125ec1bd97e55d20d6184cf9b69e441f842506d92b1c62581fd9ab79d", mode: 0o100755, kind: NativeResourceKind::GradleIntelPlatform },
            NativeResourcePin { member: "net/rubygrapefruit/platform/x86_64-windows-gnu/gradle-fileevents.dll", bytes: 465408,
                sha256: "c22c800a9fd7115eb90dc745cda3a821b5e1032f45c946ad8e00bf62a45a29a1", mode: 0o100755, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/kotlin-compiler-embeddable-2.0.21.jar", bytes: 58272093,
        sha256: "9fa8cdd1de0dccffe154c997d423ec6b5f53cd6d9177e3a77a9b0de03fb1bc81", members: &[
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/linux/aarch64/liblz4-java.so", bytes: 77859,
                sha256: "a732552e3855c4f81d70f34a7468c26ffd4f3babcf20a06fa309082905ec4e81", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/linux/amd64/liblz4-java.so", bytes: 203408,
                sha256: "108157738367c0a972c2228dead1af896bf5d5a7fc7f58fcbf855aa2b67049ea", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/linux/i386/liblz4-java.so", bytes: 68840,
                sha256: "f72fff01f82b13bf54e945d1d9158a4b6c10caabca0a102fba5477c8d8baa8b4", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/linux/ppc64le/liblz4-java.so", bytes: 209016,
                sha256: "c6dd51e13b98853688589828e6760f334088bec00a143197c05486bb94fd8495", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/linux/s390x/liblz4-java.so", bytes: 89200,
                sha256: "9584dad637d5241fdb649f1db07835623a7c567c43f0c9450249c72a81657990", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/net/jpountz/util/win32/amd64/liblz4-java.so", bytes: 516677,
                sha256: "1ba944ded629f0ea2c7669c9cb4b3a39b2d773142a0b5f8fce8e11d6a50800fd", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/FreeBSD/x86/libjansi.so", bytes: 12100,
                sha256: "71d4e610ba70854a344078512afd3ca42676107e48cd753ecd91e806abb45569", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/FreeBSD/x86_64/libjansi.so", bytes: 15308,
                sha256: "8c56980e59f79e7a95b8edcbfe0a4f6b54bb6964aa9034efa7617725179d1d52", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/arm/libjansi.so", bytes: 22232,
                sha256: "fc3bb7c1178369ae6d3b07e51b0590eb8a6bb6dd6acd90115afeb18c65d85ad6", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/arm64/libjansi.so", bytes: 15952,
                sha256: "a807b7b420a15ee48e13c694f1e4d84b0d69c8857c2f0008c484328522bc69e5", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/armv6/libjansi.so", bytes: 15068,
                sha256: "402a6ee45d724e95eacace01e4e17029e10869ddaa5f5f4b45e13eed33d016d7", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/armv7/libjansi.so", bytes: 12236,
                sha256: "f01f068c1be78380c36868b4f47f8f24877a17a3e2269cc43c43615f9aee3ecb", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/ppc64/libjansi.so", bytes: 18064,
                sha256: "8d97571bb654005984c4d7595062f94a7bdb8f11203abc9efe005c22571def43", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/x86/libjansi.so", bytes: 17580,
                sha256: "8bdd29ef7e167116e848594760fe49546cd7a3e45f130bc30766ba1490193653", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/x86_64/libjansi.so", bytes: 15800,
                sha256: "4bf8600bdeee40175ee1f5978c76bc9caa5083c35d6a7844d5ede74a669fb234", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/arm64/libjansi.jnilib", bytes: 53036,
                sha256: "a2d8080e97424ddc0c21b6c16326eaa8b5e5c7a6aca0de2113da3ea1aa6726aa", mode: 0o0, kind: NativeResourceKind::Arm64 },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86/libjansi.jnilib", bytes: 14748,
                sha256: "ea7ceaf2b63f95ac34822fed2f4cdfd436599c682e04383fac3736dd4c4a41a6", mode: 0o0, kind: NativeResourceKind::GradleIntelPlatform },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86_64/libjansi.jnilib", bytes: 15612,
                sha256: "537d38ad49b9d159eef64ed0a774c816e679606d9c37266776b74c2cd6074f3f", mode: 0o0, kind: NativeResourceKind::GradleIntelPlatform },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Windows/x86/jansi.dll", bytes: 113924,
                sha256: "1d6314da4b3a7a5e9dded6b0cc1b83f15f8f603897ae00cfe98ef171285620f3", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Windows/x86_64/jansi.dll", bytes: 127010,
                sha256: "d23fc9293b68781d43314403048d6dc655fa4620b6b4db3dcd345c52c332a2f4", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "bundletool/bundletool.jar", bytes: 32520401,
        sha256: "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29", members: &[
            NativeResourcePin { member: "com/sun/jna/darwin/libjnidispatch.jnilib", bytes: 180932,
                sha256: "e8ad39879b107ed955388d29555ddbcff3ada41598780eef579246752dd96c75", mode: 0o0, kind: NativeResourceKind::BundletoolDarwinI386X64 },
            NativeResourcePin { member: "com/sun/jna/freebsd-x86-64/libjnidispatch.so", bytes: 112729,
                sha256: "38c4aa3bd608dd4c302dd0f264bb123c87d8772b4df0ad2414e4b0a0d1cba021", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/freebsd-x86/libjnidispatch.so", bytes: 105753,
                sha256: "53e715c8b4369698dd208b48af825837a7668206ed384b303ff930ef912e7e7e", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-aarch64/libjnidispatch.so", bytes: 105088,
                sha256: "a9f3438531dca3fc4b4aa1604b717ded3d17c16f5d1324a02e5a3f64b30e77a9", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-arm/libjnidispatch.so", bytes: 107768,
                sha256: "7069629bbbc234c65843ecb0311ec734b62a3678b33bd6873248c6715b2b8848", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-armel/libjnidispatch.so", bytes: 111904,
                sha256: "1ef653d2b66998a43836cc703040c62618d95b7ea1e872b35bab13469bfd58fa", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-mips64el/libjnidispatch.so", bytes: 133240,
                sha256: "da1420335d2093646f0ade14aec2e30504ba3aeaeaa26a190e558782d0663f32", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-ppc/libjnidispatch.so", bytes: 123208,
                sha256: "490b3d5bf012b4648a9e12d66f53a580835bca0cec52e536f0575f340794fee1", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-ppc64le/libjnidispatch.so", bytes: 133536,
                sha256: "cd92dbee6af2f1b7dda0ca7e43ac885772008a3867e0357e1942410f690c1429", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-s390x/libjnidispatch.so", bytes: 132568,
                sha256: "48d005078a4afe54e96ee759b442a33a9111418410a4deb7c0c8188cd0106658", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-x86-64/libjnidispatch.so", bytes: 112848,
                sha256: "3812ee8afe5f712ca1f045350ed5ddfd83b2ba1dae5c55f4f17a4babeafbf8fd", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/linux-x86/libjnidispatch.so", bytes: 102079,
                sha256: "2e122dd90d46abaaffadff7cb239914019e0c6e09015bbe6893d51acf19de09c", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/openbsd-x86-64/libjnidispatch.so", bytes: 114291,
                sha256: "53be2755c82dec64edf98fe588331ad61cdf2e4c4685d533ea107dadf423271a", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/openbsd-x86/libjnidispatch.so", bytes: 107877,
                sha256: "c1d8be647e4973215329d3a2c82f6cd9beefec65601b7b230add1d573989c81a", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/sunos-sparc/libjnidispatch.so", bytes: 127616,
                sha256: "76bee038bbf5fe47c327571f887fa04c88904a7b467321b9f19ad9c0542cc333", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/sunos-sparcv9/libjnidispatch.so", bytes: 139232,
                sha256: "12eb13f9695aee0cce59383905b18f9992ce4ad6b3a8e40f8a862293701c47cc", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/sunos-x86-64/libjnidispatch.so", bytes: 132352,
                sha256: "a6d90b8048bf0d970b29e16d3464b0c5ec1a8a0a326c4abe908e7c9fd8b3007b", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/sunos-x86/libjnidispatch.so", bytes: 121120,
                sha256: "625e2c2d1ca776feeafbbbf413af4f1965ab49d01b1a954efccbb58f48f0442b", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "com/sun/jna/win32-x86-64/jnidispatch.dll", bytes: 246784,
                sha256: "a66959bec2ef5af730198db9f3b3f7cab0d4ae70ce01bec02bf1d738e6d1ee7a", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "com/sun/jna/win32-x86/jnidispatch.dll", bytes: 207872,
                sha256: "04c9a8ab43d1eb616b84d0686c8ae1d881ef03fe4f3aa26511e5b19d35ef16af", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "linux/aapt2", bytes: 6511488,
                sha256: "f2652fdbfcec58657ab718b28abf6b6d7ac90d61a8298341d86c8d837a6d7e98", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "macos/aapt2", bytes: 11186368,
                sha256: "995cf1a04fb55045dd22ae3d6248f32d649bac9dfa7bf9357507499794051c6b", mode: 0o100755, kind: NativeResourceKind::Arm64 },
            NativeResourcePin { member: "windows/aapt2.exe", bytes: 4106240,
                sha256: "c8c138022012e577aa4d3d3808079e017c8746d876ceaf10decefdc0645508cb", mode: 0o100755, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/jansi-1.18.jar", bytes: 287352,
        sha256: "109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b", members: &[
            NativeResourcePin { member: "META-INF/native/freebsd32/libjansi.so", bytes: 98380,
                sha256: "c220943d4c08ec91c1389a73e582ffacaefc4e42f85a9905d1d9c895c955f207", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "META-INF/native/freebsd64/libjansi.so", bytes: 104088,
                sha256: "96acfecb89242a9555242e19c25988d7f476ce696573b0155598cff6d453d987", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "META-INF/native/linux32/libjansi.so", bytes: 98876,
                sha256: "7732526b162b66835a53ad73e0731819b49fb585fdb3936bbc472ae7dfc3011e", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "META-INF/native/linux64/libjansi.so", bytes: 109048,
                sha256: "dcf42b19feb29d697ee3575fd622f96165b2f9e294d4d53f6274070bd5869ede", mode: 0o0, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "META-INF/native/osx/libjansi.jnilib", bytes: 20676,
                sha256: "9fe58e627b8c81d1ef9bdd7eab4b2ae84da1847d13b44c364f16f2cc85d63654", mode: 0o0, kind: NativeResourceKind::GradlePlainJansiIntel },
            NativeResourcePin { member: "META-INF/native/windows32/jansi.dll", bytes: 21504,
                sha256: "3c130ad32a4186adb5316a3458b0c1844ebef43e52fc09797b96cad9eb159d18", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
            NativeResourcePin { member: "META-INF/native/windows64/jansi.dll", bytes: 26112,
                sha256: "629af6e8e32dac48131a0607dc70c62a2d2a1dac6315d96b95449db141e13acb", mode: 0o0, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-freebsd-amd64-libcpp-0.22-milestone-28.jar", bytes: 19750,
        sha256: "88c670d679d37551bc7e799c854348aec3c0098ff52badbb9e3c246c4a023f56", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/freebsd-amd64-libcpp/libnative-platform-curses.so", bytes: 25480,
                sha256: "35b7e87244420d3beb56cf7180b6e3c195b7ef7d6c5a632cac2f6447e117383d", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
            NativeResourcePin { member: "net/rubygrapefruit/platform/freebsd-amd64-libcpp/libnative-platform.so", bytes: 32984,
                sha256: "c040fb2812b076d9795d6b9683feba37eb6843b58b26ae40021e440719834f91", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-aarch64-0.22-milestone-28.jar", bytes: 11768,
        sha256: "8d984ab5612b95aa9d24ead48039742a318ef21a488e2d4eadc0478a0f27dc4f", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-aarch64/libnative-platform.so", bytes: 76592,
                sha256: "4b3f13f6572ccf429f29570ea0d9804f159bc9eb0d6a7586e7b0dd3b90a37124", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-aarch64-ncurses5-0.22-milestone-28.jar", bytes: 8397,
        sha256: "a5a8908eb46d33708dfb052cc65ab9426624f88fb012faee3a5e1f3f42d3cd07", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-aarch64-ncurses5/libnative-platform-curses.so", bytes: 26080,
                sha256: "c0b5382fd53a721465f985b17b27b2d024d2f3b3915f1a7cd0a702d1607277ea", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-aarch64-ncurses6-0.22-milestone-28.jar", bytes: 9069,
        sha256: "1ff2ee4b58a77916d3faec4204eaee795358ba342e5638d4c80c89298698e85f", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-aarch64-ncurses6/libnative-platform-curses.so", bytes: 74768,
                sha256: "d45843a884c557cd6257572b0d28f56102f7f1a7a2acc8d4e70e2c585d672566", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-amd64-0.22-milestone-28.jar", bytes: 11250,
        sha256: "340c82470fcd12dff02c8a7cae0cf80dcbce447b1b6f9c3a8fd2df74a080b1ed", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-amd64/libnative-platform.so", bytes: 34496,
                sha256: "49ee56cfe70dfd243258c64bdf90a013471b302f099a89f66d62e08951684a88", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-amd64-ncurses5-0.22-milestone-28.jar", bytes: 8228,
        sha256: "6816b0bf9170f27a802682c9c8342c9abcfdac3cce0e6143cdbb04a2254cd6b7", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-amd64-ncurses5/libnative-platform-curses.so", bytes: 24816,
                sha256: "e0e7e84abe2624d974858eab31833ff718d4574c77b2e75c23ad64eb6646c8c9", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-linux-amd64-ncurses6-0.22-milestone-28.jar", bytes: 7950,
        sha256: "49c7b6a93ba9a14482fada6e891e5d09a46411bb372235b8c8686182fe762061", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/linux-amd64-ncurses6/libnative-platform-curses.so", bytes: 24336,
                sha256: "eb8677ba6c72d236b20d82145c009dce25463cdf3f38e18b39e0c0e6a0b20dce", mode: 0o100755, kind: NativeResourceKind::OtherPlatformElf },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-osx-aarch64-0.22-milestone-28.jar", bytes: 14261,
        sha256: "7cb8f8246c50a07f52e40b698f0a229271237e0bc59a4184e6b5ccc65d9f0847", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/osx-aarch64/libnative-platform-curses.dylib", bytes: 55072,
                sha256: "f1f5514b5bff4490262c81baa2eb217f6662f0d801e63e436a950e1e60039e85", mode: 0o100755, kind: NativeResourceKind::Arm64 },
            NativeResourcePin { member: "net/rubygrapefruit/platform/osx-aarch64/libnative-platform.dylib", bytes: 57112,
                sha256: "4f458e0b0bd6f63da23b3c97e878526d07318db0ef5616355c1fd7a35d910e27", mode: 0o100755, kind: NativeResourceKind::Arm64 },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-osx-amd64-0.22-milestone-28.jar", bytes: 12867,
        sha256: "61ab872b419deae8cdf37d1a0d5f6916b170ada1226129741fceb3ebd56b950f", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/osx-amd64/libnative-platform-curses.dylib", bytes: 17736,
                sha256: "10c96874bb236f931b735c22178ab57d796b5edab907cd69ede56ab2080cb3e4", mode: 0o100755, kind: NativeResourceKind::GradleIntelPlatform },
            NativeResourcePin { member: "net/rubygrapefruit/platform/osx-amd64/libnative-platform.dylib", bytes: 23896,
                sha256: "7749b8307a1834bc009358b1187b3066f91a5cee231eafec65ad62b7dd45a0e8", mode: 0o100755, kind: NativeResourceKind::GradleIntelPlatform },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-windows-amd64-0.22-milestone-28.jar", bytes: 71157,
        sha256: "18803842185961617abf2a2f52da063daae6b440437b441d605a0002336963d0", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/windows-amd64/native-platform.dll", bytes: 141312,
                sha256: "681a9775db6be81a3e9e160dfc2365764e06af4f92cfbb42618a4a36c2d8fd7d", mode: 0o100644, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-windows-amd64-min-0.22-milestone-28.jar", bytes: 70274,
        sha256: "b2758b8593cb0f4b6d41edb89cdcbbacd4754f2f6469f3c66c43beee1a11cf22", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/windows-amd64-min/native-platform.dll", bytes: 139264,
                sha256: "2fc2febe2cbe4e1d5324efa97ef67425392c6ed1dbbfc6df86a529e05b167877", mode: 0o100644, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-windows-i386-0.22-milestone-28.jar", bytes: 62992,
        sha256: "81721cfed8ffe07be279adf876f1e3c86dfe9428a59e5fe7a713f8ccc7120a09", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/windows-i386/native-platform.dll", bytes: 115712,
                sha256: "4db97376c46a0bf89dbf4aff446cf6995e46f34e7fc81f549e61af6ed1e3c3c8", mode: 0o100644, kind: NativeResourceKind::OtherPlatformPe },
        ] },
    NativeArchivePin { path: "gradle/lib/native-platform-windows-i386-min-0.22-milestone-28.jar", bytes: 62076,
        sha256: "0f32b0012ebe1f52de052d2988773755f0c053248c7fd23cd88a93d63a69ecd4", members: &[
            NativeResourcePin { member: "net/rubygrapefruit/platform/windows-i386-min/native-platform.dll", bytes: 114176,
                sha256: "112ec3a23028432599900c763a16d51eb89461e60cdac2fcee1bf97642a2d08b", mode: 0o100644, kind: NativeResourceKind::OtherPlatformPe },
        ] },
];
fn native_archive(path: &str) -> Option<&'static NativeArchivePin> {
    NATIVE_ARCHIVES.iter().find(|archive| archive.path == path)
}
fn native_members_match(file: &CanonicalFile, members: &[NestedNative]) -> bool {
    if let Some(archive) = native_profile::jdk_jvm_archive(file.path) {
        return file.size == archive.bytes && file.sha256 == archive.sha256 && file.mode == 0o444
            && members.len() == archive.members.len()
            && members.iter().zip(archive.members).all(|(actual, expected)| {
                if (actual.member, actual.bytes, actual.sha256, actual.mode)
                    != (expected.member, expected.bytes, expected.sha256, expected.mode)
                    || actual.kind != if expected.counterpart.is_some() {
                        NativeResourceKind::JdkInstalledCounterpart } else { NativeResourceKind::JdkJpackageTemplate } { return false; }
                let Some(header) = &actual.header else { return false; };
                expected.header().is_some_and(|pin| native_snapshot_matches(header, pin))
            });
    }
    let Some(archive) = native_archive(file.path) else {
        // Unlisted foreign resources have no exception. Existing ARM64-only
        // unlisted archives still require their native header/system-load proof.
        return members.iter().all(|m| m.kind == NativeResourceKind::Arm64 && m.header.is_some());
    };
    file.size == archive.bytes && file.sha256 == archive.sha256 && file.mode == 0o444
        && members.len() == archive.members.len()
        && members.iter().zip(archive.members).all(|(actual, expected)|
            (actual.member, actual.bytes, actual.sha256, actual.mode, actual.kind)
                == (expected.member, expected.bytes, expected.sha256, expected.mode, expected.kind)
                && actual.header.is_some() == (expected.kind == NativeResourceKind::Arm64))
}

#[derive(Clone, Copy, Serialize)]
struct VersionSpec {
    jdk_vendor: &'static str, jdk_version: &'static str,
    gradle_version: &'static str, agp_version: &'static str,
    sdk_platform: &'static str, sdk_platform_revision: &'static str,
    sdk_build_tools_version: &'static str,
}
#[derive(Clone, Copy, Serialize)]
struct RoleSpec {
    java: &'static str, javac: &'static str, gradle: &'static str,
    bundletool: &'static str, sdk: &'static str,
}
#[derive(Clone, Copy, Serialize)]
struct Reference {
    /// Fixed compiled profile only. Not a saved-project compatibility claim.
    profile: &'static str,
    observed_jdk_vendor: &'static str,
    observed_jdk_version: &'static str,
    versions: VersionSpec,
    roles: RoleSpec,
    gradle_distribution_url: &'static str,
    gradle_distribution_sha256: &'static str,
    archives: &'static [OfficialArchive],
    trees: &'static [SourceTree],
    source_members: &'static [SourceMemberSpec],
    source_bindings: &'static [SourceBinding],
    support: &'static [SupportOriginalSpec],
    support_members: &'static [SupportMemberSpec],
    payload: &'static [PayloadSource],
    classes: &'static [FileClass],
    aliases: &'static [CanonicalAlias],
    directories: &'static [&'static str],
}

// Complete immutable observations for the fixed official toolchain.
// Comparison DATA, never runtime registration or native qualification.
// Structural, inventory, native, support and whole-owner gates still apply.
include!("android_supplier_macos_catalogue.rs");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedNotice<'a> {
    member: &'a str, resource_path: &'a str, size: u64, sha256: &'a str,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedArchive<'a, const N: usize> {
    id: &'a str, file_name: &'a str, resource_path: &'a str, url: &'a str,
    size: u64, sha256: &'a str,
    #[serde(borrow, bound(deserialize = "[FixedNotice<'a>; N]: Deserialize<'de>"))]
    notices: [FixedNotice<'a>; N],
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixedManifest<'a> {
    schema_version: u32, platform: &'a str,
    #[serde(borrow)]
    archives: (FixedArchive<'a, 7>, FixedArchive<'a, 1>),
}
fn fixed_manifest() -> Option<FixedManifest<'static>> {
    // The SAME source-reviewed packaging manifest is compile-bound. There is
    // no runtime path, renderer, mutable JSON, environment or flag override.
    const SOURCE: &[u8] = include_bytes!("../../macos-installed-inputs/android-support.json");
    // The exact source has no escaped strings/unknown fields. Refuse any
    // alternate bytes before serde can allocate scratch or an error string.
    // Both archives and their exact seven/one notices decode into stack arrays.
    if SOURCE.len() != 3023 || !policy::digest_matches(SOURCE,
        "3450a83882cecdc9d8e402380ccf21e6dc5cec65382cbc7c18b4e6ff6a9aeb8f") { return None; }
    let value: FixedManifest<'static> = serde_json::from_slice(SOURCE).ok()?;
    if value.schema_version != 1 || value.platform != "macos" { return None; }
    Some(value)
}
fn support_archive_matches<const N: usize>(reference: &Reference, entry: &FixedArchive<'_, N>,
    index: usize, expected: (&str, &str, usize)) -> bool {
    let archive = &reference.archives[expected.2];
    let support = reference.support[index];
    if entry.id != expected.0 || entry.file_name != expected.1
        || entry.resource_path.strip_prefix("Contents/Resources/android-support/") != Some(expected.1)
        || entry.url != archive.official_source || entry.size != archive.archive.bytes
        || entry.sha256 != archive.archive.sha256 || entry.size != support.archive.bytes
        || entry.sha256 != support.archive.sha256 { return false; }
    for (index, notice) in entry.notices.iter().enumerate() {
        if !archive_relative(notice.member) || !hex(notice.sha256, 64)
            || notice.size == 0 || notice.size > 256 * 1024
            || notice.resource_path.strip_prefix("Contents/Resources/android-support/notices/")
                .and_then(|tail| tail.strip_prefix(entry.id)).and_then(|tail| tail.strip_prefix('/')) != Some(notice.member)
            || entry.notices[..index].iter().any(|n| n.member == notice.member)
            || !archive.members.iter().any(|m| m.name == notice.member
                && matches!(m.kind, ArchiveKind::File { bytes, sha256, .. } if bytes == notice.size && sha256 == notice.sha256)) {
            return false;
        }
    }
    true
}
fn support_manifest_matches(reference: &Reference) -> bool {
    let Some(manifest) = fixed_manifest() else { return false; };
    reference.support.len() == 2 && reference.archives.len() == COMPONENTS.len()
        && support_archive_matches(reference, &manifest.archives.0, 0, ("bundletool", "bundletool-all-1.18.3.jar", 5))
        && support_archive_matches(reference, &manifest.archives.1, 1, ("aapt2", "aapt2-8.9.2-12782657-osx.jar", 4))
}


fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn folded(left: &str, right: &str) -> Ordering {
    left.bytes().map(|b| b.to_ascii_lowercase()).cmp(right.bytes().map(|b| b.to_ascii_lowercase()))
}
fn archive_order(component: Component, left: &str, right: &str) -> Ordering {
    // Only this sealed JAR preserves the JVM's case-sensitive class namespace.
    // No member is projected into the installed filesystem.
    if component == Component::Bundletool { left.cmp(right) } else { folded(left, right) }
}
fn archive_mode(component: Component, sha256: &str, mode: u32, kind: u32) -> bool {
    let observed_jdk_directory = component == Component::Jdk && sha256 == JDK17_ARCHIVE_SHA
        && mode == 0o042755 && kind == 0o040000;
    (mode & !0o170777 == 0 || observed_jdk_directory)
        && (mode & 0o170000 == 0 || mode & 0o170000 == kind)
}
// Archive-internal Java class names legitimately contain '$'. This grammar
// does not replace installed-path policy or authorize archive extraction.
fn archive_relative(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.split('/').count() <= 16
        && value.split('/').all(|part| !part.is_empty() && part.len() <= 255
            && !matches!(part, "." | "..") && !part.ends_with('.') && !part.ends_with(' ')
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+@.,= $-".contains(&b)))
}
fn source_order(group: SourceGroup, name: &str, other: &SourceMemberSpec) -> Ordering {
    group.cmp(&other.group).then_with(|| folded(name, other.relative))
}
fn modes(value: &[u32]) -> bool {
    !value.is_empty() && value.len() <= 4 && value.windows(2).all(|w| w[0] < w[1])
        && value.iter().all(|mode| mode & !0o777 == 0)
}
fn archive_pin(value: ArchivePin<'_>) -> bool {
    value.bytes > 0 && value.bytes <= ARCHIVE_BYTES && hex(value.sha256, 64)
}
fn zip_member(value: ZipMemberSpec<'_>, archive: ArchivePin<'_>) -> bool {
    archive_relative(value.name) && value.bytes > 0 && value.bytes <= policy::FILE_LIMIT
        && hex(value.sha256, 64) && value.flags & !0x080e == 0 && (value.method != ZipMethod::Stored || value.flags & 6 == 0)
        && value.local_header_offset.checked_add(30).is_some_and(|at| at <= value.data_offset)
        && value.data_offset.checked_add(value.compressed_bytes).is_some_and(|end| end <= archive.bytes)
        && value.compressed_bytes > 0
        && (value.method != ZipMethod::Stored || value.compressed_bytes == value.bytes)
}
fn source_index(reference: &Reference, group: SourceGroup, name: &str) -> Option<usize> {
    let index = reference.source_members.binary_search_by(|value| source_order(group, name, value).reverse()).ok()?;
    let source = &reference.source_members[index];
    (source.group == group && source.relative == name).then_some(index)
}
fn member_under(reference: &Reference, value: &SourceMemberSpec) -> bool {
    source_tree(reference, value).is_some()
}
fn source_tree(reference: &Reference, value: &SourceMemberSpec) -> Option<SourceTree> {
    reference.trees.iter().find(|tree| tree.group == value.group && (tree.prefix.is_empty()
        || value.relative == tree.prefix || value.relative.strip_prefix(tree.prefix).is_some_and(|s| s.starts_with('/')))).copied()
}
fn component_source(reference: &Reference, component: Component, source: &SourceMemberSpec, name: &str) -> bool {
    let Some(tree) = source_tree(reference, source) else { return false; };
    match component {
        Component::Jdk => {
            let Some(root) = reference.archives.first().and_then(|a| a.members.first())
                .and_then(|m| m.name.split('/').next()) else { return false; };
            tree.group == SourceGroup::Jdk && tree.prefix.is_empty()
                && name.strip_prefix(root).and_then(|s| s.strip_prefix('/')) == Some(source.relative)
        }
        Component::Gradle => tree.group == SourceGroup::Gradle && tree.prefix.is_empty()
            && name.strip_prefix("gradle-").and_then(|s| s.strip_prefix(reference.versions.gradle_version))
                .and_then(|s| s.strip_prefix('/')) == Some(source.relative),
        Component::SdkPlatform => tree.group == SourceGroup::Sdk
            && tree.prefix.strip_prefix("platforms/") == Some(reference.versions.sdk_platform)
            && name.strip_prefix(reference.versions.sdk_platform) == source.relative.strip_prefix(tree.prefix),
        Component::SdkBuildTools => tree.group == SourceGroup::Sdk
            && tree.prefix.strip_prefix("build-tools/") == Some(reference.versions.sdk_build_tools_version)
            && reference.versions.sdk_build_tools_version == "35.0.0"
            && name.strip_prefix("android-15") == source.relative.strip_prefix(tree.prefix),
        Component::Aapt2 | Component::Bundletool => false,
    }
}
fn wrapper_directory(reference: &Reference, archive: &OfficialArchive, member: &OfficialMember) -> bool {
    if !matches!(member.kind, ArchiveKind::Directory { .. }) { return false; }
    // Only retained bundle/distribution roots sit outside SourceMembers. All
    // selected descendants and SDK package roots need their ordinary binding;
    // sealed support archives never supply picked wrapper directories.
    match archive.component {
        Component::Jdk => archive.members.first().and_then(|first| first.name.split('/').next())
            .is_some_and(|root| member.name == root),
        Component::Gradle => member.name.strip_prefix("gradle-") == Some(reference.versions.gradle_version),
        Component::SdkPlatform | Component::SdkBuildTools | Component::Aapt2 | Component::Bundletool => false,
    }
}
fn parent_spelling(left: &str, right: &str) -> bool {
    for (a, b) in left.split('/').zip(right.split('/')) {
        if !a.eq_ignore_ascii_case(b) { break; }
        if a != b { return false; }
    }
    true
}
fn folded_under(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        && name.as_bytes().get(prefix.len()) == Some(&b'/')
}
fn source_origin(reference: &Reference, index: usize) -> Option<(u8, &'static str)> {
    match reference.source_bindings.get(index)?.provenance {
        SourceProvenance::Vendor { archive, member } => Some((archive,
            reference.archives.get(usize::from(archive))?.members.get(member as usize)?.name)),
        SourceProvenance::ArchiveParent { archive, prefix } => Some((archive, prefix)),
    }
}
fn same_source_archive(source: &SourceMemberSpec, archive: &OfficialMember) -> bool {
    match (&source.kind, &archive.kind) {
        (SourceKindSpec::Directory { .. }, ArchiveKind::Directory { .. }) => true,
        (SourceKindSpec::File { bytes, sha256, .. }, ArchiveKind::File { bytes: n, sha256: h, .. }) => bytes == n && sha256 == h,
        (SourceKindSpec::Alias { target, .. }, ArchiveKind::Alias { target: t, .. }) => target == t,
        _ => false,
    }
}
fn canonical_source(reference: &Reference, group: SourceGroup, relative: &str, canonical: &str) -> bool {
    match group {
        SourceGroup::Jdk => reference.roles.java.strip_suffix("Contents/Home/bin/java")
            .is_some_and(|prefix| canonical.strip_prefix(prefix) == Some(relative)),
        SourceGroup::Sdk => canonical.strip_prefix("sdk/") == Some(relative),
        SourceGroup::Gradle => canonical.strip_prefix("gradle/") == Some(relative),
        SourceGroup::FixedSupport => false,
    }
}
fn source_file(source: &SourceMemberSpec, file: &CanonicalFile) -> bool {
    matches!(source.kind, SourceKindSpec::File { bytes, sha256, .. } if bytes == file.size && sha256 == file.sha256)
}
/// Pure bounded byte pins only: structural()/available()/reservation discovery
/// call this before there is a native work charge. Do not parse Mach-O here.
fn native_snapshot_matches(value: &NativeHeader, pin: &native_profile::MachPin) -> bool {
    value.prefix.len() <= 4096 && (32..=NATIVE_HEADER).contains(&value.commands.len())
        && pin.snapshot_bytes(value.prefix, value.commands)
}
fn native_header(value: &NativeHeader, bytes: u64) -> Option<policy::MachCommands> {
    native_header_for(value, bytes, policy::MachArchitecture::Arm64)
}
fn native_header_for(value: &NativeHeader, bytes: u64, architecture: policy::MachArchitecture) -> Option<policy::MachCommands> {
    if value.prefix.len() > 4096 || value.commands.len() > NATIVE_HEADER || value.commands.len() < 32 { return None; }
    let commands = u32::from_le_bytes(value.commands.get(16..20)?.try_into().ok()?);
    if commands > NATIVE_COMMANDS { return None; }
    let slice = policy::native_slice(value.prefix, bytes, architecture)?;
    if slice.offset == 0 && value.prefix.get(..32) != value.commands.get(..32) { return None; }
    let result = policy::native_commands(value.commands, slice, architecture)?;
    if result.rpaths.len() > NATIVE_RPATHS { return None; }
    Some(result)
}
/// Small structural/digest/layout headroom is retained in BOTH phases. Reproof
/// never creates a second inventory/proposal, but this preserves all existing
/// fixed supplier/parser/native allowances rather than guessing a zero budget.
fn fixed_working_bytes() -> Option<usize> {
    262144usize.checked_add(sdk_metadata::PARSER_WORK_BYTES)?.checked_add(policy::NATIVE_WORK_BYTES)
}
impl Reference {
    fn source_storage(&self) -> Option<SourceStorage> { SourceStorage::for_roster(self.source_members, self.payload) }
    fn working_bytes(&self) -> Option<usize> {
        self.source_storage()?;
        let n = self.payload.len(); let a = self.aliases.len(); let d = self.directories.len();
        if n == 0 || n > policy::FILE_COUNT || a > policy::ALIAS_COUNT
            || n.checked_add(a)?.checked_add(d)?.checked_add(3)? > policy::ENTRY_LIMIT
            || self.source_members.len() > policy::ENTRY_LIMIT { return None; }
        let p = self.payload.iter().try_fold(0usize, |sum, f| sum.checked_add(f.installed.path.len()))?
            .checked_add(self.aliases.iter().try_fold(0usize, |sum, a| sum.checked_add(a.path.len()))?)?;
        let directory = self.directories.iter().try_fold(0usize, |sum, v| sum.checked_add(v.len()))?;
        // Dynamic header/profile/instance/digest/provider strings fit this
        // fixed allowance; all variable canonical paths are charged below.
        let fixed = [self.versions.jdk_vendor, self.versions.jdk_version, self.versions.gradle_version,
            self.versions.agp_version, self.versions.sdk_platform, self.versions.sdk_platform_revision,
            self.versions.sdk_build_tools_version, self.gradle_distribution_url, self.gradle_distribution_sha256,
            self.roles.java, self.roles.javac, self.roles.gradle, self.roles.bundletool, self.roles.sdk]
            .iter().try_fold(4096usize, |sum, s| sum.checked_add(s.len()))?;
        let strings = self.payload.iter().try_fold(fixed, |sum, f| sum.checked_add(f.installed.path.len())?.checked_add(64))?
            .checked_add(self.aliases.iter().try_fold(0usize, |sum, a|
                sum.checked_add(a.path.len())?.checked_add(a.target.len())?.checked_add(a.canonical.len()))?)?;
        // ProposalDocuments borrows the compiled payload slice. There is no
        // runtime-owned Vec<PayloadSource>; real FileSpec/Alias capacity remains.
        let dynamic = n.checked_add(policy::OS_FILES.len())?.checked_mul(size_of::<FileSpec>())?
            .checked_add(a.checked_mul(size_of::<Alias>())?)?.checked_mul(2)?;
        let string_space = strings.checked_add(p)?.checked_add(directory.checked_mul(2)?)?.checked_mul(2)?;
        let tree_bytes = policy::proposal_tree_reservation_bytes(n, a, d)?;
        fixed_working_bytes()?
            .checked_add(policy::MANIFEST_LIMIT)?.checked_add(policy::PROVIDER_LIMIT)?
            .checked_add(policy::RECORD_LIMIT)?.checked_add(dynamic)?.checked_add(string_space)?
            .checked_add(tree_bytes)?.checked_add(size_of::<ProposalDocuments>())?
            .le_checked(APP_BYTES)
    }
}
trait CheckedLimit { fn le_checked(self, limit: usize) -> Option<usize>; }
impl CheckedLimit for usize {
    fn le_checked(self, limit: usize) -> Option<usize> { (self <= limit).then_some(self) }
}


fn sdk_source_matches(archive: &OfficialArchive, member: &OfficialMember,
    source: &SourceMemberSpec, pin: &policy::Sdk35Pin) -> bool {
    archive.component == Component::SdkBuildTools && archive.archive.bytes == policy::SDK35_ARCHIVE_BYTES
        && archive.archive.sha256 == policy::SDK35_ARCHIVE_SHA && member.name == pin.member
        && matches!(member.kind, ArchiveKind::File { mode, bytes, sha256 }
            if mode == (0o100000 | pin.original_mode) && bytes == pin.bytes && sha256 == pin.sha256)
        && source.group == SourceGroup::Sdk && pin.path.strip_prefix("sdk/") == Some(source.relative)
        && matches!(source.kind, SourceKindSpec::File { bytes, sha256, modes }
            if bytes == pin.bytes && sha256 == pin.sha256 && modes == [pin.original_mode])
}
impl Reference {
    fn sdk_original(&self, file: &CanonicalFile, kind: policy::Sdk35File) -> bool {
        let pin = kind.pin();
        if !pin.matches(file.path, file.size, file.sha256, file.mode) { return false; }
        let Some(relative) = pin.path.strip_prefix("sdk/") else { return false; };
        let Some(index) = source_index(self, SourceGroup::Sdk, relative) else { return false; };
        let Some(binding) = self.source_bindings.get(index) else { return false; };
        let SourceProvenance::Vendor { archive, member } = binding.provenance else { return false; };
        let Some(archive) = self.archives.get(usize::from(archive)) else { return false; };
        let Some(member) = archive.members.get(member as usize) else { return false; };
        sdk_source_matches(archive, member, &self.source_members[index], pin)
    }
    fn vendor_payload(&self, file: &CanonicalFile, group: SourceGroup, component: Component,
        archive_pin: ArchivePin<'_>, member_prefix: &str, member_name: &str, original_mode: u32) -> bool {
        let relative = match group {
            SourceGroup::Jdk => native_profile::jdk_relative(file.path),
            SourceGroup::Sdk => file.path.strip_prefix("sdk/"),
            SourceGroup::Gradle => file.path.strip_prefix("gradle/"),
            SourceGroup::FixedSupport => None,
        };
        let Some(relative) = relative else { return false; };
        let Some(index) = source_index(self, group, relative) else { return false; };
        let Some(binding) = self.source_bindings.get(index) else { return false; };
        let SourceProvenance::Vendor { archive, member } = binding.provenance else { return false; };
        let Some(archive) = self.archives.get(archive as usize) else { return false; };
        let Some(member) = archive.members.get(member as usize) else { return false; };
        let SourceDisposition::Payload(ordinal) = binding.disposition else { return false; };
        // Exact complete member equality without constructing prefix + relative.
        archive.component == component && archive.archive == archive_pin
            && member.name.strip_prefix(member_prefix) == Some(member_name)
            && canonical_source(self, group, relative, file.path)
            && matches!(member.disposition, ArchiveDisposition::Picked { source_index } if source_index as usize == index)
            && matches!(member.kind, ArchiveKind::File { mode, bytes, sha256 }
                if mode == (0o100000 | original_mode) && bytes == file.size && sha256 == file.sha256)
            && matches!(self.source_members[index].kind, SourceKindSpec::File { bytes, sha256, modes }
                if bytes == file.size && sha256 == file.sha256 && modes == [original_mode])
            && self.payload.get(ordinal as usize).is_some_and(|payload|
                payload.installed == *file && payload.origin == PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                    group, relative: self.source_members[index].relative }))
    }
    fn target_original(&self, file: &CanonicalFile) -> bool {
        let Some(pin) = native_profile::target_elf_reserved(file.path) else { return false; };
        pin.matches(file.path, file.size, file.sha256, file.mode)
            && self.vendor_payload(file, SourceGroup::Sdk, Component::SdkBuildTools,
                ArchivePin { bytes: policy::SDK35_ARCHIVE_BYTES, sha256: policy::SDK35_ARCHIVE_SHA },
                "", pin.member, pin.original_mode)
    }
    fn gradle_foreign_original(&self, file: &CanonicalFile) -> bool {
        let pin = &native_profile::GRADLE_BAT;
        file.path == pin.path && file.size == pin.bytes && file.sha256 == pin.sha256 && file.mode == 0o444
            && self.versions.gradle_version == "8.14.5" && self.gradle_distribution_sha256 == GRADLE_ARCHIVE_SHA
            && self.vendor_payload(file, SourceGroup::Gradle, Component::Gradle,
                ArchivePin { bytes: 138068841, sha256: GRADLE_ARCHIVE_SHA }, "", pin.member, pin.original_mode)
    }
    fn jdk_original(&self, file: &CanonicalFile, original_mode: u32) -> bool {
        let Some(relative) = native_profile::jdk_relative(file.path) else { return false; };
        file.mode == (original_mode & !0o222)
            && self.versions.jdk_vendor == "temurin" && self.versions.jdk_version == "17.0.20.1"
            && self.observed_jdk_vendor == "Eclipse Adoptium" && self.observed_jdk_version == "17.0.20.1"
            && self.vendor_payload(file, SourceGroup::Jdk, Component::Jdk, ArchivePin {
                bytes: native_profile::JDK_ARCHIVE_BYTES, sha256: native_profile::JDK_ARCHIVE_SHA256 },
                "jdk-17.0.20.1+1/", relative, original_mode)
    }
    /// Generated metadata joins actual vendor properties/archive identities;
    /// picked package.xml observations are deliberately not SourceBindings.
    fn compiled_metadata_origin(&self, kind: SdkMetadataKind, file: &CanonicalFile) -> bool {
        let document = sdk_metadata::compiled_sdk_metadata(kind);
        let archive_index = kind.index() + 1;
        let Some(archive) = self.archives.get(archive_index) else { return false; };
        if *file != document.file || !sdk_metadata::compiled_valid(kind)
            || archive.archive != document.input_archive
            || archive.component != COMPONENTS[archive_index]
            || self.versions.sdk_platform != "android-35" || self.versions.sdk_platform_revision != "2"
            || self.versions.sdk_build_tools_version != "35.0.0" { return false; }
        let Some(index) = source_index(self, SourceGroup::Sdk, document.source_properties_relative) else { return false; };
        let Some(binding) = self.source_bindings.get(index) else { return false; };
        let SourceProvenance::Vendor { archive: origin, member } = binding.provenance else { return false; };
        let Some(member) = archive.members.get(member as usize) else { return false; };
        let SourceDisposition::Payload(ordinal) = binding.disposition else { return false; };
        let Some(properties) = self.payload.get(ordinal as usize) else { return false; };
        origin as usize == archive_index && member.name == document.source_properties_member
            && matches!(member.disposition, ArchiveDisposition::Picked { source_index } if source_index as usize == index)
            && matches!(member.kind, ArchiveKind::File { mode, bytes, sha256 }
                if mode == (0o100000 | document.source_properties_mode)
                    && bytes == document.source_properties_bytes && sha256 == document.source_properties_sha256)
            && matches!(self.source_members[index].kind, SourceKindSpec::File { bytes, sha256, modes }
                if bytes == document.source_properties_bytes && sha256 == document.source_properties_sha256
                    && modes == [document.source_properties_mode])
            && properties.origin == PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                group: SourceGroup::Sdk, relative: document.source_properties_relative })
            && properties.installed.path.strip_prefix("sdk/") == Some(document.source_properties_relative)
            && properties.installed.size == document.source_properties_bytes
            && properties.installed.sha256 == document.source_properties_sha256 && properties.installed.mode == 0o444
    }
    fn compiled_metadata_pair(&self) -> bool {
        // Inert synthetic references have neither original SDK archive pin.
        // They never populate REFERENCES. Either genuine selected archive
        // requires BOTH generated documents and both exact original joins.
        let required = [SdkMetadataKind::Platform35Revision2, SdkMetadataKind::BuildTools35]
            .iter().any(|kind| self.archives.get(kind.index() + 1).is_some_and(|archive|
                archive.archive.sha256 == sdk_metadata::compiled_sdk_metadata(*kind).input_archive.sha256));
        let mut counts = [0usize; 2];
        for payload in self.payload {
            if let PayloadOrigin::CompiledSdkMetadata(kind) = payload.origin {
                if !self.compiled_metadata_origin(kind, &payload.installed) { return false; }
                counts[kind.index()] += 1;
            }
        }
        counts == if required { [1, 1] } else { [0, 0] }
    }
    /// Called only after sorted/size/grammar/reciprocal binding preflight.
    /// All checks borrow static tables: <=16 ancestor searches per source and
    /// one bounded archive-prefix range per derived directory. No directory
    /// tree, fabricated archive row, native call or source observation is made.
    fn source_directory_closure(&self) -> bool {
        for tree in self.trees {
            if !tree.prefix.is_empty() {
                let Some(index) = source_index(self, tree.group, tree.prefix) else { return false; };
                if !matches!(self.source_members[index].kind, SourceKindSpec::Directory { .. }) { return false; }
            }
        }
        for (index, source) in self.source_members.iter().enumerate() {
            let Some(tree) = source_tree(self, source) else { return false; };
            let Some((archive_index, name)) = source_origin(self, index) else { return false; };
            let Some(archive) = self.archives.get(usize::from(archive_index)) else { return false; };
            if !component_source(self, archive.component, source, name) { return false; }
            let mut path = source.relative;
            while let Some((parent, _)) = path.rsplit_once('/') {
                // The SDK picker is broad; only the selected package itself
                // and its descendants belong to the observed member roster.
                if !tree.prefix.is_empty() && parent.len() < tree.prefix.len() { break; }
                let Some(parent_index) = source_index(self, source.group, parent) else { return false; };
                if !matches!(self.source_members[parent_index].kind, SourceKindSpec::Directory { .. }) { return false; }
                let Some((parent_archive, parent_name)) = source_origin(self, parent_index) else { return false; };
                let Some(tail) = source.relative.strip_prefix(parent) else { return false; };
                if parent_archive != archive_index || !tail.starts_with('/')
                    || name.strip_suffix(tail) != Some(parent_name) { return false; }
                path = parent;
            }
            if let SourceProvenance::ArchiveParent { prefix, .. } = self.source_bindings[index].provenance {
                // An explicit header (even a differently cased file/alias) can
                // never be replaced by derived provenance or mode laundering.
                if archive.members.binary_search_by(|m| archive_order(archive.component, m.name, prefix)).is_ok() {
                    return false;
                }
                let first = archive.members.partition_point(|m| m.name.bytes().map(|b| b.to_ascii_lowercase())
                    .cmp(prefix.bytes().chain(std::iter::once(b'/')).map(|b| b.to_ascii_lowercase())) == Ordering::Less);
                let mut required = false;
                // The entire actual archive prefix, not one convenient child,
                // must map to this SAME selected source prefix and component.
                for member in archive.members[first..].iter().take_while(|m| folded_under(m.name, prefix)) {
                    let Some(tail) = member.name.strip_prefix(prefix).filter(|tail| tail.starts_with('/')) else { return false; };
                    let ArchiveDisposition::Picked { source_index } = member.disposition else { return false; };
                    let Some(child) = self.source_members.get(source_index as usize) else { return false; };
                    if child.group != source.group || child.relative.strip_prefix(source.relative) != Some(tail) { return false; }
                    required = true;
                }
                if !required { return false; }
            }
        }
        true
    }
    fn structural(&self) -> bool {
        if self.working_bytes().is_none()
            || self.profile != crate::android_build_protocol::MAC_TOOLCHAIN_PROFILE
            || self.observed_jdk_vendor.is_empty() || self.observed_jdk_vendor.len() > 128
            || self.observed_jdk_version.is_empty() || self.observed_jdk_version.len() > 64
            || self.archives.len() != COMPONENTS.len() || self.classes.len() != self.payload.len()
            || self.source_members.len() != self.source_bindings.len() || self.source_members.is_empty()
            || self.archives.get(3).is_none_or(|a| a.archive.sha256 != self.gradle_distribution_sha256)
            || self.trees.len() != 4 || self.support.len() != 2 || self.support_members.len() != 1
            || self.support[0].asset != SupportAsset::BundletoolJar || self.support[1].asset != SupportAsset::Aapt2OsxJar
            || self.support_members[0].asset != SupportAsset::Aapt2OsxJar || self.support_members[0].member.name != "aapt2"
            || !self.payload.windows(2).all(|w| w[0].installed.path < w[1].installed.path)
            || !self.aliases.windows(2).all(|w| w[0].path < w[1].path)
            || !self.directories.windows(2).all(|w| w[0] < w[1])
            || !self.source_members.windows(2).all(|w| source_order(w[0].group, w[0].relative, &w[1]) == Ordering::Less) {
            return false;
        }
        let trees = |group, expected: &str| self.trees.iter().filter(|t| t.group == group && t.prefix == expected).count();
        if trees(SourceGroup::Jdk, "") != 1 || trees(SourceGroup::Gradle, "") != 1
            || self.trees.iter().filter(|t| t.group == SourceGroup::Sdk
                && t.prefix.strip_prefix("platforms/") == Some(self.versions.sdk_platform)).count() != 1
            || self.trees.iter().filter(|t| t.group == SourceGroup::Sdk
                && t.prefix.strip_prefix("build-tools/") == Some(self.versions.sdk_build_tools_version)).count() != 1
            || self.trees.iter().any(|t| !t.prefix.is_empty() && !policy::relative(t.prefix)) {
            return false;
        }
        for (index, source) in self.source_members.iter().enumerate() {
            if source.group == SourceGroup::FixedSupport || !policy::relative(source.relative) || !member_under(self, source)
                || source.group == SourceGroup::Sdk && sdk_metadata::OPTIONAL.iter().any(|spec|
                    folded(source.relative, spec.relative) == Ordering::Equal) { return false; }
            let mode_valid = match source.kind {
                SourceKindSpec::Directory { modes: values } => modes(values),
                SourceKindSpec::File { bytes, sha256, modes: values } =>
                    bytes <= policy::FILE_LIMIT && hex(sha256, 64) && modes(values),
                SourceKindSpec::Alias { target, canonical, modes: values } =>
                    source.group == SourceGroup::Jdk && modes(values)
                        && policy::jdk_source_alias_resolves(source.relative, target, canonical)
                        && source_index(self, source.group, canonical).is_some_and(|i|
                            matches!(self.source_members[i].kind, SourceKindSpec::File { .. })),
            };
            if !mode_valid { return false; }
            let binding = &self.source_bindings[index];
            match binding.provenance {
                SourceProvenance::Vendor { archive, member } => {
                    let Some(archive) = self.archives.get(usize::from(archive)) else { return false; };
                    let Some(member) = archive.members.get(member as usize) else { return false; };
                    if !matches!(member.disposition, ArchiveDisposition::Picked { source_index } if source_index as usize == index)
                        || !same_source_archive(source, member) || !component_source(self, archive.component, source, member.name) { return false; }
                    if let (ArchiveKind::File { mode, .. }, SourceDisposition::Payload(payload)) = (&member.kind, &binding.disposition) {
                        if mode & 0o111 != 0 && matches!(self.classes.get(*payload as usize), Some(FileClass::Data)) { return false; }
                    }
                }
                SourceProvenance::ArchiveParent { archive, prefix } => {
                    let Some(archive) = self.archives.get(usize::from(archive)) else { return false; };
                    if !archive_relative(prefix) || !component_source(self, archive.component, source, prefix)
                        || !matches!(source.kind, SourceKindSpec::Directory { .. })
                        || !matches!(binding.disposition, SourceDisposition::Directory) { return false; }
                }
            }
            match binding.disposition {
                SourceDisposition::Payload(ordinal) => {
                    let Some(payload) = self.payload.get(ordinal as usize) else { return false; };
                    if payload.origin != PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                        group: source.group, relative: source.relative }) || !source_file(source, &payload.installed)
                        || !canonical_source(self, source.group, source.relative, payload.installed.path) { return false; }
                }
                SourceDisposition::Alias(ordinal) => {
                    let Some(alias) = self.aliases.get(ordinal as usize) else { return false; };
                    if alias.source_index as usize != index
                        || !matches!(source.kind, SourceKindSpec::Alias { target, canonical, .. } if target == alias.target
                            && canonical_source(self, source.group, canonical, alias.canonical))
                        || !canonical_source(self, source.group, source.relative, alias.path) { return false; }
                }
                SourceDisposition::Directory => if !matches!(source.kind, SourceKindSpec::Directory { .. }) { return false; },
            }
        }
        for (index, archive) in self.archives.iter().enumerate() {
            if archive.component != COMPONENTS[index] || !archive_pin(archive.archive)
                || !archive.official_source.starts_with("https://") || archive.official_source.len() > 2048
                || archive.official_source.bytes().any(|b| b <= b' ' || b == 127)
                || archive.vendor_release.is_empty() || archive.vendor_release.len() > 128
                || archive.members.is_empty() || archive.members.len() != archive.member_count as usize
                || archive.members.len() > policy::ENTRY_LIMIT || archive.expanded_bytes > policy::TOTAL_LIMIT
                || !archive.members.windows(2).all(|w| archive_order(archive.component, w[0].name, w[1].name) == Ordering::Less
                    && (archive.component == Component::Bundletool || parent_spelling(w[0].name, w[1].name))) {
                return false;
            }
            if !match archive.published {
                PublishedChecksum::Sha256(value) => hex(value, 64) && value == archive.archive.sha256,
                PublishedChecksum::Sha1(value) => hex(value, 40),
            } { return false; }
            let mut bytes = 0u64; let mut files = 0usize; let mut aliases = 0usize;
            for (member_index, member) in archive.members.iter().enumerate() {
                if !archive_relative(member.name) { return false; }
                let (mode, expected_kind) = match member.kind {
                    ArchiveKind::Directory { mode } => (mode, 0o040000),
                    ArchiveKind::File { mode, bytes: size, sha256 } => {
                        if size > policy::FILE_LIMIT || !hex(sha256, 64) { return false; }
                        let Some(total) = bytes.checked_add(size) else { return false; }; bytes = total; files += 1;
                        (mode, 0o100000)
                    }
                    ArchiveKind::Alias { mode, target } => {
                        if archive.component != Component::Jdk || target.is_empty() || target.len() > 512 || target.starts_with('/') { return false; }
                        aliases += 1; (mode, 0o120000)
                    }
                };
                if !archive_mode(archive.component, archive.archive.sha256, mode, expected_kind) { return false; }
                let mut path = member.name;
                while let Some((parent, _)) = path.rsplit_once('/') {
                    if let Ok(index) = archive.members.binary_search_by(|m| archive_order(archive.component, m.name, parent)) {
                        if archive.members[index].name != parent
                            || !matches!(archive.members[index].kind, ArchiveKind::Directory { .. }) { return false; }
                    }
                    path = parent;
                }
                match member.disposition {
                    ArchiveDisposition::Picked { source_index } => {
                        let Some(binding) = self.source_bindings.get(source_index as usize) else { return false; };
                        if !matches!(binding.provenance, SourceProvenance::Vendor { archive, member }
                            if archive as usize == index && member as usize == member_index) { return false; }
                    }
                    ArchiveDisposition::SealedSupport(asset) => {
                        if !matches!((archive.component, asset),
                            (Component::Aapt2, SupportAsset::Aapt2OsxJar) | (Component::Bundletool, SupportAsset::BundletoolJar)) { return false; }
                    }
                    ArchiveDisposition::WrapperDirectory => if !wrapper_directory(self, archive, member) { return false; },
                }
            }
            if bytes != archive.expanded_bytes || files > policy::FILE_COUNT || aliases > policy::ALIAS_COUNT { return false; }
        }
        if !self.source_directory_closure() { return false; }
        for support in self.support {
            let component = match support.asset { SupportAsset::BundletoolJar => Component::Bundletool, SupportAsset::Aapt2OsxJar => Component::Aapt2 };
            let Some(archive) = self.archives.iter().find(|a| a.component == component) else { return false; };
            if !modes(support.modes) || support.archive != archive.archive { return false; }
        }
        if !support_manifest_matches(self) { return false; }
        let projected = self.support_members[0];
        let Some(support) = self.support.iter().find(|s| s.asset == projected.asset) else { return false; };
        if !zip_member(projected.member, support.archive) { return false; }
        let Some(aapt_archive) = self.archives.iter().find(|a| a.component == Component::Aapt2) else { return false; };
        if !aapt_archive.members.iter().any(|m| m.name == projected.member.name
            && matches!(m.kind, ArchiveKind::File { bytes, sha256, .. } if bytes == projected.member.bytes && sha256 == projected.member.sha256)) { return false; }
        let mut total = 0u64; let mut bundletool = 0usize; let mut aapt2 = 0usize;
        for (ordinal, payload) in self.payload.iter().enumerate() {
            let file = &payload.installed;
            if !policy::relative(file.path) || !hex(file.sha256, 64) || file.size > policy::FILE_LIMIT
                || !matches!(file.mode, 0o444 | 0o555) { return false; }
            let Some(sum) = total.checked_add(file.size) else { return false; }; total = sum;
            match payload.origin {
                PayloadOrigin::CompiledSdkMetadata(kind) => {
                    if !matches!(self.classes[ordinal], FileClass::Data)
                        || !self.compiled_metadata_origin(kind, file) { return false; }
                }
                PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) => {
                    let Some(index) = source_index(self, group, relative) else { return false; };
                    if !source_file(&self.source_members[index], file)
                        || !matches!(self.source_bindings[index].disposition, SourceDisposition::Payload(value) if value as usize == ordinal) {
                        return false;
                    }
                }
                PayloadOrigin::DirectOriginal(OriginalSource::Support(asset)) => {
                    if asset != SupportAsset::BundletoolJar || file.path != self.roles.bundletool || file.mode != 0o444 { return false; }
                    let Some(support) = self.support.iter().find(|s| s.asset == asset) else { return false; };
                    if file.size != support.archive.bytes || file.sha256 != support.archive.sha256 { return false; }
                    bundletool += 1;
                }
                PayloadOrigin::MemberOfSameOriginalArchive { asset, archive, member } => {
                    if asset != SupportAsset::Aapt2OsxJar || file.path != policy::AAPT2 || file.mode != 0o555
                        || self.support[1].archive != archive || projected.member != member
                        || file.size != member.bytes || file.sha256 != member.sha256 { return false; }
                    aapt2 += 1;
                }
            }
            if (file.path.ends_with(".jar") || file.path.ends_with(".jmod"))
                && !matches!(self.classes[ordinal], FileClass::JvmArchive { .. }) { return false; }
            if (file.path.ends_with(".dylib") || file.path.ends_with(".jnilib"))
                && !matches!(self.classes[ordinal], FileClass::MachO(_) | FileClass::SdkLegacyIntel(_, _)) { return false; }
            if let Some(kind) = policy::sdk35_reserved(file.path) {
                let exact_class = match &self.classes[ordinal] {
                    FileClass::SdkBash(actual) => *actual == kind && kind.script(),
                    FileClass::SdkLegacyIntel(actual, _) => *actual == kind && kind.legacy() && !kind.script(),
                    _ => false,
                };
                if !exact_class || !self.sdk_original(file, kind) { return false; }
            }
            if native_profile::target_elf_reserved(file.path).is_some()
                && !matches!(self.classes[ordinal], FileClass::AndroidTargetElf) { return false; }
            if file.path == native_profile::GRADLE_BAT.path
                && !matches!(self.classes[ordinal], FileClass::GradleForeignLauncher) { return false; }
            if self.archives[0].archive.sha256 == JDK17_ARCHIVE_SHA && file.path.starts_with("jdk/") {
                if let Some(pin) = native_profile::jdk_native(native_profile::jdk_relative(file.path).unwrap_or("")) {
                    let FileClass::MachO(header) = &self.classes[ordinal] else { return false; };
                    if !pin.matches(file.path, file.size, file.sha256, file.mode)
                        || !native_snapshot_matches(header, &pin.header) || !self.jdk_original(file, pin.original_mode) { return false; }
                } else if matches!(self.classes[ordinal], FileClass::MachO(_)) { return false; }
                if native_profile::jdk_jvm_archive(file.path).is_some() && !self.jdk_original(file, 0o644) { return false; }
            }
            // No generic "strip execute" disposition hides an unknown script.
            match &self.classes[ordinal] {
                FileClass::Data if file.mode != 0o444 => return false,
                FileClass::LicenseText => {
                    let name = file.path.rsplit('/').next().unwrap_or("");
                    if file.mode != 0o444 || !matches!(name, "NOTICE" | "LICENSE" | "LICENSE.txt" | "NOTICE.txt") { return false; }
                }
                FileClass::GradleShell if file.path != self.roles.gradle || file.mode != 0o555 => return false,
                FileClass::GradleForeignLauncher if !self.gradle_foreign_original(file) => return false,
                FileClass::AndroidTargetElf if !self.target_original(file) => return false,
                FileClass::SdkBash(kind) if !kind.script() || !self.sdk_original(file, *kind) => return false,
                FileClass::SdkLegacyIntel(kind, _) if kind.script() || !kind.legacy() || !self.sdk_original(file, *kind) => return false,
                FileClass::JvmArchive { native_members } => {
                    if file.mode != 0o444 || !(file.path.ends_with(".jar") || file.path.ends_with(".jmod")) || native_members.len() > 128
                        || !native_members.windows(2).all(|w| folded(w[0].member, w[1].member) == Ordering::Less)
                        || native_members.iter().any(|n| !archive_relative(n.member) || n.bytes == 0
                            || n.bytes > policy::FILE_LIMIT || !hex(n.sha256, 64) || n.mode & !0o170777 != 0)
                        || !native_members_match(file, native_members) { return false; }
                    if native_archive(file.path).is_some() && file.path.starts_with("gradle/")
                        && (self.versions.gradle_version != "8.14.5" || self.gradle_distribution_sha256 != GRADLE_ARCHIVE_SHA) { return false; }
                }
                _ => {}
            }
        }
        if total > policy::TOTAL_LIMIT || bundletool != 1 || aapt2 != 1
            || !self.compiled_metadata_pair() { return false; }
        if self.archives[2].archive.sha256 == policy::SDK35_ARCHIVE_SHA
            && policy::SDK35_PINS.iter().any(|pin| !self.payload.iter().any(|p|
                pin.matches(p.installed.path, p.installed.size, p.installed.sha256, p.installed.mode))) { return false; }
        if self.archives[2].archive.sha256 == policy::SDK35_ARCHIVE_SHA
            && native_profile::SDK_TARGET_ELFS.iter().any(|pin| !self.payload.iter().any(|p|
                pin.matches(p.installed.path, p.installed.size, p.installed.sha256, p.installed.mode))) { return false; }
        if self.gradle_distribution_sha256 == GRADLE_ARCHIVE_SHA
            && !self.payload.iter().any(|p| self.gradle_foreign_original(&p.installed)) { return false; }
        if self.archives[0].archive.sha256 == JDK17_ARCHIVE_SHA {
            if native_profile::JDK_NATIVE.iter().any(|pin| !self.payload.iter().any(|p|
                pin.matches(p.installed.path, p.installed.size, p.installed.sha256, p.installed.mode)))
                || native_profile::JDK_JVM_ARCHIVES.iter().any(|pin| !self.payload.iter().any(|p|
                    native_profile::jdk_relative(p.installed.path) == Some(pin.relative)
                        && p.installed.size == pin.bytes && p.installed.sha256 == pin.sha256 && p.installed.mode == 0o444)) { return false; }
            for (relative, bytes, sha256) in [
                ("Contents/Home/release", 1638, "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b"),
                ("Contents/Home/lib/jvm.cfg", 29, "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0"),
            ] {
                if !self.payload.iter().any(|p| native_profile::jdk_relative(p.installed.path) == Some(relative)
                    && p.installed.size == bytes && p.installed.sha256 == sha256 && p.installed.mode == 0o444
                    && self.jdk_original(&p.installed, 0o644)) { return false; }
            }
        }
        if self.gradle_distribution_sha256 == GRADLE_ARCHIVE_SHA
            && NATIVE_ARCHIVES.iter().filter(|a| a.path.starts_with("gradle/")).any(|a|
                !self.payload.iter().any(|p| p.installed.path == a.path && p.installed.size == a.bytes
                    && p.installed.sha256 == a.sha256)) { return false; }
        for alias in self.aliases {
            let Some(source) = self.source_members.get(alias.source_index as usize) else { return false; };
            if !matches!(source.kind, SourceKindSpec::Alias { target, .. } if target == alias.target)
                || !policy::relative(alias.path) || !policy::relative(alias.canonical) { return false; }
        }
        // Every actual prefix must already be in the static closure BEFORE
        // the validator allocates a tree; an undersized directory budget cannot
        // be discovered only after that allocation. All checks here borrow.
        for path in self.payload.iter().map(|p| p.installed.path).chain(self.aliases.iter().map(|a| a.path)) {
            let mut part = path;
            while let Some((parent, _)) = part.rsplit_once('/') {
                if self.directories.binary_search(&parent).is_err() { return false; }
                part = parent;
            }
        }
        for directory in self.directories {
            if !policy::relative(directory) { return false; }
            let under = |path: &str| path.strip_prefix(directory).is_some_and(|tail| tail.starts_with('/'));
            // Lower-bound against directory+"/" without allocating a String.
            let file = self.payload.partition_point(|p| p.installed.path.bytes()
                .cmp(directory.bytes().chain(std::iter::once(b'/'))) == Ordering::Less);
            let alias = self.aliases.partition_point(|a| a.path.bytes()
                .cmp(directory.bytes().chain(std::iter::once(b'/'))) == Ordering::Less);
            if !self.payload.get(file).is_some_and(|p| under(p.installed.path))
                && !self.aliases.get(alias).is_some_and(|a| under(a.path)) { return false; }
        }
        true
    }

    fn matches_inventory(&self, inventory: &Inventory) -> bool {
        let data = &inventory.data; let v = &data.versions; let r = &data.roles;
        self.structural()
            && (v.jdk_vendor.as_str(), v.jdk_version.as_str(), v.gradle_version.as_str(), v.agp_version.as_str(),
                v.sdk_platform.as_str(), v.sdk_platform_revision.as_str(), v.sdk_build_tools_version.as_str())
                == (self.versions.jdk_vendor, self.versions.jdk_version, self.versions.gradle_version, self.versions.agp_version,
                    self.versions.sdk_platform, self.versions.sdk_platform_revision, self.versions.sdk_build_tools_version)
            && (r.java.as_str(), r.javac.as_str(), r.gradle.as_str(), r.bundletool.as_str(), r.sdk.as_str())
                == (self.roles.java, self.roles.javac, self.roles.gradle, self.roles.bundletool, self.roles.sdk)
            && data.gradle_distribution.url == self.gradle_distribution_url
            && data.gradle_distribution.sha256 == self.gradle_distribution_sha256
            && data.files.len() == self.payload.len()
            && data.files.iter().zip(self.payload).all(|(actual, row)| actual.path == row.installed.path
                && actual.size == row.installed.size && actual.sha256 == row.installed.sha256 && actual.mode == row.installed.mode)
            && data.aliases.len() == self.aliases.len()
            && data.aliases.iter().zip(self.aliases).all(|(actual, row)|
                actual.path == row.path && actual.target == row.target && actual.canonical == row.canonical)
            && inventory.directories.len() == self.directories.len()
            && inventory.directories.iter().map(String::as_str).eq(self.directories.iter().copied())
            && self.native_closure(inventory)
    }

    fn native_closure(&self, inventory: &Inventory) -> bool {
        for (file, class) in self.payload.iter().zip(self.classes) {
            match class {
                FileClass::MachO(header) => {
                    let Some(commands) = native_header(header, file.installed.size) else { return false; };
                    if self.archives.first().is_some_and(|archive| archive.archive.sha256 == JDK17_ARCHIVE_SHA)
                        && file.installed.path.starts_with("jdk/") {
                        let Some(pin) = native_profile::jdk_native(native_profile::jdk_relative(file.installed.path).unwrap_or("")) else { return false; };
                        if !pin.header.snapshot(header.prefix, &commands) { return false; }
                    }
                    if !policy::local_loads(file.installed.path, &commands, inventory) { return false; }
                }
                FileClass::SdkLegacyIntel(kind, header) => {
                    if kind.script() || !kind.legacy() || !self.sdk_original(&file.installed, *kind) { return false; }
                    let Some(commands) = native_header_for(header, file.installed.size, policy::MachArchitecture::X86_64) else { return false; };
                    if !policy::local_loads(file.installed.path, &commands, inventory) { return false; }
                }
                FileClass::JvmArchive { native_members } => {
                    if !native_members_match(&file.installed, native_members) { return false; }
                    for member in *native_members {
                        if let Some(archive) = native_profile::jdk_jvm_archive(file.installed.path) {
                            let Some(expected) = archive.members.iter().find(|p| p.member == member.member) else { return false; };
                            let Some(header) = &member.header else { return false; };
                            let Some(commands) = native_header(header, member.bytes) else { return false; };
                            if !expected.header().is_some_and(|pin| pin.snapshot(header.prefix, &commands)) { return false; }
                            if let Some(relative) = expected.counterpart {
                                // The JMOD and its installed counterpart belong to
                                // the same retained bundle, not a hash-only search.
                                let Some(bundle) = file.installed.path.strip_suffix(archive.relative) else { return false; };
                                let Some(pin) = native_profile::jdk_native(relative) else { return false; };
                                let Some(counterpart) = inventory.data.files.iter().find(|f|
                                    f.path.strip_prefix(bundle) == Some(relative)) else { return false; };
                                if counterpart.size != member.bytes || counterpart.sha256 != member.sha256
                                    || !pin.matches(&counterpart.path, counterpart.size, &counterpart.sha256, counterpart.mode)
                                    || !policy::local_loads(&counterpart.path, &commands, inventory) { return false; }
                            } else if !commands.loads.iter().all(|p| policy::system_load(p))
                                || !commands.rpaths.iter().all(|p| policy::OS_ROOTS.contains(&p.as_str()) || policy::system_load(p)) { return false; }
                            continue;
                        }
                        // A no-header resource has already matched the complete
                        // finite foreign tuple, not a path or caller flag.
                        let Some(header) = &member.header else { continue; };
                        let Some(commands) = native_header(header, member.bytes) else { return false; };
                        // Extracted current-platform natives keep their actual
                        // system-only loader proof; no external provider is added.
                        if !commands.loads.iter().all(|p| policy::system_load(p))
                            || !commands.rpaths.iter().all(|p| policy::OS_ROOTS.contains(&p.as_str()) || policy::system_load(p)) { return false; }
                    }
                }
                _ => {}
            }
        }
        true
    }
}
struct ReferenceDigest { count: usize, hash: Sha256 }
impl std::io::Write for ReferenceDigest {
    fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
        self.count = self.count.checked_add(value.len()).filter(|n| *n <= REFERENCE_STREAM_BYTES)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        self.hash.update(value); Ok(value.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn reference_digest(reference: &Reference) -> Option<[u8; 32]> {
    let mut writer = ReferenceDigest { count: 0, hash: Sha256::new() };
    std::io::Write::write_all(&mut writer, b"mrk-macos-android-canonical-supplier-reference-v3\0").ok()?;
    // Bind full compiled provenance and the fixed optional observation contract,
    // not only enum identities. Generated XML bytes have exact document pins.
    serde_json::to_writer(&mut writer, &(reference, &sdk_metadata::OPTIONAL,
        [sdk_metadata::compiled_sdk_metadata(SdkMetadataKind::Platform35Revision2),
         sdk_metadata::compiled_sdk_metadata(SdkMetadataKind::BuildTools35)],
         native_profile::record_authority())).ok()?;
    Some(writer.hash.finalize().into())
}
pub(crate) fn available() -> bool {
    !REFERENCES.is_empty() && REFERENCES.iter().all(|r| r.structural() && reference_digest(r).is_some())
}
/// Pure compiled DATA, not a grant or a second64MiB pool. The app source book
/// adds its concrete layout/capacities and the whole existing caller census.
#[derive(Clone, Copy)]
pub(crate) struct SourceCatalogueBudget {
    pub(crate) storage: SourceStorage,
    pub(crate) proposal_work: usize,
    pub(crate) reproof_work: usize,
}
fn catalogue_budget(catalogue: &[Reference]) -> Result<SourceCatalogueBudget, Failure> {
    let mut maximum: Option<SourceCatalogueBudget> = None;
    for reference in catalogue {
        if !reference.structural() || reference_digest(reference).is_none() { return Err(Failure::Reference); }
        let storage = reference.source_storage().ok_or(Failure::Bounds)?;
        let proposal_work = reference.working_bytes().filter(|n| *n > 0).ok_or(Failure::Bounds)?;
        let reproof_work = fixed_working_bytes().ok_or(Failure::Bounds)?;
        maximum = Some(match maximum {
            Some(previous) => SourceCatalogueBudget { storage: previous.storage.maximum(storage),
                proposal_work: previous.proposal_work.max(proposal_work), reproof_work: previous.reproof_work.max(reproof_work) },
            None => SourceCatalogueBudget { storage, proposal_work, reproof_work },
        });
    }
    maximum.ok_or(Failure::Unavailable)
}
pub(crate) fn source_catalogue_budget() -> Result<SourceCatalogueBudget, Failure> { catalogue_budget(REFERENCES) }
/// Full construction validity remains required even for a read-only reproof.
pub(crate) fn max_working_reservation_bytes() -> Result<usize, Failure> {
    source_catalogue_budget().map(|budget| budget.proposal_work)
}
/// Full tuple/membership is compared in the same predicate used by canonical
/// proposal, Publisher and installed readback. A claimed digest alone cannot
/// admit any inventory, and no file/local report fills REFERENCES.
pub(crate) fn admit(inventory: &Inventory, supplier_record: &[u8; 32]) -> Result<(), SupplierFailure> {
    let mut matches = 0usize;
    for reference in REFERENCES {
        if reference_digest(reference).as_ref() == Some(supplier_record) && reference.matches_inventory(inventory) { matches += 1; }
    }
    if matches == 1 { Ok(()) } else { Err(SupplierFailure::Unavailable) }
}


pub(crate) struct Recipe {
    reference: &'static Reference,
    layout: JdkLayout,
}
fn choose<'a>(catalogue: &'static [Reference], layout: &SourceLayouts<'a>) -> Result<Recipe, Failure> {
    if layout.jdk_vendor.is_empty() || layout.jdk_vendor.len() > 128
        || layout.jdk_version.is_empty() || layout.jdk_version.len() > 64 { return Err(Failure::UnsupportedLayout); }
    let mut chosen = None;
    for reference in catalogue {
        if reference.observed_jdk_vendor == layout.jdk_vendor && reference.observed_jdk_version == layout.jdk_version {
            if chosen.is_some() || !reference.structural() || reference_digest(reference).is_none() { return Err(Failure::Reference); }
            chosen = Some(reference);
        }
    }
    Ok(Recipe { reference: chosen.ok_or(Failure::Unavailable)?, layout: layout.jdk })
}
pub(crate) fn recipe(layout: &SourceLayouts<'_>) -> Result<Recipe, Failure> {
    choose(REFERENCES, layout)
}
impl Recipe {
    /// Exact roster first. The source book must retain the selected roots and
    /// enumerate these complete closures, rejecting unexplained extra entries.
    pub(crate) fn source_roster(&self) -> SourceRoster {
        SourceRoster { trees: self.reference.trees, members: self.reference.source_members,
            support: self.reference.support, archive_members: self.reference.support_members,
            optional_sdk_metadata: &sdk_metadata::OPTIONAL }
    }
    pub(crate) fn jdk_layout(&self) -> JdkLayout { self.layout }
    /// Compiled tuple labels only; never project or renderer compatibility claims.
    pub(crate) fn source_versions(&self) -> [&'static str; 3] {
        [self.reference.versions.jdk_version, self.reference.versions.sdk_build_tools_version,
            self.reference.versions.gradle_version]
    }
    /// DATA reservation, not a new pool/grant. App owner must reserve its actual
    /// simultaneous source/native/Review data PLUS this within the same64MiB.
    pub(crate) fn working_reservation_bytes(&self) -> Result<usize, Failure> {
        self.reference.working_bytes().ok_or(Failure::Bounds)
    }
    pub(crate) fn source_storage(&self) -> Result<SourceStorage, Failure> {
        self.reference.source_storage().ok_or(Failure::Bounds)
    }
    fn observations_match(&self, observations: &SourceObservations<'_>) -> bool {
        let reference = self.reference;
        if observations.members.len() != reference.source_members.len()
            || observations.support.len() != reference.support.len()
            || observations.archive_members.len() != reference.support_members.len()
            || !observations.optional_sdk_metadata.iter().zip(&sdk_metadata::OPTIONAL).all(|(value, spec)|
                value.as_ref().is_none_or(|value| sdk_metadata::observation_valid(spec, value))) { return false; }
        for (observed, expected) in observations.members.iter().zip(reference.source_members) {
            if observed.group != expected.group || observed.relative() != expected.relative { return false; }
            let same = match (observed.kind, expected.kind) {
                (SourceMemberKind::Directory { mode, .. }, SourceKindSpec::Directory { modes }) => modes.contains(&mode),
                (SourceMemberKind::File(file), SourceKindSpec::File { bytes, sha256, modes }) =>
                    file.size == bytes && file.sha256 == sha256 && modes.contains(&file.mode),
                (SourceMemberKind::Alias { data, mode }, SourceKindSpec::Alias { target, canonical, modes }) =>
                    data.target == target && data.canonical == canonical && modes.contains(&mode),
                _ => false,
            };
            if !same { return false; }
        }
        observations.support.iter().zip(reference.support).all(|(actual, expected)|
            actual.asset == expected.asset && actual.archive == expected.archive && expected.modes.contains(&actual.mode))
            && observations.archive_members.iter().zip(reference.support_members).all(|(actual, expected)|
                actual.asset == expected.asset && actual.member == expected.member)
    }
    /// Non-authorizing proposal only. Same original identity/custody, current
    /// acknowledgement, source-consent binding and original deadline/finality
    /// remain mandatory in the app before actual service admission/Hello.
    pub(crate) fn finalize_proposal(&self, instance: &str, account: u32,
        observations: &SourceObservations<'_>, os_provider_files: &[FileSpec]) -> Result<ProposalDocuments, Failure> {
        self.working_reservation_bytes()?;
        if account == 0 || account == u32::MAX || !hex(instance, 32) || !self.observations_match(observations) {
            return Err(Failure::SourceMismatch);
        }
        if os_provider_files.len() != policy::OS_FILES.len() { return Err(Failure::Metadata); }
        let payload_bytes = self.reference.payload.iter().try_fold(0u64, |sum, value| sum.checked_add(value.installed.size))
            .ok_or(Failure::Bounds)?;
        let provider_bytes = os_provider_files.iter().try_fold(0u64, |sum, file| sum.checked_add(file.size))
            .ok_or(Failure::Bounds)?;
        // Existing Python parse_profile counts BOTH payload and actual OS files.
        if payload_bytes.checked_add(provider_bytes).is_none_or(|n| n > policy::TOTAL_LIMIT) { return Err(Failure::Bounds); }
        let mut os_files = bounded_vec(os_provider_files.len())?;
        for (file, expected) in os_provider_files.iter().zip(policy::OS_FILES) {
            if file.path != expected || !hex(&file.sha256, 64) || file.size == 0 || file.size > policy::FILE_LIMIT {
                return Err(Failure::Metadata);
            }
            os_files.push(FileSpec { path: owned(&file.path)?, size: file.size, sha256: owned(&file.sha256)?, mode: file.mode });
        }
        let provider = policy::proposal_provider(os_files).ok_or(Failure::Metadata)?;
        let provider = policy::encode_provider(&provider).ok_or(Failure::Bounds)?;
        let os_digest = provider.digest_hex();
        let r = self.reference; let v = &r.versions; let role = &r.roles;
        let mut files = bounded_vec(r.payload.len())?;
        for value in r.payload {
            files.push(FileSpec { path: owned(value.installed.path)?, size: value.installed.size,
                sha256: owned(value.installed.sha256)?, mode: value.installed.mode });
        }
        let mut aliases = bounded_vec(r.aliases.len())?;
        for value in r.aliases {
            aliases.push(Alias { path: owned(value.path)?, target: owned(value.target)?, canonical: owned(value.canonical)? });
        }
        let fields = policy::ProposalManifestData {
            versions: Versions { jdk_vendor: owned(v.jdk_vendor)?, jdk_version: owned(v.jdk_version)?,
                gradle_version: owned(v.gradle_version)?, agp_version: owned(v.agp_version)?,
                sdk_platform: owned(v.sdk_platform)?, sdk_platform_revision: owned(v.sdk_platform_revision)?,
                sdk_build_tools_version: owned(v.sdk_build_tools_version)? },
            gradle_distribution: Distribution { url: owned(r.gradle_distribution_url)?, sha256: owned(r.gradle_distribution_sha256)? },
            roles: Roles { java: owned(role.java)?, javac: owned(role.javac)?, gradle: owned(role.gradle)?,
                bundletool: owned(role.bundletool)?, sdk: owned(role.sdk)? },
            files, aliases,
        };
        let inventory = policy::proposal_inventory(fields, instance, &os_digest).ok_or(Failure::Metadata)?;
        if !r.matches_inventory(&inventory) { return Err(Failure::Reference); }
        let supplier_record = reference_digest(r).ok_or(Failure::Bounds)?;
        // Same full-tuple predicate as admit; production r came only from the
        // compiled REFERENCES. Tests use a deliberately separate inert catalogue.
        let manifest = policy::encode_inventory(&inventory).ok_or(Failure::Bounds)?;
        let manifest_hash = manifest.digest_hex();
        let record = policy::encode_registration_proposal(account, instance, &manifest_hash, &os_digest)
            .ok_or(Failure::Metadata)?;
        let metadata_bytes = [manifest.bytes.len(), record.bytes.len(), provider.bytes.len()].into_iter()
            .try_fold(0u64, |sum, n| sum.checked_add(u64::try_from(n).ok()?)).ok_or(Failure::Bounds)?;
        // Publisher content bytes are payload + exact3 metadata, with no OS
        // read bytes mixed into the copied transfer accounting.
        if payload_bytes.checked_add(metadata_bytes).is_none_or(|n| n > policy::TOTAL_LIMIT) { return Err(Failure::Bounds); }
        let entries = r.payload.len().checked_add(r.aliases.len()).and_then(|n| n.checked_add(r.directories.len()))
            .and_then(|n| n.checked_add(3)).ok_or(Failure::Bounds)?;
        if entries > policy::ENTRY_LIMIT { return Err(Failure::Bounds); }
        // Typed inventory and all its validator BTree collections are not part
        // of the returned Review/proposal. No payload body was retained.
        drop(inventory);
        let result = ProposalDocuments { documents: [manifest, record, provider], supplier_record,
            payload: r.payload, payload_bytes, metadata_bytes,
            directory_count: r.directories.len() as u32, alias_count: r.aliases.len() as u32 };
        if result.retained_bytes().is_none_or(|n| n > APP_BYTES) { return Err(Failure::Bounds); }
        Ok(result)
    }
}
fn owned(value: &str) -> Result<String, Failure> {
    if value.len() > 2048 { return Err(Failure::Bounds); }
    let mut output = String::new(); output.try_reserve_exact(value.len()).map_err(|_| Failure::Bounds)?;
    if output.capacity() > value.len().checked_mul(2).ok_or(Failure::Bounds)? { return Err(Failure::Bounds); }
    output.push_str(value); Ok(output)
}
fn bounded_vec<T>(length: usize) -> Result<Vec<T>, Failure> {
    if length > policy::ENTRY_LIMIT { return Err(Failure::Bounds); }
    let mut value = Vec::new(); value.try_reserve_exact(length).map_err(|_| Failure::Bounds)?;
    if value.capacity() > length.checked_mul(2).ok_or(Failure::Bounds)? { return Err(Failure::Bounds); }
    Ok(value)
}
/// Static mapping is borrowed compiled DATA, not owned source paths/payloads.
/// The original app owner separately retains all source/custody/generation
/// evidence and must continue accounting for its simultaneous allocations.
pub(crate) struct ProposalDocuments {
    documents: [policy::CanonicalDocument; 3],
    supplier_record: [u8; 32],
    payload: &'static [PayloadSource],
    payload_bytes: u64,
    metadata_bytes: u64,
    directory_count: u32,
    alias_count: u32,
}
impl ProposalDocuments {
    /// Exact protocol order: manifest, registration proposal, OS provider.
    pub(crate) fn documents(&self) -> [&[u8]; 3] {
        [&self.documents[0].bytes, &self.documents[1].bytes, &self.documents[2].bytes]
    }
    pub(crate) fn hashes(&self) -> [[u8; 32]; 3] {
        [self.documents[0].sha256, self.documents[1].sha256, self.documents[2].sha256]
    }
    pub(crate) fn supplier_record(&self) -> &[u8; 32] { &self.supplier_record }
    pub(crate) fn payload_map(&self) -> &'static [PayloadSource] { self.payload }
    pub(crate) fn payload_bytes(&self) -> u64 { self.payload_bytes }
    pub(crate) fn metadata_bytes(&self) -> u64 { self.metadata_bytes }
    pub(crate) fn directory_count(&self) -> u32 { self.directory_count }
    pub(crate) fn alias_count(&self) -> u32 { self.alias_count }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        // CanonicalDocument inline storage is already part of Self.
        self.documents.iter().try_fold(size_of::<Self>(), |sum, d| sum.checked_add(d.bytes.capacity()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    const HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const BUNDLE_SHA: &str = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29";
    const AAPT_SHA: &str = "5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1";
    const THIN: &[u8] = &[0xcf,0xfa,0xed,0xfe, 0x0c,0,0,1, 0,0,0,0, 2,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
    fn static_slice<T: 'static>(value: Vec<T>) -> &'static [T] { Box::leak(value.into_boxed_slice()) }
    fn static_text(value: String) -> &'static str { Box::leak(value.into_boxed_str()) }
    fn retained(reference: Reference) -> &'static Reference { Box::leak(Box::new(reference)) }
    fn assert_fixture_is_not_compiled(reference: &Reference) {
        let digest = reference_digest(reference).expect("bounded comparison fixture digest");
        assert!(REFERENCES.iter().all(|compiled| reference_digest(compiled) != Some(digest)),
            "comparison fixtures must never be production suppliers");
    }
    fn native_fixture(file: &CanonicalFile) -> &'static [NestedNative] {
        // Exact tuple/roster comparison DATA with deliberately synthetic headers.
        // This is NOT an actual archive-byte/native execution receipt.
        static_slice(native_archive(file.path).map_or_else(Vec::new, |archive| archive.members.iter().map(|pin|
            NestedNative { member: pin.member, bytes: pin.bytes, sha256: pin.sha256, mode: pin.mode, kind: pin.kind,
                header: (pin.kind == NativeResourceKind::Arm64).then_some(NativeHeader { prefix: THIN, commands: THIN }) }
        ).collect()))
    }
    /// Deliberately synthetic comparison DATA; never a production supplier and
    /// never executed or installed. The production catalogue remains separate.
    fn fixture() -> Reference { fixture_with_source_alias(None) }
    fn fixture_with_source_alias(alias: Option<(&'static str, &'static str)>) -> Reference {
        let support = static_slice(vec![
            SupportOriginalSpec { asset: SupportAsset::BundletoolJar,
                archive: ArchivePin { bytes: 32_520_401, sha256: BUNDLE_SHA }, modes: &[0o444] },
            SupportOriginalSpec { asset: SupportAsset::Aapt2OsxJar,
                archive: ArchivePin { bytes: 4_339_472, sha256: AAPT_SHA }, modes: &[0o444] },
        ]);
        let projected = ZipMemberSpec { name: "aapt2", method: ZipMethod::Stored, flags: 0,
            local_header_offset: 0, data_offset: 35, compressed_bytes: 32, bytes: 32, crc32: 0, sha256: HASH };
        let mut payload = vec![
            PayloadSource { installed: CanonicalFile { path: "bundletool/bundletool.jar",
                size: support[0].archive.bytes, sha256: BUNDLE_SHA, mode: 0o444 },
                origin: PayloadOrigin::DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar)) },
            PayloadSource { installed: CanonicalFile { path: policy::AAPT2, size: 32, sha256: HASH, mode: 0o555 },
                origin: PayloadOrigin::MemberOfSameOriginalArchive { asset: SupportAsset::Aapt2OsxJar,
                    archive: support[1].archive, member: projected } },
        ];
        for (group, relative, canonical, mode, size) in [
            (SourceGroup::Gradle, "bin/gradle", "gradle/bin/gradle", 0o555, 32),
            (SourceGroup::Jdk, "Contents/Home/bin/java", "jdk/Test.jdk/Contents/Home/bin/java", 0o555, 32),
            (SourceGroup::Jdk, "Contents/Home/bin/javac", "jdk/Test.jdk/Contents/Home/bin/javac", 0o555, 32),
            (SourceGroup::Jdk, "Contents/Home/bin/jarsigner", "jdk/Test.jdk/Contents/Home/bin/jarsigner", 0o555, 32),
            (SourceGroup::Jdk, "Contents/Home/bin/keytool", "jdk/Test.jdk/Contents/Home/bin/keytool", 0o555, 32),
            (SourceGroup::Sdk, "build-tools/35.0.0/source.properties", "sdk/build-tools/35.0.0/source.properties", 0o444, 1),
            (SourceGroup::Sdk, "platforms/android-35/android.jar", "sdk/platforms/android-35/android.jar", 0o444, 1),
        ] {
            payload.push(PayloadSource { installed: CanonicalFile { path: canonical, size, sha256: HASH, mode },
                origin: PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) });
        }
        payload.sort_by_key(|p| p.installed.path);
        let payload = static_slice(payload);
        let mut sources = Vec::new();
        for file in payload {
            if let PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) = file.origin {
                sources.push(SourceMemberSpec { group, relative, kind: SourceKindSpec::File {
                    bytes: file.installed.size, sha256: file.installed.sha256,
                    modes: if file.installed.mode == 0o555 { &[0o755] } else { &[0o644] },
                }});
                let mut name = relative;
                while let Some((parent, _)) = name.rsplit_once('/') {
                    if group == SourceGroup::Sdk && !parent.contains('/') { break; }
                    sources.push(SourceMemberSpec { group, relative: parent,
                        kind: SourceKindSpec::Directory { modes: &[0o755] } });
                    name = parent;
                }
            }
        }
        if let Some((target, canonical)) = alias {
            sources.push(SourceMemberSpec { group: SourceGroup::Jdk, relative: "Contents/Home/bin/java-link",
                kind: SourceKindSpec::Alias { target, canonical, modes: &[0o777] } });
        }
        sources.sort_by(|a,b| source_order(a.group, a.relative, b));
        sources.dedup_by(|a,b| a.group == b.group && a.relative == b.relative);
        let sources = static_slice(sources);
        let mut members: Vec<Vec<OfficialMember>> = (0..6).map(|_| Vec::new()).collect();
        members[0].push(OfficialMember { name: "Test.jdk", kind: ArchiveKind::Directory { mode: 0o040755 },
            disposition: ArchiveDisposition::WrapperDirectory });
        members[3].push(OfficialMember { name: "gradle-8.14.5", kind: ArchiveKind::Directory { mode: 0o040755 },
            disposition: ArchiveDisposition::WrapperDirectory });
        let mut bindings = Vec::new();
        for (source_index, source) in sources.iter().enumerate() {
            let (archive, name) = match source.group {
                SourceGroup::Jdk => (0, format!("Test.jdk/{}", source.relative)),
                SourceGroup::Gradle => (3, format!("gradle-8.14.5/{}", source.relative)),
                SourceGroup::Sdk if source.relative.starts_with("platforms/") =>
                    (1, source.relative.strip_prefix("platforms/").unwrap().to_string()),
                SourceGroup::Sdk => (2, format!("android-15{}", source.relative.strip_prefix("build-tools/35.0.0").unwrap())),
                SourceGroup::FixedSupport => unreachable!(),
            };
            let kind = match source.kind {
                SourceKindSpec::Directory { .. } => ArchiveKind::Directory { mode: 0o040755 },
                SourceKindSpec::File { bytes, sha256, modes } =>
                    ArchiveKind::File { mode: 0o100000 | modes[0], bytes, sha256 },
                SourceKindSpec::Alias { target, .. } => ArchiveKind::Alias { mode: 0o120777, target },
            };
            members[archive].push(OfficialMember { name: static_text(name), kind,
                disposition: ArchiveDisposition::Picked { source_index: source_index as u32 } });
            let disposition = match source.kind {
                SourceKindSpec::Directory { .. } => SourceDisposition::Directory,
                SourceKindSpec::Alias { .. } => SourceDisposition::Alias(0),
                _ => SourceDisposition::Payload(payload.iter().position(|p|
                    p.origin == PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                        group: source.group, relative: source.relative })).unwrap() as u32),
            };
            bindings.push(SourceBinding { provenance: SourceProvenance::Vendor { archive: archive as u8, member: 0 }, disposition });
        }
        members[4].push(OfficialMember { name: "aapt2", kind: ArchiveKind::File { mode: 0o100755, bytes: 32, sha256: HASH },
            disposition: ArchiveDisposition::SealedSupport(SupportAsset::Aapt2OsxJar) });
        members[5].push(OfficialMember { name: "META-INF/MANIFEST.MF", kind: ArchiveKind::File { mode: 0o100644, bytes: 1, sha256: HASH },
            disposition: ArchiveDisposition::SealedSupport(SupportAsset::BundletoolJar) });
        let packaging = fixed_manifest().unwrap();
        for (notices, archive_index) in [
            (&packaging.archives.0.notices[..], 5usize), (&packaging.archives.1.notices[..], 4),
        ] {
            for notice in notices {
                members[archive_index].push(OfficialMember { name: notice.member,
                    kind: ArchiveKind::File { mode: 0o100644, bytes: notice.size, sha256: notice.sha256 },
                    disposition: ArchiveDisposition::SealedSupport(if archive_index == 5 {
                        SupportAsset::BundletoolJar } else { SupportAsset::Aapt2OsxJar }),
                });
            }
        }
        let mut archives = Vec::new();
        for (index, mut rows) in members.into_iter().enumerate() {
            rows.sort_by(|a,b| archive_order(COMPONENTS[index], a.name, b.name));
            for (member_index, row) in rows.iter().enumerate() {
                if let ArchiveDisposition::Picked { source_index } = row.disposition {
                    bindings[source_index as usize].provenance = SourceProvenance::Vendor {
                        archive: index as u8, member: member_index as u32 };
                }
            }
            let expanded = rows.iter().map(|row| match row.kind { ArchiveKind::File { bytes, .. } => bytes, _ => 0 }).sum();
            let pin = if index == 4 { support[1].archive } else if index == 5 { support[0].archive }
                else { ArchivePin { bytes: 128, sha256: HASH } };
            archives.push(OfficialArchive { component: COMPONENTS[index],
                official_source: if index == 4 { packaging.archives.1.url } else if index == 5 { packaging.archives.0.url }
                    else { "https://example.invalid/inert-fixture-not-a-supplier" },
                vendor_release: "test-only", archive: pin, published: PublishedChecksum::Sha256(pin.sha256),
                member_count: rows.len() as u32, expanded_bytes: expanded, members: static_slice(rows) });
        }
        let aliases = static_slice(sources.iter().enumerate().filter_map(|(source_index, source)| {
            let SourceKindSpec::Alias { target, canonical, .. } = source.kind else { return None; };
            Some(CanonicalAlias { path: static_text(format!("jdk/Test.jdk/{}", source.relative)), target,
                canonical: static_text(format!("jdk/Test.jdk/{canonical}")), source_index: source_index as u32 })
        }).collect());
        let mut directories = std::collections::BTreeSet::new();
        for mut name in payload.iter().map(|p| p.installed.path).chain(aliases.iter().map(|a| a.path)) {
            while let Some((parent, _)) = name.rsplit_once('/') { directories.insert(parent); name = parent; }
        }
        let classes = payload.iter().map(|p| if p.installed.path.ends_with(".jar") {
            FileClass::JvmArchive { native_members: native_fixture(&p.installed) }
        } else if p.installed.path == "gradle/bin/gradle" { FileClass::GradleShell }
        else if p.installed.mode == 0o555 { FileClass::MachO(NativeHeader { prefix: THIN, commands: THIN }) }
        else { FileClass::Data }).collect();
        Reference { profile: crate::android_build_protocol::MAC_TOOLCHAIN_PROFILE,
            observed_jdk_vendor: "test", observed_jdk_version: "17.0.1",
            versions: VersionSpec { jdk_vendor: "test", jdk_version: "17.0.1", gradle_version: "8.14.5", agp_version: "8.9.2",
                sdk_platform: "android-35", sdk_platform_revision: "2", sdk_build_tools_version: "35.0.0" },
            roles: RoleSpec { java: "jdk/Test.jdk/Contents/Home/bin/java", javac: "jdk/Test.jdk/Contents/Home/bin/javac",
                gradle: "gradle/bin/gradle", bundletool: "bundletool/bundletool.jar", sdk: "sdk" },
            gradle_distribution_url: "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip",
            gradle_distribution_sha256: HASH, archives: static_slice(archives),
            trees: &[SourceTree { group: SourceGroup::Jdk, prefix: "" }, SourceTree { group: SourceGroup::Gradle, prefix: "" },
                SourceTree { group: SourceGroup::Sdk, prefix: "platforms/android-35" },
                SourceTree { group: SourceGroup::Sdk, prefix: "build-tools/35.0.0" }],
            source_members: sources, source_bindings: static_slice(bindings), support,
            support_members: static_slice(vec![SupportMemberSpec { asset: SupportAsset::Aapt2OsxJar, member: projected }]),
            payload, classes: static_slice(classes), aliases,
            directories: static_slice(directories.into_iter().collect()) }
    }
    fn observed<T>(r: &Reference, f: impl FnOnce(&SourceObservations<'_>) -> T) -> T {
        let files: Vec<_> = r.source_members.iter().map(|s| {
            let (size, sha, mode) = match s.kind {
                SourceKindSpec::File { bytes, sha256, modes } => (bytes, sha256, modes[0]),
                _ => (0, HASH, 0o755),
            };
            FileSpec { path: s.relative.into(), size, sha256: sha.into(), mode }
        }).collect();
        let aliases: Vec<_> = r.source_members.iter().map(|s| match s.kind {
            SourceKindSpec::Alias { target, canonical, .. } => Some(Alias {
                path: s.relative.into(), target: target.into(), canonical: canonical.into() }),
            _ => None,
        }).collect();
        let members: Vec<_> = r.source_members.iter().zip(&files).zip(&aliases).map(|((s,file),alias)| SourceMemberData { group: s.group,
            kind: match s.kind {
                SourceKindSpec::Directory { modes } => SourceMemberKind::Directory { relative: s.relative, mode: modes[0] },
                SourceKindSpec::File { .. } => SourceMemberKind::File(file),
                SourceKindSpec::Alias { modes, .. } => SourceMemberKind::Alias { data: alias.as_ref().unwrap(), mode: modes[0] },
            }
        }).collect();
        let support: Vec<_> = r.support.iter().map(|s| SupportOriginalData { asset: s.asset, archive: s.archive, mode: s.modes[0] }).collect();
        let projected: Vec<_> = r.support_members.iter().map(|s| SupportMemberData { asset: s.asset, member: s.member }).collect();
        f(&SourceObservations { members: &members, support: &support, archive_members: &projected,
            optional_sdk_metadata: [None, None] })
    }
    // One complete projection shared by the genuine roundtrip and whole-owner
    // budget contract. os_files is explicitly synthetic provider comparison DATA.
    pub(super) fn complete_compiled_observations<T>(r:&Reference,
        f:impl FnOnce(SourceObservations<'_>,&[FileSpec])->T)->T{
        observed(r,|observations|{
            let metadata=[sdk_metadata::compiled_sdk_metadata(SdkMetadataKind::Platform35Revision2),
                sdk_metadata::compiled_sdk_metadata(SdkMetadataKind::BuildTools35)];
            let picked:Vec<_>=metadata.iter().zip(&sdk_metadata::OPTIONAL).map(|(doc,spec)|
                FileSpec{path:spec.relative.into(),size:doc.bytes.len() as u64,
                    sha256:policy::digest(doc.bytes),mode:0o644}).collect();
            let complete=SourceObservations{members:observations.members,support:observations.support,
                archive_members:observations.archive_members,optional_sdk_metadata:[
                    Some(PickedSdkMetadataData{file:&picked[0],contents:metadata[0].bytes}),
                    Some(PickedSdkMetadataData{file:&picked[1],contents:metadata[1].bytes})]};
            let provider=os_files();f(complete,&provider)
        })
    }
    fn implicit_directory(mut r: Reference, group: SourceGroup, relative: &str) -> Reference {
        let index = source_index(&r, group, relative).unwrap();
        let SourceProvenance::Vendor { archive, member } = r.source_bindings[index].provenance else { panic!("fixture directory") };
        let mut archives = r.archives.to_vec();
        let original = archives[usize::from(archive)].members[member as usize];
        assert!(matches!(original.kind, ArchiveKind::Directory { .. }));
        let rows = archives[usize::from(archive)].members.iter().enumerate()
            .filter(|(ordinal, _)| *ordinal != member as usize).map(|(_, row)| *row).collect();
        archives[usize::from(archive)].members = static_slice(rows);
        archives[usize::from(archive)].member_count -= 1;
        let mut bindings = r.source_bindings.to_vec();
        for binding in &mut bindings {
            if let SourceProvenance::Vendor { archive: other, member: ordinal } = &mut binding.provenance {
                if *other == archive && *ordinal > member { *ordinal -= 1; }
            }
        }
        bindings[index].provenance = SourceProvenance::ArchiveParent { archive, prefix: original.name };
        r.archives = static_slice(archives); r.source_bindings = static_slice(bindings); r
    }
    fn change_platform_parent(mut r: Reference, change: impl FnOnce(&mut SourceBinding)) -> Reference {
        let index = source_index(&r, SourceGroup::Sdk, "platforms/android-35").unwrap();
        let mut bindings = r.source_bindings.to_vec(); change(&mut bindings[index]);
        r.source_bindings = static_slice(bindings); r
    }
    fn extra_wrapper_directory(mut r: Reference, archive_index: usize, name: &'static str) -> Reference {
        let mut archives = r.archives.to_vec();
        let archive = &archives[archive_index];
        let mut members = archive.members.to_vec();
        assert!(members.iter().all(|member| archive_order(archive.component, member.name, name) != Ordering::Equal));
        members.push(OfficialMember { name, kind: ArchiveKind::Directory { mode: 0o040755 },
            disposition: ArchiveDisposition::WrapperDirectory });
        members.sort_by(|a, b| archive_order(archive.component, a.name, b.name));
        let mut bindings = r.source_bindings.to_vec();
        for (member_index, member) in members.iter().enumerate() {
            if let ArchiveDisposition::Picked { source_index } = member.disposition {
                assert!(matches!(bindings[source_index as usize].provenance,
                    SourceProvenance::Vendor { archive, .. } if usize::from(archive) == archive_index));
                bindings[source_index as usize].provenance = SourceProvenance::Vendor {
                    archive: u8::try_from(archive_index).unwrap(), member: u32::try_from(member_index).unwrap() };
            }
        }
        archives[archive_index].member_count = u32::try_from(members.len()).unwrap();
        archives[archive_index].members = static_slice(members);
        r.archives = static_slice(archives); r.source_bindings = static_slice(bindings); r
    }
    pub(super) fn implicit_archive_parents_bind_complete_source_closure_data() {
        let original = fixture(); let old_digest = reference_digest(&original).unwrap();
        let mut r = implicit_directory(original, SourceGroup::Sdk, "platforms/android-35");
        assert_eq!(r.archives[1].member_count, 1);
        assert!(r.archives[1].members.iter().all(|m| matches!(m.kind, ArchiveKind::File { .. })));
        assert!(r.structural());
        // SourceSlots still receives the original directory expectations. The
        // provenance correction neither removes them nor supplies observations.
        assert_eq!(r.source_members.as_ptr(), original.source_members.as_ptr());
        assert_eq!(r.working_bytes(), original.working_bytes());
        assert_ne!(reference_digest(&r).unwrap(), old_digest);
        r = implicit_directory(r, SourceGroup::Jdk, "Contents");
        r = implicit_directory(r, SourceGroup::Gradle, "bin");
        assert!(r.structural()); // mixed real headers and necessary implicit parents
        let index = source_index(&r, SourceGroup::Sdk, "platforms/android-35").unwrap();
        let serialized = serde_json::to_string(&r.source_bindings[index]).unwrap();
        assert!(serialized.contains("ArchiveParent") && serialized.contains("android-35"));
        assert!(!serialized.contains("member") && !serialized.contains("mode"));
        assert_fixture_is_not_compiled(&r);
    }
    pub(super) fn implicit_archive_parent_component_prefix_and_bounds_refuse_data() {
        let r = implicit_directory(fixture(), SourceGroup::Sdk, "platforms/android-35");
        for archive in [0, 2, 3, 4, 5, u8::MAX] {
            assert!(!change_platform_parent(r, |b| b.provenance = SourceProvenance::ArchiveParent {
                archive, prefix: "android-35" }).structural());
        }
        for prefix in ["", "android-3", "android-35x", "ANDROID-35", "android-35/orphan",
            static_text("x".repeat(513)), static_text(["x"; 17].join("/"))] {
            let changed = change_platform_parent(r, |b| b.provenance = SourceProvenance::ArchiveParent { archive: 1, prefix });
            assert!(!changed.structural());
            assert_ne!(reference_digest(&changed), reference_digest(&r));
        }
        let mut too_many = r;
        too_many.source_members = static_slice(vec![r.source_members[0]; policy::ENTRY_LIMIT + 1]);
        too_many.source_bindings = static_slice(vec![r.source_bindings[0]; policy::ENTRY_LIMIT + 1]);
        assert!(too_many.working_bytes().is_none());
        assert!(!too_many.structural());
        assert!(r.working_bytes().unwrap() <= APP_BYTES);
    }
    pub(super) fn implicit_archive_parent_cannot_replace_headers_payload_or_observations_data() {
        let explicit = fixture();
        // Keep the real header: derived provenance may not relabel it.
        assert!(!change_platform_parent(explicit, |b| b.provenance = SourceProvenance::ArchiveParent {
            archive: 1, prefix: "android-35" }).source_directory_closure());
        let r = implicit_directory(explicit, SourceGroup::Sdk, "platforms/android-35");
        for disposition in [SourceDisposition::Payload(0), SourceDisposition::Alias(0)] {
            assert!(!change_platform_parent(r, |b| b.disposition = disposition).structural());
        }
        let index = source_index(&r, SourceGroup::Sdk, "platforms/android-35").unwrap();
        let mut changed = r; let mut members = r.source_members.to_vec();
        members[index].kind = SourceKindSpec::Directory { modes: &[0o2755] };
        changed.source_members = static_slice(members); assert!(!changed.structural());
        let mut members = r.source_members.to_vec();
        members[index].kind = SourceKindSpec::File { bytes: 0, sha256: HASH, modes: &[0o644] };
        changed.source_members = static_slice(members); assert!(!changed.source_directory_closure());
        let mut members = r.source_members.to_vec(); members.remove(index);
        let mut bindings = r.source_bindings.to_vec(); bindings.remove(index);
        changed.source_members = static_slice(members); changed.source_bindings = static_slice(bindings);
        assert!(!changed.source_directory_closure()); // selected prefix cannot be omitted
    }
    pub(super) fn implicit_archive_parent_inverse_range_and_case_closure_are_complete_data() {
        let explicit = fixture();
        assert!(explicit.structural());
        // The existing complete fixture already has both genuine outer roots.
        for (index, name) in [(0, "Test.jdk"), (3, "gradle-8.14.5")] {
            let archive = &explicit.archives[index];
            let member = archive.members.iter().find(|member| member.name == name).unwrap();
            assert!(matches!(member.disposition, ArchiveDisposition::WrapperDirectory));
            assert!(wrapper_directory(&explicit, archive, member));
        }
        // Keep every explicit parent and reciprocal Vendor ordinal valid. The
        // old ArchiveParent-only inverse check misses these hidden directories.
        for (index, name) in [(0, "Test.jdk/Contents/unmapped-empty"),
            (3, "gradle-8.14.5/bin/unmapped-empty"), (1, "android-35/unmapped-empty"),
            (2, "android-15/unmapped-empty"), (4, "unmapped-empty"), (5, "unmapped-empty")] {
            let changed = extra_wrapper_directory(explicit, index, name);
            assert_eq!(changed.source_members.as_ptr(), explicit.source_members.as_ptr());
            assert!(changed.source_directory_closure()); // Isolate the additional wrapper rule.
            let archive = &changed.archives[index];
            let member = archive.members.iter().find(|member| member.name == name).unwrap();
            assert!(!wrapper_directory(&changed, archive, member));
            assert!(!changed.structural(), "{name}");
        }
        let r = implicit_directory(explicit, SourceGroup::Sdk, "platforms/android-35");
        let mut changed = r; let mut archives = r.archives.to_vec();
        let mut members = archives[1].members.to_vec();
        members.push(OfficialMember { name: "android-35/unmapped", kind: ArchiveKind::File { mode: 0o100644, bytes: 1, sha256: HASH },
            disposition: ArchiveDisposition::Picked { source_index: source_index(&r, SourceGroup::Gradle, "bin/gradle").unwrap() as u32 } });
        members.sort_by(|a, b| folded(a.name, b.name));
        archives[1].members = static_slice(members); archives[1].member_count += 1; archives[1].expanded_bytes += 1;
        changed.archives = static_slice(archives);
        assert!(!changed.source_directory_closure()); // one correct child is insufficient
        let mut archives = r.archives.to_vec();
        let mut members = archives[1].members.to_vec(); members[0].name = "wrong-root/android.jar";
        archives[1].members = static_slice(members);
        changed = change_platform_parent(r, |b| b.provenance = SourceProvenance::ArchiveParent {
            archive: 1, prefix: "wrong-root" });
        changed.archives = static_slice(archives);
        assert!(!changed.structural()); // even a coherent remap is not this package's mapping
        let parent = source_index(&r, SourceGroup::Sdk, "platforms/android-35").unwrap();
        let mut sources = r.source_members.to_vec(); sources.insert(parent, sources[parent]);
        let mut bindings = r.source_bindings.to_vec(); bindings.insert(parent, bindings[parent]);
        changed = r; changed.source_members = static_slice(sources); changed.source_bindings = static_slice(bindings);
        assert!(!changed.structural()); // no duplicate explicit/derived source row
        let mut sources = r.source_members.to_vec(); sources[parent].relative = "platforms/Android-35";
        changed = r; changed.source_members = static_slice(sources);
        assert!(!changed.structural());
        assert!(!parent_spelling("android-35/Dir/a", "android-35/dir/b"));
        assert!(!parent_spelling("android-35/Dir", "android-35/dir/b"));
        assert!(parent_spelling("android-35/Dir/a", "android-35/Dir/b"));
        assert!(!folded_under("android-350/file", "android-35"));
        assert!(folded_under("android-35/file", "android-35"));
        // A genuine explicit empty directory needs no descendant witness.
        // This focused closure fixture uses the SAME tree/root binding shape,
        // without pretending its reduced rows form a six-component reference.
        let empty_members = static_slice(vec![OfficialMember { name: "android-35", kind: ArchiveKind::Directory { mode: 0o040755 },
            disposition: ArchiveDisposition::Picked { source_index: 0 } }]);
        let mut archives = r.archives.to_vec(); archives[1].members = empty_members; archives[1].member_count = 1; archives[1].expanded_bytes = 0;
        let empty = Reference { archives: static_slice(archives), trees: &[SourceTree { group: SourceGroup::Sdk, prefix: "platforms/android-35" }],
            source_members: &[SourceMemberSpec { group: SourceGroup::Sdk, relative: "platforms/android-35", kind: SourceKindSpec::Directory { modes: &[0o755] } }],
            source_bindings: &[SourceBinding { provenance: SourceProvenance::Vendor { archive: 1, member: 0 }, disposition: SourceDisposition::Directory }], ..r };
        assert!(empty.source_directory_closure());
        assert!(!change_platform_parent(empty, |b| b.provenance = SourceProvenance::ArchiveParent { archive: 1, prefix: "android-35/missing" }).source_directory_closure());
    }
    #[test]
    fn implicit_archive_parents_bind_complete_source_closure() { implicit_archive_parents_bind_complete_source_closure_data(); }
    #[test]
    fn implicit_archive_parent_component_prefix_and_bounds_refuse() { implicit_archive_parent_component_prefix_and_bounds_refuse_data(); }
    #[test]
    fn implicit_archive_parent_cannot_replace_headers_payload_or_observations() { implicit_archive_parent_cannot_replace_headers_payload_or_observations_data(); }
    #[test]
    fn implicit_archive_parent_inverse_range_and_case_closure_are_complete() { implicit_archive_parent_inverse_range_and_case_closure_are_complete_data(); }
    fn os_files() -> Vec<FileSpec> {
        policy::OS_FILES.iter().map(|p| FileSpec { path: (*p).into(), size: 1, sha256: HASH.into(),
            mode: if p.ends_with(".plist") { 0o644 } else { 0o755 } }).collect()
    }


    pub(super) fn canonical_fixture_roundtrips_but_never_enables_production_data() {
        let r = retained(fixture());
        assert!(r.structural());
        let layouts = SourceLayouts { jdk: JdkLayout::Bundle, jdk_vendor: "test", jdk_version: "17.0.1" };
        assert_fixture_is_not_compiled(r);
        assert!(matches!(recipe(&layouts), Err(Failure::Unavailable)));
        let recipe = choose(std::slice::from_ref(r), &layouts).unwrap();
        assert_eq!(recipe.source_roster().members.len(), r.source_members.len());
        assert_eq!(recipe.jdk_layout(), JdkLayout::Bundle);
        assert!(recipe.working_reservation_bytes().unwrap() <= APP_BYTES);
        let instance = "a".repeat(32);
        observed(r, |observations| {
            let result = recipe.finalize_proposal(&instance, 501, observations, &os_files()).unwrap();
            let bytes = result.documents();
            let hashes = result.hashes();
            for (raw, expected) in bytes.iter().zip(hashes) {
                assert_eq!(<[u8;32]>::from(Sha256::digest(raw)), expected);
            }
            let selection = crate::android_build_protocol::MacToolchainSelection {
                instance: instance.clone(), owner_uid: 501, catalog_generation: 1,
                record_sha256: policy::digest(bytes[1]), inventory_sha256: policy::digest(bytes[0]),
                os_provider_sha256: policy::digest(bytes[2]),
            };
            let parsed = policy::parse_manifest(bytes[0], &selection).unwrap();
            assert!(policy::Provider::parse(bytes[2], &selection).is_some());
            assert!(policy::Registration::parse(bytes[1], 501, &instance).unwrap().matches(&selection));
            assert!(r.matches_inventory(&parsed));
            // Even a fixture with matching DATA/commitment is NOT in production.
            assert_eq!(admit(&parsed, result.supplier_record()), Err(SupplierFailure::Unavailable));
            assert_eq!(result.payload_map(), r.payload);
            assert!(std::ptr::eq(result.payload_map(), r.payload)); // Borrow, not an uncharged Vec copy.
            assert_eq!(result.payload_map()[0].installed.path, "bundletool/bundletool.jar");
            assert_eq!(result.payload_bytes(), r.payload.iter().map(|p| p.installed.size).sum::<u64>());
            assert_eq!(result.metadata_bytes(), bytes.iter().map(|v| v.len() as u64).sum::<u64>());
            assert_eq!(result.directory_count() as usize, r.directories.len());
            assert_eq!(result.alias_count(), 0);
            assert!(result.retained_bytes().unwrap() <= recipe.working_reservation_bytes().unwrap());
        });
    }
    pub(super) fn compiled_sdk_metadata_does_not_forge_picked_source_observations_data() {
        let base = fixture();
        let recipe = Recipe { reference: retained(base), layout: JdkLayout::Bundle };
        assert!(std::ptr::eq(recipe.source_roster().optional_sdk_metadata, &sdk_metadata::OPTIONAL));
        observed(&base, |obs| {
            let doc = sdk_metadata::compiled_sdk_metadata(SdkMetadataKind::Platform35Revision2);
            let raw = std::str::from_utf8(doc.bytes).unwrap().replace("xmlns:common=", "xmlns:r=")
                .replace("<common:repository", "<r:repository").replace("</common:repository>", "</r:repository>");
            let picked = FileSpec { path: sdk_metadata::OPTIONAL[0].relative.into(),
                size: raw.len() as u64, sha256: policy::digest(raw.as_bytes()), mode: 0o644 };
            let mut present = SourceObservations { members: obs.members, support: obs.support,
                archive_members: obs.archive_members, optional_sdk_metadata: [
                    Some(PickedSdkMetadataData { file: &picked, contents: raw.as_bytes() }), None] };
            assert!(recipe.observations_match(&present));
            let absent = recipe.finalize_proposal(&"a".repeat(32), 501, obs, &os_files()).unwrap();
            let result = recipe.finalize_proposal(&"a".repeat(32), 501, &present, &os_files()).unwrap();
            assert_eq!(absent.documents(), result.documents());
            assert_eq!(result.payload_map(), absent.payload_map());
            // Presence never changes payload identity. Moving it to the other
            // fixed slot or substituting bytes fails the observation contract.
            present.optional_sdk_metadata.swap(0, 1);
            assert!(!recipe.observations_match(&present));
            present.optional_sdk_metadata = [Some(PickedSdkMetadataData { file: &picked, contents: b"<untrusted/>" }), None];
            assert!(!recipe.observations_match(&present));
        });
        let mut picked_xml = base.source_members.to_vec();
        let at = picked_xml.iter().position(|s| s.group == SourceGroup::Sdk && matches!(s.kind, SourceKindSpec::File { .. })).unwrap();
        picked_xml[at].relative = "build-tools/35.0.0/package.xml";
        let mut fake = base; fake.source_members = static_slice(picked_xml);
        assert!(!fake.structural());

        // A minimal DATA-only provenance fragment exercises the exact original
        // join; it is NOT a full supplier and cannot populate REFERENCES.
        let mut sources = Vec::new(); let mut bindings = Vec::new(); let mut payload = Vec::new();
        for kind in [SdkMetadataKind::BuildTools35, SdkMetadataKind::Platform35Revision2] {
            let doc = sdk_metadata::compiled_sdk_metadata(kind);
            let source_index = sources.len();
            sources.push(SourceMemberSpec { group: SourceGroup::Sdk, relative: doc.source_properties_relative,
                kind: SourceKindSpec::File { bytes: doc.source_properties_bytes, sha256: doc.source_properties_sha256, modes: &[0o644] } });
            bindings.push(SourceBinding { provenance: SourceProvenance::Vendor { archive: (kind.index() + 1) as u8, member: 0 },
                disposition: SourceDisposition::Payload(payload.len() as u32) });
            let path = if kind == SdkMetadataKind::Platform35Revision2 {
                "sdk/platforms/android-35/source.properties" } else { "sdk/build-tools/35.0.0/source.properties" };
            payload.push(PayloadSource { installed: CanonicalFile { path, size: doc.source_properties_bytes,
                sha256: doc.source_properties_sha256, mode: 0o444 }, origin: PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                    group: SourceGroup::Sdk, relative: doc.source_properties_relative }) });
            payload.push(PayloadSource { installed: doc.file, origin: PayloadOrigin::CompiledSdkMetadata(kind) });
            assert_eq!(source_index, 1 - kind.index());
        }
        let archives = base.archives.iter().enumerate().map(|(index, old)| {
            let selected = match index { 1 => Some(SdkMetadataKind::Platform35Revision2), 2 => Some(SdkMetadataKind::BuildTools35), _ => None };
            let (archive, members) = if let Some(kind) = selected {
                let doc = sdk_metadata::compiled_sdk_metadata(kind);
                (doc.input_archive, static_slice(vec![OfficialMember { name: doc.source_properties_member,
                    kind: ArchiveKind::File { mode: 0o100644, bytes: doc.source_properties_bytes, sha256: doc.source_properties_sha256 },
                    disposition: ArchiveDisposition::Picked { source_index: (1 - kind.index()) as u32 } }]))
            } else { (old.archive, old.members) };
            OfficialArchive { component: old.component, official_source: old.official_source, vendor_release: old.vendor_release,
                archive, published: PublishedChecksum::Sha256(archive.sha256), member_count: members.len() as u32,
                expanded_bytes: old.expanded_bytes, members }
        }).collect();
        let mut exact = base; exact.source_members = static_slice(sources); exact.source_bindings = static_slice(bindings);
        exact.archives = static_slice(archives); exact.payload = static_slice(payload);
        assert!(exact.compiled_metadata_pair());
        assert_ne!(reference_digest(&exact), reference_digest(&base));
        for kind in [SdkMetadataKind::Platform35Revision2, SdkMetadataKind::BuildTools35] {
            let doc = sdk_metadata::compiled_sdk_metadata(kind);
            assert!(exact.compiled_metadata_origin(kind, &doc.file));
            assert!(!exact.compiled_metadata_origin(kind, &CanonicalFile { sha256: HASH, ..doc.file }));
            assert!(!exact.compiled_metadata_origin(kind, &CanonicalFile { mode: 0o644, ..doc.file }));
        }
        let mut wrong_sources = exact.source_members.to_vec();
        wrong_sources[0].kind = SourceKindSpec::File { bytes: 63, sha256: HASH, modes: &[0o644] };
        let mut wrong = exact; wrong.source_members = static_slice(wrong_sources);
        assert!(!wrong.compiled_metadata_pair());
        wrong = exact; wrong.payload = &exact.payload[1..];
        assert!(!wrong.compiled_metadata_pair());
        let mut replaced = exact.payload.to_vec();
        replaced[1].origin = PayloadOrigin::DirectOriginal(OriginalSource::Picked {
            group: SourceGroup::Sdk, relative: "build-tools/35.0.0/package.xml" });
        wrong = exact; wrong.payload = static_slice(replaced);
        assert!(!wrong.compiled_metadata_pair());
        assert_fixture_is_not_compiled(&exact);
    }
    #[test]
    fn compiled_sdk_metadata_does_not_forge_picked_source_observations() {
        compiled_sdk_metadata_does_not_forge_picked_source_observations_data();
    }
    pub(super) fn complete_observations_and_provider_budget_are_required_data() {
        let r = retained(fixture());
        let recipe = Recipe { reference: r, layout: JdkLayout::HomeInSameBundle };
        observed(r, |obs| {
            assert!(recipe.observations_match(obs));
            let missing = SourceObservations { members: &obs.members[1..], support: obs.support,
                archive_members: obs.archive_members, optional_sdk_metadata: [None, None] };
            assert!(!recipe.observations_match(&missing));
            let mut members = obs.members.to_vec(); members.swap(0, 1);
            let mut changed = SourceObservations { members: &members, support: obs.support,
                archive_members: obs.archive_members, optional_sdk_metadata: [None, None] };
            assert!(!recipe.observations_match(&changed));
            let mut duplicate = obs.members.to_vec(); duplicate.push(obs.members[0]);
            changed.members = &duplicate;
            assert!(!recipe.observations_match(&changed));
            let index = obs.members.iter().position(|s| matches!(s.kind, SourceMemberKind::File(_))).unwrap();
            let SourceMemberKind::File(file) = obs.members[index].kind else { unreachable!() };
            let mut wrong_file = file.clone(); wrong_file.sha256 = "f".repeat(64);
            let mut wrong = obs.members.to_vec();
            wrong[index].kind = SourceMemberKind::File(&wrong_file);
            changed.members = &wrong;
            assert!(!recipe.observations_match(&changed));
            let mut projected = obs.archive_members.to_vec();
            projected[0].member.data_offset += 1;
            changed.members = obs.members;
            changed.archive_members = &projected;
            assert!(!recipe.observations_match(&changed));
            let mut fixed = obs.support.to_vec(); fixed[0].archive.bytes += 1;
            changed.archive_members = obs.archive_members;
            changed.support = &fixed;
            assert!(!recipe.observations_match(&changed));
            let mut provider = os_files();
            provider[0].size = policy::FILE_LIMIT; provider[1].size = policy::FILE_LIMIT;
            assert!(matches!(recipe.finalize_proposal(&"a".repeat(32), 501, obs, &provider), Err(Failure::Bounds)));
            assert!(matches!(recipe.finalize_proposal(&"a".repeat(32), 0, obs, &os_files()), Err(Failure::SourceMismatch)));
        });
    }
    pub(super) fn incomplete_reference_mapping_namespace_and_stream_bounds_refuse_data() {
        let r = fixture();
        assert!(r.structural());
        // Start from a complete reciprocal inert alias reference, not a
        // missing-binding negative. No real supplier or native link is used.
        let linked = retained(fixture_with_source_alias(Some(("java", "Contents/Home/bin/java"))));
        assert!(linked.structural());
        assert_eq!(linked.aliases.len(), 1);
        let linked_recipe = Recipe { reference: linked, layout: JdkLayout::Bundle };
        observed(linked, |observations| {
            assert!(linked_recipe.observations_match(observations));
            assert!(linked_recipe.finalize_proposal(&"a".repeat(32), 501, observations, &os_files()).is_ok());
        });
        for (target, canonical) in [
            ("missing", "Contents/Home/bin/missing"),
            ("..", "Contents/Home"),
            ("java-link", "Contents/Home/bin/java-link"),
            ("../../../build-tools/35.0.0/source.properties", "build-tools/35.0.0/source.properties"),
            ("JAVA", "Contents/Home/bin/JAVA"),
        ] {
            let wrong = fixture_with_source_alias(Some((target, canonical)));
            let index = source_index(&wrong, SourceGroup::Jdk, "Contents/Home/bin/java-link").unwrap();
            assert!(policy::jdk_source_alias_resolves(wrong.source_members[index].relative, target, canonical));
            assert!(matches!(wrong.source_bindings[index].disposition, SourceDisposition::Alias(0)));
            assert_eq!(wrong.aliases[0].source_index as usize, index);
            assert!(canonical_source(&wrong, SourceGroup::Jdk, canonical, wrong.aliases[0].canonical));
            assert!(!wrong.structural(), "{canonical}"); // Missing/nonregular/other-group/exact-case canonical.
        }
        let mut bad = r;
        bad.directories = &r.directories[1..];
        assert!(!bad.structural()); // Closure checked BEFORE validator growth.
        let mut paths = r.payload.to_vec();
        paths[0].installed.sha256 = HASH;
        bad = r; bad.payload = static_slice(paths);
        assert!(!bad.structural()); // Fixed original no longer corresponds.
        let mut sources = r.source_members.to_vec();
        sources[0].relative = "Contents/../foreign";
        bad = r; bad.source_members = static_slice(sources);
        assert!(!bad.structural());
        let mut classes: Vec<_> = r.payload.iter().map(|_| FileClass::Data).collect();
        classes[0] = FileClass::JvmArchive { native_members: &[] };
        bad = r; bad.classes = static_slice(classes);
        assert!(!bad.structural()); // Scripts/native modes cannot become DATA.
        assert!(archive_relative("com/example/Entry$Inner.class"));
        assert!(!policy::relative("com/example/Entry$Inner.class"));
        for name in ["../Entry.class", "/Entry.class", "C:/Entry.class", "x\\Entry.class", "x//Entry.class", "x/./Entry.class"] {
            assert!(!archive_relative(name));
        }
        let mut writer = ReferenceDigest { count: REFERENCE_STREAM_BYTES - 1, hash: Sha256::new() };
        assert!(std::io::Write::write_all(&mut writer, b"xx").is_err());
        assert!(reference_digest(&r).is_some());
        let changed = Reference { gradle_distribution_sha256: BUNDLE_SHA, ..r };
        assert_ne!(reference_digest(&r), reference_digest(&changed));
        let duplicate = static_slice(vec![r, r]);
        assert!(matches!(choose(duplicate, &SourceLayouts { jdk: JdkLayout::Bundle,
            jdk_vendor: "test", jdk_version: "17.0.1" }), Err(Failure::Reference)));
    }

    pub(super) fn exact_native_resource_rosters_cannot_be_reclassified_or_omitted_data() {
        // Isolated source/archive comparisons, not a fabricated full supplier.
        for pin in policy::SDK35_PINS {
            let mut archive = OfficialArchive { component: Component::SdkBuildTools,
                official_source: "https://example.invalid/inert-comparison", vendor_release: "inert",
                archive: ArchivePin { bytes: policy::SDK35_ARCHIVE_BYTES, sha256: policy::SDK35_ARCHIVE_SHA },
                published: PublishedChecksum::Sha256(policy::SDK35_ARCHIVE_SHA), member_count: 1,
                expanded_bytes: pin.bytes, members: &[] };
            let mut member = OfficialMember { name: pin.member, kind: ArchiveKind::File {
                mode: 0o100000 | pin.original_mode, bytes: pin.bytes, sha256: pin.sha256 },
                disposition: ArchiveDisposition::Picked { source_index: 0 } };
            let mut source = SourceMemberSpec { group: SourceGroup::Sdk, relative: pin.path.strip_prefix("sdk/").unwrap(),
                kind: SourceKindSpec::File { bytes: pin.bytes, sha256: pin.sha256, modes: static_slice(vec![pin.original_mode]) } };
            assert!(sdk_source_matches(&archive, &member, &source, &pin));
            archive.archive.sha256 = HASH;
            assert!(!sdk_source_matches(&archive, &member, &source, &pin));
            archive.archive.sha256 = policy::SDK35_ARCHIVE_SHA;
            member.name = "android-15/unlisted";
            assert!(!sdk_source_matches(&archive, &member, &source, &pin));
            member.name = pin.member;
            member.kind = ArchiveKind::File { mode: 0o100444, bytes: pin.bytes, sha256: pin.sha256 };
            assert!(!sdk_source_matches(&archive, &member, &source, &pin));
            member.kind = ArchiveKind::File { mode: 0o100000 | pin.original_mode, bytes: pin.bytes, sha256: pin.sha256 };
            source.kind = SourceKindSpec::File { bytes: pin.bytes, sha256: pin.sha256, modes: &[0o444] };
            assert!(!sdk_source_matches(&archive, &member, &source, &pin));
        }
        assert_eq!(NATIVE_ARCHIVES.len(), 17);
        assert_eq!(NATIVE_ARCHIVES.iter().map(|a| a.members.len()).sum::<usize>(), 74);
        for archive in NATIVE_ARCHIVES {
            let file = CanonicalFile { path: archive.path, size: archive.bytes, sha256: archive.sha256, mode: 0o444 };
            let members = native_fixture(&file);
            assert!(native_members_match(&file, members));
            assert!(!native_members_match(&file, &members[1..]));
            let mut extra = members.to_vec(); extra.push(members[0]);
            assert!(!native_members_match(&file, &extra));
            for changed_file in [CanonicalFile { size: file.size + 1, ..file },
                CanonicalFile { sha256: HASH, ..file }, CanonicalFile { mode: 0o555, ..file }] {
                assert!(!native_members_match(&changed_file, members));
            }
            for mutation in 0..6 {
                let mut changed = members.to_vec();
                match mutation {
                    0 => changed[0].member = "wrong/native.dylib",
                    1 => changed[0].bytes += 1,
                    2 => changed[0].sha256 = HASH,
                    3 => changed[0].mode ^= 1,
                    4 => changed[0].kind = if changed[0].kind == NativeResourceKind::Arm64 {
                        NativeResourceKind::OtherPlatformElf } else { NativeResourceKind::Arm64 },
                    _ => changed[0].header = if changed[0].header.is_some() { None }
                        else { Some(NativeHeader { prefix: THIN, commands: THIN }) },
                }
                assert!(!native_members_match(&file, &changed), "{} {mutation}", file.path);
            }
            if members.iter().any(|m| m.kind != NativeResourceKind::Arm64) {
                assert!(!native_members_match(&CanonicalFile { path: "gradle/lib/unlisted.jar", ..file }, members));
            }
        }
        // The existing canonical fixture carries the complete known bundletool
        // roster; omitting it is not harmless just because the outer hash matches.
        let r = fixture(); assert!(r.structural());
        let mut classes: Vec<_> = r.payload.iter().map(|p| if p.installed.path.ends_with(".jar") {
            FileClass::JvmArchive { native_members: native_fixture(&p.installed) }
        } else if p.installed.path == r.roles.gradle { FileClass::GradleShell }
        else if p.installed.mode == 0o555 { FileClass::MachO(NativeHeader { prefix: THIN, commands: THIN }) }
        else { FileClass::Data }).collect();
        classes[0] = FileClass::JvmArchive { native_members: &[] };
        assert!(!Reference { classes: static_slice(classes), ..r }.structural());
        assert_eq!(max_working_reservation_bytes(), Err(Failure::Unavailable));
        let recipe = Recipe { reference: retained(r), layout: JdkLayout::Bundle };
        assert_eq!(recipe.source_versions(), ["17.0.1", "35.0.0", "8.14.5"]);
    }

// Genuine captured header SOURCE only; not an original read or native-run receipt.
    const JMOD_MANAGEMENT_PREFIX: &[u8] = &[
        207, 250, 237, 254, 12, 0, 0, 1, 0, 0, 0, 0, 6, 0, 0, 0, 18, 0, 0, 0, 168, 5, 0, 0, 133, 0, 16, 0, 0, 0, 0, 0,
        25, 0, 0, 0, 216, 1, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0,
        5, 0, 0, 0, 0, 0, 0, 0, 95, 95, 116, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 52, 62, 0, 0, 0, 0, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0, 52, 62, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 115, 116, 117, 98, 115, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 63, 0, 0, 0, 0, 0, 0,
        48, 0, 0, 0, 0, 0, 0, 0, 24, 63, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 128, 0, 0, 0, 0,
        12, 0, 0, 0, 0, 0, 0, 0, 95, 95, 115, 116, 117, 98, 95, 104, 101, 108, 112, 101, 114, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 72, 63, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 72, 63, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 99, 115, 116, 114, 105, 110,
        103, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 63, 0, 0, 0, 0, 0, 0,
        14, 0, 0, 0, 0, 0, 0, 0, 144, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 117, 110, 119, 105, 110, 100, 95, 105, 110, 102, 111, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 160, 63, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 160, 63, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 152, 0, 0, 0,
        95, 95, 68, 65, 84, 65, 95, 67, 79, 78, 83, 84, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0,
        95, 95, 103, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 68, 65, 84, 65, 95, 67, 79, 78, 83, 84, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        6, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 232, 0, 0, 0, 95, 95, 68, 65, 84, 65, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 95, 95, 108, 97, 95, 115, 121, 109,
        98, 111, 108, 95, 112, 116, 114, 0, 95, 95, 68, 65, 84, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        32, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 5, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 100, 97, 116, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 68, 65, 84, 65, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 32, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 32, 128, 0, 0, 3, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 72, 0, 0, 0,
        95, 95, 76, 73, 78, 75, 69, 68, 73, 84, 0, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        0, 192, 0, 0, 0, 0, 0, 0, 64, 81, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        13, 0, 0, 0, 64, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108,
        105, 98, 109, 97, 110, 97, 103, 101, 109, 101, 110, 116, 95, 97, 103, 101, 110, 116, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0, 0, 0, 0,
        34, 0, 0, 128, 48, 0, 0, 0, 0, 192, 0, 0, 8, 0, 0, 0, 8, 192, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        32, 192, 0, 0, 128, 0, 0, 0, 160, 192, 0, 0, 96, 0, 0, 0, 2, 0, 0, 0, 24, 0, 0, 0, 8, 193, 0, 0, 8, 0, 0, 0,
        176, 193, 0, 0, 208, 0, 0, 0, 11, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0,
        3, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        136, 193, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 24, 0, 0, 0,
        229, 134, 175, 37, 196, 128, 48, 52, 179, 219, 28, 31, 43, 131, 218, 85, 50, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 11, 0,
        0, 2, 14, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 1, 254, 3, 42, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        12, 0, 0, 0, 48, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108,
        105, 98, 106, 97, 118, 97, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 12, 0, 0, 0, 48, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108, 105, 98, 106, 118, 109, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0,
        12, 0, 0, 0, 56, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 1, 61, 56, 5, 0, 0, 1, 0, 47, 117, 115, 114, 47, 108, 105, 98,
        47, 108, 105, 98, 83, 121, 115, 116, 101, 109, 46, 66, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0, 0, 28, 0, 0, 128, 32, 0, 0, 0,
        12, 0, 0, 0, 64, 108, 111, 97, 100, 101, 114, 95, 112, 97, 116, 104, 47, 46, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 16, 0, 0, 0,
        0, 193, 0, 0, 8, 0, 0, 0, 41, 0, 0, 0, 16, 0, 0, 0, 8, 193, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 16, 0, 0, 0,
        128, 194, 0, 0, 192, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const JMOD_MANAGEMENT_COMMANDS: &[u8] = &[
        207, 250, 237, 254, 12, 0, 0, 1, 0, 0, 0, 0, 6, 0, 0, 0, 18, 0, 0, 0, 168, 5, 0, 0, 133, 0, 16, 0, 0, 0, 0, 0,
        25, 0, 0, 0, 216, 1, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0,
        5, 0, 0, 0, 0, 0, 0, 0, 95, 95, 116, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 52, 62, 0, 0, 0, 0, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0, 52, 62, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 115, 116, 117, 98, 115, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 63, 0, 0, 0, 0, 0, 0,
        48, 0, 0, 0, 0, 0, 0, 0, 24, 63, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 128, 0, 0, 0, 0,
        12, 0, 0, 0, 0, 0, 0, 0, 95, 95, 115, 116, 117, 98, 95, 104, 101, 108, 112, 101, 114, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 72, 63, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 72, 63, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 99, 115, 116, 114, 105, 110,
        103, 0, 0, 0, 0, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 144, 63, 0, 0, 0, 0, 0, 0,
        14, 0, 0, 0, 0, 0, 0, 0, 144, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 117, 110, 119, 105, 110, 100, 95, 105, 110, 102, 111, 0, 0, 0, 95, 95, 84, 69, 88, 84, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 160, 63, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 160, 63, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 152, 0, 0, 0,
        95, 95, 68, 65, 84, 65, 95, 67, 79, 78, 83, 84, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0,
        95, 95, 103, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 68, 65, 84, 65, 95, 67, 79, 78, 83, 84, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        6, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 232, 0, 0, 0, 95, 95, 68, 65, 84, 65, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        0, 64, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 95, 95, 108, 97, 95, 115, 121, 109,
        98, 111, 108, 95, 112, 116, 114, 0, 95, 95, 68, 65, 84, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        32, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 5, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 100, 97, 116, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 95, 68, 65, 84, 65, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 32, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 32, 128, 0, 0, 3, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 72, 0, 0, 0,
        95, 95, 76, 73, 78, 75, 69, 68, 73, 84, 0, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0,
        0, 192, 0, 0, 0, 0, 0, 0, 64, 81, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        13, 0, 0, 0, 64, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108,
        105, 98, 109, 97, 110, 97, 103, 101, 109, 101, 110, 116, 95, 97, 103, 101, 110, 116, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0, 0, 0, 0,
        34, 0, 0, 128, 48, 0, 0, 0, 0, 192, 0, 0, 8, 0, 0, 0, 8, 192, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        32, 192, 0, 0, 128, 0, 0, 0, 160, 192, 0, 0, 96, 0, 0, 0, 2, 0, 0, 0, 24, 0, 0, 0, 8, 193, 0, 0, 8, 0, 0, 0,
        176, 193, 0, 0, 208, 0, 0, 0, 11, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0,
        3, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        136, 193, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 0, 0, 24, 0, 0, 0,
        229, 134, 175, 37, 196, 128, 48, 52, 179, 219, 28, 31, 43, 131, 218, 85, 50, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 11, 0,
        0, 2, 14, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 1, 254, 3, 42, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        12, 0, 0, 0, 48, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108,
        105, 98, 106, 97, 118, 97, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 12, 0, 0, 0, 48, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 1, 0, 64, 114, 112, 97, 116, 104, 47, 108, 105, 98, 106, 118, 109, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0,
        12, 0, 0, 0, 56, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 1, 61, 56, 5, 0, 0, 1, 0, 47, 117, 115, 114, 47, 108, 105, 98,
        47, 108, 105, 98, 83, 121, 115, 116, 101, 109, 46, 66, 46, 100, 121, 108, 105, 98, 0, 0, 0, 0, 0, 0, 28, 0, 0, 128, 32, 0, 0, 0,
        12, 0, 0, 0, 64, 108, 111, 97, 100, 101, 114, 95, 112, 97, 116, 104, 47, 46, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 16, 0, 0, 0,
        0, 193, 0, 0, 8, 0, 0, 0, 41, 0, 0, 0, 16, 0, 0, 0, 8, 193, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 16, 0, 0, 0,
        128, 194, 0, 0, 192, 78, 0, 0,
    ];


    fn finite_jdk_inventory() -> Inventory {
        // Expected DATA only: these identities do not attest to installed files.
        let base = fixture();
        let mut files: Vec<_> = base.payload.iter().filter(|p| !p.installed.path.starts_with("jdk/"))
            .map(|p| FileSpec { path: p.installed.path.into(), size: p.installed.size,
                sha256: p.installed.sha256.into(), mode: p.installed.mode }).collect();
        for pin in native_profile::JDK_NATIVE {
            files.push(FileSpec { path: format!("jdk/Test.jdk/{}", pin.relative), size: pin.bytes,
                sha256: pin.sha256.into(), mode: pin.original_mode & !0o222 });
        }
        for (relative, size, sha256) in [
            ("Contents/Home/release", 1638, "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b"),
            ("Contents/Home/lib/jvm.cfg", 29, "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0"),
        ] {
            files.push(FileSpec { path: format!("jdk/Test.jdk/{relative}"), size, sha256: sha256.into(), mode: 0o444 });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        policy::proposal_inventory(policy::ProposalManifestData {
            versions: Versions { jdk_vendor: "temurin".into(), jdk_version: "17.0.20.1".into(),
                gradle_version: "8.14.5".into(), agp_version: "8.9.2".into(), sdk_platform: "android-35".into(),
                sdk_platform_revision: "2".into(), sdk_build_tools_version: "35.0.0".into() },
            gradle_distribution: Distribution { url: base.gradle_distribution_url.into(), sha256: HASH.into() },
            roles: Roles { java: base.roles.java.into(), javac: base.roles.javac.into(), gradle: base.roles.gradle.into(),
                bundletool: base.roles.bundletool.into(), sdk: base.roles.sdk.into() },
            files, aliases: Vec::new(),
        }, &"a".repeat(32), HASH).unwrap()
    }
    pub(super) fn genuine_jmod_header_and_installed_counterpart_context_are_joined_data() {
        let file = CanonicalFile {
            path: "jdk/Test.jdk/Contents/Home/jmods/jdk.management.agent.jmod", size: 102338,
            sha256: "24621a245cd5d7e6ee84f14a168ec6ea06922e55d1eebcabcfbcc09abe56317d", mode: 0o444,
        };
        let member = NestedNative { member: "lib/libmanagement_agent.dylib", bytes: 69952,
            sha256: "79917926692f3921a3e7f32f78cd6a7f0c2f8b570ece2e28ec6c9a414ce2ca0e", mode: 0,
            kind: NativeResourceKind::JdkInstalledCounterpart,
            header: Some(NativeHeader { prefix: JMOD_MANAGEMENT_PREFIX, commands: JMOD_MANAGEMENT_COMMANDS }) };
        // The complete genuine archive has this one native member. Header arrays
        // were projected from captured original DATA, never executed here.
        let expected = native_profile::jdk_jvm_archive(file.path).unwrap();
        assert_eq!(expected.members.len(), 1);
        assert_eq!(member.mode, expected.members[0].mode);
        assert!(native_members_match(&file, &[member]));
        assert!(!native_members_match(&file, &[]));
        assert!(!native_members_match(&file, &[member, member]));
        for changed in [
            NestedNative { member: "lib/changed.dylib", ..member },
            NestedNative { bytes: member.bytes + 1, ..member },
            NestedNative { sha256: HASH, ..member },
            NestedNative { mode: member.mode ^ 1, ..member },
            NestedNative { kind: NativeResourceKind::Arm64, ..member },
            NestedNative { kind: NativeResourceKind::JdkJpackageTemplate, ..member },
            NestedNative { header: None, ..member },
        ] {
            assert!(!native_members_match(&file, &[changed]));
        }
        for changed in [CanonicalFile { path: "jdk/Test.jdk/Contents/Home/jmods/unlisted.jmod", ..file },
            CanonicalFile { size: file.size + 1, ..file }, CanonicalFile { sha256: HASH, ..file },
            CanonicalFile { mode: 0o555, ..file }] {
            assert!(!native_members_match(&changed, &[member]));
        }
        let mut bad_prefix = JMOD_MANAGEMENT_PREFIX.to_vec(); bad_prefix[4095] ^= 1;
        assert!(!native_members_match(&file, &[NestedNative { header: Some(NativeHeader {
            prefix: static_slice(bad_prefix), commands: JMOD_MANAGEMENT_COMMANDS }), ..member }]));
        let mut wrong_cpu = JMOD_MANAGEMENT_COMMANDS.to_vec(); wrong_cpu[4] = 7;
        assert!(!native_members_match(&file, &[NestedNative { header: Some(NativeHeader {
            prefix: JMOD_MANAGEMENT_PREFIX, commands: static_slice(wrong_cpu) }), ..member }]));
        let native_members = static_slice(vec![member]);
        let payload = static_slice(vec![PayloadSource { installed: file,
            origin: PayloadOrigin::DirectOriginal(OriginalSource::Picked {
                group: SourceGroup::Jdk, relative: "Contents/Home/jmods/jdk.management.agent.jmod" }) }]);
        let subject = Reference { payload, classes: static_slice(vec![FileClass::JvmArchive { native_members }]), ..fixture() };
        assert!(!subject.structural()); // Deliberately incomplete comparison fixture, never an admitted reference.
        let mut inventory = finite_jdk_inventory();
        assert!(subject.native_closure(&inventory));
        let target = "jdk/Test.jdk/Contents/Home/lib/libmanagement_agent.dylib";
        let saved = inventory.data.files.iter().find(|f| f.path == target).unwrap().clone();
        inventory.data.files.retain(|f| f.path != target);
        assert!(!subject.native_closure(&inventory));
        inventory.data.files.push(FileSpec { mode: saved.mode ^ 0o111, ..saved.clone() });
        assert!(!subject.native_closure(&inventory));
        *inventory.data.files.iter_mut().find(|f| f.path == target).unwrap() = saved;
        assert!(subject.native_closure(&inventory));
        inventory.data.files.iter_mut().find(|f|
            f.path.ends_with("/lib/server/libjvm.dylib")).unwrap().sha256 = HASH.into();
        assert!(!subject.native_closure(&inventory));
        let elsewhere = Reference { payload: static_slice(vec![PayloadSource {
            installed: CanonicalFile { path: "jdk/Other.jdk/Contents/Home/jmods/jdk.management.agent.jmod", ..file },
            ..payload[0] }]), ..subject };
        assert!(!elsewhere.native_closure(&finite_jdk_inventory()));
        assert_eq!(native_profile::JDK_JVM_ARCHIVES.len(), 71);
        assert_eq!(native_profile::JDK_JVM_ARCHIVES.iter().map(|a| a.members.len()).sum::<usize>(), 71);
        assert_eq!(native_profile::JDK_JVM_ARCHIVES.iter().flat_map(|a| a.members).filter(|m| m.counterpart.is_some()).count(), 70);
        assert_fixture_is_not_compiled(&subject); // A header/data predicate is never supplier activation.
    }
    fn direct_tuple_reference(base: Reference, file: CanonicalFile, group: SourceGroup, component: Component,
        archive: ArchivePin<'static>, member: &'static str, original_mode: u32) -> Reference {
        let relative = match group {
            SourceGroup::Jdk => native_profile::jdk_relative(file.path).unwrap(),
            SourceGroup::Sdk => file.path.strip_prefix("sdk/").unwrap(),
            SourceGroup::Gradle => file.path.strip_prefix("gradle/").unwrap(),
            SourceGroup::FixedSupport => unreachable!(),
        };
        Reference {
            versions: VersionSpec { jdk_vendor: "temurin", jdk_version: "17.0.20.1", ..base.versions },
            observed_jdk_vendor: "Eclipse Adoptium", observed_jdk_version: "17.0.20.1",
            gradle_distribution_sha256: GRADLE_ARCHIVE_SHA,
            archives: static_slice(vec![OfficialArchive { component,
                official_source: "https://example.invalid/inert-original-tuple-comparison", vendor_release: "inert",
                archive, published: PublishedChecksum::Sha256(archive.sha256), member_count: 1, expanded_bytes: file.size,
                members: static_slice(vec![OfficialMember { name: member,
                    kind: ArchiveKind::File { mode: 0o100000 | original_mode, bytes: file.size, sha256: file.sha256 },
                    disposition: ArchiveDisposition::Picked { source_index: 0 } }]) }]),
            source_members: static_slice(vec![SourceMemberSpec { group, relative, kind: SourceKindSpec::File {
                bytes: file.size, sha256: file.sha256, modes: static_slice(vec![original_mode]) } }]),
            source_bindings: static_slice(vec![SourceBinding { provenance: SourceProvenance::Vendor { archive: 0, member: 0 },
                disposition: SourceDisposition::Payload(0) }]),
            payload: static_slice(vec![PayloadSource { installed: file,
                origin: PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) }]),
            ..base
        }
    }
    pub(super) fn finite_nonhost_and_jdk_original_tuples_preserve_vendor_modes_data() {
        let base = fixture();
        let mut tuples: Vec<_> = native_profile::SDK_TARGET_ELFS.iter().map(|pin| (
            CanonicalFile { path: pin.path, size: pin.bytes, sha256: pin.sha256, mode: 0o444 },
            SourceGroup::Sdk, Component::SdkBuildTools,
            ArchivePin { bytes: policy::SDK35_ARCHIVE_BYTES, sha256: policy::SDK35_ARCHIVE_SHA },
            pin.member, pin.original_mode)).collect();
        let bat = &native_profile::GRADLE_BAT;
        tuples.push((CanonicalFile { path: bat.path, size: bat.bytes, sha256: bat.sha256, mode: 0o444 },
            SourceGroup::Gradle, Component::Gradle, ArchivePin { bytes: 138068841, sha256: GRADLE_ARCHIVE_SHA },
            bat.member, bat.original_mode));
        let jdk = native_profile::jdk_native("Contents/Home/lib/libmanagement_agent.dylib").unwrap();
        tuples.push((CanonicalFile { path: "jdk/Test.jdk/Contents/Home/lib/libmanagement_agent.dylib",
            size: jdk.bytes, sha256: jdk.sha256, mode: jdk.original_mode & !0o222 },
            SourceGroup::Jdk, Component::Jdk,
            ArchivePin { bytes: native_profile::JDK_ARCHIVE_BYTES, sha256: native_profile::JDK_ARCHIVE_SHA256 },
            "jdk-17.0.20.1+1/Contents/Home/lib/libmanagement_agent.dylib", jdk.original_mode));
        for (file, group, component, archive, member, mode) in tuples {
            let accepted = |r: &Reference, f: &CanonicalFile| match component {
                Component::SdkBuildTools => r.target_original(f),
                Component::Gradle => r.gradle_foreign_original(f),
                Component::Jdk => r.jdk_original(f, mode),
                _ => unreachable!(),
            };
            let r = direct_tuple_reference(base, file, group, component, archive, member, mode);
            assert!(accepted(&r, &file), "{}", file.path);
            assert!(!r.structural()); // Single rows are never a complete supplier.
            assert!(!accepted(&direct_tuple_reference(base, file, group, component,
                ArchivePin { bytes: archive.bytes + 1, ..archive }, member, mode), &file));
            assert!(!accepted(&direct_tuple_reference(base, file, group, component, archive, "wrong/member", mode), &file));
            assert!(!accepted(&Reference { source_members: static_slice(vec![SourceMemberSpec {
                group, relative: r.source_members[0].relative,
                kind: SourceKindSpec::File { bytes: file.size, sha256: file.sha256, modes: &[0o444] } }]), ..r }, &file));
            assert!(!accepted(&Reference { source_bindings: static_slice(vec![SourceBinding {
                provenance: SourceProvenance::Vendor { archive: 0, member: 0 },
                disposition: SourceDisposition::Payload(1) }]), ..r }, &file));
            let changed = CanonicalFile { mode: file.mode ^ 0o111, ..file };
            assert!(!accepted(&direct_tuple_reference(base, changed, group, component, archive, member, mode), &changed));
        }
        assert_eq!(NATIVE_ARCHIVES.iter().filter(|a| a.path.starts_with("gradle/")).count(), 16);
        assert_eq!(NATIVE_ARCHIVES.iter().filter(|a| a.path.starts_with("gradle/"))
            .map(|a| a.members.len()).sum::<usize>(), 51);
    }
    #[test]
    fn genuine_jmod_header_and_installed_counterpart_context_are_joined() {
        genuine_jmod_header_and_installed_counterpart_context_are_joined_data();
    }
    #[test]
    fn finite_nonhost_and_jdk_original_tuples_preserve_vendor_modes() {
        finite_nonhost_and_jdk_original_tuples_preserve_vendor_modes_data();
    }

    pub(super) fn catalogue_phase_budget_preserves_validity_without_phantom_payload_copy_data() {
        let base = fixture();
        let linked = fixture_with_source_alias(Some(("java", "Contents/Home/bin/java")));
        let catalogue = catalogue_budget(&[base, linked]).unwrap();
        assert_eq!(catalogue.storage, base.source_storage().unwrap().maximum(linked.source_storage().unwrap()));
        assert_eq!(catalogue.proposal_work, base.working_bytes().unwrap().max(linked.working_bytes().unwrap()));
        assert_eq!(catalogue.reproof_work, 262144 + sdk_metadata::PARSER_WORK_BYTES + policy::NATIVE_WORK_BYTES);
        assert!(catalogue.proposal_work > catalogue.reproof_work);
        assert!(matches!(catalogue_budget(&[]), Err(Failure::Unavailable)));
        let invalid = Reference { profile: "not-the-compiled-profile", ..base };
        assert!(matches!(catalogue_budget(&[base, invalid]), Err(Failure::Reference)));

        // Deliberately invalid duplicate DATA isolates the allocation formula,
        // not structural acceptance or genuine-catalogue admission/fit.
        let extra = base.payload[0];
        let mut map = base.payload.to_vec(); map.push(extra);
        let duplicate = Reference { payload: static_slice(map), ..base };
        assert!(!duplicate.structural());
        let delta = duplicate.working_bytes().unwrap() - base.working_bytes().unwrap();
        assert_eq!(delta, 2 * size_of::<FileSpec>() + 4 * extra.installed.path.len() + 128
            + policy::proposal_tree_reservation_bytes(1, 0, 0).unwrap()
            - policy::proposal_tree_reservation_bytes(0, 0, 0).unwrap());
        let layouts = SourceLayouts { jdk: JdkLayout::Bundle, jdk_vendor: "test", jdk_version: "17.0.1" };
        assert!(matches!(choose(&[], &layouts), Err(Failure::Unavailable)));
        assert!(matches!(choose(REFERENCES, &layouts), Err(Failure::Unavailable)));
    }
    #[test]
    fn catalogue_phase_budget_preserves_validity_without_phantom_payload_copy() {
        catalogue_phase_budget_preserves_validity_without_phantom_payload_copy_data();
    }

    // Strict integration gate: no skip, fallback fixture or synthetic table. This
    // remains intentionally unsatisfied until the reviewed generated include is
    // integrated. Expected observations below are DATA comparisons, not custody,
    // installed-file observations, consent or native-execution evidence.
    pub(super) fn compiled_six_component_catalogue_roundtrips_and_rejects_mismatches_data() {
        assert_eq!(REFERENCES.len(), 1, "integrate the genuine combined six-component catalogue");
        let r = &REFERENCES[0];
        assert!(r.archives.iter().map(|archive| archive.component).eq(COMPONENTS));
        let expected_archives: [(u64, &str, &str, &str); 6] = [
            (185_851_019, JDK17_ARCHIVE_SHA,
                "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz", "jdk-17.0.20.1+1"),
            (64_273_788, "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0",
                "https://dl.google.com/android/repository/platform-35_r02.zip", "platform-35_r02"),
            (76_857_898, "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48",
                "https://dl.google.com/android/repository/build-tools_r35_macosx.zip", "build-tools-35.0.0"),
            (138_068_841, GRADLE_ARCHIVE_SHA,
                "https://github.com/gradle/gradle-distributions/releases/download/v8.14.5/gradle-8.14.5-bin.zip", "gradle-8.14.5"),
            (4_339_472, AAPT_SHA,
                "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar", "8.9.2-12782657-osx"),
            (32_520_401, BUNDLE_SHA,
                "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar", "1.18.3"),
        ];
        for (archive, expected) in r.archives.iter().zip(expected_archives) {
            assert_eq!((archive.archive.bytes, archive.archive.sha256, archive.official_source, archive.vendor_release), expected);
        }
        assert_eq!(r.profile, crate::android_build_protocol::MAC_TOOLCHAIN_PROFILE);
        assert_eq!((r.observed_jdk_vendor, r.observed_jdk_version), ("Eclipse Adoptium", "17.0.20.1"));
        let v = &r.versions;
        assert_eq!((v.jdk_vendor, v.jdk_version, v.gradle_version, v.agp_version,
            v.sdk_platform, v.sdk_platform_revision, v.sdk_build_tools_version),
            ("temurin", "17.0.20.1", "8.14.5", "8.9.2", "android-35", "2", "35.0.0"));
        assert_eq!((r.roles.java, r.roles.javac, r.roles.gradle, r.roles.bundletool, r.roles.sdk),
            ("jdk/temurin-17.jdk/Contents/Home/bin/java", "jdk/temurin-17.jdk/Contents/Home/bin/javac",
             "gradle/bin/gradle", "bundletool/bundletool.jar", "sdk"));
        // Wrapper selection and acquisition provenance have distinct URL roles.
        assert_eq!(r.gradle_distribution_url, "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip");
        assert_eq!(r.gradle_distribution_sha256, r.archives[3].archive.sha256);
        assert!(r.structural() && r.source_directory_closure() && r.compiled_metadata_pair());
        assert!(support_manifest_matches(r) && available());
        let digest = reference_digest(r).expect("complete reference fits the bounded Rust commitment stream");

        // Supplier-side storage/phase accounting only. Fresh Inspect, retained-
        // Review Inspect and Register still require their real combined caller
        // totals and actual target allocations under the SAME whole-app64MiB cap.
        let budget = source_catalogue_budget().unwrap();
        assert_eq!(budget.storage, r.source_storage().unwrap());
        assert_eq!(budget.proposal_work, r.working_bytes().unwrap());
        assert_eq!(budget.reproof_work, fixed_working_bytes().unwrap());
        assert!(budget.reproof_work > 0 && budget.reproof_work < budget.proposal_work);
        assert!(budget.proposal_work <= APP_BYTES);
        assert_eq!(max_working_reservation_bytes().unwrap(), budget.proposal_work);
        let layouts = [JdkLayout::Bundle, JdkLayout::HomeInSameBundle];
        let recipes = layouts.map(|jdk| recipe(&SourceLayouts {
            jdk, jdk_vendor: "Eclipse Adoptium", jdk_version: "17.0.20.1" }).unwrap());
        for (selected, layout) in recipes.iter().zip(layouts) {
            assert_eq!(selected.jdk_layout(), layout);
            assert_eq!(reference_digest(selected.reference), Some(digest));
            assert_eq!(selected.source_versions(), ["17.0.20.1", "35.0.0", "8.14.5"]);
            assert_eq!(selected.source_storage().unwrap(), budget.storage);
            assert_eq!(selected.working_reservation_bytes().unwrap(), budget.proposal_work);
            let roster = selected.source_roster();
            assert!(std::ptr::eq(roster.members, selected.reference.source_members));
            assert!(std::ptr::eq(roster.trees, selected.reference.trees));
            assert!(std::ptr::eq(roster.support, selected.reference.support));
            assert!(std::ptr::eq(roster.archive_members, selected.reference.support_members));
            assert!(std::ptr::eq(roster.optional_sdk_metadata, &sdk_metadata::OPTIONAL));
        }
        assert!(matches!(recipe(&SourceLayouts { jdk: JdkLayout::Bundle,
            jdk_vendor: "temurin", jdk_version: "17.0.20.1" }), Err(Failure::Unavailable)));

        // Borrow shifted slices rather than cloning the complete catalogue.
        // Payload/class reindexing may not silently rebind source ordinals.
        let shifted = Reference { payload: &r.payload[1..], classes: &r.classes[1..], ..*r };
        assert!(!shifted.structural());
        assert_ne!(reference_digest(&shifted).unwrap(), digest);
        let oversized = Reference { directories: &["oversized"; policy::ENTRY_LIMIT], ..*r };
        assert!(oversized.working_bytes().is_none() && !oversized.structural());
        let mut support_member = r.support_members[0];
        support_member.member.crc32 ^= 1;
        let support_drift = Reference { support_members: static_slice(vec![support_member]), ..*r };
        assert!(!support_drift.structural());
        assert_ne!(reference_digest(&support_drift).unwrap(), digest);

        // Reach actual compiled JMOD and foreign-resource joins, not fixture
        // headers. Removing a member or changing its header remains a refusal.
        for path in ["jdk/temurin-17.jdk/Contents/Home/jmods/jdk.management.agent.jmod",
            "gradle/lib/gradle-fileevents-0.2.7.jar"] {
            let (file, class) = r.payload.iter().zip(r.classes).find(|(file, _)| file.installed.path == path).unwrap();
            let FileClass::JvmArchive { native_members } = class else { panic!("compiled native archive class") };
            assert!(!native_members.is_empty() && native_members_match(&file.installed, native_members));
            assert!(!native_members_match(&file.installed, &native_members[1..]));
            if path.starts_with("gradle/") {
                assert_eq!(native_members[0].kind, NativeResourceKind::OtherPlatformElf);
            } else {
                let header = native_members[0].header.unwrap();
                let mut prefix = header.prefix.to_vec(); prefix[0] ^= 1;
                let mut changed = native_members.to_vec();
                changed[0].header = Some(NativeHeader { prefix: static_slice(prefix), ..header });
                assert!(!native_members_match(&file.installed, &changed));
            }
        }

        let selected = &recipes[0];
        let instance = "a".repeat(32);
        complete_compiled_observations(r, |complete, provider| {
            assert!(selected.observations_match(&complete));
            let missing = SourceObservations { members: &complete.members[1..], ..complete };
            assert!(matches!(selected.finalize_proposal(&instance, 501, &missing, provider), Err(Failure::SourceMismatch)));
            let result = selected.finalize_proposal(&instance, 501, &complete, provider).unwrap();
            let bytes = result.documents();
            for (raw, expected) in bytes.iter().zip(result.hashes()) {
                assert_eq!(<[u8; 32]>::from(Sha256::digest(raw)), expected);
            }
            let selection = crate::android_build_protocol::MacToolchainSelection {
                instance: instance.clone(), owner_uid: 501, catalog_generation: 1,
                record_sha256: policy::digest(bytes[1]), inventory_sha256: policy::digest(bytes[0]),
                os_provider_sha256: policy::digest(bytes[2]),
            };
            let mut parsed = policy::parse_manifest(bytes[0], &selection).unwrap();
            assert!(policy::Provider::parse(bytes[2], &selection).is_some());
            assert!(policy::Registration::parse(bytes[1], 501, &instance).unwrap().matches(&selection));
            assert!(r.matches_inventory(&parsed) && r.native_closure(&parsed));
            assert_eq!(result.supplier_record(), &digest);
            assert_eq!(admit(&parsed, &digest), Ok(()));
            assert_eq!(result.payload_map(), r.payload);
            assert!(std::ptr::eq(result.payload_map(), selected.reference.payload));
            assert_eq!(result.payload_bytes(), r.payload.iter().map(|p| p.installed.size).sum::<u64>());
            assert_eq!(result.metadata_bytes(), bytes.iter().map(|v| v.len() as u64).sum::<u64>());
            assert_eq!(result.directory_count() as usize, r.directories.len());
            assert_eq!(result.alias_count() as usize, r.aliases.len());
            assert!(result.retained_bytes().unwrap() <= budget.proposal_work);

            let mut wrong_digest = digest; wrong_digest[0] ^= 1;
            assert_eq!(admit(&parsed, &wrong_digest), Err(SupplierFailure::Unavailable));
            parsed.data.versions.gradle_version.push('x');
            assert!(!r.matches_inventory(&parsed));
            assert_eq!(admit(&parsed, &digest), Err(SupplierFailure::Unavailable));
            parsed.data.versions.gradle_version.pop();
            let at = parsed.data.files.iter().position(|file|
                file.path == "jdk/temurin-17.jdk/Contents/Home/lib/server/libjvm.dylib").unwrap();
            let saved = std::mem::replace(&mut parsed.data.files[at].sha256, HASH.into());
            assert!(!r.native_closure(&parsed) && !r.matches_inventory(&parsed));
            assert_eq!(admit(&parsed, &digest), Err(SupplierFailure::Unavailable));
            parsed.data.files[at].sha256 = saved;
            assert!(r.matches_inventory(&parsed) && r.native_closure(&parsed));
            parsed.data.files.remove(at);
            assert!(!r.native_closure(&parsed) && !r.matches_inventory(&parsed));
            assert_eq!(admit(&parsed, &digest), Err(SupplierFailure::Unavailable));
        });
    }
    #[test]
    fn compiled_six_component_catalogue_roundtrips_and_rejects_mismatches() {
        compiled_six_component_catalogue_roundtrips_and_rejects_mismatches_data();
    }

    pub(super) fn archive_only_vendor_metadata_never_grants_filesystem_policy_data() {
        assert!(archive_mode(Component::Jdk, JDK17_ARCHIVE_SHA, 0o042755, 0o040000));
        for (component, hash, mode, kind) in [
            (Component::Gradle, JDK17_ARCHIVE_SHA, 0o042755, 0o040000),
            (Component::Jdk, HASH, 0o042755, 0o040000),
            (Component::Jdk, JDK17_ARCHIVE_SHA, 0o102755, 0o100000),
            (Component::Jdk, JDK17_ARCHIVE_SHA, 0o044755, 0o040000),
            (Component::Jdk, JDK17_ARCHIVE_SHA, 0o041755, 0o040000),
            (Component::Jdk, JDK17_ARCHIVE_SHA, 0o042700, 0o040000),
        ] {
            assert!(!archive_mode(component, hash, mode, kind));
        }
        assert!(!modes(&[0o2755])); // Picked source permission policy stays strict.
        assert_eq!(archive_order(Component::Bundletool, "r8/A.class", "r8/a.class"), Ordering::Less);
        assert_eq!(archive_order(Component::Bundletool, "r8/A.class", "r8/A.class"), Ordering::Equal);
        assert_eq!(archive_order(Component::Gradle, "r8/A.class", "r8/a.class"), Ordering::Equal);
        assert_eq!(archive_order(Component::SdkBuildTools, "r8/A.class", "r8/a.class"), Ordering::Equal);
        assert_eq!(archive_order(Component::Aapt2, "r8/A.class", "r8/a.class"), Ordering::Equal);
    }

    #[test]
    fn archive_only_vendor_metadata_never_grants_filesystem_policy() { archive_only_vendor_metadata_never_grants_filesystem_policy_data(); }

    #[test]
    fn exact_native_resource_rosters_cannot_be_reclassified_or_omitted() { exact_native_resource_rosters_cannot_be_reclassified_or_omitted_data(); }
    #[test]
    fn canonical_fixture_roundtrips_but_never_enables_production() { canonical_fixture_roundtrips_but_never_enables_production_data(); }
    #[test]
    fn complete_observations_and_provider_budget_are_required() { complete_observations_and_provider_budget_are_required_data(); }
    #[test]
    fn incomplete_reference_mapping_namespace_and_stream_bounds_refuse() { incomplete_reference_mapping_namespace_and_stream_bounds_refuse_data(); }
}
// Only the genuine compiled tuple enters this DATA seam. Recipe is move-only;
// copy its static reference before moving it into the callback, not its owners.
#[cfg(test)]
pub(crate) fn with_compiled_catalogue_data<T>(
    f:impl FnOnce(Recipe,SourceObservations<'_>,&[FileSpec],&'static [PayloadSource])->T)->T{
    assert_eq!(REFERENCES.len(),1,"genuine complete compiled catalogue is required");
    let reference=&REFERENCES[0];
    let selected=recipe(&SourceLayouts{jdk:JdkLayout::Bundle,jdk_vendor:reference.observed_jdk_vendor,
        jdk_version:reference.observed_jdk_version}).unwrap();
    tests::complete_compiled_observations(reference,|observations,provider|
        f(selected,observations,provider,reference.payload))
}
/// Same inert regression bodies for the repository's harness=false runner.
#[cfg(test)]
pub(crate) fn assert_macos_supplier_builder_data_contract() {
    crate::android_supplier_macos_source::assert_source_storage_data_contract();
    tests::catalogue_phase_budget_preserves_validity_without_phantom_payload_copy_data();
    tests::compiled_six_component_catalogue_roundtrips_and_rejects_mismatches_data();
    #[cfg(all(target_os="macos",target_arch="aarch64",not(feature="macos-android-registration-helper")))]
    crate::saved_command_owner::SavedCommandOwner::assert_android_catalogue_whole_owner_data_contract();
    tests::implicit_archive_parents_bind_complete_source_closure_data();
    tests::implicit_archive_parent_component_prefix_and_bounds_refuse_data();
    tests::implicit_archive_parent_cannot_replace_headers_payload_or_observations_data();
    tests::implicit_archive_parent_inverse_range_and_case_closure_are_complete_data();
    tests::canonical_fixture_roundtrips_but_never_enables_production_data();
    tests::complete_observations_and_provider_budget_are_required_data();
    tests::incomplete_reference_mapping_namespace_and_stream_bounds_refuse_data();
    tests::exact_native_resource_rosters_cannot_be_reclassified_or_omitted_data();
    tests::archive_only_vendor_metadata_never_grants_filesystem_policy_data();
    tests::compiled_sdk_metadata_does_not_forge_picked_source_observations_data();
    tests::genuine_jmod_header_and_installed_counterpart_context_are_joined_data();
    tests::finite_nonhost_and_jdk_original_tuples_preserve_vendor_modes_data();
    sdk_metadata::assert_sdk_metadata_data_contract();
}
