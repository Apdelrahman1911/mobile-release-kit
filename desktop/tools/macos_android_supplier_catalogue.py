"""Pure, bounded observation-DATA to private Rust catalogue SOURCE projection.

No filesystem, archive, network, native tool, subprocess, selected-root or Store
access. An external owner supplies already admitted original DATA bytes and owns
all output custody, limits, original clocks and finality. A generated table is
proposed SOURCE, never supplier/native/runtime qualification. Rust's existing
reference_digest remains the sole reference commitment implementation.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Mapping

DOCUMENT_LIMIT = 4 * 1024 * 1024
INPUT_LIMIT = 24 * 1024 * 1024
OUTPUT_LIMIT = 32 * 1024 * 1024
RECORD_LIMIT = 512
ENTRY_LIMIT = 32768
FILE_COUNT = 16384
ALIAS_COUNT = 128
TOTAL_LIMIT = 1024 * 1024 * 1024
ARM64 = 0x0100000C
LABELS = ("jdk", "sdk-platform", "sdk-build-tools", "gradle", "aapt2", "bundletool")
COMPONENTS = ("Jdk", "SdkPlatform", "SdkBuildTools", "Gradle", "Aapt2", "Bundletool")
COLUMNS = ("name", "kind", "mode", "size", "sha256", "target", "localHeaderOffset", "dataOffset",
           "compressedSize", "method", "flags", "crc32", "creatorSystem", "formatHint")
FORMATS = ("Archive", "Data", "ELF", "JavaClass", "MachO", "PE")
JDK_ROOT = "jdk-17.0.20.1+1"
JDK_HOME = "Contents/Home/"
INSTALLED_JDK = "jdk/temurin-17.jdk/"
AAPT2_PATH = "gradle/native/aapt2/aapt2"
# Project wrapper selection is canonical; ARCHIVES keeps acquisition provenance.
GRADLE_WRAPPER_URL = "https://services.gradle.org/distributions/gradle-8.14.5-bin.zip"
ARCHIVES = {
    "jdk": (185851019, "196d13ba5f10414bef7f6a05a9b3f00edacb18ebacef2b99485db9e2ee18f0e8",
            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz", "jdk-17.0.20.1+1"),
    "sdk-platform": (64273788, "0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0",
                     "https://dl.google.com/android/repository/platform-35_r02.zip", "platform-35_r02"),
    "sdk-build-tools": (76857898, "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48",
                        "https://dl.google.com/android/repository/build-tools_r35_macosx.zip", "build-tools-35.0.0"),
    "gradle": (138068841, "6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854",
               "https://github.com/gradle/gradle-distributions/releases/download/v8.14.5/gradle-8.14.5-bin.zip", "gradle-8.14.5"),
    "aapt2": (4339472, "5d0aec6851fffbc9f6c8a8b50390c0bc976aa0ddf57a8a3a39061ed54b609ad1",
              "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar", "8.9.2-12782657-osx"),
    "bundletool": (32520401, "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
                   "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar", "1.18.3"),
}
SDK_SHA1 = {"sdk-platform": "0bb560a90a7a2cbd0dd8348224d518b638fe7949", "sdk-build-tools": "93ab8ce91230e067b5add4bfa79919c52b27f072"}
RETAINED = {
    "sdk-platform-data.json": (2219325, "db21716251963ea99e07b4274833a48960f240ef6d47ce98a979d68fcbb12144"),
    "gradle-data.json": (64059, "a27c4f27180dcc8c35eb1448983d1e6c02da9672c485311ea4d60930eb330033"),
    "aapt2-data.json": (1048, "7119f3a1a4f5512aac7e1f028227d10b05c4b4eead32eb0e59a460ea3ca738fd"),
    "gradle-native-data.json": (246063, "79be1718a74ff941b6e212610f88fa2799335cdac070e4d17cd7d3f2fd9c7281"),
}
OUTERS = {label: label + "-data.json" if label in ("sdk-platform", "gradle", "aapt2")
          else "evidence/outer-" + label + ".json" for label in LABELS}
SELECTED = (
    (JDK_ROOT + "/Contents/Home/release", 1638, "cb6064fe4d7b87d9fbb8b8c7702047044d1bbeac38e0c5217f595579b6cc764b", "evidence/jdk-release-bytes.json"),
    (JDK_ROOT + "/Contents/Home/lib/jvm.cfg", 29, "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0", "evidence/jdk-jvm-cfg-bytes.json"),
)
XML_FILES = (
    ("sdk/platforms/android-35/package.xml", 17832, "385364dad6ba50838ec90abc8e4593976e0e0c54c87cf703857ba0a1aad63fe2", "Platform35Revision2"),
    ("sdk/build-tools/35.0.0/package.xml", 17719, "6f7a9969f1bb25e39ae22fa5690b878e6806217453acf3b534712fb3a76ad1d4", "BuildTools35"),
)
SDK_PROPERTIES = (
    ("sdk-platform", "android-35/source.properties", 257, "2c3764446f335ad2cc44383a0360fe247620b7c774ec100d5087771ac8ed3b28"),
    ("sdk-build-tools", "android-15/source.properties", 63, "084847d70abc41284feee7ea717e7c92eab0d1be05f048c27445a359cfe109d8"),
)
# The existing 3023B compile-bound android-support.json's seven/one notices.
SUPPORT_NOTICES = {
    "bundletool": (
        ("LICENSE", 19782, "65df395b026964510cd1af832232fce9d1c217cfeda70b25d27e8fd1299a6e14"),
        ("NOTICE", 10694, "8d3aac34baacf26983c482ad1c1715cfcaf87f38f77ac2beb1157890d6b568b9"),
        ("META-INF/LICENSE", 11358, "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"),
        ("META-INF/LICENSE.txt", 1126, "e90eaa08dea089df10f2bf7f9dba63a5f6237c01562c4741e2e86773e78582d5"),
        ("macos/NOTICE", 10694, "8d3aac34baacf26983c482ad1c1715cfcaf87f38f77ac2beb1157890d6b568b9"),
        ("linux/NOTICE", 10694, "8d3aac34baacf26983c482ad1c1715cfcaf87f38f77ac2beb1157890d6b568b9"),
        ("windows/NOTICE", 10694, "8d3aac34baacf26983c482ad1c1715cfcaf87f38f77ac2beb1157890d6b568b9"),
    ),
    "aapt2": (("NOTICE", 107181, "1c0a082e6d1591229d5bc1f93b52bafafa26eb4d0628055f296bd754d26c462c"),),
}
SDK_SPECIAL = {
    "android-15/d8": "D8", "android-15/apksigner": "Apksigner", "android-15/lld": "LldShell",
    "android-15/lld-bin/lld": "LldIntel", "android-15/lib64/libc++.1.dylib": "CxxIntel",
    "android-15/lib64/libc++abi.1.dylib": "CxxAbiIntel",
}
SDK_NEGATIVE = {
    "sdk-platform": frozenset("android-35/" + leaf for leaf in (
        "android-stubs-src.jar", "android.jar", "core-for-system-modules.jar", "data/annotations.zip",
        "optional/android.car.jar", "optional/android.test.base.jar", "optional/android.test.mock.jar",
        "optional/android.test.runner.jar", "optional/org.apache.http.legacy.jar", "uiautomator.jar")),
    "sdk-build-tools": frozenset("android-15/" + leaf for leaf in (
        "core-lambda-stubs.jar", "lib/apksigner.jar", "lib/d8.jar", "renderscript/lib/renderscript-v8.jar", "renderscript/lib/androidx-rs.jar")),
}

# Fixed observation validators transcribed from the existing compiled SOURCE.
# No runtime Rust parsing and no profile widening. The Rust predicates remain
# authoritative; these tuples reject unsupported DATA before literal emission.
# android_supplier_macos.rs SHA256 ebf68ad822e8d8a3868dfbd915896dc47daa67fa0c328dc823c417d06d375756
# android_native_macos_profile.rs SHA256 f982f6adb30517a914192657889d33b2e197d00068747146b535176805320e69
# android_toolchain_macos_policy.rs SHA256 f2208f7a185cf1d999ef28a0b8ce66555b1fc66e69da974280331b11b4cb329b
NATIVE_PINS = {
    'bundletool/bundletool.jar': (32520401, 'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29', (
        ('com/sun/jna/darwin/libjnidispatch.jnilib', 180932, 'e8ad39879b107ed955388d29555ddbcff3ada41598780eef579246752dd96c75', 0, 'BundletoolDarwinI386X64'),
        ('com/sun/jna/freebsd-x86-64/libjnidispatch.so', 112729, '38c4aa3bd608dd4c302dd0f264bb123c87d8772b4df0ad2414e4b0a0d1cba021', 0, 'OtherPlatformElf'),
        ('com/sun/jna/freebsd-x86/libjnidispatch.so', 105753, '53e715c8b4369698dd208b48af825837a7668206ed384b303ff930ef912e7e7e', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-aarch64/libjnidispatch.so', 105088, 'a9f3438531dca3fc4b4aa1604b717ded3d17c16f5d1324a02e5a3f64b30e77a9', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-arm/libjnidispatch.so', 107768, '7069629bbbc234c65843ecb0311ec734b62a3678b33bd6873248c6715b2b8848', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-armel/libjnidispatch.so', 111904, '1ef653d2b66998a43836cc703040c62618d95b7ea1e872b35bab13469bfd58fa', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-mips64el/libjnidispatch.so', 133240, 'da1420335d2093646f0ade14aec2e30504ba3aeaeaa26a190e558782d0663f32', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-ppc/libjnidispatch.so', 123208, '490b3d5bf012b4648a9e12d66f53a580835bca0cec52e536f0575f340794fee1', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-ppc64le/libjnidispatch.so', 133536, 'cd92dbee6af2f1b7dda0ca7e43ac885772008a3867e0357e1942410f690c1429', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-s390x/libjnidispatch.so', 132568, '48d005078a4afe54e96ee759b442a33a9111418410a4deb7c0c8188cd0106658', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-x86-64/libjnidispatch.so', 112848, '3812ee8afe5f712ca1f045350ed5ddfd83b2ba1dae5c55f4f17a4babeafbf8fd', 0, 'OtherPlatformElf'),
        ('com/sun/jna/linux-x86/libjnidispatch.so', 102079, '2e122dd90d46abaaffadff7cb239914019e0c6e09015bbe6893d51acf19de09c', 0, 'OtherPlatformElf'),
        ('com/sun/jna/openbsd-x86-64/libjnidispatch.so', 114291, '53be2755c82dec64edf98fe588331ad61cdf2e4c4685d533ea107dadf423271a', 0, 'OtherPlatformElf'),
        ('com/sun/jna/openbsd-x86/libjnidispatch.so', 107877, 'c1d8be647e4973215329d3a2c82f6cd9beefec65601b7b230add1d573989c81a', 0, 'OtherPlatformElf'),
        ('com/sun/jna/sunos-sparc/libjnidispatch.so', 127616, '76bee038bbf5fe47c327571f887fa04c88904a7b467321b9f19ad9c0542cc333', 0, 'OtherPlatformElf'),
        ('com/sun/jna/sunos-sparcv9/libjnidispatch.so', 139232, '12eb13f9695aee0cce59383905b18f9992ce4ad6b3a8e40f8a862293701c47cc', 0, 'OtherPlatformElf'),
        ('com/sun/jna/sunos-x86-64/libjnidispatch.so', 132352, 'a6d90b8048bf0d970b29e16d3464b0c5ec1a8a0a326c4abe908e7c9fd8b3007b', 0, 'OtherPlatformElf'),
        ('com/sun/jna/sunos-x86/libjnidispatch.so', 121120, '625e2c2d1ca776feeafbbbf413af4f1965ab49d01b1a954efccbb58f48f0442b', 0, 'OtherPlatformElf'),
        ('com/sun/jna/win32-x86-64/jnidispatch.dll', 246784, 'a66959bec2ef5af730198db9f3b3f7cab0d4ae70ce01bec02bf1d738e6d1ee7a', 0, 'OtherPlatformPe'),
        ('com/sun/jna/win32-x86/jnidispatch.dll', 207872, '04c9a8ab43d1eb616b84d0686c8ae1d881ef03fe4f3aa26511e5b19d35ef16af', 0, 'OtherPlatformPe'),
        ('linux/aapt2', 6511488, 'f2652fdbfcec58657ab718b28abf6b6d7ac90d61a8298341d86c8d837a6d7e98', 33261, 'OtherPlatformElf'),
        ('macos/aapt2', 11186368, '995cf1a04fb55045dd22ae3d6248f32d649bac9dfa7bf9357507499794051c6b', 33261, 'Arm64'),
        ('windows/aapt2.exe', 4106240, 'c8c138022012e577aa4d3d3808079e017c8746d876ceaf10decefdc0645508cb', 33261, 'OtherPlatformPe'),
    )),
    'gradle/lib/gradle-fileevents-0.2.7.jar': (1433862, '9f8d26b0057ed645af68c8d4139988d69ee884ad8d009e98a793c08cbdd3d2f8', (
        ('net/rubygrapefruit/platform/aarch64-linux-gnu/libgradle-fileevents.so', 569592, 'e32f36eeb112888078b6edb33e5c9aea764401e2b6719a753b2fe24c32a319d9', 33261, 'OtherPlatformElf'),
        ('net/rubygrapefruit/platform/aarch64-linux-musl/libgradle-fileevents.so', 573080, 'ad2564b331076dd6ce4cf71f3b4f30224329cd5fa491f204371d1de26f66cbe8', 33261, 'OtherPlatformElf'),
        ('net/rubygrapefruit/platform/aarch64-macos/libgradle-fileevents.dylib', 534584, '94f6518ba52029073c3fde817647ff8d8a9941b483e028616b9e06eb7235d91b', 33261, 'Arm64'),
        ('net/rubygrapefruit/platform/aarch64-windows-gnu/gradle-fileevents.dll', 437760, 'd91e361294f1a3673d18e41ee82185cf427004593d98d4972018783d7e3b81d3', 33261, 'OtherPlatformPe'),
        ('net/rubygrapefruit/platform/x86_64-linux-gnu/libgradle-fileevents.so', 571128, '64c77581ccffde085b013ad20f235d5200bac7c34a44ad5ea9241f1a5dd2c8e5', 33261, 'OtherPlatformElf'),
        ('net/rubygrapefruit/platform/x86_64-linux-musl/libgradle-fileevents.so', 573760, '93454d59e9f0380dcf797a93766f05e6da4fee6f2002a92ed329fcae18d4000f', 33261, 'OtherPlatformElf'),
        ('net/rubygrapefruit/platform/x86_64-macos/libgradle-fileevents.dylib', 447852, 'a691507125ec1bd97e55d20d6184cf9b69e441f842506d92b1c62581fd9ab79d', 33261, 'GradleIntelPlatform'),
        ('net/rubygrapefruit/platform/x86_64-windows-gnu/gradle-fileevents.dll', 465408, 'c22c800a9fd7115eb90dc745cda3a821b5e1032f45c946ad8e00bf62a45a29a1', 33261, 'OtherPlatformPe'),
    )),
    'gradle/lib/jansi-1.18.jar': (287352, '109e64fc65767c7a1a3bd654709d76f107b0a3b39db32cbf11139e13a6f5229b', (
        ('META-INF/native/freebsd32/libjansi.so', 98380, 'c220943d4c08ec91c1389a73e582ffacaefc4e42f85a9905d1d9c895c955f207', 0, 'OtherPlatformElf'),
        ('META-INF/native/freebsd64/libjansi.so', 104088, '96acfecb89242a9555242e19c25988d7f476ce696573b0155598cff6d453d987', 0, 'OtherPlatformElf'),
        ('META-INF/native/linux32/libjansi.so', 98876, '7732526b162b66835a53ad73e0731819b49fb585fdb3936bbc472ae7dfc3011e', 0, 'OtherPlatformElf'),
        ('META-INF/native/linux64/libjansi.so', 109048, 'dcf42b19feb29d697ee3575fd622f96165b2f9e294d4d53f6274070bd5869ede', 0, 'OtherPlatformElf'),
        ('META-INF/native/osx/libjansi.jnilib', 20676, '9fe58e627b8c81d1ef9bdd7eab4b2ae84da1847d13b44c364f16f2cc85d63654', 0, 'GradlePlainJansiIntel'),
        ('META-INF/native/windows32/jansi.dll', 21504, '3c130ad32a4186adb5316a3458b0c1844ebef43e52fc09797b96cad9eb159d18', 0, 'OtherPlatformPe'),
        ('META-INF/native/windows64/jansi.dll', 26112, '629af6e8e32dac48131a0607dc70c62a2d2a1dac6315d96b95449db141e13acb', 0, 'OtherPlatformPe'),
    )),
    'gradle/lib/kotlin-compiler-embeddable-2.0.21.jar': (58272093, '9fa8cdd1de0dccffe154c997d423ec6b5f53cd6d9177e3a77a9b0de03fb1bc81', (
        ('org/jetbrains/kotlin/net/jpountz/util/linux/aarch64/liblz4-java.so', 77859, 'a732552e3855c4f81d70f34a7468c26ffd4f3babcf20a06fa309082905ec4e81', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/net/jpountz/util/linux/amd64/liblz4-java.so', 203408, '108157738367c0a972c2228dead1af896bf5d5a7fc7f58fcbf855aa2b67049ea', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/net/jpountz/util/linux/i386/liblz4-java.so', 68840, 'f72fff01f82b13bf54e945d1d9158a4b6c10caabca0a102fba5477c8d8baa8b4', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/net/jpountz/util/linux/ppc64le/liblz4-java.so', 209016, 'c6dd51e13b98853688589828e6760f334088bec00a143197c05486bb94fd8495', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/net/jpountz/util/linux/s390x/liblz4-java.so', 89200, '9584dad637d5241fdb649f1db07835623a7c567c43f0c9450249c72a81657990', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/net/jpountz/util/win32/amd64/liblz4-java.so', 516677, '1ba944ded629f0ea2c7669c9cb4b3a39b2d773142a0b5f8fce8e11d6a50800fd', 0, 'OtherPlatformPe'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/FreeBSD/x86/libjansi.so', 12100, '71d4e610ba70854a344078512afd3ca42676107e48cd753ecd91e806abb45569', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/FreeBSD/x86_64/libjansi.so', 15308, '8c56980e59f79e7a95b8edcbfe0a4f6b54bb6964aa9034efa7617725179d1d52', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/arm/libjansi.so', 22232, 'fc3bb7c1178369ae6d3b07e51b0590eb8a6bb6dd6acd90115afeb18c65d85ad6', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/arm64/libjansi.so', 15952, 'a807b7b420a15ee48e13c694f1e4d84b0d69c8857c2f0008c484328522bc69e5', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/armv6/libjansi.so', 15068, '402a6ee45d724e95eacace01e4e17029e10869ddaa5f5f4b45e13eed33d016d7', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/armv7/libjansi.so', 12236, 'f01f068c1be78380c36868b4f47f8f24877a17a3e2269cc43c43615f9aee3ecb', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/ppc64/libjansi.so', 18064, '8d97571bb654005984c4d7595062f94a7bdb8f11203abc9efe005c22571def43', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/x86/libjansi.so', 17580, '8bdd29ef7e167116e848594760fe49546cd7a3e45f130bc30766ba1490193653', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Linux/x86_64/libjansi.so', 15800, '4bf8600bdeee40175ee1f5978c76bc9caa5083c35d6a7844d5ede74a669fb234', 0, 'OtherPlatformElf'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/arm64/libjansi.jnilib', 53036, 'a2d8080e97424ddc0c21b6c16326eaa8b5e5c7a6aca0de2113da3ea1aa6726aa', 0, 'Arm64'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86/libjansi.jnilib', 14748, 'ea7ceaf2b63f95ac34822fed2f4cdfd436599c682e04383fac3736dd4c4a41a6', 0, 'GradleIntelPlatform'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86_64/libjansi.jnilib', 15612, '537d38ad49b9d159eef64ed0a774c816e679606d9c37266776b74c2cd6074f3f', 0, 'GradleIntelPlatform'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Windows/x86/jansi.dll', 113924, '1d6314da4b3a7a5e9dded6b0cc1b83f15f8f603897ae00cfe98ef171285620f3', 0, 'OtherPlatformPe'),
        ('org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Windows/x86_64/jansi.dll', 127010, 'd23fc9293b68781d43314403048d6dc655fa4620b6b4db3dcd345c52c332a2f4', 0, 'OtherPlatformPe'),
    )),
    'gradle/lib/native-platform-freebsd-amd64-libcpp-0.22-milestone-28.jar': (19750, '88c670d679d37551bc7e799c854348aec3c0098ff52badbb9e3c246c4a023f56', (
        ('net/rubygrapefruit/platform/freebsd-amd64-libcpp/libnative-platform-curses.so', 25480, '35b7e87244420d3beb56cf7180b6e3c195b7ef7d6c5a632cac2f6447e117383d', 33261, 'OtherPlatformElf'),
        ('net/rubygrapefruit/platform/freebsd-amd64-libcpp/libnative-platform.so', 32984, 'c040fb2812b076d9795d6b9683feba37eb6843b58b26ae40021e440719834f91', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-aarch64-0.22-milestone-28.jar': (11768, '8d984ab5612b95aa9d24ead48039742a318ef21a488e2d4eadc0478a0f27dc4f', (
        ('net/rubygrapefruit/platform/linux-aarch64/libnative-platform.so', 76592, '4b3f13f6572ccf429f29570ea0d9804f159bc9eb0d6a7586e7b0dd3b90a37124', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-aarch64-ncurses5-0.22-milestone-28.jar': (8397, 'a5a8908eb46d33708dfb052cc65ab9426624f88fb012faee3a5e1f3f42d3cd07', (
        ('net/rubygrapefruit/platform/linux-aarch64-ncurses5/libnative-platform-curses.so', 26080, 'c0b5382fd53a721465f985b17b27b2d024d2f3b3915f1a7cd0a702d1607277ea', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-aarch64-ncurses6-0.22-milestone-28.jar': (9069, '1ff2ee4b58a77916d3faec4204eaee795358ba342e5638d4c80c89298698e85f', (
        ('net/rubygrapefruit/platform/linux-aarch64-ncurses6/libnative-platform-curses.so', 74768, 'd45843a884c557cd6257572b0d28f56102f7f1a7a2acc8d4e70e2c585d672566', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-amd64-0.22-milestone-28.jar': (11250, '340c82470fcd12dff02c8a7cae0cf80dcbce447b1b6f9c3a8fd2df74a080b1ed', (
        ('net/rubygrapefruit/platform/linux-amd64/libnative-platform.so', 34496, '49ee56cfe70dfd243258c64bdf90a013471b302f099a89f66d62e08951684a88', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-amd64-ncurses5-0.22-milestone-28.jar': (8228, '6816b0bf9170f27a802682c9c8342c9abcfdac3cce0e6143cdbb04a2254cd6b7', (
        ('net/rubygrapefruit/platform/linux-amd64-ncurses5/libnative-platform-curses.so', 24816, 'e0e7e84abe2624d974858eab31833ff718d4574c77b2e75c23ad64eb6646c8c9', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-linux-amd64-ncurses6-0.22-milestone-28.jar': (7950, '49c7b6a93ba9a14482fada6e891e5d09a46411bb372235b8c8686182fe762061', (
        ('net/rubygrapefruit/platform/linux-amd64-ncurses6/libnative-platform-curses.so', 24336, 'eb8677ba6c72d236b20d82145c009dce25463cdf3f38e18b39e0c0e6a0b20dce', 33261, 'OtherPlatformElf'),
    )),
    'gradle/lib/native-platform-osx-aarch64-0.22-milestone-28.jar': (14261, '7cb8f8246c50a07f52e40b698f0a229271237e0bc59a4184e6b5ccc65d9f0847', (
        ('net/rubygrapefruit/platform/osx-aarch64/libnative-platform-curses.dylib', 55072, 'f1f5514b5bff4490262c81baa2eb217f6662f0d801e63e436a950e1e60039e85', 33261, 'Arm64'),
        ('net/rubygrapefruit/platform/osx-aarch64/libnative-platform.dylib', 57112, '4f458e0b0bd6f63da23b3c97e878526d07318db0ef5616355c1fd7a35d910e27', 33261, 'Arm64'),
    )),
    'gradle/lib/native-platform-osx-amd64-0.22-milestone-28.jar': (12867, '61ab872b419deae8cdf37d1a0d5f6916b170ada1226129741fceb3ebd56b950f', (
        ('net/rubygrapefruit/platform/osx-amd64/libnative-platform-curses.dylib', 17736, '10c96874bb236f931b735c22178ab57d796b5edab907cd69ede56ab2080cb3e4', 33261, 'GradleIntelPlatform'),
        ('net/rubygrapefruit/platform/osx-amd64/libnative-platform.dylib', 23896, '7749b8307a1834bc009358b1187b3066f91a5cee231eafec65ad62b7dd45a0e8', 33261, 'GradleIntelPlatform'),
    )),
    'gradle/lib/native-platform-windows-amd64-0.22-milestone-28.jar': (71157, '18803842185961617abf2a2f52da063daae6b440437b441d605a0002336963d0', (
        ('net/rubygrapefruit/platform/windows-amd64/native-platform.dll', 141312, '681a9775db6be81a3e9e160dfc2365764e06af4f92cfbb42618a4a36c2d8fd7d', 33188, 'OtherPlatformPe'),
    )),
    'gradle/lib/native-platform-windows-amd64-min-0.22-milestone-28.jar': (70274, 'b2758b8593cb0f4b6d41edb89cdcbbacd4754f2f6469f3c66c43beee1a11cf22', (
        ('net/rubygrapefruit/platform/windows-amd64-min/native-platform.dll', 139264, '2fc2febe2cbe4e1d5324efa97ef67425392c6ed1dbbfc6df86a529e05b167877', 33188, 'OtherPlatformPe'),
    )),
    'gradle/lib/native-platform-windows-i386-0.22-milestone-28.jar': (62992, '81721cfed8ffe07be279adf876f1e3c86dfe9428a59e5fe7a713f8ccc7120a09', (
        ('net/rubygrapefruit/platform/windows-i386/native-platform.dll', 115712, '4db97376c46a0bf89dbf4aff446cf6995e46f34e7fc81f549e61af6ed1e3c3c8', 33188, 'OtherPlatformPe'),
    )),
    'gradle/lib/native-platform-windows-i386-min-0.22-milestone-28.jar': (62076, '0f32b0012ebe1f52de052d2988773755f0c053248c7fd23cd88a93d63a69ecd4', (
        ('net/rubygrapefruit/platform/windows-i386-min/native-platform.dll', 114176, '112ec3a23028432599900c763a16d51eb89461e60cdac2fcee1bf97642a2d08b', 33188, 'OtherPlatformPe'),
    )),
}
JDK_NATIVE_PINS = {
    'Contents/Home/bin/jar': (70448, 'c55e508c52019bb483ee2e737b751ed44d5e9e86abe660c713404db43c58803d', 493, 4096, 'a69e71ca440e5664e069f67df8d05af5ecb41e7b25c94f085199651c94f26c0f', 'ef2ba338a4d0915c69b2fb01ca0ccf3b47effe8d13bbc544a4fcde3570c064a6'),
    'Contents/Home/bin/jarsigner': (70464, 'fe9a1276c5a18c115177f0e7a5bea9b3163739e280332044564089be7f766c64', 493, 4096, 'adfb52ad634cc896febbc2db158bc8bfadb30bac8accd7ce894a59d387f0510b', 'f03f73bc040f338a1aef0304dfcd5decc842915cd88c5627aacde6ae8667816a'),
    'Contents/Home/bin/java': (70464, 'af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0', 493, 4096, 'ede2f2280dd632c1c4322098e231f5eedf454c2241ae0103d4e6661ead98a757', '481b50738668eddfc3d0a0047e5283fd2a481a57ca784a3ab32c6b4f810ab0f9'),
    'Contents/Home/bin/javac': (70464, '6f5159301c750bba340390eda5fdd4a0959445355f97c40aa9c2addb00ede5ab', 493, 4096, '467e3f2172ad919033c544582201051b702b4ff2964f06566d92b1c519020070', '59ad97d854eb58f030501fd1771ee81d490fe4377b323f0fbf9f499b28ec9e43'),
    'Contents/Home/bin/javadoc': (70464, '16c9e93773c99393bac5bbbe12ad23472dfacdb77732da1b8720e743b787bb06', 493, 4096, 'eed46b663fffc82c541850e7f703eb6cb8328976d2acb356ec2ebdcab8ea5732', 'dd8c5c38d35a33dd65095fc8c44860501be48acce7d34e51897b12bc8255692d'),
    'Contents/Home/bin/javap': (70464, '0b318cfea6a2866918cda88c64db9919e9d668aa2f7cc1bb0ccb11f49b243bbb', 493, 4096, 'eab183dc78c24f01e837923a0be850a065dcebbebc20d90fa59b6ec66fd621fd', '1039661d394725ba7da0aeb3f87aa2036469a0fe3b744772f24c476370cc5224'),
    'Contents/Home/bin/jcmd': (70464, 'e3aebdd820297b64e041203f766ebf28986abf0c8cf3e59ba0681d935160c0eb', 493, 4096, '7c5aa80d8cd9a87b0705c1382b90527ceccfd00bf6bcfee0e32782385bf5a8d7', '10b5c6f119fdb56bcc2f8654f28a223a86cb16a1d26498e8e8c238ea2e593f17'),
    'Contents/Home/bin/jconsole': (70464, 'a7ddaf2cbea00efdbdb6eeaf1075ea2c6ae726da656831c5f832680fea80d504', 493, 4096, 'a7c19e64c0759493287fd75117dc4da7b4357f24e36bbf97ba2ed4ec14847625', 'e3d7e38bd048b636a4c6d65c4a7ad10a5571e488201ab3be92574903cff25bff'),
    'Contents/Home/bin/jdb': (70448, '229e5965e072b20783c5bd008c39dd914bcd4223d5058767a3f4af2be0f2cb83', 493, 4096, '213b2be4a3a58d861d6b4bbf9c1ff8c24e5e4b02a6fea646e45874510f6cd165', 'e5b94ef1b77dde3fd6ad1f762a727d8b46a9c6bbfd8d985fac975d282dd28da5'),
    'Contents/Home/bin/jdeprscan': (70464, 'b68b8f98cda671af91f9c1efc4a014828cf34d80d8487d2e222f82b55bb373b6', 493, 4096, '515aaae101cac6611e19801ddaa9702c508a86a37ced72538547ac62e49ff7a5', '9308b3e1b03d90e0bdd79aae53c3bfbced108848bbacb4dd404a120f65d31e92'),
    'Contents/Home/bin/jdeps': (70464, '530d87e93a3321c91a0e5603077dc7a759b96e139bea8348fb1cd78c8059b90f', 493, 4096, 'af1a8e56858102d4937d9ebf8f1116b678e722e5d2f36c2b093dbef90811494b', '382543aefbe9fce3e7fce194c0dd824528ef86833d12721cc6386b1235a44ab5'),
    'Contents/Home/bin/jfr': (70448, 'da2a39b0eb0baae163398254c02f0e74d67b0d3b5dd4faedf500eac7bf11a630', 493, 4096, '596e4e7ee74a9ad7be008db88b83e1561f5e54ba59a2a8897763912cc5040292', '48957eac1ba519b63a62776feaf2c5310d48438fd24be5307422fcdc684c0923'),
    'Contents/Home/bin/jhsdb': (70464, '12c20fd4facc8ed4f31c813bf140b1da596797a5e0932ffba13c48f72f22bc3e', 493, 4096, '4519d71c6c97fdf69e1cab403427f2fb5c108acbf04889b70c02d79738745a03', 'f5cce32096dd9c0cb8322ebd2fc82251f9b3d0c5185ebb1eaf1d4da5492bb40f'),
    'Contents/Home/bin/jimage': (70464, '66ff78759e96a1e130a0fb8cdcf37eac7d542ca49860726b0bed79f311405522', 493, 4096, '16c0c8e650aa89be03c281c51ff8970e746468d752255ab165af27f3e4ff5f2c', '0e905d84de5ddd3790bf56971c2f38e6c7fb81df8826541e128dbfb763d19d6b'),
    'Contents/Home/bin/jinfo': (70464, '939b38d404cc9055d2d3039a6fbfdfea4d783a370512bf1d7084f340e3a7337e', 493, 4096, 'a6e8e7171b048aa6f66ff8e6deeafba66a96ca4c01705587f50adc6780fd3fe7', '4a3c231449dd55dd334cfb2b00b192258da743ed403d3d8bbda0f05bcd801846'),
    'Contents/Home/bin/jlink': (70464, '601685bdfbfd2eb31d01e11dee94865f48910d90610829aa2c010c3ababf7650', 493, 4096, 'db5057e2f3bbdddc6d32bfd1a43644807dc2325a59006f1ba264b9dee8ca2b17', '1099be60788715e2e8471925548112910bbf9270c1eff0194ccdfbb0edb904e2'),
    'Contents/Home/bin/jmap': (70464, 'b491f891489a84c668915be116b28f26ef399501f249751a7ee197ba4b03e078', 493, 4096, '42e54588578e73186732ad7d49f66a5381cbcf1560c46e90800f1ef7a549697a', 'bda5570207c8134f6cec0031094269d40774ef217a6478cbe442c2d862762679'),
    'Contents/Home/bin/jmod': (70464, 'fc3a0982042318463a1648324f2432a71893f745f0e780b87ee75c3f6e7af4c8', 493, 4096, 'a8cb05917e7aa70550e31c26040c9d801e613d268020d7fc5216ac5ad5fe7ae8', '0096e5af87d7f90af3cd93281c21fa7970d7cd377c8ff41a50fdb9b8ac0e4965'),
    'Contents/Home/bin/jpackage': (70464, 'c4aa90b52f2904e5abb87ea52ce108b25b733b5b2dd4a1c0cfd2fa61ac305342', 493, 4096, 'be1203dd2929066440192d842cf8f2d89dadb685d0c87e6f1c0895c21817a432', '020e586fede9fd6ce9277c3bdddf63d381e8218dd1569285e770add45d85de28'),
    'Contents/Home/bin/jps': (70448, '5c09726ceee3b97982540aeaa84be190b8e6ac155d88b8507235079ba8310fe1', 493, 4096, '764eaec74eaff7b2d9237256906e04221df00ecf4729a81e2484813bdd114325', '4bd5e82bc234409ae9bf84d17ed7ac60404056f320f24e442f805c8f603266e0'),
    'Contents/Home/bin/jrunscript': (70464, '9bd7764585944634431ca97193f2c714c562b06ce6ab6aa918b84d36274a3283', 493, 4096, '6c69de25dc3ce0e79f0397ef07779f0508896615c145241c0972bd9cc62ff6a8', 'ab611d3979cec2ae3d531b5634d70471fa74ec2a6fc22e0e2c91d2cabca9f32d'),
    'Contents/Home/bin/jshell': (70464, '73c4db331de31cb6c261fe5593d6d40cd2023cf6d584f0cb2b3f5fb03fa7a609', 493, 4096, '13922c137c85385af5a2e1952cf09fff4c06f3bc7cf5574d38b42aaa18bc503a', '1e961900eaf6b4be5715dc859f6c800fcad540c9ade39d785a7b5822f56c9ce4'),
    'Contents/Home/bin/jstack': (70464, 'edbd8c8b0690b4844a75d2bd17ae6563baf63ef4942bedd16d5230f6e4b974a1', 493, 4096, 'b042e6bef47c682332a7ce76e0fa99c046947a7f809a3a48842b80d784623e94', '80d64976e66076fc9c74cb09d580e9fa36cd270cf920cb3c9d2f6554fa50d4d9'),
    'Contents/Home/bin/jstat': (70464, '3fd61c3e2c179717a92fb19ebea8ffbe56a9eedad8eec82482695c38ce4f3cfc', 493, 4096, 'a144ae28b9b5e4760fa99649386ee8f7922e35f3d83198cabba25a93d8510ba2', 'b1b7d9364195a23d0e46207453f4c729972a8c18c40aa44a0e954d735a5a0ad2'),
    'Contents/Home/bin/jstatd': (70464, '13e9c26d467d2791d6dc5902d876d0a1a323e8472133d436ae64df65ce219aa0', 493, 4096, 'f34c6aa53d12a35ae3b8785750b6fed6b20da4d9204321548a3ac0fe407a6937', '384d92de1c853361a53cf7ba764e24572ab3d2115310de674c6ecf20c3a0f09a'),
    'Contents/Home/bin/keytool': (70464, 'af587a253678cda7ca2704daee936af1993305ce9a9bc6d5018f37f49d425fcb', 493, 4096, '1944c0db18d910e87962f3aaa016564aa5adc29a10ac7ec90799a6324a40ff7c', 'a6219e55dbb53c08bbd481bac9d564d0d36f32ac4da863ed3ecef90f62dc31e9'),
    'Contents/Home/bin/rmiregistry': (70464, 'aea46addd6ba9f6a44b119550000cac3e999bf2bd85673e5105ae0609c960850', 493, 4096, 'da1a281f1ff098103c7f8b42ed0ff66f8b5bd38c9fdb9a2bc2e8eaf977a18de0', '50cabbf5086377d2c29f6affa836dca99fa4a00351c5c373b37abc3efcf2d30d'),
    'Contents/Home/bin/serialver': (70464, 'fdfd5b5d9929c77750e480951212eabe800e4a2daa3b73995539242333d6f22e', 493, 4096, '2f72430af795d3aa01fea30abf182cbc03d0154a0eb4e5ad4aa1208534467f6d', '9f0580bf73f5d27b1796d518c6c727d91c70878ec075bba6bfc6d883455d19df'),
    'Contents/Home/lib/jspawnhelper': (72048, '269bbc5ed0956cd58014f0a02f3b31ab7b0bf3202bbdbc66457f06dbe50fbaed', 493, 4096, '2136eccb8c8b10fcd46b414f82a66c358ec8a6fea6b4c004134b274a41cdbc49', '5820206411f05fe727c9c952031928bf75639ea5e1e7e909bbd6c265dcfecd5c'),
    'Contents/Home/lib/libattach.dylib': (71888, 'd6f8a37fc720a762582b3b088197f06fb959f64119d977effe30ac842eb345ad', 420, 4096, '1ee039c359a984b05440cba20cec37d53a58d6fbc5f235336bcc2b6160c5374f', 'cf1204e6e3e6d0e51e74109aa06f76d4ead31674610d352ac7144853e2faace0'),
    'Contents/Home/lib/libawt.dylib': (551776, 'cede2c8c314eb780fb2c7a2d0055de9324290449d4c0f1ef0e7fd684b84b2e8a', 420, 4096, '1971f636d24d6bfaf94b39e142ef4a6fca27e4b074e949830103e78b9e6d708a', '95448e55077f380bad0d446aeddeb2e7574166f0fc7395d17c03197ed4f35b47'),
    'Contents/Home/lib/libawt_lwawt.dylib': (1237072, 'a540b8ca7a8c8c77f0db3f80c2b3449537b4a758bf1727f45361c4dcccf0b7ac', 420, 4096, 'b7abc398794a3df3dde66fdd307bed2b8620391a1806e82d322ae1fcedb44013', 'c3afa5e4073fe15c3469906cf55fa61af1cb7c96f8332afbb33540f2fc89410a'),
    'Contents/Home/lib/libdt_socket.dylib': (73968, '586dcfb17ad55d03f46aa75bf0b8ccd622a31bca3eab8cf3fdd673c3e0f380b4', 420, 4096, '25dfbf9858a080d336761db51c91a15743b3c7b6c4014777196ee6ca508fdff2', '56bab82e7d9d746751f7bf5adc56ea45232a1c3c8cc6eda1eec2022476e2ff82'),
    'Contents/Home/lib/libextnet.dylib': (70688, 'af867a2643ec8ad87410d25f1ac9a1558a12f7b0607971980e7d367f44fc7c05', 420, 4096, '19ce2735eaecb88e1357eb2b0f812735f754c00c40d8a630f47103c6bd46a6ed', '4bb722382fc9a5b0952c9c00326cc1cb750f1d1ff42bf197f603d9b177371b65'),
    'Contents/Home/lib/libfontmanager.dylib': (1495264, '767ef168afd12358fb5cfea40e81de48db6ff098ac0b749107fb2a991e5b932c', 420, 4096, '709e45b1c7f08af7d2066437871de13d033641576bbc75436890c9fd860dd905', '6bddbaf14a03552723e7de068c63444e38505c4aca5143dc74c0616e9f400af7'),
    'Contents/Home/lib/libfreetype.dylib': (655312, '15ea8e49a8664d567c8ea7a322cb27acec314c4c24b45fbadae293804a94c46e', 420, 4096, 'a42a4f338dab4bea4d122f52620562cb1732ef541424f3495b5a09e3703bed75', '0a293e16bf09f4fc912bfc83a4a817ed8f9873491a1045428eef818813428c05'),
    'Contents/Home/lib/libinstrument.dylib': (109296, '9414eb2d038ae3e6a528190dff15d742162272af222cce70d977765b298002d7', 420, 4096, '72af516595aa054024ed9b2dc2f06b42427ba4fc878f6f67e12118eabd4c32c3', 'a811950afc23460fdd481ddee89cfdbb0bbf1bd980f5128619f517a8296b1b5a'),
    'Contents/Home/lib/libj2gss.dylib': (92912, '0a994ea5b716ce8f03558bc42380f58276bec45802389216c64602348546946c', 420, 4096, '2bfd8c08c11fc8f53b30dc1e561ca0a6913ef0362048cc91df00d98bf9365ee2', '0170321b65c0f6971eaf7206813e925c9956bde972cd26f7583dc9acf877c894'),
    'Contents/Home/lib/libj2pcsc.dylib': (71776, '963aded7be912370462f5697567dd00d11ac7c547f0f5dfae5340208262f8cdb', 420, 4096, 'd14db42aa3626c6cbdf045d48e432ff835337b412ec7efde5ac13dfd3021ac25', '56f26ee391c975b3a706366d555e710217a4565649c4fd141bcdd1e2d977559d'),
    'Contents/Home/lib/libj2pkcs11.dylib': (131184, '459d504968c04ba459a4b3f1072fe68dae46a72d7e2c617fa5ffc6c9201a079b', 420, 4096, 'bc665e93021f092dbbe35e0103c3c6091d6c0f844c62fd879c978ebd02e1a43a', '51d88f235e9532055626ed261f13f3b0314a37a28a0ad1e7ec56149f23f0e362'),
    'Contents/Home/lib/libjaas.dylib': (69952, '8222b05dae683eaaae32b669d06c7fad715a212e0e03432494c194bb41f5abb3', 420, 4096, '22e5e64c92f1376a2a63d083971964b7205ef4707e69c876999446351a01ade3', 'ab0f96f517fd4341df38665cd2209499e392791a0b2f69a56e97fa36f9706b29'),
    'Contents/Home/lib/libjava.dylib': (203936, '96fefffa347ac39ca5be9c350789132e60a9fc32f32f64e45ca275a53069d180', 420, 4096, '86ff9751cd8864bc4f640c92f9e7d5f1d6ad6c1fbe96a5b6601cb42021d3e402', '55980713cf82f5ccb411483d1713ca4e8b8341e0514795370641e021525dc028'),
    'Contents/Home/lib/libjavajpeg.dylib': (265104, '1de5afec8ff0d2c6de9247bae481aab16ad150ace09ded7f484cb3328efa6f90', 420, 4096, '9e8f8d3d18b549f26796cd13c0352b6bf0fb97e2519c7a4903dfb96833924286', '566d1fbcc15115e954765adc0c7867d03c9705c34d9c3bce56369cce7480e4a3'),
    'Contents/Home/lib/libjawt.dylib': (53424, '436546305b4797b81a53440efcdd3b2bccd0c0dff220205f0bb3b719e37ac2db', 420, 4096, '8a51e7243a7abd496b56918bbae3dc85b8d149ecb248cb7b5975a9b9a0157e24', '3d17e8d1d9445a3f997324b3ed0185323d431cc9549c4c794a38844377876ddf'),
    'Contents/Home/lib/libjdwp.dylib': (295552, '9f62afe88f66fed3cc3eda753a606f69667737199ab57d25eaa377ac24bc266d', 420, 4096, '025d5d0bf1e2f73360903d765af66f931d4ea6b51f8426b45300047495c779f9', '1886e2515d24177901078c5d151a6e67f98abe3dc1338dd1bbc1f6d06d9eafb6'),
    'Contents/Home/lib/libjimage.dylib': (77584, '3de8cc93f13b0c5e3ec7a55f4e761c0f5b7e6b26416aef0b70205b9200d9e31d', 420, 4096, 'd00eb1df3f22d3b37c351dc64e1cc014ff4f15713ce9403e350e5462e86c9acb', '5bcda65633e9475b99adce393d84d145093c7ead279266aeff63efa5f51b5f6d'),
    'Contents/Home/lib/libjli.dylib': (148752, 'f3041707b3589a2221fd7c866ac190814c80814d78ec6fafe750fc79fe7e6ff3', 420, 4096, '783d5d077782a46ae06e863b908eddf3e1ec459650d76c6b394cb5efb89e2b32', 'ba15aa097f9675bd3f1c5e5f126ff9df0b13d28bf4c28b59a61775526be44c4e'),
    'Contents/Home/lib/libjsig.dylib': (70896, '312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4', 420, 4096, 'fe71612f678286f30767f60ef377da9110dd43bccaffef1d00cb4d9cf23b9b61', '6ac13bf4d377ce935beaa1c9f3f45bed877fc862de994a6daf4d7837cb7c471d'),
    'Contents/Home/lib/libjsound.dylib': (136000, '28d4a07c3c63db5bca3c94de49266f4093d9a83a4d343588e4d3099d1bdab0c4', 420, 4096, '24c523ef44509477a200348152fe3b826bfa5c01c67d539a10e95dfd15c338e3', '59b21714ef5e4eb7ba54aa7cd1d9865941bfd3a7f4349b6475da26e6fe146c42'),
    'Contents/Home/lib/liblcms.dylib': (410656, 'a02a051e7e49ef1796b06532c4adab1b413c54558bd1fa097d2a8204381f049f', 420, 4096, 'c249a088a2b7d9b5dd044dee3611357b289b6d610e43ed9bae5e636b904dbb27', 'd9bd1bd67cea2666eb9fcaa2a7ce7d1fb489436dcd16643cc7e7c8e4c13e7fb6'),
    'Contents/Home/lib/libmanagement.dylib': (76880, '3e54899c2f6c47dd377a3db9b3a9d617e2b7d90a5268ebac6bfb2114b08bef32', 420, 4096, '0d158c40f7e0dc7a54f8a94c2114ef542bf555c032cbc66b695c2322205106eb', '4f3d862f339e65e9f05d2c05e9300aa4d6987df77883424ab51825b299e0ea54'),
    'Contents/Home/lib/libmanagement_agent.dylib': (69952, '79917926692f3921a3e7f32f78cd6a7f0c2f8b570ece2e28ec6c9a414ce2ca0e', 420, 4096, 'fa713d3b5c6717de38a4e36b9438fce2e84100a89a7772f95c38a7a1b8277b17', '8690884888e0b5de9734d584935ce8e16ae898f2730ba4612e1ef37355a60a0d'),
    'Contents/Home/lib/libmanagement_ext.dylib': (75280, 'daaed83579929aa49972046d23f6e8ca8450473b9f7088ad903457632a453e1f', 420, 4096, '213a0935b96e25fa402c1ed0804af38747f38a4caf3e3e98abaed65a3b7c2136', 'b47349ce52afd805cc72be1fcdc8c05d6d9b03bbee98a1b2e5b9d0b6d7e90143'),
    'Contents/Home/lib/libmlib_image.dylib': (507888, 'b89ee32dbc71d17f8691e0d5978f29337dfd16f9fc1402836183b21b192225ea', 420, 4096, '43b7accc902a71c1008b4956e0b5fda9348d6a89f3b20ee7b64cfb8dbdd31123', 'ffd71e64406496f6ddae12a55d1eebf178f548b8d5326c98f348c276a9eab97d'),
    'Contents/Home/lib/libnet.dylib': (138800, '2d1eed9237de915d58f5f241f5c3d4f7811444b150f31e4eff56fa45ae503466', 420, 4096, '0902c50e4b235039f6a32503afbbe5cf34c34cce4f18712a61b5f23774d2c97a', '575609f4984ed613877e8f50e1f03946db69f08bcc03d9b17daeef6ad04dd376'),
    'Contents/Home/lib/libnio.dylib': (126432, 'f58fb9a0dbdd37c5322e72fc1633998d37a85303c11c7f37812acdc94ea8cc08', 420, 4096, 'a42942e4fc95f14aa811c1d83c457b1de112360e99ff0bfa4443372f80d3304a', '1340cd81c7b2ba1f63826693554b1638ac99e77b1222615786aced39a2b6ba13'),
    'Contents/Home/lib/libosx.dylib': (74720, '7b7043220f041ce3a51cf2d05618fd776e7421a360697c726d337de33f3e7dae', 420, 4096, '11855fc8a57d5c4f9c60877a41235d2bdf553db4ce68abaf24f1e8bbb969e79e', 'ccf3f951681d2be3f426cd57e5c46a3b6458b0c6c82391df1fa0d56661ec4058'),
    'Contents/Home/lib/libosxapp.dylib': (189680, '940108380533f4d499665a48b17814c7009103751976b64879106e6297f035cf', 420, 4096, '8a1439d49b65d14cdf076ad63cd98699437926dced9897f000fec309ecf458bf', '0fcccd6bc1268ec703519c397a1c824fd0b37cfce3f2d728e73d3b4081c25ff2'),
    'Contents/Home/lib/libosxkrb5.dylib': (74496, 'f947c8a361de60081d345500a5d1db749dcdd6a5d637d9f2ff2c95ce90281edf', 420, 4096, '5c31d7c6bc75189a75ba8ce8ac39d8e872ca8469702566f032a4bf9efa5dca4b', '739cebafc9cc727f0b34797754a9e1bfda57505cd377bb1808e637aa0d824892'),
    'Contents/Home/lib/libosxsecurity.dylib': (75104, 'd811ef63c36b09d7d8dcb3d272376eacb44d048b006fbe8171b793112a1be1ec', 420, 4096, 'd9dcfb0de287b182c6779799427e5a68d6f1c9a2b2816321219f749d350eb167', 'c500e7f044a771db98a93666269abd45c5d301223b53591e0642cc026507aa74'),
    'Contents/Home/lib/libosxui.dylib': (99616, '7125eea603a7edf20d613677e533e979eafa2f5ee4ad34210ed0f86204a3a012', 420, 4096, '24df56495d85659cfa9a202709b021637417d71f38c2a7834faa5eb37515af48', 'ac0e1a60eba322b922bcc3d9f8d9ff5eb9c7ee244f46cc23c639b02ac4dc4c0b'),
    'Contents/Home/lib/libprefs.dylib': (74560, '7d58fe5f2de374a98cfa0a0b934516de3916e01a99b675a48a83a11395c8bd8d', 420, 4096, '8131f8229e57f86e089a0c0414ffb9d27140c7ebc3ff3941b15e0d705e92f5a6', '14170c78ae26df08c66060cc66259d3150d390dc13849ce86f25c7e5fdc44206'),
    'Contents/Home/lib/librmi.dylib': (69648, 'c9f1a107df0b5d3571344aad2bd411a7ae38ba574061f93403880f0e05b999f4', 420, 4096, 'e2fd1c47f643109da628764161437a0cff379c0a4126458a1aa29822164ff2f6', 'ca5be22595ea80a27d0dac1cdf3b0de40ca70cad061ef3c65c0de6002b58b4b6'),
    'Contents/Home/lib/libsaproc.dylib': (112288, '0c1673963910b0acd284f2703632d82629880e31d2200927bcc477425dc56fe2', 420, 4096, '7fd522459f9437945c4206896291f21a0fd5046ecd2352021075b65f2da2dc0f', '8e0fa2fea573ab0056601697c33bbaec888b5a1ab461387cbe77be8efcd8a6e2'),
    'Contents/Home/lib/libsplashscreen.dylib': (457552, '97a03f3694205e2b0e6bd44e09e8e8b24eaa26a9d23fc63c7875ba4e1245f1bf', 420, 4096, '9a6b5055f2aec1a32b3abf6ea85aa4325b9232b4c38fe1cfe27d70746653713a', '5f8996334dd5e8c1cc774e8da64c5dff2bb40d66d86fb57cb1b8d7b76e86a7b7'),
    'Contents/Home/lib/libsyslookup.dylib': (36352, 'ac3566ac84ee620c01aaed05cf954b8eb5c418c6c99a229aa9d2d5b6459b14f3', 420, 4096, '3f2c8c14571118f7f8e732a105de18c6121412f35cc1361e4590aed82c02dfbd', '6eea9dcb1bec37c1488127501d1207fb76f0dba70d9094256cf8b2d04a971fa8'),
    'Contents/Home/lib/libverify.dylib': (106848, 'bc8fbc7b5152404d3d0580513ee6f9de056edf1525baf0413afbd126a51cba42', 420, 4096, '02511543daad02fac1fa80872a6b36bde23a10f7f69463ce127d1cf2fc020cf9', '604ef8a399557b7feddd81d505e946a1419565a25e2e161978a360f4f8739487'),
    'Contents/Home/lib/libzip.dylib': (162912, '78b7745680a58cf63c527d9bf1e2db4e65d699b6c203e7974b94da221755d832', 420, 4096, 'd4816306ccb1eaf498e0c13c5d93aa17cc4f0951a485a060285a222eac1fe732', '39afe0f7e7f9bb4be519257163c3a51b16479e6901f2aa68265cf55d8328fdd2'),
    'Contents/Home/lib/server/libjsig.dylib': (70896, '312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4', 420, 4096, 'fe71612f678286f30767f60ef377da9110dd43bccaffef1d00cb4d9cf23b9b61', '6ac13bf4d377ce935beaa1c9f3f45bed877fc862de994a6daf4d7837cb7c471d'),
    'Contents/Home/lib/server/libjvm.dylib': (16882064, 'aee1f37674901ee3fa41886743f3382e6e1445482aab66fe34576f30d01f7749', 420, 4096, '5017912d5ca187bc2c633ea6a2e5bf8bbca44580f9569a2ef3555649d32bd496', '27f3b95b1696f8512a173a5ee3f87cbd9af2a67efc7e62014499997ba668c862'),
    'Contents/MacOS/libjli.dylib': (147472, 'ba172dd8aab9b629864af3eddf195c076d1b49c04e8522a7a4f10c27aa6ca895', 420, 4096, 'db60a15d9d1304fbc39fdf19528f3ccfd0fe5e89a9640667d692a9fbbf6fec40', '1b12b617e666a3dafbf009903e600f1fd7c9a81f0aab1356546eddd4a82b1381'),
}
JDK_JVM_PINS = {
    'Contents/Home/jmods/java.base.jmod': (18551178, 'c5b13c8664f0b2c1d466a38a458210fef11e90218d23a1b0833856bbc9fa7f72', (
        ('bin/java', 70464, 'af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0', 0, 'Contents/Home/bin/java'),
        ('bin/keytool', 70464, 'af587a253678cda7ca2704daee936af1993305ce9a9bc6d5018f37f49d425fcb', 0, 'Contents/Home/bin/keytool'),
        ('lib/jspawnhelper', 72048, '269bbc5ed0956cd58014f0a02f3b31ab7b0bf3202bbdbc66457f06dbe50fbaed', 0, 'Contents/Home/lib/jspawnhelper'),
        ('lib/libjava.dylib', 203936, '96fefffa347ac39ca5be9c350789132e60a9fc32f32f64e45ca275a53069d180', 0, 'Contents/Home/lib/libjava.dylib'),
        ('lib/libjimage.dylib', 77584, '3de8cc93f13b0c5e3ec7a55f4e761c0f5b7e6b26416aef0b70205b9200d9e31d', 0, 'Contents/Home/lib/libjimage.dylib'),
        ('lib/libjli.dylib', 148752, 'f3041707b3589a2221fd7c866ac190814c80814d78ec6fafe750fc79fe7e6ff3', 0, 'Contents/Home/lib/libjli.dylib'),
        ('lib/libjsig.dylib', 70896, '312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4', 0, 'Contents/Home/lib/libjsig.dylib'),
        ('lib/libnet.dylib', 138800, '2d1eed9237de915d58f5f241f5c3d4f7811444b150f31e4eff56fa45ae503466', 0, 'Contents/Home/lib/libnet.dylib'),
        ('lib/libnio.dylib', 126432, 'f58fb9a0dbdd37c5322e72fc1633998d37a85303c11c7f37812acdc94ea8cc08', 0, 'Contents/Home/lib/libnio.dylib'),
        ('lib/libosxsecurity.dylib', 75104, 'd811ef63c36b09d7d8dcb3d272376eacb44d048b006fbe8171b793112a1be1ec', 0, 'Contents/Home/lib/libosxsecurity.dylib'),
        ('lib/libverify.dylib', 106848, 'bc8fbc7b5152404d3d0580513ee6f9de056edf1525baf0413afbd126a51cba42', 0, 'Contents/Home/lib/libverify.dylib'),
        ('lib/libzip.dylib', 162912, '78b7745680a58cf63c527d9bf1e2db4e65d699b6c203e7974b94da221755d832', 0, 'Contents/Home/lib/libzip.dylib'),
        ('lib/server/libjsig.dylib', 70896, '312471769e31f436e86ad1893a53f571e550e607f38b6e04aacd8337ca056ae4', 0, 'Contents/Home/lib/server/libjsig.dylib'),
        ('lib/server/libjvm.dylib', 16882064, 'aee1f37674901ee3fa41886743f3382e6e1445482aab66fe34576f30d01f7749', 0, 'Contents/Home/lib/server/libjvm.dylib'),
    )),
    'Contents/Home/jmods/java.compiler.jmod': (130713, '65a54bafb1c6d0bfc41a7230bf5f4b8b05e653a5815065343a53c3402c80f7d2', (
    )),
    'Contents/Home/jmods/java.datatransfer.jmod': (59211, '7c82d763d44b1afb1bf5aa9f71fe4daf1cc7d6925febb54b381e6f58785b4a76', (
    )),
    'Contents/Home/jmods/java.desktop.jmod': (13735658, '2e130b3645a8b8786d2a1ac43033fed2783262e3320a58bb701d4bb6f92da35c', (
        ('lib/libawt.dylib', 551776, 'cede2c8c314eb780fb2c7a2d0055de9324290449d4c0f1ef0e7fd684b84b2e8a', 0, 'Contents/Home/lib/libawt.dylib'),
        ('lib/libawt_lwawt.dylib', 1237072, 'a540b8ca7a8c8c77f0db3f80c2b3449537b4a758bf1727f45361c4dcccf0b7ac', 0, 'Contents/Home/lib/libawt_lwawt.dylib'),
        ('lib/libfontmanager.dylib', 1495264, '767ef168afd12358fb5cfea40e81de48db6ff098ac0b749107fb2a991e5b932c', 0, 'Contents/Home/lib/libfontmanager.dylib'),
        ('lib/libfreetype.dylib', 655312, '15ea8e49a8664d567c8ea7a322cb27acec314c4c24b45fbadae293804a94c46e', 0, 'Contents/Home/lib/libfreetype.dylib'),
        ('lib/libjavajpeg.dylib', 265104, '1de5afec8ff0d2c6de9247bae481aab16ad150ace09ded7f484cb3328efa6f90', 0, 'Contents/Home/lib/libjavajpeg.dylib'),
        ('lib/libjawt.dylib', 53424, '436546305b4797b81a53440efcdd3b2bccd0c0dff220205f0bb3b719e37ac2db', 0, 'Contents/Home/lib/libjawt.dylib'),
        ('lib/libjsound.dylib', 136000, '28d4a07c3c63db5bca3c94de49266f4093d9a83a4d343588e4d3099d1bdab0c4', 0, 'Contents/Home/lib/libjsound.dylib'),
        ('lib/liblcms.dylib', 410656, 'a02a051e7e49ef1796b06532c4adab1b413c54558bd1fa097d2a8204381f049f', 0, 'Contents/Home/lib/liblcms.dylib'),
        ('lib/libmlib_image.dylib', 507888, 'b89ee32dbc71d17f8691e0d5978f29337dfd16f9fc1402836183b21b192225ea', 0, 'Contents/Home/lib/libmlib_image.dylib'),
        ('lib/libosx.dylib', 74720, '7b7043220f041ce3a51cf2d05618fd776e7421a360697c726d337de33f3e7dae', 0, 'Contents/Home/lib/libosx.dylib'),
        ('lib/libosxapp.dylib', 189680, '940108380533f4d499665a48b17814c7009103751976b64879106e6297f035cf', 0, 'Contents/Home/lib/libosxapp.dylib'),
        ('lib/libosxui.dylib', 99616, '7125eea603a7edf20d613677e533e979eafa2f5ee4ad34210ed0f86204a3a012', 0, 'Contents/Home/lib/libosxui.dylib'),
        ('lib/libsplashscreen.dylib', 457552, '97a03f3694205e2b0e6bd44e09e8e8b24eaa26a9d23fc63c7875ba4e1245f1bf', 0, 'Contents/Home/lib/libsplashscreen.dylib'),
    )),
    'Contents/Home/jmods/java.instrument.jmod': (48218, 'fa990db928823d00d7f5d446d983a0d1052b4cb4247460fbcd981f378fbd329f', (
        ('lib/libinstrument.dylib', 109296, '9414eb2d038ae3e6a528190dff15d742162272af222cce70d977765b298002d7', 0, 'Contents/Home/lib/libinstrument.dylib'),
    )),
    'Contents/Home/jmods/java.logging.jmod': (128181, '49fbd84f70d917d852ee0dbad2d239ec72dde4ecc7e408ba6104d28fb1b3420c', (
    )),
    'Contents/Home/jmods/java.management.jmod': (907722, 'a86f8d54dea42825cf4fd91bcfdd32ae0888241a5e08d068f3f733ff727ca29c', (
        ('lib/libmanagement.dylib', 76880, '3e54899c2f6c47dd377a3db9b3a9d617e2b7d90a5268ebac6bfb2114b08bef32', 0, 'Contents/Home/lib/libmanagement.dylib'),
    )),
    'Contents/Home/jmods/java.management.rmi.jmod': (99522, 'f89d40da7c63b043494ca1d549f77b82a0479c3db9db3eb0210d9997b1c2c80f', (
    )),
    'Contents/Home/jmods/java.naming.jmod': (483330, '5bc68c04d7e8c709b79adb30527a566a753a90936c77d3b9bd989a3712d7471d', (
    )),
    'Contents/Home/jmods/java.net.http.jmod': (780867, '9d392605dbb6df1d53e6e8df5d929e453b677f3bbe3ce644e559611e0d74ca5c', (
    )),
    'Contents/Home/jmods/java.prefs.jmod': (90192, 'be17cb21c5c3fd7d424b1720d01da6083dda57af96ffba0f0b6233fad305efc5', (
        ('lib/libprefs.dylib', 74560, '7d58fe5f2de374a98cfa0a0b934516de3916e01a99b675a48a83a11395c8bd8d', 0, 'Contents/Home/lib/libprefs.dylib'),
    )),
    'Contents/Home/jmods/java.rmi.jmod': (282812, '7ab12d3c8f653e67c22d153b3721f22047b84b6af6c3dd7215c6af17b0bf6e5e', (
        ('bin/rmiregistry', 70464, 'aea46addd6ba9f6a44b119550000cac3e999bf2bd85673e5105ae0609c960850', 0, 'Contents/Home/bin/rmiregistry'),
        ('lib/librmi.dylib', 69648, 'c9f1a107df0b5d3571344aad2bd411a7ae38ba574061f93403880f0e05b999f4', 0, 'Contents/Home/lib/librmi.dylib'),
    )),
    'Contents/Home/jmods/java.scripting.jmod': (53024, '00c7790218521c4911969b6487b0159ce3c008484a0161b217d194ba4a83d90e', (
        ('bin/jrunscript', 70464, '9bd7764585944634431ca97193f2c714c562b06ce6ab6aa918b84d36274a3283', 0, 'Contents/Home/bin/jrunscript'),
    )),
    'Contents/Home/jmods/java.se.jmod': (9861, '5a4954612f22633eb6e8ff6d248afe71a28dcea875ded17de51195685e83d259', (
    )),
    'Contents/Home/jmods/java.security.jgss.jmod': (635142, 'd3a56dfba805cb9cbc96818b09c63041b9746818a782183455d5aad05a6113ef', (
        ('lib/libj2gss.dylib', 92912, '0a994ea5b716ce8f03558bc42380f58276bec45802389216c64602348546946c', 0, 'Contents/Home/lib/libj2gss.dylib'),
        ('lib/libosxkrb5.dylib', 74496, 'f947c8a361de60081d345500a5d1db749dcdd6a5d637d9f2ff2c95ce90281edf', 0, 'Contents/Home/lib/libosxkrb5.dylib'),
    )),
    'Contents/Home/jmods/java.security.sasl.jmod': (89370, '22ff2e4627cc75819a7b2350385246d7727d43a5e5861904604919a71eb045e3', (
    )),
    'Contents/Home/jmods/java.smartcardio.jmod': (67826, 'fa14fcb5449fb8d4b3156341d8d63a3e14ea1a961a5164daae67d6c3abc69403', (
        ('lib/libj2pcsc.dylib', 71776, '963aded7be912370462f5697567dd00d11ac7c547f0f5dfae5340208262f8cdb', 0, 'Contents/Home/lib/libj2pcsc.dylib'),
    )),
    'Contents/Home/jmods/java.sql.jmod': (83694, '2a8a9c368e5bd64db223a61dd700f478fb4cbc96fe3eaa5a43d2236d69e0bd61', (
    )),
    'Contents/Home/jmods/java.sql.rowset.jmod': (221191, 'e32dfff580146e74abecf98ba3aaa47eff832d82b926698986056ad79818882f', (
    )),
    'Contents/Home/jmods/java.transaction.xa.jmod': (11688, 'c4c3798c40a017a75a3c727d12fadfe357b743b401729ea8f5102bcc7cf031eb', (
    )),
    'Contents/Home/jmods/java.xml.crypto.jmod': (706479, '12052954b9d0b8cb49d15f4d36be080929bf4390c89b6c5237c58c471f3ec58b', (
    )),
    'Contents/Home/jmods/java.xml.jmod': (5235159, '21f3c25826a06c24078bfdd7eb7b98976f70eb8f205b731f72d040cbd98563ca', (
    )),
    'Contents/Home/jmods/jdk.accessibility.jmod': (58053, '2f1a266e82b92bd0c68ffe09d7edb4ace387a1af8f4e8d6f6b23845f5a7a18ab', (
    )),
    'Contents/Home/jmods/jdk.attach.jmod': (42665, '1812e21e1c4580cb021b97925c37202ce09e44d25e8ce5e38e225432ecaa5955', (
        ('lib/libattach.dylib', 71888, 'd6f8a37fc720a762582b3b088197f06fb959f64119d977effe30ac842eb345ad', 0, 'Contents/Home/lib/libattach.dylib'),
    )),
    'Contents/Home/jmods/jdk.charsets.jmod': (1713214, '4c707f9b9a1000e3356cd7134e935c3a814d25a5fb3a193d90d81c32226773f3', (
    )),
    'Contents/Home/jmods/jdk.compiler.jmod': (9266695, '0d3e5c397104cf7994c01facc6f82c84cbe374b93ccb6fffc9537d53a612d2a0', (
        ('bin/javac', 70464, '6f5159301c750bba340390eda5fdd4a0959445355f97c40aa9c2addb00ede5ab', 0, 'Contents/Home/bin/javac'),
        ('bin/serialver', 70464, 'fdfd5b5d9929c77750e480951212eabe800e4a2daa3b73995539242333d6f22e', 0, 'Contents/Home/bin/serialver'),
    )),
    'Contents/Home/jmods/jdk.crypto.cryptoki.jmod': (387773, '6034469b16af2df3e794d58576124b17bfd5e27bc16ae729a097d42a6c4dfc8d', (
        ('lib/libj2pkcs11.dylib', 131184, '459d504968c04ba459a4b3f1072fe68dae46a72d7e2c617fa5ffc6c9201a079b', 0, 'Contents/Home/lib/libj2pkcs11.dylib'),
    )),
    'Contents/Home/jmods/jdk.crypto.ec.jmod': (139832, '2571836a0f27019ad24b91c1b45baea3ff14b72896cd7f16c5712d41df1f44e2', (
    )),
    'Contents/Home/jmods/jdk.dynalink.jmod': (166030, '23e1257378ff83ab4dab243d74ae7e370d3774c747fd3f78d2e4831915e0171e', (
    )),
    'Contents/Home/jmods/jdk.editpad.jmod': (15299, 'cb9786df0921480e5d027db774b01e882e14a8f869b2dce25f3ca383048d4664', (
    )),
    'Contents/Home/jmods/jdk.hotspot.agent.jmod': (2294768, '8a30c9924f49113838d9b8f0a713f840f6982b1579949a4e411bfd8747251dd4', (
        ('bin/jhsdb', 70464, '12c20fd4facc8ed4f31c813bf140b1da596797a5e0932ffba13c48f72f22bc3e', 0, 'Contents/Home/bin/jhsdb'),
        ('lib/libsaproc.dylib', 112288, '0c1673963910b0acd284f2703632d82629880e31d2200927bcc477425dc56fe2', 0, 'Contents/Home/lib/libsaproc.dylib'),
    )),
    'Contents/Home/jmods/jdk.httpserver.jmod': (117549, 'd94986a7f8233914e912065d407ca495b2b5698c5e05c6066c6b2ec3a29a3a92', (
    )),
    'Contents/Home/jmods/jdk.incubator.foreign.jmod': (330457, '8f33107630784a9597c0ee15e3780cb057e8e12fe1404c5decca23df7175fb77', (
        ('lib/libsyslookup.dylib', 36352, 'ac3566ac84ee620c01aaed05cf954b8eb5c418c6c99a229aa9d2d5b6459b14f3', 0, 'Contents/Home/lib/libsyslookup.dylib'),
    )),
    'Contents/Home/jmods/jdk.incubator.vector.jmod': (712944, '20ccbace5a4491de3dde916b49063b4dbb3fc685b172047bcf21132d05f3b65a', (
    )),
    'Contents/Home/jmods/jdk.internal.ed.jmod': (15171, 'c2b3c62764d01d3026154821f5296ed95caa7b2a7cb478595fda90941369a70f', (
    )),
    'Contents/Home/jmods/jdk.internal.jvmstat.jmod': (98912, 'b9ef5e76fe07b4c9b11bd095b41594f93d1ed9d2ec4a5d4b8786b271673b5b59', (
    )),
    'Contents/Home/jmods/jdk.internal.le.jmod': (465317, '2e924a6a29b7b59bf6035e5417878d2ebfd7da9d63a955c3dfb7ff14e81364d7', (
    )),
    'Contents/Home/jmods/jdk.internal.opt.jmod': (90621, 'e35f5503f26d477a2b686c7a3453f0aaf78c3da59f18fd214db74af11e660e5c', (
    )),
    'Contents/Home/jmods/jdk.internal.vm.ci.jmod': (454061, '74d08c1f7e9175dbe177f1f34c6b455aa6568141a4145a195526045675688adc', (
    )),
    'Contents/Home/jmods/jdk.internal.vm.compiler.jmod': (9648, 'eff467c1a1759c7a33a3d22c8c2ccb55714ec670e5a17613b652d309c692d0e3', (
    )),
    'Contents/Home/jmods/jdk.internal.vm.compiler.management.jmod': (9652, '12a199c77fa95f730c1143ef6fed0555815817ca4672ced7f5bd95b47b22b7c5', (
    )),
    'Contents/Home/jmods/jdk.jartool.jmod': (282133, '7fc983678c884f5e12afb2bd44c8422d6fb12afaf7e982ca88199d4fbf275b92', (
        ('bin/jar', 70448, 'c55e508c52019bb483ee2e737b751ed44d5e9e86abe660c713404db43c58803d', 0, 'Contents/Home/bin/jar'),
        ('bin/jarsigner', 70464, 'fe9a1276c5a18c115177f0e7a5bea9b3163739e280332044564089be7f766c64', 0, 'Contents/Home/bin/jarsigner'),
    )),
    'Contents/Home/jmods/jdk.javadoc.jmod': (1390142, '4e8d87380429738fa9398a4c63be419974e282eaa4700ba0e7e19ff8a31a00f9', (
        ('bin/javadoc', 70464, '16c9e93773c99393bac5bbbe12ad23472dfacdb77732da1b8720e743b787bb06', 0, 'Contents/Home/bin/javadoc'),
    )),
    'Contents/Home/jmods/jdk.jcmd.jmod': (167370, 'a9ad60567d9dec840d044b9ec1be7291b2444efc5dc68a029c5bd975269d6011', (
        ('bin/jcmd', 70464, 'e3aebdd820297b64e041203f766ebf28986abf0c8cf3e59ba0681d935160c0eb', 0, 'Contents/Home/bin/jcmd'),
        ('bin/jinfo', 70464, '939b38d404cc9055d2d3039a6fbfdfea4d783a370512bf1d7084f340e3a7337e', 0, 'Contents/Home/bin/jinfo'),
        ('bin/jmap', 70464, 'b491f891489a84c668915be116b28f26ef399501f249751a7ee197ba4b03e078', 0, 'Contents/Home/bin/jmap'),
        ('bin/jps', 70448, '5c09726ceee3b97982540aeaa84be190b8e6ac155d88b8507235079ba8310fe1', 0, 'Contents/Home/bin/jps'),
        ('bin/jstack', 70464, 'edbd8c8b0690b4844a75d2bd17ae6563baf63ef4942bedd16d5230f6e4b974a1', 0, 'Contents/Home/bin/jstack'),
        ('bin/jstat', 70464, '3fd61c3e2c179717a92fb19ebea8ffbe56a9eedad8eec82482695c38ce4f3cfc', 0, 'Contents/Home/bin/jstat'),
    )),
    'Contents/Home/jmods/jdk.jconsole.jmod': (482846, 'f93a2e0de191abfc1887109d8c880ed20633e5afd646c5ecff3ff3c53421d69e', (
        ('bin/jconsole', 70464, 'a7ddaf2cbea00efdbdb6eeaf1075ea2c6ae726da656831c5f832680fea80d504', 0, 'Contents/Home/bin/jconsole'),
    )),
    'Contents/Home/jmods/jdk.jdeps.jmod': (761505, 'd91ae45f53b149f40247a680698e748e0738e7c90405edc142a333c2c788063f', (
        ('bin/javap', 70464, '0b318cfea6a2866918cda88c64db9919e9d668aa2f7cc1bb0ccb11f49b243bbb', 0, 'Contents/Home/bin/javap'),
        ('bin/jdeprscan', 70464, 'b68b8f98cda671af91f9c1efc4a014828cf34d80d8487d2e222f82b55bb373b6', 0, 'Contents/Home/bin/jdeprscan'),
        ('bin/jdeps', 70464, '530d87e93a3321c91a0e5603077dc7a759b96e139bea8348fb1cd78c8059b90f', 0, 'Contents/Home/bin/jdeps'),
    )),
    'Contents/Home/jmods/jdk.jdi.jmod': (855863, '4ecb7b3b3a0879d8b628c8c1d17cdafd0116183226e194eb690c3c7504968325', (
        ('bin/jdb', 70448, '229e5965e072b20783c5bd008c39dd914bcd4223d5058767a3f4af2be0f2cb83', 0, 'Contents/Home/bin/jdb'),
    )),
    'Contents/Home/jmods/jdk.jdwp.agent.jmod': (129776, '8e5934f5f19a79bec5ddad6b179fb3a92c5578bb600bee7f6147a1b04c800d3d', (
        ('lib/libdt_socket.dylib', 73968, '586dcfb17ad55d03f46aa75bf0b8ccd622a31bca3eab8cf3fdd673c3e0f380b4', 0, 'Contents/Home/lib/libdt_socket.dylib'),
        ('lib/libjdwp.dylib', 295552, '9f62afe88f66fed3cc3eda753a606f69667737199ab57d25eaa377ac24bc266d', 0, 'Contents/Home/lib/libjdwp.dylib'),
    )),
    'Contents/Home/jmods/jdk.jfr.jmod': (653424, '3829993357ec5d588a3f4f2e1f6cf64bdfb5f0d63745f481f6660f94babd16c3', (
        ('bin/jfr', 70448, 'da2a39b0eb0baae163398254c02f0e74d67b0d3b5dd4faedf500eac7bf11a630', 0, 'Contents/Home/bin/jfr'),
    )),
    'Contents/Home/jmods/jdk.jlink.jmod': (425901, '488aeb6c2b0ed5ecd7f299a40145e589a0218bfaa5912a36aad83839e6451c31', (
        ('bin/jimage', 70464, '66ff78759e96a1e130a0fb8cdcf37eac7d542ca49860726b0bed79f311405522', 0, 'Contents/Home/bin/jimage'),
        ('bin/jlink', 70464, '601685bdfbfd2eb31d01e11dee94865f48910d90610829aa2c010c3ababf7650', 0, 'Contents/Home/bin/jlink'),
        ('bin/jmod', 70464, 'fc3a0982042318463a1648324f2432a71893f745f0e780b87ee75c3f6e7af4c8', 0, 'Contents/Home/bin/jmod'),
    )),
    'Contents/Home/jmods/jdk.jpackage.jmod': (695574, '2eb37c39930a3d8d046e180c8ad65630a0b83dc5b63791c115c78f856e14dd6b', (
        ('bin/jpackage', 70464, 'c4aa90b52f2904e5abb87ea52ce108b25b733b5b2dd4a1c0cfd2fa61ac305342', 0, 'Contents/Home/bin/jpackage'),
        ('classes/jdk/jpackage/internal/resources/jpackageapplauncher', 185600, '73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442', 0, None),
    )),
    'Contents/Home/jmods/jdk.jshell.jmod': (691552, '8441d5ef733f33aba718ad2ed48610ddd39f43efadeca596b20010bd316de2b0', (
        ('bin/jshell', 70464, '73c4db331de31cb6c261fe5593d6d40cd2023cf6d584f0cb2b3f5fb03fa7a609', 0, 'Contents/Home/bin/jshell'),
    )),
    'Contents/Home/jmods/jdk.jsobject.jmod': (10757, '6d15a02fabc9c9d24100b296dd1918f41d37a0d7d829d3edf5a90f4761a068ef', (
    )),
    'Contents/Home/jmods/jdk.jstatd.jmod': (42575, '3f98f2dacdf9530e36f359962277463519ea18cbb61460bf5131a93fb96a585b', (
        ('bin/jstatd', 70464, '13e9c26d467d2791d6dc5902d876d0a1a323e8472133d436ae64df65ce219aa0', 0, 'Contents/Home/bin/jstatd'),
    )),
    'Contents/Home/jmods/jdk.localedata.jmod': (10252728, '633545f4957ed2891cd2d35478397b9a08bb18137d5ff845c7439edb64f4d143', (
    )),
    'Contents/Home/jmods/jdk.management.agent.jmod': (102338, '24621a245cd5d7e6ee84f14a168ec6ea06922e55d1eebcabcfbcc09abe56317d', (
        ('lib/libmanagement_agent.dylib', 69952, '79917926692f3921a3e7f32f78cd6a7f0c2f8b570ece2e28ec6c9a414ce2ca0e', 0, 'Contents/Home/lib/libmanagement_agent.dylib'),
    )),
    'Contents/Home/jmods/jdk.management.jfr.jmod': (62410, '7c72a851837eaf38fbc0e1c9306c10be25d6262aa01cd745efee8059a1e179ee', (
    )),
    'Contents/Home/jmods/jdk.management.jmod': (80055, 'bdb1d3929ac992562e667c32aeac4d26c7b23affc1419a717acdc04466d858ca', (
        ('lib/libmanagement_ext.dylib', 75280, 'daaed83579929aa49972046d23f6e8ca8450473b9f7088ad903457632a453e1f', 0, 'Contents/Home/lib/libmanagement_ext.dylib'),
    )),
    'Contents/Home/jmods/jdk.naming.dns.jmod': (69884, '9e186d77fc05166aed951ac607569eaca5b1fee6e9caa70a7ace7a378cfbc536', (
    )),
    'Contents/Home/jmods/jdk.naming.rmi.jmod': (30997, 'b190a44217052d7dc2fcdc9b77986f8964b8e0da0b67fec0f50ca495f1a614ae', (
    )),
    'Contents/Home/jmods/jdk.net.jmod': (35355, '8d5a877d2a481231624572e6a14f705de2aa650b04dd62a25d855222a5d8baa7', (
        ('lib/libextnet.dylib', 70688, 'af867a2643ec8ad87410d25f1ac9a1558a12f7b0607971980e7d367f44fc7c05', 0, 'Contents/Home/lib/libextnet.dylib'),
    )),
    'Contents/Home/jmods/jdk.nio.mapmode.jmod': (10225, '640d5b4cb5a975c9fdf6d87d10ea09a887f9260ee8fdf1196b8e3a1e20eb3a52', (
    )),
    'Contents/Home/jmods/jdk.random.jmod': (29530, 'eba11c06b11e7ab8970ae61a6e52b498c76cab8b055a0146515cd17d4eb64c4e', (
    )),
    'Contents/Home/jmods/jdk.sctp.jmod': (31222, 'b224332e3f4867dad790b8fa8dbf4d8f7ae512ad57aea2ef133251205bc3fc64', (
    )),
    'Contents/Home/jmods/jdk.security.auth.jmod': (80035, '3fb7d9684c3202f85cdb95681ae6d50fa2956289748f7458cfdde3606b53e6f8', (
        ('lib/libjaas.dylib', 69952, '8222b05dae683eaaae32b669d06c7fad715a212e0e03432494c194bb41f5abb3', 0, 'Contents/Home/lib/libjaas.dylib'),
    )),
    'Contents/Home/jmods/jdk.security.jgss.jmod': (32855, 'fe87ba695930c3210259990d3252062c05234539336a17cf8a37e440f505364b', (
    )),
    'Contents/Home/jmods/jdk.unsupported.desktop.jmod': (21630, 'd256fd3b3214b8af0910f98948db73cd35575f4e83d1c1b0e36f6af869ce0d8a', (
    )),
    'Contents/Home/jmods/jdk.unsupported.jmod': (25015, '084eb63668c949ff7f740a7f96d56f891ca6bd9a25db1acbbc5d20a6ef18db6f', (
    )),
    'Contents/Home/jmods/jdk.xml.dom.jmod': (49991, '77607422ce0c32d442c09d7968fe69df1a0c37038c4f69582648d6fbcc7fe5a9', (
    )),
    'Contents/Home/jmods/jdk.zipfs.jmod': (112825, 'd12fab8df559f83488adfb877eaf84670f9c9a74c07ac2f84a36c18840f01aaa', (
    )),
    'Contents/Home/lib/jrt-fs.jar': (110514, '1c86328755f2040440d0677b124818991b60b36a37efdbca383bd6a0d64e976f', (
    )),
}
ELF_PINS = {
    'android-15/renderscript/lib/blas/arm64-v8a/libblasV8.so': ('sdk/build-tools/35.0.0/renderscript/lib/blas/arm64-v8a/libblasV8.so', 1453592, '6da7926b4509125c41c57b8ef94186eaecf86ee4b3d82448bf2ea9b7b3ce1c44', 420, b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x18'\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1c\x00\x1b\x00"),
    'android-15/renderscript/lib/blas/armeabi-v7a/libblasV8.so': ('sdk/build-tools/35.0.0/renderscript/lib/blas/armeabi-v7a/libblasV8.so', 905428, '79611c8abff2b3c5871b1635e292df51f15edb5d55a13eb33dc6d2b8cc79ff3f', 420, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\x9c\xcc\r\x00\x00\x02\x00\x054\x00 \x00\x08\x00(\x00\x1b\x00\x1a\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/blas/x86/libblasV8.so': ('sdk/build-tools/35.0.0/renderscript/lib/blas/x86/libblasV8.so', 1721288, 'eb1233432f36e652742b53c4f51402e956f397c28a40e33cf16876446efd4a6c', 420, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00h?\x1a\x00\x00\x00\x00\x004\x00 \x00\x08\x00(\x00\x1c\x00\x1b\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/blas/x86_64/libblasV8.so': ('sdk/build-tools/35.0.0/renderscript/lib/blas/x86_64/libblasV8.so', 2053256, '68231ae39ffbe51a0411d176db5b6d25e1bdff2243767e2fc32ef9e78309879e', 420, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x88M\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1c\x00\x1b\x00'),
    'android-15/renderscript/lib/intermediates/arm64-v8a/libc.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/arm64-v8a/libc.so', 1135488, 'dba9e91341c1ac3213f939e8ea796c2ef08e8ceb8c46a2c33919902b7bdf66f6', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00L\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1e\x00\x1b\x00'),
    'android-15/renderscript/lib/intermediates/arm64-v8a/libm.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/arm64-v8a/libm.so', 265496, '06058af55fc85804d8a5f9b7b38ef726e22953e0a79b3b59cbcfad490872da85', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xd8\x06\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x19\x00\x18\x00'),
    'android-15/renderscript/lib/intermediates/armeabi-v7a/libc.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/armeabi-v7a/libc.so', 786416, '112d910aaaa214789a430bfd508cf068d8deeb12be598638877621522c393940', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\xc8\xfa\x0b\x00\x00\x02\x00\x054\x00 \x00\t\x00(\x00!\x00\x1e\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/intermediates/armeabi-v7a/libm.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/armeabi-v7a/libm.so', 140720, '034f9ae227cbbe6775019b88bcec08f6436b8579c7f9f1d3c46d1b6c832ba2cb', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\xa0!\x02\x00\x00\x02\x00\x054\x00 \x00\x08\x00(\x00\x1a\x00\x19\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/intermediates/x86/libc.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86/libc.so', 1057296, '40a4fde26723d09961af85e51b475275d9d90af168fc0b18379e09bbabffc5b0', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x008\x1d\x10\x00\x00\x00\x00\x004\x00 \x00\x08\x00(\x00\x1f\x00\x1c\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/intermediates/x86/libm.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86/libm.so', 232532, 'fe45ea2bbd8e60517ca68c751171bb05f0c5a630b20cebb5a115a5fc611873fc', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00D\x88\x03\x00\x00\x00\x00\x004\x00 \x00\x08\x00(\x00\x1a\x00\x19\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/intermediates/x86_64/libc.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86_64/libc.so', 1106040, 'ab4d975e69f32a91442972b5ce38897a029b4f4c493b53276eed2a4f83388b04', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xf8\xd8\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1e\x00\x1b\x00'),
    'android-15/renderscript/lib/intermediates/x86_64/libm.so': ('sdk/build-tools/35.0.0/renderscript/lib/intermediates/x86_64/libm.so', 323448, '3d25fdb833cd12af7418c17d2dc06e11dfd7d1a2319c2bcb787186a5a88c63a2', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x008\xe9\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x19\x00\x18\x00'),
    'android-15/renderscript/lib/packaged/arm64-v8a/libRSSupport.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/libRSSupport.so', 1236904, '742f14255f7fef22836543d15efa58109ec5a4476cc348bcc77e19d6aa767a65', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00\xb0\x07\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00(\xd9\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\n\x00@\x00\x1a\x00\x18\x00'),
    'android-15/renderscript/lib/packaged/arm64-v8a/librsjni.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/librsjni.so', 72000, '78431e398edb78091f31079f47478df270d50e32c2bc52869542db17ec7c1c03', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc0\x12\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1a\x00\x19\x00'),
    'android-15/renderscript/lib/packaged/arm64-v8a/librsjni_androidx.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/arm64-v8a/librsjni_androidx.so', 70192, '2223c4b74b487e3cf863ea53004aae901c033a0be87d8f1b83fb7397db2ff0cb', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00\x01\x00\x00\x00\x00`\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00p\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\t\x00@\x00\x17\x00\x15\x00'),
    'android-15/renderscript/lib/packaged/armeabi-v7a/libRSSupport.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/libRSSupport.so', 866420, '76dfbfb158c03fa4257f4826e5cc776967d22a10472daad97471a5d4b002f56e', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x000\x05\x004\x00\x00\x00d4\r\x00\x00\x02\x00\x054\x00 \x00\n\x00(\x00\x1a\x00\x18\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/armeabi-v7a/librsjni.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/librsjni.so', 59888, 'ca754bc0d51764af3286ce6ef088473479062738648c596c8ff61fa21ab3530e', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\xb8\xe5\x00\x00\x00\x02\x00\x054\x00 \x00\x08\x00(\x00\x1b\x00\x1a\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/armeabi-v7a/librsjni_androidx.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/armeabi-v7a/librsjni_androidx.so', 54256, 'b85df50798c21d3e68e7f1ad4e62fcd296cf6378a8c9c37ec3c2bc98ec05f604', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00(\x00\x01\x00\x00\x00\x00@\x00\x004\x00\x00\x00\x08\xd0\x00\x00\x00\x02\x00\x054\x00 \x00\t\x00(\x00\x19\x00\x17\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/x86/libRSSupport.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/libRSSupport.so', 1284312, 'dbfc5ae177ef690758ad47e3f5da37fb68f8e4d1aee118e35989a81ff5315fa7', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x10\x07\x004\x00\x00\x00\xc8\x94\x13\x00\x00\x00\x00\x004\x00 \x00\x0b\x00(\x00\x1a\x00\x18\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/x86/librsjni.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/librsjni.so', 57956, '297f7750e7b435938aa32459867c6a4d8623215034bbd66328c0628f9d1604bf', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00T\xde\x00\x00\x00\x00\x00\x004\x00 \x00\x08\x00(\x00\x1a\x00\x19\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/x86/librsjni_androidx.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86/librsjni_androidx.so', 65288, 'e462b50adf7864728229b340f594bcedb89fd3447167bd3b059880b6441d4aaa', 493, b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00P\x00\x004\x00\x00\x00H\xfb\x00\x00\x00\x00\x00\x004\x00 \x00\t\x00(\x00\x18\x00\x16\x00\x06\x00\x00\x004\x00\x00\x004\x00\x00\x00'),
    'android-15/renderscript/lib/packaged/x86_64/libRSSupport.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/libRSSupport.so', 1301136, 'f3fd63755dfbfcbc68b70c09a3b5d7dd22abc17e4d696f21e6505fba5c1eda8e', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x000\x08\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x10\xd4\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x0b\x00@\x00\x1a\x00\x18\x00'),
    'android-15/renderscript/lib/packaged/x86_64/librsjni.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/librsjni.so', 67912, 'd08807dd6762afe99625fcf9f0915be8aecad30fc4e5f0b7296407f09dcd0fd3', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc8\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x08\x00@\x00\x1a\x00\x19\x00'),
    'android-15/renderscript/lib/packaged/x86_64/librsjni_androidx.so': ('sdk/build-tools/35.0.0/renderscript/lib/packaged/x86_64/librsjni_androidx.so', 74256, '49165a8e0b5a2253d35e36ba4a44077dec03d0ee0fc99a2dc0edfa537c70f7c5', 493, b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00p\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00P\x1c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\t\x00@\x00\x17\x00\x15\x00'),
}
SDK_PINS = {
    'android-15/apksigner': ('Apksigner', 'sdk/build-tools/35.0.0/apksigner', 2959, 'b47549e373b895ce6ca620d0c7887e674d9615ffa837a86ac601dcfd04adb0f0', 493),
    'android-15/d8': ('D8', 'sdk/build-tools/35.0.0/d8', 2678, 'b773a721be3d4988dea9660815a9e441b76100e5b0f5c72b5893cfadadc76c6f', 493),
    'android-15/lib64/libc++.1.dylib': ('CxxIntel', 'sdk/build-tools/35.0.0/lib64/libc++.1.dylib', 680976, '46494d6cd3737f83ddf4fcda11d69c810cd324fa0114e8110757514f8aa767c8', 420),
    'android-15/lib64/libc++abi.1.dylib': ('CxxAbiIntel', 'sdk/build-tools/35.0.0/lib64/libc++abi.1.dylib', 179936, '89194f2f5b98042d0e16c4948d9dad4905821749a90dd9326bb7ce509028ba66', 420),
    'android-15/lld': ('LldShell', 'sdk/build-tools/35.0.0/lld', 647, 'a4d5291a75bfa2350de74a00a3aa5099f190fd6bc86c581bb38215720884fc15', 493),
    'android-15/lld-bin/lld': ('LldIntel', 'sdk/build-tools/35.0.0/lld-bin/lld', 33452016, '7497b5765b30cbaf67b07de4ef631eeaab6f6a21392f2852b3ac252a44a0a250', 493),
}
JPACKAGE_PIN = (4096, "1d400c75f9c46bc79e138a9b2ddc1d0d0189c7aa57626728ef3ce19e80570033",
                "2c87bed1e51b555b5204489c65070b7fec4aa5d2ffbb19d4978f7774445920f5")


class Refused(ValueError):
    """No partially emitted SOURCE is acceptable after a refusal."""


def need(value: bool, reason: str) -> None:
    if not value:
        raise Refused(reason)


def keys(value, expected, reason="object-shape"):
    need(type(value) is dict and set(value) == set(expected), reason)
    return value


def integer(value, low=0, high=(1 << 64) - 1):
    need(type(value) is int and low <= value <= high, "integer-bound")
    return value


def sha(value):
    need(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "sha256")
    return value


def text(value, maximum=512):
    need(type(value) is str and 0 < len(value) <= maximum and value.isascii()
         and all(32 <= ord(c) < 127 for c in value), "ascii-text")
    return value


def relative(value):
    text(value)
    parts = value.split("/")
    need(len(parts) <= 16 and all(p not in ("", ".", "..") and len(p) <= 255 and not p.endswith((".", " "))
         and all(c.isascii() and (c.isalnum() or c in "_+@.,= $-") for c in p) for p in parts), "relative-path")
    return value


def source_relative(value):
    relative(value)
    need("$" not in value, "source-path-grammar")
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def _json_shape_bound(raw):
    # Allocation precheck, not a second JSON grammar/semantic parser. The real
    # standard decoder still rejects malformed syntax, numbers and escapes.
    depth = arrays = objects = separators = width = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            width += 1
            need(width <= 131072, "json-string-bound")
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted, width = True, 0
        elif byte in (91, 123):
            depth += 1
            arrays += byte == 91
            objects += byte == 123
            need(depth <= 16 and arrays <= ENTRY_LIMIT + 1024 and objects <= 8192, "json-container-bound")
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, "json-depth")
        elif byte in (44, 58):
            separators += 1
            need(separators <= ENTRY_LIMIT * 16, "json-node-bound")
    need(not quoted and depth == 0, "json-closure")


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= DOCUMENT_LIMIT, "document-bound")
    _json_shape_bound(raw)
    def numeric(value):
        need(len(value) <= 20 and value.isascii() and value.isdigit(), "json-integer")
        return integer(int(value))
    def noninteger(_):
        raise Refused("json-noninteger")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_int=numeric,
                          parse_float=noninteger, parse_constant=noninteger)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("json-invalid") from error


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")


def receipt(value):
    keys(value, ("path", "bytes", "sha256"), "receipt-shape")
    relative(value["path"])
    integer(value["bytes"], 1, DOCUMENT_LIMIT)
    sha(value["sha256"])
    return value


class Inputs:
    """Finite byte mapping, never a resolver for a supplied filesystem locator."""
    def __init__(self, documents: Mapping[str, bytes]):
        need(type(documents) is dict and 0 < len(documents) <= RECORD_LIMIT, "input-set")
        need(all(type(k) is str and type(v) is bytes for k, v in documents.items()), "input-types")
        need(sum(len(v) for v in documents.values()) <= INPUT_LIMIT, "aggregate-input-bound")
        self.documents = dict(documents)
        self.used = set()
        self.indexed = {}
        self.groups = {}
        for path, pin in RETAINED.items():
            raw = self.raw(path)
            need((len(raw), hashlib.sha256(raw).hexdigest()) == pin, "retained-current-pin")
        for group, expected in (("jdk", ["jdk"]), ("other", [label for label in LABELS if label != "jdk"])):
            path = "evidence/" + group + "-completion.json"
            index = decode(self.raw(path))
            keys(index, ("schemaVersion", "kind", "labels", "records", "nativeExecuted", "nativeClosure", "supplierAuthority"), "index-shape")
            need(index["schemaVersion"] == 1 and type(index["schemaVersion"]) is int
                 and index["kind"] == "complete-catalogue-observation-index-data" and index["labels"] == expected
                 and all(index[k] is False for k in ("nativeExecuted", "nativeClosure", "supplierAuthority")), "index-header")
            need(type(index["records"]) is list and 0 < len(index["records"]) <= RECORD_LIMIT, "index-records")
            for item in index["records"]:
                receipt(item)
                leaf = item["path"]
                need(leaf.startswith("evidence/") and leaf not in self.indexed and leaf not in RETAINED
                     and leaf not in ("evidence/jdk-completion.json", "evidence/other-completion.json"), "index-duplicate-or-reserved")
                raw = self.raw(leaf)
                need((len(raw), hashlib.sha256(raw).hexdigest()) == (item["bytes"], item["sha256"]), "index-content-join")
                self.indexed[leaf] = item
                self.groups[leaf] = group
        # Index hashing does not imply a consumer used/validated that record.
        self.used = set(RETAINED) | {"evidence/jdk-completion.json", "evidence/other-completion.json"}

    def raw(self, path):
        need(path in self.documents, "missing-data-document")
        self.used.add(path)
        return self.documents[path]

    def document(self, path):
        need(path in self.indexed or path in RETAINED, "unindexed-document")
        return decode(self.raw(path))

    def group(self, path, label):
        need(path in RETAINED or self.groups.get(path) == ("jdk" if label == "jdk" else "other"), "index-label-join")

    def parent(self, value, label):
        receipt(value)
        path = OUTERS[label]
        raw = self.documents.get(path)
        need(raw is not None and value == {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "complete-parent-join")

    def finish(self):
        need(self.used == set(self.documents) and set(self.indexed).issubset(self.used), "unconsumed-or-extra-evidence")


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    kind: str
    mode: int
    size: int
    sha256: str | None
    target: str | None
    local: int | None
    data: int | None
    compressed: int | None
    method: int | None
    flags: int | None
    crc32: int | None
    creator: int | None
    hint: str | None

    def tuple(self):
        return {"name": self.name, "kind": self.kind, "mode": self.mode, "size": self.size, "sha256": self.sha256}


def _outer_rows(label, rows, counts, archive_bytes):
    """Shared raw-row checks; callers independently bind their real schema/pin."""
    need(type(rows) is list and 0 < len(rows) <= ENTRY_LIMIT, "outer-rows-bound")
    members, by_name = [], {}
    ordering = []
    for row in rows:
        need(type(row) is list and len(row) == len(COLUMNS), "outer-columns")
        member = Member(*row)
        relative(member.name)
        need(member.kind in ("file", "directory", "alias"), "outer-kind")
        integer(member.mode, 0, 0o177777)
        need(member.mode & ~0o170777 == 0 or label == "jdk" and member.kind == "directory"
             and member.mode == 0o042755, "archive-special-mode")
        integer(member.size, 0, 512 * 1024 * 1024)
        need(member.hint is None or type(member.hint) is str and member.hint in
             ("shell", "macho", "fat-macho-or-java-class", "elf", "pe", "zip", "jmod"), "outer-format")
        if member.kind == "file":
            sha(member.sha256)
            need(member.target is None and member.mode & 0o170000 in (0, 0o100000), "file-kind-mode")
        elif member.kind == "directory":
            need(member.size == 0 and member.sha256 is None and member.target is None and member.hint is None
                 and member.mode & 0o170000 in (0, 0o040000), "directory-kind-mode")
        else:
            text(member.target)
            need(member.size == 0 and member.sha256 is None and member.hint is None
                 and member.mode & 0o170000 in (0, 0o120000) and label == "jdk", "alias-kind-mode")
        if label == "jdk":
            need(all(v is None for v in (member.local, member.data, member.compressed, member.method, member.flags, member.crc32, member.creator)), "tar-no-zip-fields")
        else:
            for value in (member.local, member.data, member.compressed):
                integer(value, 0, archive_bytes)
            need(member.local < member.data and member.data + member.compressed <= archive_bytes, "zip-range")
            need(type(member.method) is int and member.method in (0, 8), "zip-method")
            integer(member.flags, 0, 65535); integer(member.crc32, 0, (1 << 32) - 1); integer(member.creator, 0, 255)
        key = member.name if label == "bundletool" else member.name.lower()
        need(not ordering or ordering[-1] < key, "outer-order-or-collision")
        ordering.append(key)
        members.append(member)
        by_name[member.name] = member
    for key, actual in (("members", len(rows)), ("entryHeaders", len(rows)),
                        ("files", sum(m.kind == "file" for m in members)),
                        ("aliases", sum(m.kind == "alias" for m in members)),
                        ("expandedBytes", sum(m.size for m in members))):
        need(integer(counts[key]) == actual, "complete-outer-count")
    need(counts["expandedBytes"] <= TOTAL_LIMIT, "outer-expanded-bound")
    need(counts["files"] <= FILE_COUNT and counts["aliases"] <= ALIAS_COUNT, "outer-leaf-bound")
    # Case-sensitive Bundletool classes never become picked filesystem
    # paths. All other archives preserve the exact spelling of every
    # shared parent, even when it has no explicit directory header.
    prefixes = {}
    for member in members:
        parts = member.name.split("/")
        for end in range(1, len(parts)):
            parent = "/".join(parts[:end])
            key = parent if label == "bundletool" else parent.lower()
            need(key not in prefixes or prefixes[key] == parent, "archive-parent-spelling")
            prefixes[key] = parent
    named = {(m.name if label == "bundletool" else m.name.lower()): m for m in members}
    for key, spelling in prefixes.items():
        if key in named:
            need(named[key].name == spelling and named[key].kind == "directory", "archive-parent-kind")
    return members, by_name


class Outer:
    def __init__(self, label, document):
        keys(document, ("schemaVersion", "kind", "label", "archiveBytes", "archiveSha256", "completeMemberHashes",
                        "supplierAuthority", "nativeClosure", "entryHeaders", "members", "files", "aliases", "expandedBytes", "columns", "rows"), "outer-shape")
        need(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
             and document["kind"] == "offline-official-archive-correspondence-data" and document["label"] == label
             and (document["archiveBytes"], document["archiveSha256"]) == ARCHIVES[label][:2]
             and document["completeMemberHashes"] is True and document["supplierAuthority"] is False
             and document["nativeClosure"] is False and document["columns"] == list(COLUMNS), "outer-header")
        integer(document["archiveBytes"], 1)
        self.label = label
        self.members, self.by_name = _outer_rows(label, document["rows"], document, ARCHIVES[label][0])


def archive_tuple(value, label):
    keys(value, ("label", "bytes", "sha256"), "archive-tuple-shape")
    integer(value["bytes"], 1); sha(value["sha256"])
    need((value["label"], value["bytes"], value["sha256"]) == (label, *ARCHIVES[label][:2]), "archive-tuple")


def member_tuple(value):
    keys(value, ("name", "kind", "mode", "size", "sha256"), "proof-member-shape")
    relative(value["name"]); integer(value["mode"], 0, 0o177777); integer(value["size"], 0, 512 * 1024 * 1024)
    need(value["kind"] == "file", "proof-member-kind"); sha(value["sha256"])
    return value


def base64_bytes(value, length, digest, maximum):
    integer(length, 1, maximum); sha(digest)
    need(type(value) is str and len(value) == 4 * ((length + 2) // 3) and value.isascii(), "base64-extent")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Refused("base64-invalid") from error
    need(len(raw) == length and base64.b64encode(raw).decode("ascii") == value
         and hashlib.sha256(raw).hexdigest() == digest, "decoded-byte-binding")
    return raw


def header(value, file_bytes):
    keys(value, ("format", "prefixBytes", "prefixSha256", "prefixBase64", "selectedCpu", "sliceOffset", "sliceBytes",
                 "commandsBytes", "commandsSha256", "commandsBase64"), "native-header-shape")
    need(value["format"] == "MachO", "native-header-format")
    prefix = base64_bytes(value["prefixBase64"], value["prefixBytes"], value["prefixSha256"], 4096)
    commands = base64_bytes(value["commandsBase64"], value["commandsBytes"], value["commandsSha256"], 65536)
    integer(value["selectedCpu"], 0, (1 << 32) - 1)
    integer(value["sliceOffset"], 0, file_bytes); integer(value["sliceBytes"], len(commands), file_bytes)
    need(value["sliceOffset"] + value["sliceBytes"] <= file_bytes and len(prefix) == min(4096, file_bytes)
         and len(commands) >= 32, "native-header-extent")
    # Native semantics/command closure stay in the existing Rust parser. These
    # bytes are genuine observation commitments, never a new Python Mach parser.
    return (prefix, commands, value["selectedCpu"])


def negative(value):
    keys(value, ("centralMembers", "inspectedMembers", "completeMemberHashes", "expandedInspectedBytes", "files",
                 "nativeMembers", "nestedArchives", "enumerationSha256", "nativeExecution", "supplierAuthority"), "negative-inner-shape")
    count = integer(value["centralMembers"], 1, ENTRY_LIMIT)
    need(integer(value["inspectedMembers"]) == count and value["completeMemberHashes"] is True
         and value["nativeMembers"] == [] and value["nestedArchives"] == []
         and value["nativeExecution"] is False and value["supplierAuthority"] is False, "negative-inner-incomplete")
    integer(value["files"], 0, count); integer(value["expandedInspectedBytes"], 0, TOTAL_LIMIT); sha(value["enumerationSha256"])


def native_row(value):
    basic = {"name", "bytes", "mode", "sha256", "format", "prefixBytes", "prefixSha256"}
    need(type(value) is dict and value.get("format") in ("MachO", "ELF", "PE"), "native-row")
    expected = basic | ({"selectedSlice"} if value["format"] == "MachO" else set())
    if "header" in value:
        expected.add("header")
    keys(value, expected, "native-row-shape")
    relative(value["name"]); integer(value["bytes"], 1, 512 * 1024 * 1024); integer(value["mode"], 0, 0o170777)
    need(value["mode"] & ~0o170777 == 0, "inner-special-mode")
    sha(value["sha256"]); sha(value["prefixSha256"])
    need(integer(value["prefixBytes"], 1, 4096) == min(value["bytes"], 4096), "native-prefix-extent")
    parsed = None
    if value["format"] == "MachO":
        selected = keys(value["selectedSlice"], ("cpu", "offset", "bytes"), "selected-slice-shape")
        integer(selected["cpu"], 0, (1 << 32) - 1); integer(selected["offset"], 0, value["bytes"])
        integer(selected["bytes"], 1, value["bytes"])
        need(selected["offset"] + selected["bytes"] <= value["bytes"], "selected-slice-extent")
        if "header" in value:
            parsed = header(value["header"], value["bytes"])
            need((value["header"]["selectedCpu"], value["header"]["sliceOffset"], value["header"]["sliceBytes"])
                 == (selected["cpu"], selected["offset"], selected["bytes"])
                 and value["header"]["prefixSha256"] == value["prefixSha256"], "native-header-slice-join")
        need(selected["cpu"] != ARM64 or parsed is not None, "arm64-snapshot-missing")
    else:
        need("header" not in value, "non-macho-header")
    return parsed


def jvm(value, member):
    keys(value, ("name", "bytes", "sha256", "formatHint", "centralMembers", "inspectedMembers", "files", "completeMemberHashes",
                 "expandedInspectedBytes", "snapshotReinspectedBytes", "enumerationSha256", "formatCounts", "nativeMembers",
                 "nestedArchives", "nestedArchiveHashes", "innerBookReservationBytes", "nativeExecuted", "supplierAuthority"), "jvm-shape")
    need((value["name"], value["bytes"], value["sha256"], value["formatHint"])
         == (member.name, member.size, member.sha256, member.hint), "jvm-outer-join")
    integer(value["bytes"], 1, 64 * 1024 * 1024)
    count = integer(value["centralMembers"], 1, ENTRY_LIMIT)
    need(integer(value["inspectedMembers"]) == count and value["completeMemberHashes"] is True
         and value["nativeExecuted"] is False and value["supplierAuthority"] is False, "jvm-completeness")
    integer(value["files"], 0, count); integer(value["expandedInspectedBytes"], 0, TOTAL_LIMIT)
    integer(value["snapshotReinspectedBytes"], 0, TOTAL_LIMIT); integer(value["innerBookReservationBytes"], 1, 64 * 1024 * 1024)
    sha(value["enumerationSha256"])
    counts = keys(value["formatCounts"], FORMATS, "jvm-format-counts")
    need(sum(integer(n, 0, count) for n in counts.values()) == count, "jvm-format-completeness")
    native = value["nativeMembers"]
    need(type(native) is list and len(native) <= 128 and len(native) == sum(counts[k] for k in ("MachO", "ELF", "PE")), "jvm-native-count")
    names = set()
    for item in native:
        native_row(item)
        key = item["name"].lower()
        need(key not in names, "jvm-native-collision"); names.add(key)
    nested, hashes = value["nestedArchives"], value["nestedArchiveHashes"]
    need(type(nested) is list and type(hashes) is list and len(nested) == len(hashes) == counts["Archive"]
         and len(nested) <= 3, "jvm-nested-count")
    by_name = {}
    for item in hashes:
        keys(item, ("member", "sha256"), "nested-hash-shape")
        relative(item["member"]); sha(item["sha256"])
        need(item["member"] not in by_name, "nested-hash-duplicate"); by_name[item["member"]] = item["sha256"]
    for item in nested:
        keys(item, ("member", "bytes", "mode"), "nested-tuple-shape")
        relative(item["member"]); integer(item["bytes"], 1, 64 * 1024 * 1024); integer(item["mode"], 0, 0o170777)
        need(item["mode"] & ~0o170777 == 0, "nested-special-mode")
        need(item["member"] in by_name and item["member"].lower() not in names, "nested-resource-join")
        names.add(item["member"].lower())
    return value


class Proofs:
    def __init__(self, inputs, outers):
        self.inputs, self.outers = inputs, outers
        self.direct, self.jvms, self.negatives, self.nested = {}, {}, {}, {}
        self.bundle = None
        self.selected = {}
        ordinary = {"schemaVersion", "kind", "archive", "member", "completeParentEvidence", "inspection", "nativeExecuted", "nativeClosure", "supplierAuthority"}
        excluded = set(OUTERS.values()) | {spec[3] for spec in SELECTED}
        for path in sorted(set(inputs.indexed) - excluded):
            value = inputs.document(path)
            need(type(value) is dict and type(value.get("kind")) is str, "proof-kind")
            kind = value["kind"]
            if kind == "complete-support-resource-data":
                keys(value, ordinary - {"member"}, "support-proof-shape")
                label = "bundletool"
            else:
                keys(value, ordinary | ({"innerMember"} if kind == "complete-nested-negative-data" else set()), "proof-shape")
                label = value["archive"].get("label") if type(value["archive"]) is dict else None
                need(type(label) is str and label in LABELS, "proof-label")
            need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                 and all(value[k] is False for k in ("nativeExecuted", "nativeClosure", "supplierAuthority")), "proof-header")
            archive_tuple(value["archive"], label)
            inputs.group(path, label)
            if kind == "complete-nested-negative-data":
                receipt(value["completeParentEvidence"])
                parent_path = value["completeParentEvidence"]["path"]
                need(parent_path in inputs.indexed or parent_path == "gradle-native-data.json", "nested-parent-unindexed")
                need(parent_path in inputs.documents, "nested-parent-missing")
                raw = inputs.documents[parent_path]
                need(value["completeParentEvidence"] == {"path": parent_path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "nested-parent-digest")
            else:
                inputs.parent(value["completeParentEvidence"], label)
            if kind == "complete-support-resource-data":
                need(self.bundle is None, "duplicate-support-proof")
                self.bundle = value["inspection"]
                continue
            member = member_tuple(value["member"])
            row = outers[label].by_name.get(member["name"])
            need(row is not None and row.kind == "file" and member == row.tuple(), "proof-outer-member-join")
            key = (label, row.name)
            if kind == "actual-archive-native-snapshot-data":
                need(key not in self.direct, "duplicate-direct-native")
                inspection = value["inspection"]
                if row.hint == "elf":
                    keys(inspection, ("format", "prefixBytes", "prefixSha256", "prefixBase64"), "elf-observation-shape")
                    need(inspection["format"] == "ELF", "elf-observation-format")
                    raw = base64_bytes(inspection["prefixBase64"], inspection["prefixBytes"], inspection["prefixSha256"], 4096)
                    need(len(raw) == min(row.size, 4096) and raw.startswith(b"\x7fELF"), "elf-observation-prefix")
                    self.direct[key] = (raw, b"", None)
                else:
                    self.direct[key] = header(inspection, row.size)
            elif kind == "complete-jvm-resource-data":
                need(key not in self.jvms, "duplicate-jvm")
                self.jvms[key] = (jvm(value["inspection"], row), path)
            elif kind == "complete-negative-inner-data":
                need(key not in self.negatives, "duplicate-negative")
                negative(value["inspection"])
                self.negatives[key] = value["inspection"]
            elif kind == "complete-nested-negative-data":
                child = keys(value["innerMember"], ("member", "bytes", "mode", "sha256"), "child-tuple-shape")
                relative(child["member"]); integer(child["bytes"], 1, 64 * 1024 * 1024); integer(child["mode"], 0, 0o170777); sha(child["sha256"])
                need(child["mode"] & ~0o170777 == 0, "child-special-mode")
                nested_key = (*key, child["member"])
                need(nested_key not in self.nested, "duplicate-nested")
                negative(value["inspection"])
                self.nested[nested_key] = (child, value["completeParentEvidence"]["path"])
            else:
                raise Refused("unsupported-proof-kind")
        self._gradle()
        self._selected_files()
        self._complete_sets()

    def _gradle(self):
        value = self.inputs.document("gradle-native-data.json")
        keys(value, ("archive", "completeMemberHashes", "completeOuterInventory", "declaredJvmBodyCapBytes", "declaredOwnedWorkspaceCapBytes",
                     "enumeration", "historicalReuse", "jvmArchives", "jvmSelection", "kind", "nativeClosure", "nativeExecuted",
                     "nestedPayloadRecursivelyInspected", "ordering", "outerJvmEnumerationSha256", "producer", "producerFormatVersion", "schemaVersion", "summary", "supplierAuthority"), "retained-jvm-document")
        archive_tuple(value["archive"], "gradle")
        need(value["completeMemberHashes"] is True and value["completeOuterInventory"] is True
             and all(value[k] is False for k in ("nativeClosure", "nativeExecuted", "supplierAuthority", "historicalReuse", "nestedPayloadRecursivelyInspected"))
             and value["jvmSelection"] == "all-complete-outer-regular-formatHint-zip-or-jmod", "retained-jvm-header")
        rows = value["jvmArchives"]
        expected = [m for m in self.outers["gradle"].members if m.kind == "file" and m.hint in ("zip", "jmod")]
        need(type(rows) is list and len(rows) == len(expected) == 311, "retained-jvm-set")
        enumeration = hashlib.sha256()
        for actual, member in zip(rows, expected):
            key = ("gradle", member.name)
            need(key not in self.jvms, "gradle-jvm-repeated")
            self.jvms[key] = (jvm(actual, member), "gradle-native-data.json")
            enumeration.update(canonical({"name": member.name, "bytes": member.size, "sha256": member.sha256, "formatHint": member.hint}))
        need(enumeration.hexdigest() == value["outerJvmEnumerationSha256"], "retained-outer-jvm-enumeration")

    def _selected_files(self):
        fields = ("schemaVersion", "kind", "archive", "member", "completeParentEvidence", "bytesBase64", "decodedLength", "decodedSha256",
                  "nativeExecuted", "supplierAuthority", "nativeClosure")
        for name, size, digest, path in SELECTED:
            value = self.inputs.document(path)
            keys(value, fields, "selected-file-shape")
            archive_tuple(value["archive"], "jdk")
            self.inputs.group(path, "jdk")
            self.inputs.parent(value["completeParentEvidence"], "jdk")
            expected = {"name": name, "kind": "file", "mode": 0o100644, "size": size, "sha256": digest}
            member_tuple(value["member"])
            row = self.outers["jdk"].by_name.get(name)
            need(row is not None and row.tuple() == expected == value["member"]
                 and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                 and value["kind"] == "actual-jdk-selected-file-bytes-data"
                 and value["decodedLength"] == size and value["decodedSha256"] == digest
                 and all(value[k] is False for k in ("nativeExecuted", "supplierAuthority", "nativeClosure")), "selected-file-binding")
            self.selected[name] = base64_bytes(value["bytesBase64"], value["decodedLength"], value["decodedSha256"], size)

    def _complete_sets(self):
        expected_jvm, expected_direct, expected_negative = set(), set(), set()
        for label in ("jdk", "sdk-platform", "sdk-build-tools", "gradle"):
            for member in self.outers[label].members:
                if member.kind != "file":
                    continue
                key = (label, member.name)
                if label in SDK_NEGATIVE and member.hint in ("zip", "jmod"):
                    expected_negative.add(key)
                elif member.name.endswith((".jar", ".jmod")):
                    need(member.hint in ("zip", "jmod"), "jvm-format-disagreement")
                    expected_jvm.add(key)
                elif member.hint in ("zip", "jmod"):
                    expected_negative.add(key)
                elif member.hint in ("macho", "fat-macho-or-java-class", "elf", "pe"):
                    expected_direct.add(key)
        expected_direct.add(("aapt2", "aapt2"))
        need(set(self.jvms) == expected_jvm and set(self.direct) == expected_direct
             and set(self.negatives) == expected_negative, "complete-proof-inverse-set")
        need(sum(label == "jdk" for label, _ in expected_direct) == 71, "jdk-native-count")
        need(sum(label == "sdk-build-tools" and self.outers[label].by_name[name].hint in ("macho", "fat-macho-or-java-class")
                 for label, name in expected_direct) == 16, "sdk-native-count")
        for label, names in SDK_NEGATIVE.items():
            actual = {name for group, name in expected_jvm | expected_negative if group == label}
            need(actual == names, "fixed-sdk-inner-inverse-set")
        expected_nested = {}
        for (label, name), (value, path) in self.jvms.items():
            hashes = {row["member"]: row["sha256"] for row in value["nestedArchiveHashes"]}
            for row in value["nestedArchives"]:
                key = (label, name, row["member"])
                expected_nested[key] = ({**row, "sha256": hashes[row["member"]]}, path)
        need(self.nested == expected_nested, "complete-nested-inverse-join")
        need(self.bundle is not None, "bundletool-census-missing")
        allowed_nested = {
            ("gradle", "gradle-8.14.5/lib/plugins/gradle-wrapper-main-8.14.5.jar", "gradle-wrapper.jar"),
            ("jdk", JDK_ROOT + "/Contents/Home/jmods/java.base.jmod", "lib/jrt-fs.jar"),
            ("jdk", JDK_ROOT + "/Contents/Home/jmods/java.base.jmod", "lib/security/public_suffix_list.dat"),
            ("jdk", JDK_ROOT + "/Contents/Home/jmods/jdk.compiler.jmod", "lib/ct.sym"),
        }
        need(set(expected_nested) == allowed_nested, "fixed-nested-census")
        # A fixed SDK JVM-negative is still emitted as JvmArchive with an
        # explicit empty roster. A non-JVM archive remains Data only after the
        # complete negative observation, never because its extension is novel.
        for label in SDK_NEGATIVE:
            need(not any(group == label for group, _ in self.jvms), "sdk-proof-role")
        validate_bundle(self.bundle, self.outers["bundletool"])

    def release(self):
        raw = self.selected[SELECTED[0][0]]
        need(0 < len(raw) <= 65536 and raw.endswith(b"\n") and raw.isascii(), "jdk-release-lines")
        values = {}
        # Same LF/CRLF (and existing extra-CR suffix) grammar as Rust's real
        # release_layout. Python splitlines would wrongly treat VT/FF as LF.
        # This projection is NOT the required actual Rust parser regression.
        for line in raw[:-1].decode("ascii").split("\n"):
            for _ in range(2):
                if line.endswith("\r"):
                    line = line[:-1]
            if not line:
                continue
            key, delimiter, value = line.partition("=")
            need(delimiter == "=" and 0 < len(key) <= 64 and all(c.isupper() or c.isdigit() or c == "_" for c in key)
                 and key not in values and len(values) < 128 and len(value) >= 2 and value.startswith('"') and value.endswith('"'), "jdk-release-field")
            value = value[1:-1]
            need(len(value) <= 4096 and all(32 <= ord(c) < 127 and c not in '\\"' for c in value), "jdk-release-value")
            values[key] = value
        vendor, version = values.get("IMPLEMENTOR"), values.get("JAVA_VERSION")
        text(vendor, 128); text(version, 64)
        # Values come ONLY from the exact byte proof, never the archive basename.
        return vendor, version


def validate_bundle(value, outer):
    keys(value, ("kind", "label", "archiveSha256", "centralMembers", "inspectedMembers", "completeMemberHashes",
                 "enumerationSha256", "formatCounts", "nativeMembers", "nestedArchives",
                 "javaHeadersDistinguishedFromFatMacho", "allOuterMembersHashedByAcceptedParser",
                 "nativeExecution", "runtimeClosure", "supplierAuthority"), "bundle-census-shape")
    need(value["kind"] == "complete-outer-native-resource-enumeration-data" and value["label"] == "bundletool"
         and value["archiveSha256"] == ARCHIVES["bundletool"][1] and value["completeMemberHashes"] is True
         and value["allOuterMembersHashedByAcceptedParser"] is True
         and all(value[key] is False for key in ("nativeExecution", "runtimeClosure", "supplierAuthority")), "bundle-census-header")
    need(integer(value["centralMembers"], 1, ENTRY_LIMIT) == integer(value["inspectedMembers"], 1, ENTRY_LIMIT)
         == len(outer.members) and value["nestedArchives"] == [], "bundle-census-completeness")
    native = value["nativeMembers"]
    need(type(native) is list and len(native) <= 128, "bundle-native-bound")
    by_name = {}
    for row in native:
        native_row(row)
        name = row["name"]
        member = outer.by_name.get(name)
        need(name not in by_name and member is not None and member.kind == "file"
             and (row["bytes"], row["mode"], row["sha256"]) == (member.size, member.mode, member.sha256), "bundle-native-parent-join")
        by_name[name] = row
    # Complete outer order, not a filtered interesting-member digest. Every
    # ambiguous FAT/Java prefix is accounted for as either an observed native
    # row or an observed JavaClass; all known native tuples are checked below.
    counts = {name: 0 for name in FORMATS}
    enumeration = hashlib.sha256()
    for member in outer.members:
        if member.name in by_name:
            kind = by_name[member.name]["format"]
            expected = {"MachO": ("macho", "fat-macho-or-java-class"), "ELF": ("elf",), "PE": ("pe",)}[kind]
            need(member.hint in expected, "bundle-native-format-join")
        elif member.hint == "fat-macho-or-java-class":
            kind = "JavaClass"
        else:
            need(member.hint is None, "bundle-unclassified-resource")
            kind = "Data"
        counts[kind] += 1
        enumeration.update(canonical({"name": member.name, "kind": member.kind, "mode": member.mode,
            "bytes": member.size, "sha256": member.sha256, "format": kind}))
    keys(value["formatCounts"], FORMATS, "bundle-format-counts")
    for name in FORMATS:
        need(integer(value["formatCounts"][name], 0, ENTRY_LIMIT) == counts[name], "bundle-format-count")
    need(integer(value["javaHeadersDistinguishedFromFatMacho"], 0, ENTRY_LIMIT) == counts["JavaClass"]
         and sha(value["enumerationSha256"]) == enumeration.hexdigest(), "bundle-enumeration-join")
    finite_native("bundletool/bundletool.jar", ARCHIVES["bundletool"][:2], native)


def pinned_header(observed, expected):
    prefix, commands, cpu = observed
    need(cpu == ARM64 and (len(prefix), hashlib.sha256(prefix).hexdigest(), hashlib.sha256(commands).hexdigest())
         == expected, "compiled-native-snapshot-pin")


def finite_native(path, archive, rows):
    """Finite foreign exceptions are never inferred from a resource basename."""
    pin = NATIVE_PINS.get(path)
    ordered = sorted(rows, key=lambda row: row["name"].lower())
    if pin is None:
        need(not ordered, "unlisted-native-resource")
        return ()
    need(archive == pin[:2] and len(ordered) == len(pin[2]), "native-archive-pin")
    result = []
    for row, expected in zip(ordered, pin[2]):
        name, size, digest, mode, kind = expected
        need((row["name"], row["bytes"], row["sha256"], row["mode"]) == (name, size, digest, mode), "native-resource-pin")
        actual_header = native_row(row)
        expected_format = "ELF" if kind == "OtherPlatformElf" else "PE" if kind == "OtherPlatformPe" else "MachO"
        need(row["format"] == expected_format, "finite-native-format")
        if kind == "Arm64":
            need(actual_header is not None and actual_header[2] == ARM64, "finite-arm64-snapshot")
        else:
            need(actual_header is None, "foreign-resource-not-arm64")
            if expected_format == "MachO":
                need(row["selectedSlice"]["cpu"] in (7, 0x01000007), "foreign-intel-slice")
        result.append((row, kind, actual_header))
    return tuple(result)


def jdk_native_members(member, value, proofs):
    relative_name = member.name.removeprefix(JDK_ROOT + "/")
    pin = JDK_JVM_PINS.get(relative_name)
    need(pin is not None and (member.size, member.sha256, member.mode) == (*pin[:2], 0o100644), "jdk-jvm-pin")
    ordered = sorted(value["nativeMembers"], key=lambda row: row["name"].lower())
    need(len(ordered) == len(pin[2]), "jdk-jvm-native-roster")
    result = []
    for row, expected in zip(ordered, pin[2]):
        name, size, digest, mode, counterpart = expected
        need((row["name"], row["bytes"], row["sha256"], row["mode"], row["format"])
             == (name, size, digest, mode, "MachO"), "jdk-jvm-native-pin")
        snapshot = native_row(row)
        need(snapshot is not None and snapshot[2] == ARM64, "jdk-jvm-snapshot-missing")
        if counterpart is not None:
            direct_name = JDK_ROOT + "/" + counterpart
            direct = proofs.outers["jdk"].by_name.get(direct_name)
            direct_pin = JDK_NATIVE_PINS.get(counterpart)
            direct_snapshot = proofs.direct.get(("jdk", direct_name))
            need(direct is not None and direct_pin is not None and direct_snapshot is not None
                 and (direct.size, direct.sha256) == (size, digest) == direct_pin[:2]
                 and snapshot == direct_snapshot, "jdk-counterpart-exact-join")
            pinned_header(snapshot, direct_pin[3:])
            kind = "JdkInstalledCounterpart"
        else:
            need((name, size, digest) == ("classes/jdk/jpackage/internal/resources/jpackageapplauncher", 185600,
                 "73403782287c715055d9f58cca4571add26f01817d710186bf6e52fa5ac1b442"), "jdk-template-tuple")
            pinned_header(snapshot, JPACKAGE_PIN)
            kind = "JdkJpackageTemplate"
        result.append((row, kind, snapshot))
    return tuple(result)


@dataclass(slots=True)
class Source:
    group: str
    relative: str
    kind: str
    mode: int
    size: int
    sha256: str | None
    target: str | None
    canonical: str | None
    archive: int
    member: int | None
    prefix: str


@dataclass(frozen=True, slots=True)
class Payload:
    path: str
    size: int
    sha256: str
    mode: int
    origin: tuple
    classification: tuple


GROUPS = ("Jdk", "Sdk", "Gradle")
TREES = (("Jdk", ""), ("Sdk", "platforms/android-35"), ("Sdk", "build-tools/35.0.0"), ("Gradle", ""))


def source_name(label, name):
    if label == "jdk":
        need(name.startswith(JDK_ROOT + "/"), "jdk-wrapper-prefix")
        group, value = "Jdk", name[len(JDK_ROOT) + 1:]
    elif label == "gradle":
        prefix = "gradle-8.14.5/"
        need(name.startswith(prefix), "gradle-wrapper-prefix")
        group, value = "Gradle", name[len(prefix):]
    elif label in ("sdk-platform", "sdk-build-tools"):
        before, after = (("android-35", "platforms/android-35") if label == "sdk-platform"
                         else ("android-15", "build-tools/35.0.0"))
        need(name == before or name.startswith(before + "/"), "sdk-package-prefix")
        group, value = "Sdk", after + name[len(before):]
    else:
        raise Refused("support-is-not-picked-source")
    return group, source_relative(value)


def canonical_source(group, name):
    need(group in GROUPS, "source-group")
    return source_relative((INSTALLED_JDK if group == "Jdk" else "sdk/" if group == "Sdk" else "gradle/") + name)


def resolve_alias(name, target):
    source_relative(name); text(target)
    need(not target.startswith("/"), "absolute-alias")
    stack = name.split("/")[:-1]
    for part in target.split("/"):
        if part == "..":
            need(bool(stack), "alias-bundle-escape")
            stack.pop()
        elif part != ".":
            source_relative(part)
            stack.append(part)
            need(len(stack) <= 271, "alias-depth")
    return source_relative("/".join(stack))


def source_parents(relative_name, group):
    floor = next((prefix for candidate, prefix in TREES if group == candidate
                  and (not prefix or relative_name == prefix or relative_name.startswith(prefix + "/"))), None)
    need(floor is not None, "source-tree-membership")
    at = relative_name
    while "/" in at:
        at = at.rsplit("/", 1)[0]
        if floor and len(at) < len(floor):
            break
        yield at


def collect_sources(outers):
    sources, folded_names = {}, {}
    for archive, label in enumerate(LABELS[:4]):
        for ordinal, member in enumerate(outers[label].members):
            if label in ("jdk", "gradle") and member.name == (JDK_ROOT if label == "jdk" else "gradle-8.14.5"):
                need(member.kind == "directory", "wrapper-is-not-directory")
                continue
            group, name = source_name(label, member.name)
            key = (group, name)
            folded_key = (group, name.lower())
            need(folded_key not in folded_names, "source-case-collision")
            folded_names[folded_key] = name
            sources[key] = Source(group, name, member.kind, member.mode & 0o777, member.size,
                                  member.sha256, member.target, None, archive, ordinal, member.name)
            need(len(sources) <= ENTRY_LIMIT, "source-count-bound")
    # First insert ALL genuine headers, then only necessary missing parents.
    # This cannot replace a present header or hide an empty source directory.
    originals = tuple(sources.values())
    for child in originals:
        for parent in source_parents(child.relative, child.group):
            tail = child.relative[len(parent):]
            need(tail.startswith("/") and child.prefix.endswith(tail), "derived-parent-mapping")
            prefix = child.prefix[:-len(tail)]
            key = (child.group, parent)
            folded_key = (child.group, parent.lower())
            existing_name = folded_names.get(folded_key)
            need(existing_name is None or existing_name == parent, "source-parent-spelling")
            existing = sources.get(key)
            if existing is not None:
                need(existing.kind == "directory" and existing.archive == child.archive and existing.prefix == prefix,
                     "source-parent-provenance-conflict")
            else:
                sources[key] = Source(child.group, parent, "directory", 0o755, 0, None, None, None, child.archive, None, prefix)
                folded_names[folded_key] = parent
                need(len(sources) <= ENTRY_LIMIT, "source-count-bound")
    for source in sources.values():
        if source.kind == "alias":
            need(source.group == "Jdk", "non-jdk-alias")
            source.canonical = resolve_alias(source.relative, source.target)
            target = sources.get((source.group, source.canonical))
            need(target is not None and target.kind == "file", "alias-not-regular-counterpart")
    ordered = sorted(sources.values(), key=lambda s: (GROUPS.index(s.group), s.relative.lower()))
    return ordered


def classify(member, label, path, proofs, *, profile="arm64"):
    _projection_profile(profile)
    if profile == "x86_64":
        return _classify_intel(member, label, path, proofs)
    key = (label, member.name)
    if member.name.endswith((".jar", ".jmod")):
        if label in SDK_NEGATIVE:
            need(key in proofs.negatives, "sdk-jvm-negative-missing")
            native = ()
        else:
            need(key in proofs.jvms, "jvm-complete-observation-missing")
            value = proofs.jvms[key][0]
            native = (jdk_native_members(member, value, proofs) if label == "jdk"
                      else finite_native(path, (member.size, member.sha256), value["nativeMembers"]))
        return 0o444, ("JvmArchive", native)
    if label == "sdk-build-tools" and member.name in SDK_PINS:
        kind, expected_path, size, digest, mode = SDK_PINS[member.name]
        need((path, member.size, member.sha256, member.mode) == (expected_path, size, digest, 0o100000 | mode), "sdk-special-pin")
        if kind in ("D8", "Apksigner", "LldShell"):
            need(member.hint == "shell", "sdk-script-prefix")
            return mode & ~0o222, ("SdkBash", kind)
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] == 0x01000007, "sdk-legacy-intel-snapshot")
        return mode & ~0o222, ("SdkLegacyIntel", kind, snapshot)
    if member.hint == "elf":
        pin = ELF_PINS.get(member.name) if label == "sdk-build-tools" else None
        need(pin is not None and (path, member.size, member.sha256, member.mode)
             == (pin[0], pin[1], pin[2], 0o100000 | pin[3]), "unlisted-target-elf")
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] is None and snapshot[0].startswith(pin[4]), "target-elf-header-pin")
        return 0o444, ("AndroidTargetElf",)
    if member.hint in ("macho", "fat-macho-or-java-class"):
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] == ARM64, "direct-arm64-snapshot")
        if label == "jdk":
            pin = JDK_NATIVE_PINS.get(member.name.removeprefix(JDK_ROOT + "/"))
            need(pin is not None and (member.size, member.sha256, member.mode) == (*pin[:2], 0o100000 | pin[2]), "jdk-direct-native-pin")
            pinned_header(snapshot, pin[3:])
        else:
            need(label == "sdk-build-tools", "unlisted-direct-native")
        mode = (member.mode & 0o777) & ~0o222
        need(mode in (0o444, 0o555), "direct-installed-mode")
        return mode, ("MachO", snapshot)
    if label == "gradle" and member.name == "gradle-8.14.5/bin/gradle":
        need((member.size, member.sha256, member.mode, member.hint) == (8817,
             "35886267baa57c8a15176749dfad4468f2228fc46d15d91c600e34fe46eb1a77", 0o100755, "shell"), "gradle-shell-pin")
        return 0o555, ("GradleShell",)
    if label == "gradle" and member.name == "gradle-8.14.5/bin/gradle.bat":
        need((member.size, member.sha256, member.mode, member.hint) == (3018,
             "d20e9ded0291e1ed6552d1df30022d2e5952ad493f9d3380f6a32b97f0cc80c7", 0o100755, None), "gradle-foreign-launcher-pin")
        return 0o444, ("GradleForeignLauncher",)
    if member.hint in ("zip", "jmod"):
        need(key in proofs.negatives and member.mode & 0o111 == 0, "non-jvm-negative-missing")
        return 0o444, ("Data",)
    need(member.hint is None and not member.name.endswith((".dylib", ".jnilib")), "unclassified-executable-content")
    if member.name.rsplit("/", 1)[-1] in ("NOTICE", "LICENSE", "LICENSE.txt", "NOTICE.txt"):
        return 0o444, ("LicenseText",)
    need(member.mode & 0o111 == 0, "unclassified-executable-mode")
    return 0o444, ("Data",)


class Projection:
    def __init__(self, outers, proofs, *, profile="arm64"):
        archives = _projection_profile(profile)
        self.profile = profile
        self.outers, self.proofs = outers, proofs
        for label, name, size, digest in SDK_PROPERTIES:
            row = outers[label].by_name.get(name)
            need(row is not None and (row.kind, row.mode, row.size, row.sha256) == ("file", 0o100644, size, digest),
                 "compiled-sdk-properties-original")
        for label, notices in SUPPORT_NOTICES.items():
            for name, size, digest in notices:
                row = outers[label].by_name.get(name)
                need(row is not None and (row.kind, row.size, row.sha256) == ("file", size, digest), "compiled-support-notice-original")
        self.sources = collect_sources(outers)
        self.source_ids = {(source.group, source.relative): i for i, source in enumerate(self.sources)}
        self.vendor_ids = {(source.archive, source.member): i for i, source in enumerate(self.sources) if source.member is not None}
        need(len(self.source_ids) == len(self.sources), "source-id-collision")
        self.payload, self.aliases = [], []
        for source in self.sources:
            if source.kind == "file":
                member = outers[LABELS[source.archive]].members[source.member]
                path = canonical_source(source.group, source.relative)
                mode, classification = classify(member, LABELS[source.archive], path, proofs, profile=profile)
                self.payload.append(Payload(path, member.size, member.sha256, mode,
                                           ("Picked", source.group, source.relative), classification))
            elif source.kind == "alias":
                self.aliases.append((canonical_source(source.group, source.relative), source.target,
                    canonical_source(source.group, source.canonical), self.source_ids[(source.group, source.relative)]))
        # Compiled SDK XML is not a fabricated selected package.xml header.
        for path, size, digest, kind in XML_FILES:
            self.payload.append(Payload(path, size, digest, 0o444, ("CompiledSdkMetadata", kind), ("Data",)))
        bundle = (finite_native("bundletool/bundletool.jar", archives["bundletool"][:2], proofs.bundle["nativeMembers"])
                  if profile == "arm64" else _intel_finite_native("bundletool/bundletool.jar",
                      archives["bundletool"][:2], _intel_native_rows(proofs.bundle)))
        self.payload.append(Payload("bundletool/bundletool.jar", *ARCHIVES["bundletool"][:2], 0o444,
                                   ("Support", "BundletoolJar"), ("JvmArchive", bundle)))
        aapt = outers["aapt2"].by_name.get("aapt2")
        need(aapt is not None and (aapt.size, aapt.sha256, aapt.mode) == (11143368,
             "213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e", 0o100755), "aapt2-member-pin")
        snapshot = proofs.direct[("aapt2", "aapt2")]
        need(snapshot[2] == (ARM64 if profile == "arm64" else 0x01000007), "aapt2-selected-snapshot")
        self.payload.append(Payload(AAPT2_PATH, aapt.size, aapt.sha256, 0o555,
                                   ("MemberOfSameOriginalArchive",), ("MachO", snapshot)))
        self.aapt = aapt
        self.payload.sort(key=lambda p: p.path)
        self.aliases.sort()
        self.payload_ids = {p.origin[1:]: i for i, p in enumerate(self.payload) if p.origin[0] == "Picked"}
        self.alias_ids = {a[3]: i for i, a in enumerate(self.aliases)}
        need(len(self.payload) <= FILE_COUNT and len(self.aliases) <= ALIAS_COUNT, "payload-leaf-bound")
        need(len(self.payload_ids) == sum(s.kind == "file" for s in self.sources), "payload-source-inverse-set")
        names, spelling, directories = set(), {}, set()
        for path in [p.path for p in self.payload] + [a[0] for a in self.aliases]:
            source_relative(path)
            need(path.lower() not in names, "installed-case-collision")
            names.add(path.lower())
            at = path
            while "/" in at:
                at = at.rsplit("/", 1)[0]
                need(at.lower() not in spelling or spelling[at.lower()] == at, "installed-parent-spelling")
                spelling[at.lower()] = at
                directories.add(at)
        need(not names.intersection(spelling) and len(names) + len(directories) + 3 <= ENTRY_LIMIT, "installed-directory-conflict")
        self.directories = sorted(directories)
        need(sum(p.size for p in self.payload) <= TOTAL_LIMIT, "installed-expanded-bound")
        expected_jdk = {JDK_ROOT + "/" + name for name in JDK_NATIVE_PINS}
        need({name for label, name in proofs.direct if label == "jdk"} == expected_jdk, "jdk-complete-direct-pin-set")
        need({name for label, name in proofs.jvms if label == "jdk"} == {JDK_ROOT + "/" + name for name in JDK_JVM_PINS}, "jdk-complete-jvm-pin-set")
        need(set(ELF_PINS) == {name for label, name in proofs.direct if label == "sdk-build-tools"
                             and outers[label].by_name[name].hint == "elf"}, "sdk-complete-elf-pin-set")
        need(set(SDK_PINS).issubset(outers["sdk-build-tools"].by_name), "sdk-special-completeness")
        self.vendor, self.version = proofs.release()
        need((self.vendor, self.version) == ("Eclipse Adoptium", "17.0.20.1"), "observed-release-profile")

    def summary(self):
        return {"schemaVersion": 1, "kind": "proposed-compiled-catalogue-source", "references": 1,
                "archiveMembers": {label: len(self.outers[label].members) for label in LABELS},
                "sourceMembers": len(self.sources), "sourceFiles": sum(s.kind == "file" for s in self.sources),
                "sourceAliases": len(self.aliases), "derivedSourceParents": sum(s.member is None for s in self.sources),
                "payloadFiles": len(self.payload), "directories": len(self.directories),
                "jvmPayloads": sum(p.classification[0] == "JvmArchive" for p in self.payload),
                "nativeResources": sum(len(p.classification[1]) for p in self.payload if p.classification[0] == "JvmArchive"),
                "nativeExecuted": False, "supplierAuthority": False, "nativeClosure": False}


def rust_string(value):
    need(type(value) is str and len(value) <= 2048 and value.isascii()
         and all(32 <= ord(char) < 127 for char in value), "rust-string-literal")
    # Printable ASCII means JSON's quotes/backslashes are also valid Rust
    # escapes; there is no supplied expression, Unicode escape or identifier.
    return json.dumps(value, ensure_ascii=True)


def archive_literal(label, *, profile="arm64"):
    size, digest = _projection_profile(profile)[label][:2]
    return "ArchivePin { bytes: " + str(size) + ", sha256: " + rust_string(digest) + " }"


def zip_literal(member):
    need(member.kind == "file" and member.method in (0, 8) and member.flags & ~0x080E == 0
         and (member.method != 0 or member.flags & 6 == 0 and member.compressed == member.size)
         and member.local + 30 <= member.data and member.compressed > 0
         and member.data + member.compressed <= ARCHIVES["aapt2"][0], "projected-zip-member")
    return ("ZipMemberSpec { name: " + rust_string(member.name) + ", method: ZipMethod::" + ("Stored" if member.method == 0 else "Deflate")
            + ", flags: " + str(member.flags) + ", local_header_offset: " + str(member.local) + ", data_offset: " + str(member.data)
            + ", compressed_bytes: " + str(member.compressed) + ", bytes: " + str(member.size) + ", crc32: " + str(member.crc32)
            + ", sha256: " + rust_string(member.sha256) + " }")


class Emitter:
    """At most one <=64KiB UTF8 chunk live; output always tentative until return."""
    def __init__(self, sink: Callable[[bytes], None]):
        need(callable(sink), "output-sink")
        self.sink, self.total, self.digest = sink, 0, hashlib.sha256()
        self.buffer = bytearray()

    def put(self, line):
        need(type(line) is str and line.isascii(), "output-source-encoding")
        raw = line.encode("ascii")
        need(len(raw) <= 65536 and self.total + len(raw) <= OUTPUT_LIMIT, "output-bound")
        self.total += len(raw)
        self.digest.update(raw)
        if len(self.buffer) + len(raw) > 65536:
            self.flush()
        self.buffer.extend(raw)

    def flush(self):
        if self.buffer:
            raw = bytes(self.buffer)
            self.buffer.clear()
            self.sink(raw)

    def finish(self):
        self.flush()
        return {"bytes": self.total, "sha256": self.digest.hexdigest()}


def render(projection, sink, *, profile="arm64"):
    archives = _projection_profile(profile)
    need(projection.profile == profile, "projection-render-profile")
    output = Emitter(sink)
    put = output.put
    headers, header_ids = [], {}
    for payload in projection.payload:
        kind = payload.classification
        selected = ([kind[1]] if kind[0] == "MachO" else [kind[2]] if kind[0] == "SdkLegacyIntel"
                    else [row[2] for row in kind[1] if row[2] is not None] if kind[0] == "JvmArchive" else [])
        for value in selected:
            if value not in header_ids:
                header_ids[value] = len(headers)
                headers.append(value)
    def native(value):
        ordinal = header_ids[value]
        return "NativeHeader { prefix: CAT_H" + str(ordinal) + "_PREFIX, commands: CAT_H" + str(ordinal) + "_COMMANDS }"
    put("// Generated proposed SOURCE from complete admitted official observation DATA.\n")
    put("// No IO, mutable runtime registration, reference digest or native qualification.\n")
    if profile == "x86_64":
        put("use super::*;\n")
    for ordinal, (prefix, commands, _) in enumerate(headers):
        for suffix, raw in (("PREFIX", prefix), ("COMMANDS", commands)):
            put("const CAT_H" + str(ordinal) + "_" + suffix + ": &[u8] = &[\n")
            for at in range(0, len(raw), 32):
                put("    " + ",".join(str(byte) for byte in raw[at:at + 32]) + ",\n")
            put("];\n")
    for ordinal, payload in enumerate(projection.payload):
        if payload.classification[0] != "JvmArchive" or not payload.classification[1]:
            continue
        put("const CAT_N" + str(ordinal) + ": &[NestedNative] = &[\n")
        for row, kind, snapshot in payload.classification[1]:
            need(kind in ("Arm64", "JdkInstalledCounterpart", "JdkJpackageTemplate", "OtherPlatformElf", "OtherPlatformPe",
                          "GradleIntelPlatform", "GradlePlainJansiIntel", "BundletoolDarwinI386X64")
                 or profile == "x86_64" and kind in ("CurrentX64", "OtherPlatformArm64", "OtherPlatformI386"),
                 "native-literal-kind")
            put("    NestedNative { member: " + rust_string(row["name"]) + ", bytes: " + str(row["bytes"])
                + ", sha256: " + rust_string(row["sha256"]) + ", mode: " + oct(row["mode"])
                + ", kind: NativeResourceKind::" + kind + ", header: " + ("Some(" + native(snapshot) + ")" if snapshot is not None else "None") + " },\n")
        put("];\n")
    for archive, label in enumerate(LABELS):
        put("const CAT_A" + str(archive) + ": &[OfficialMember] = &[\n")
        for ordinal, member in enumerate(projection.outers[label].members):
            if label in ("aapt2", "bundletool"):
                disposition = "ArchiveDisposition::SealedSupport(SupportAsset::" + ("Aapt2OsxJar" if label == "aapt2" else "BundletoolJar") + ")"
            elif (archive, ordinal) in projection.vendor_ids:
                disposition = "ArchiveDisposition::Picked { source_index: " + str(projection.vendor_ids[(archive, ordinal)]) + " }"
            else:
                need(member.kind == "directory" and (label, member.name) in (("jdk", JDK_ROOT), ("gradle", "gradle-8.14.5")), "unbound-archive-member")
                disposition = "ArchiveDisposition::WrapperDirectory"
            if member.kind == "file":
                kind = "ArchiveKind::File { mode: " + oct(member.mode) + ", bytes: " + str(member.size) + ", sha256: " + rust_string(member.sha256) + " }"
            elif member.kind == "alias":
                kind = "ArchiveKind::Alias { mode: " + oct(member.mode) + ", target: " + rust_string(member.target) + " }"
            else:
                kind = "ArchiveKind::Directory { mode: " + oct(member.mode) + " }"
            put("    OfficialMember { name: " + rust_string(member.name) + ", kind: " + kind + ", disposition: " + disposition + " },\n")
        put("];\n")
    put("const CAT_ARCHIVES: &[OfficialArchive] = &[\n")
    for archive, label in enumerate(LABELS):
        published = "Sha1(" + rust_string(SDK_SHA1[label]) + ")" if label in SDK_SHA1 else "Sha256(" + rust_string(archives[label][1]) + ")"
        put("    OfficialArchive { component: Component::" + COMPONENTS[archive] + ", official_source: " + rust_string(archives[label][2])
            + ", vendor_release: " + rust_string(archives[label][3]) + ", archive: " + archive_literal(label, profile=profile)
            + ", published: PublishedChecksum::" + published + ", member_count: " + str(len(projection.outers[label].members))
            + ", expanded_bytes: " + str(sum(m.size for m in projection.outers[label].members)) + ", members: CAT_A" + str(archive) + " },\n")
    put("];\nconst CAT_TREES: &[SourceTree] = &[\n")
    for group, prefix in TREES:
        put("    SourceTree { group: SourceGroup::" + group + ", prefix: " + rust_string(prefix) + " },\n")
    put("];\nconst CAT_SOURCES: &[SourceMemberSpec] = &[\n")
    for source in projection.sources:
        modes = "modes: &[" + oct(source.mode) + "]"
        if source.kind == "file":
            kind = "File { bytes: " + str(source.size) + ", sha256: " + rust_string(source.sha256) + ", " + modes + " }"
        elif source.kind == "alias":
            kind = "Alias { target: " + rust_string(source.target) + ", canonical: " + rust_string(source.canonical) + ", " + modes + " }"
        else:
            kind = "Directory { " + modes + " }"
        put("    SourceMemberSpec { group: SourceGroup::" + source.group + ", relative: " + rust_string(source.relative) + ", kind: SourceKindSpec::" + kind + " },\n")
    put("];\nconst CAT_BINDINGS: &[SourceBinding] = &[\n")
    for ordinal, source in enumerate(projection.sources):
        provenance = ("Vendor { archive: " + str(source.archive) + ", member: " + str(source.member) + " }" if source.member is not None
                      else "ArchiveParent { archive: " + str(source.archive) + ", prefix: " + rust_string(source.prefix) + " }")
        if source.kind == "file":
            disposition = "Payload(" + str(projection.payload_ids[(source.group, source.relative)]) + ")"
        elif source.kind == "alias":
            disposition = "Alias(" + str(projection.alias_ids[ordinal]) + ")"
        else:
            disposition = "Directory"
        put("    SourceBinding { provenance: SourceProvenance::" + provenance + ", disposition: SourceDisposition::" + disposition + " },\n")
    put("];\nconst CAT_SUPPORT: &[SupportOriginalSpec] = &[\n")
    for label, asset in (("bundletool", "BundletoolJar"), ("aapt2", "Aapt2OsxJar")):
        put("    SupportOriginalSpec { asset: SupportAsset::" + asset + ", archive: " + archive_literal(label, profile=profile) + ", modes: &[0o444] },\n")
    put("];\nconst CAT_PROJECTED: ZipMemberSpec<'static> = " + zip_literal(projection.aapt) + ";\n")
    put("const CAT_SUPPORT_MEMBERS: &[SupportMemberSpec] = &[SupportMemberSpec { asset: SupportAsset::Aapt2OsxJar, member: CAT_PROJECTED }];\n")
    put("const CAT_PAYLOAD: &[PayloadSource] = &[\n")
    for payload in projection.payload:
        origin = payload.origin
        if origin[0] == "Picked":
            value = "DirectOriginal(OriginalSource::Picked { group: SourceGroup::" + origin[1] + ", relative: " + rust_string(origin[2]) + " })"
        elif origin[0] == "Support":
            value = "DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar))"
        elif origin[0] == "CompiledSdkMetadata":
            need(origin[1] in ("Platform35Revision2", "BuildTools35"), "metadata-literal-kind")
            value = "CompiledSdkMetadata(SdkMetadataKind::" + origin[1] + ")"
        else:
            need(origin == ("MemberOfSameOriginalArchive",), "payload-origin-kind")
            value = "MemberOfSameOriginalArchive { asset: SupportAsset::Aapt2OsxJar, archive: " + archive_literal("aapt2", profile=profile) + ", member: CAT_PROJECTED }"
        put("    PayloadSource { installed: CanonicalFile { path: " + rust_string(payload.path) + ", size: " + str(payload.size)
            + ", sha256: " + rust_string(payload.sha256) + ", mode: " + oct(payload.mode) + " }, origin: PayloadOrigin::" + value + " },\n")
    put("];\nconst CAT_CLASSES: &[FileClass] = &[\n")
    for ordinal, payload in enumerate(projection.payload):
        kind = payload.classification
        if kind[0] == "JvmArchive":
            value = "JvmArchive { native_members: " + ("CAT_N" + str(ordinal) if kind[1] else "&[]") + " }"
        elif kind[0] == "MachO":
            value = "MachO(" + native(kind[1]) + ")"
        elif kind[0] == "SdkLegacyIntel":
            need(kind[1] in ("LldIntel", "CxxIntel", "CxxAbiIntel"), "intel-literal-kind")
            value = "SdkLegacyIntel(policy::Sdk35File::" + kind[1] + ", " + native(kind[2]) + ")"
        elif kind[0] == "SdkBash":
            need(kind[1] in ("D8", "Apksigner", "LldShell"), "script-literal-kind")
            value = "SdkBash(policy::Sdk35File::" + kind[1] + ")"
        else:
            need(kind[0] in ("Data", "LicenseText", "GradleShell", "GradleForeignLauncher", "AndroidTargetElf"), "file-literal-kind")
            value = kind[0]
        put("    FileClass::" + value + ",\n")
    put("];\nconst CAT_ALIASES: &[CanonicalAlias] = &[\n")
    for path, target, canonical_name, source_id in projection.aliases:
        put("    CanonicalAlias { path: " + rust_string(path) + ", target: " + rust_string(target) + ", canonical: "
            + rust_string(canonical_name) + ", source_index: " + str(source_id) + " },\n")
    put("];\nconst CAT_DIRECTORIES: &[&str] = &[\n")
    for path in projection.directories:
        put("    " + rust_string(path) + ",\n")
    put("];\n" + ("pub(super) " if profile == "x86_64" else "") + "const REFERENCES: &[Reference] = &[Reference {\n")
    put("    profile: crate::android_build_protocol::" + ("MAC_TOOLCHAIN_PROFILE" if profile == "arm64"
        else "MAC_X64_TOOLCHAIN_PROFILE") + ",\n")
    put("    observed_jdk_vendor: " + rust_string(projection.vendor) + ", observed_jdk_version: " + rust_string(projection.version) + ",\n")
    put('    versions: VersionSpec { jdk_vendor: "temurin", jdk_version: "17.0.20.1", gradle_version: "8.14.5", agp_version: "8.9.2",\n')
    put('        sdk_platform: "android-35", sdk_platform_revision: "2", sdk_build_tools_version: "35.0.0" },\n')
    put("    roles: RoleSpec { java: " + rust_string(INSTALLED_JDK + "Contents/Home/bin/java") + ", javac: " + rust_string(INSTALLED_JDK + "Contents/Home/bin/javac")
        + ', gradle: "gradle/bin/gradle", bundletool: "bundletool/bundletool.jar", sdk: "sdk" },\n')
    put("    gradle_distribution_url: " + rust_string(GRADLE_WRAPPER_URL) + ", gradle_distribution_sha256: " + rust_string(archives["gradle"][1]) + ",\n")
    put("    archives: CAT_ARCHIVES, trees: CAT_TREES, source_members: CAT_SOURCES, source_bindings: CAT_BINDINGS,\n")
    put("    support: CAT_SUPPORT, support_members: CAT_SUPPORT_MEMBERS, payload: CAT_PAYLOAD, classes: CAT_CLASSES,\n")
    put("    aliases: CAT_ALIASES, directories: CAT_DIRECTORIES,\n}];\n")
    return output.finish()


def generate(documents: Mapping[str, bytes], sink: Callable[[bytes], None]):
    """Validate all DATA, then emit proposed SOURCE to the owner's private sink.

    The normal return binds emitted bytes, not publication/owner finality and
    not native qualification. On any exception the owner must reject ALL output.
    No filesystem pathname is opened and no executable/native bytes are run.
    """
    inputs = Inputs(documents)
    outers = {}
    for label in LABELS:
        path = OUTERS[label]
        inputs.group(path, label)
        outers[label] = Outer(label, inputs.document(path))
    proofs = Proofs(inputs, outers)
    projection = Projection(outers, proofs)
    inputs.finish()
    summary = projection.summary()
    summary["output"] = render(projection, sink)
    # These hashes bind exact supplied observation bytes, not a Python copy of
    # Reference's Rust/serde commitment. The existing Rust digest stays sole.
    summary["inputs"] = [{"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                         for path, raw in sorted(inputs.documents.items())]
    return summary


# Fresh Intel observations are a different DATA protocol, not replacements for
# Inputs' historical ARM documents. Private admission below is DATA only; the
# separate generate_intel entry can propose SOURCE, never a runtime grant.
_FRESH_INTEL_ROLES = (
    "jdk-correspondence.json", "jdk-inspection.json", "gradle-inspection.json",
    "sdk-platform-inspection.json", "sdk-build-tools-inspection.json",
    "aapt2-inspection.json", "bundletool-inspection.json", "jdk-release.bytes", "jdk-jvm-cfg.bytes",
)
_FRESH_INTEL_JDK = (180578248, "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a")
_FRESH_INTEL_CORRESPONDENCE = (100949, "fd4287337be6dc07ebb3576e1790a2c708487899637ed945d60d5197e8d30e46")
_FRESH_INTEL_SELECTED = (
    ("jdk-release.bytes", JDK_ROOT + "/Contents/Home/release", 1637,
     "edbe3a2e6b6a3186010a3b75257685d943a8baa013a92174c9a48b8c1a73886b"),
    ("jdk-jvm-cfg.bytes", JDK_ROOT + "/Contents/Home/lib/jvm.cfg", 29,
     "aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0"),
)
# One observed SDK member is inert manifest text despite its raw execute mode.
# This is a DATA classification, never a native role or a complete-negative claim.
_FRESH_SDK_MANIFEST = (
    ("sdk-build-tools", 76857898, "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48"),
    ("android-15/renderscript/lib/androidx-rs.jar", 0o100644, 155117,
     "174eb53df52a9cca7bf9c396ba93bf4ac0262a48f2a1375f626efddf405d4666"),
    ("META-INF/MANIFEST.MF", 0o100700, 45,
     "5b85b9d62b7ac535a1d6d3c4801a50d63a08bc1cc31d55ca1396c34c8be6d332"),
    b"Manifest-Version: 1.0\nCreated-By: soong_zip\n\n",
    (87, 87, 84, 3, 338616, "841abae6dabfdc606b1188d54e0a1e7d7ae2875380ccc5b95ec2a9de44c3efee"),
)
_FRESH_FORMATS = ("macho", "java-class-header", "unsupported-native", "ambiguous-native",
                  "foreign-native", "zip", "jmod", "unsupported-jmod", "shell", "opaque")
_FRESH_COMPLETE_OBLIGATIONS = ["fresh-complete-target-reference", "target-native-role-review",
                              "installed-loader-provider-custody", "native-Mac-qualification"]
_FRESH_SELECTED_OBLIGATIONS = ["kotlin-shaded-jansi", "sdk-platform", "sdk-build-tools",
                              "installed-loader-provider-custody", "native-Mac-qualification"]
_FRESH_RESOURCE_KEYS = ("issuedReadBytes", "innerExpandedBytes", "prepublicationPeakReservedBytes",
                        "prepublicationPeakReservations", "reservationMeaning")


class _FreshIntelInputs:
    """Nine immutable originals supplied by an owner, never filesystem paths.

    Commitments cover the ORIGINAL bytes, not reserialized/normalized reports.
    This bookkeeping alone does not validate a component or grant authority.
    """
    def __init__(self, documents: Mapping[str, bytes]):
        need(type(documents) is dict and set(documents) == set(_FRESH_INTEL_ROLES), "fresh-input-roles")
        need(all(type(k) is str and type(v) is bytes and 0 < len(v) <= DOCUMENT_LIMIT
                 for k, v in documents.items()), "fresh-input-bytes")
        need(len(documents) <= RECORD_LIMIT and sum(map(len, documents.values())) <= INPUT_LIMIT,
             "aggregate-input-bound")
        self.documents = dict(documents)
        self.commitments = tuple((name, len(documents[name]), hashlib.sha256(documents[name]).hexdigest())
                                 for name in _FRESH_INTEL_ROLES)
        self.used = set()
        self.finished = False

    def raw(self, role):
        need(type(role) is str and role in self.documents and role not in self.used and not self.finished,
             "fresh-input-missing-duplicate-or-finished")
        self.used.add(role)
        return self.documents[role]

    def document(self, role):
        need(role in _FRESH_INTEL_ROLES[:-2], "fresh-not-a-json-role")
        return decode(self.raw(role))

    def finish(self):
        need(not self.finished and self.used == set(_FRESH_INTEL_ROLES), "fresh-unconsumed-or-finished")
        self.finished = True
        return self.commitments


@dataclass(frozen=True, slots=True)
class _FreshOuter:
    label: str
    members: list[Member]
    by_name: dict[str, Member]


def _fresh_pin(label):
    need(type(label) is str and label in LABELS, "fresh-component")
    return _FRESH_INTEL_JDK if label == "jdk" else ARCHIVES[label][:2]


def _fresh_archive(value, label):
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["target"] == "x86_64-apple-darwin"
         and (integer(value["archiveBytes"], 1), sha(value["archiveSha256"])) == _fresh_pin(label)
         and all(value[k] is False for k in ("nativeExecuted", "nativeClosure", "supplierAuthority")),
         "fresh-report-header")


def _fresh_outer(label, summary, rows):
    keys(summary, ("entryHeaders", "members", "files", "aliases", "expandedBytes",
                   "issuedReadBytes", "rosterReservationBytes"), "fresh-outer-summary")
    members, by_name = _outer_rows(label, rows, summary, _fresh_pin(label)[0])
    need(summary["aliases"] == 0, "fresh-outer-aliases")
    integer(summary["issuedReadBytes"], _fresh_pin(label)[0], 768 * 1024 * 1024)
    expected = sum(1536 + 8 * len(row.name) + 8 * len(row.target or "") for row in members)
    need(integer(summary["rosterReservationBytes"], 1, 48 * 1024 * 1024) == expected,
         "fresh-outer-roster-accounting")
    return _FreshOuter(label, members, by_name)


def _fresh_file(value, member=None):
    relative(value["name"])
    integer(value["bytes"], 0, 512 * 1024 * 1024)
    mode = integer(value["mode"], 0, 0o170777)
    need(mode & ~0o170777 == 0 and mode & 0o170000 in (0, 0o100000), "fresh-file-mode")
    sha(value["sha256"])
    if member is not None:
        need(member.kind == "file" and (value["name"], value["bytes"], mode, value["sha256"])
             == (member.name, member.size, member.mode, member.sha256), "fresh-containing-member-join")


def _fresh_slice(prefix, size):
    # Match the producer's bounded snapshot-placement facts only. Load commands,
    # dyld roles and supported supplier CPU policy still belong to Rust.
    need(len(prefix) >= 32 and size >= 32, "fresh-native-prefix")
    def number(at, width=4, order="big"):
        return int.from_bytes(prefix[at:at + width], order)
    magic = prefix[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu, subtype = number(4, order="little"), number(8, order="little")
        return (0, size, cpu, subtype) if cpu == 0x01000007 else None
    need(magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"), "fresh-native-magic")
    count, width = number(4), 20 if magic == b"\xca\xfe\xba\xbe" else 32
    end = 8 + count * width
    need(1 <= count <= 4 and end <= len(prefix), "fresh-native-fat-table")
    cpus, ranges, selected = set(), [], None
    for index in range(count):
        at = 8 + index * width
        cpu, subtype = number(at), number(at + 4)
        field = 4 if width == 20 else 8
        offset, extent = number(at + 8, field), number(at + 8 + field, field)
        alignment = number(at + 8 + 2 * field)
        need(width == 20 or number(at + 28) == 0, "fresh-native-fat-reserved")
        need(cpu not in cpus and alignment <= 20 and offset >= end and extent >= 32
             and offset % (1 << alignment) == 0 and offset + extent <= size
             and all(offset + extent <= lo or offset >= hi for lo, hi in ranges), "fresh-native-fat-range")
        cpus.add(cpu); ranges.append((offset, offset + extent))
        if cpu == 0x01000007:
            selected = (offset, extent, cpu, subtype)
    return selected


def _fresh_native(value, member=None, *, counterpart=False):
    expected = ("name", "bytes", "mode", "sha256", "format", "prefixBytes", "prefixSha256", "prefixBase64",
                "selectedCpu", "sliceOffset", "sliceBytes", "commandsBytes", "commandsSha256", "commandsBase64")
    keys(value, (*expected, "counterpart") if counterpart else expected, "fresh-native-shape")
    _fresh_file(value, member)
    need(value["format"] == "macho", "fresh-native-format")
    if counterpart:
        claim = keys(value["counterpart"], ("candidate", "matched", "status"), "fresh-counterpart-shape")
        if claim["candidate"] is not None:
            relative(claim["candidate"])
        need(type(claim["matched"]) is bool and claim["status"] in
             ("exact-byte-and-snapshot-match", "different-bytes-or-snapshot",
              "embedded-jpackage-template-observed", "unmatched"), "fresh-counterpart-fields")
    prefix = base64_bytes(value["prefixBase64"], value["prefixBytes"], value["prefixSha256"], 4096)
    need(len(prefix) == min(value["bytes"], 4096), "fresh-native-prefix-extent")
    if len(prefix) == value["bytes"]:
        need(value["prefixSha256"] == value["sha256"], "fresh-complete-prefix-hash")
    selected = _fresh_slice(prefix, value["bytes"])
    if selected is None:
        need(value["selectedCpu"] is None and value["sliceOffset"] is None and value["sliceBytes"] is None
             and type(value["commandsBytes"]) is int and value["commandsBytes"] == 0
             and value["commandsSha256"] is None and value["commandsBase64"] is None,
             "fresh-nonhost-has-no-selected-snapshot")
        return (prefix, None)
    need(value["selectedCpu"] == "x86_64" and
         (integer(value["sliceOffset"], 0, value["bytes"]), integer(value["sliceBytes"], 32, value["bytes"]))
         == selected[:2], "fresh-selected-slice-join")
    commands = base64_bytes(value["commandsBase64"], value["commandsBytes"], value["commandsSha256"], 65536)
    need(32 <= len(commands) <= selected[1], "fresh-selected-command-extent")
    words = tuple(int.from_bytes(commands[at:at + 4], "little") for at in range(0, 32, 4))
    need(words[0] == 0xFEEDFACF and words[1:3] == selected[2:] and words[3] in (2, 6, 8)
         and 1 <= words[4] <= 1024 and 8 * words[4] <= words[5] and 32 + words[5] == len(commands),
         "fresh-selected-command-header")
    overlap = max(0, min(len(prefix) - selected[0], len(commands)))
    need(prefix[selected[0]:selected[0] + overlap] == commands[:overlap], "fresh-prefix-command-overlap")
    return (prefix, commands)


def _fresh_foreign(value, member=None, *, complete):
    basic = ("name", "bytes", "mode", "sha256", "format", "prefixBase64")
    keys(value, (*basic, "prefixBytes", "prefixSha256") if complete else basic, "fresh-foreign-shape")
    _fresh_file(value, member)
    if complete:
        need(value["format"] in ("ELF", "PE"), "fresh-foreign-format")
        prefix = base64_bytes(value["prefixBase64"], value["prefixBytes"], value["prefixSha256"], 4096)
        need(len(prefix) == min(value["bytes"], 4096), "fresh-foreign-prefix-extent")
        if len(prefix) == value["bytes"]:
            need(value["prefixSha256"] == value["sha256"], "fresh-complete-prefix-hash")
    else:
        # Legacy reports have the actual small prefix but NO separate prefix
        # digest. Do not invent one or silently convert this to the new schema.
        need(value["format"] == "foreign-native" and type(value["prefixBase64"]) is str
             and len(value["prefixBase64"]) == 4 * ((min(160, value["bytes"]) + 2) // 3),
             "fresh-legacy-foreign-prefix")
        try:
            prefix = base64.b64decode(value["prefixBase64"], validate=True)
        except (ValueError, binascii.Error) as error:
            raise Refused("fresh-legacy-base64") from error
        need(len(prefix) == min(160, value["bytes"])
             and base64.b64encode(prefix).decode("ascii") == value["prefixBase64"], "fresh-legacy-base64")
        if len(prefix) == value["bytes"]:
            need(hashlib.sha256(prefix).hexdigest() == value["sha256"], "fresh-complete-prefix-hash")
    kind = "ELF" if prefix.startswith(b"\x7fELF") else "PE" if prefix.startswith(b"MZ") else None
    need(kind is not None and (not complete or value["format"] == kind), "fresh-foreign-prefix-format")
    return kind


def _fresh_counts(value, files):
    counts = keys(value, _FRESH_FORMATS, "fresh-format-counts")
    need(sum(integer(n, 0, files) for n in counts.values()) == files, "fresh-file-format-census")
    need(all(counts[k] == 0 for k in ("unsupported-native", "ambiguous-native", "unsupported-jmod")),
         "fresh-unresolved-format")
    return counts


def _fresh_sdk_manifest(value, counts, container, containing):
    """Retain the exact executable-opaque observation as finite inert DATA."""
    archive, jar, manifest, body, census = _FRESH_SDK_MANIFEST
    need(type(container) is _FreshOuter and type(containing) is Member
         and container.label == archive[0] and _fresh_pin(container.label) == archive[1:]
         and container.by_name.get(jar[0]) is containing, "fresh-inert-containing-origin")
    need(containing.kind == "file" and containing.hint == "zip"
         and (containing.name, containing.mode, containing.size, containing.sha256) == jar
         and (value["name"], value["mode"], value["bytes"], value["sha256"]) == jar
         and value["format"] == "zip" and type(value["zipViewOffset"]) is int
         and value["zipViewOffset"] == 0, "fresh-inert-containing-tuple")
    observed = tuple(integer(value[k]) for k in ("centralMembers", "inspectedMembers", "files",
                     "directoryMembers", "expandedInspectedBytes")) + (sha(value["enumerationSha256"]),)
    need(observed == census and counts == {key: 83 if key == "java-class-header" else
         1 if key == "opaque" else 0 for key in _FRESH_FORMATS}, "fresh-inert-containing-census")
    unknown = value["unknownMembers"]
    need(len(unknown) == 1, "fresh-unresolved-resource")
    item = keys(unknown[0], ("name", "bytes", "mode", "sha256", "format", "prefixBytes",
                "prefixSha256", "prefixBase64", "reason"), "fresh-inert-row")
    _fresh_file(item)
    need((item["name"], item["mode"], item["bytes"], item["sha256"]) == manifest
         and item["format"] == "opaque" and item["reason"] == "executable-opaque",
         "fresh-inert-member-tuple")
    prefix = base64_bytes(item["prefixBase64"], item["prefixBytes"], item["prefixSha256"], 45)
    need(len(prefix) == item["bytes"] == 45 and item["prefixSha256"] == manifest[3]
         and prefix == body, "fresh-inert-complete-bytes")
    return item["name"]


def _fresh_specials(value, counts, *, complete, outer=None, counterpart=False, container=None, containing=None):
    native = value["nativeMembers"]
    unknown = value["unknownMembers"]
    need(type(native) is list and len(native) <= 128 and type(unknown) is list, "fresh-special-lists")
    names = set()
    if complete:
        if unknown:
            if outer is not None and outer.label == "gradle":
                names.add(_fresh_gradle_launcher(value, outer))
            elif _fresh_gradle_context(container, containing) is not None:
                names.update(_fresh_gradle_specials(value, counts, container, containing))
            else:
                names.add(_fresh_sdk_manifest(value, counts, container, containing))
        foreign = value["foreignNativeMembers"]
    else:
        # Only the old producer's explicitly recognized ELF/PE rows can move
        # forward as foreign DATA. Unsupported/ambiguous records still refuse.
        foreign = unknown
    need(type(foreign) is list and len(native) + len(foreign) <= 128
         and len(native) == counts["macho"] and len(foreign) == counts["foreign-native"],
         "fresh-native-census")
    for items, is_native in ((native, True), (foreign, False)):
        previous = None
        for item in items:
            need(type(item) is dict and type(item.get("name")) is str, "fresh-special-row")
            name = item["name"]
            need(name not in names and (previous is None or previous < name), "fresh-special-order-or-duplicate")
            names.add(name); previous = name
            member = None if outer is None else outer.by_name.get(name)
            need(outer is None or member is not None, "fresh-special-outer-name")
            if is_native:
                _fresh_native(item, member, counterpart=counterpart)
                need(member is None or member.hint in ("macho", "fat-macho-or-java-class"), "fresh-native-outer-hint")
            else:
                kind = _fresh_foreign(item, member, complete=complete)
                need(member is None or member.hint == ("elf" if kind == "ELF" else "pe"), "fresh-foreign-outer-hint")
    return names


def _fresh_inner(value, member=None, *, complete, counterpart=False, depth=0, nested=None, container=None):
    basic = ("name", "bytes", "sha256", "mode", "format", "zipViewOffset", "centralMembers", "inspectedMembers",
             "files", "completeMemberHashes", "expandedInspectedBytes", "enumerationSha256", "formatCounts",
             "nativeMembers", "unknownMembers", "nestedArchives", "innerBookReservationBytes", "issuedReadBytes",
             "nativeExecuted", "supplierAuthority")
    keys(value, (*basic, "directoryMembers", "foreignNativeMembers", "negativeEvidence") if complete else basic,
         "fresh-inner-shape")
    _fresh_file(value, member)
    integer(value["bytes"], 1, 64 * 1024 * 1024)
    need(value["format"] in ("zip", "jmod") and type(value["zipViewOffset"]) is int
         and value["zipViewOffset"] == (4 if value["format"] == "jmod" else 0)
         and value["bytes"] >= 22 + value["zipViewOffset"]
         and (member is None or member.hint == value["format"]), "fresh-inner-format")
    count = integer(value["centralMembers"], 1, ENTRY_LIMIT)
    files = integer(value["files"], 0, count)
    need(integer(value["inspectedMembers"]) == count and value["completeMemberHashes"] is True
         and value["nativeExecuted"] is False and value["supplierAuthority"] is False, "fresh-inner-complete")
    if complete:
        need(integer(value["directoryMembers"]) == count - files, "fresh-inner-directory-census")
    expanded = integer(value["expandedInspectedBytes"], 0, TOTAL_LIMIT)
    reads = integer(value["issuedReadBytes"], value["bytes"] - value["zipViewOffset"], 768 * 1024 * 1024)
    integer(value["innerBookReservationBytes"], 1, 48 * 1024 * 1024)
    sha(value["enumerationSha256"])
    counts = _fresh_inner_counts(value, files, container, member)  # Files, NOT centralMembers.
    need(container is None or depth == 0, "fresh-inert-origin-depth")
    names = _fresh_specials(value, counts, complete=complete, counterpart=counterpart,
                           container=container, containing=member)
    children = value["nestedArchives"]
    need(type(children) is list and len(children) <= 3
         and len(children) == counts["zip"] + counts["jmod"], "fresh-nested-census")
    nested = [0] if nested is None else nested
    previous = None
    own_special_bytes = sum(item["bytes"] for item in value["nativeMembers"] + value["unknownMembers"])
    if complete:
        own_special_bytes += sum(item["bytes"] for item in value["foreignNativeMembers"])
    for child in children:
        need(type(child) is dict and type(child.get("name")) is str, "fresh-nested-row")
        name = child["name"]
        need(name not in names and (previous is None or previous < name), "fresh-nested-order-or-duplicate")
        names.add(name); previous = name
        nested[0] += 1
        need(depth < 2 and nested[0] <= 3, "fresh-nested-depth-or-count")
        child_expanded, child_reads = _fresh_inner(child, complete=complete, depth=depth + 1, nested=nested)
        expanded += child_expanded; reads += child_reads
        own_special_bytes += child["bytes"]
    need(all(sum(child["format"] == kind for child in children) == counts[kind] for kind in ("zip", "jmod")),
         "fresh-nested-format-census")
    need(own_special_bytes <= value["expandedInspectedBytes"], "fresh-inner-special-byte-census")
    for name in names:
        parts = name.split("/")
        need(all("/".join(parts[:end]) not in names for end in range(1, len(parts))), "fresh-resource-file-parent")
    if complete:
        eligible = not names and all(n == 0 for k, n in counts.items() if k not in ("java-class-header", "opaque"))
        need((value["negativeEvidence"] is not None) == eligible, "fresh-negative-presence")
    if complete and value["negativeEvidence"] is not None:
        negative_value = value["negativeEvidence"]
        expected = {key: value[key] for key in ("centralMembers", "inspectedMembers", "files", "completeMemberHashes",
                    "expandedInspectedBytes", "enumerationSha256")}
        expected.update(kind="complete-recognized-format-negative", nativeMembers=[], nestedArchives=[],
                        nativeExecution=False, supplierAuthority=False)
        keys(negative_value, expected, "fresh-negative-shape")
        # Equality alone would admit bools in numeric positions.
        for key in ("centralMembers", "inspectedMembers", "files", "expandedInspectedBytes"):
            integer(negative_value[key])
        need(negative_value == expected and negative_value["completeMemberHashes"] is True
             and negative_value["nativeExecution"] is False and negative_value["supplierAuthority"] is False
             and not names and all(n == 0 for k, n in counts.items() if k not in ("java-class-header", "opaque")),
             "fresh-negative-binding")
    need(expanded <= TOTAL_LIMIT and reads <= 768 * 1024 * 1024, "fresh-inner-aggregate")
    # No inner rows were supplied: enumerationSha256 remains the producer's
    # bound observation, not a recreated legacy enumeration/proof document.
    return expanded, reads


def _fresh_resources(value, reads, expanded):
    need(integer(value["issuedReadBytes"], 1, 768 * 1024 * 1024) == reads
         and integer(value["innerExpandedBytes"], 0, TOTAL_LIMIT) == expanded, "fresh-aggregate-counters")
    peaks = keys(value["prepublicationPeakReservations"], ("payload", "rows", "facts", "output", "other"),
                 "fresh-reservation-shape")
    for kind, maximum in (("payload", 64 * 1024 * 1024), ("rows", 48 * 1024 * 1024),
                          ("facts", 128 * 1024 * 1024), ("output", 0), ("other", 128 * 1024 * 1024)):
        integer(peaks[kind], 0, maximum)
    peak = integer(value["prepublicationPeakReservedBytes"], 8 * 1024 * 1024, 128 * 1024 * 1024)
    need(peaks["other"] >= 8 * 1024 * 1024 and max(peaks.values()) <= peak <= sum(peaks.values())
         and value["reservationMeaning"] == "explicit-owned-allocation-budget-not-total-interpreter-memory",
         "fresh-reservation-meaning")


def _fresh_outer_observation(value, outer, archives, *, complete, jdk=False):
    counts = _fresh_counts(value["formatCounts"], sum(m.kind == "file" for m in outer.members))
    names = _fresh_specials(value, counts, complete=complete, outer=outer)
    need(type(archives) is list and len(archives) <= ENTRY_LIMIT
         and len(archives) == counts["zip"] + counts["jmod"], "fresh-outer-inner-census")
    expected = {m.name for m in outer.members if m.kind == "file" and m.hint in ("zip", "jmod")}
    visited, previous, expanded, reads = set(), None, 0, 0
    for archive in archives:
        need(type(archive) is dict and type(archive.get("name")) is str, "fresh-outer-inner-row")
        name = archive["name"]
        need(name in expected and name not in names and name not in visited
             and (previous is None or previous < name), "fresh-outer-inner-inverse")
        visited.add(name); previous = name
        amount, issued = _fresh_inner(archive, outer.by_name[name], complete=complete,
                                      counterpart=jdk and archive.get("format") == "jmod", container=outer)
        expanded += amount; reads += issued
    need(visited == expected, "fresh-missing-inner-report")
    if complete:
        for member in outer.members:
            if member.kind != "file":
                continue
            name = member.name
            need(not name.endswith((".jar", ".jmod"))
                 or member.hint == ("jmod" if name.endswith(".jmod") else "zip"), "fresh-outer-archive-suffix")
            need(not name.endswith(".class") or member.hint == "fat-macho-or-java-class" and name not in names,
                 "fresh-outer-class-suffix")
            need(not name.endswith((".dylib", ".jnilib", ".so", ".dll", ".exe")) or name in names,
                 "fresh-outer-native-suffix")
            need(member.hint is not None or not member.mode & 0o111
                 or outer.label == "gradle" and name == _INTEL_GRADLE_LAUNCHER[0] and name in names,
                 "fresh-outer-executable-opaque")
    # Exact inverse for the independently supplied OUTER rows. The ambiguous
    # FAT/class hint is divided by the actual native list, not guessed as x64.
    hints = {hint: sum(m.kind == "file" and m.hint == hint for m in outer.members)
             for hint in (None, "shell", "macho", "fat-macho-or-java-class", "elf", "pe", "zip", "jmod")}
    fat_native = sum(outer.by_name[item["name"]].hint == "fat-macho-or-java-class" for item in value["nativeMembers"])
    need(counts["macho"] - fat_native == hints["macho"]
         and counts["java-class-header"] + fat_native == hints["fat-macho-or-java-class"]
         and counts["foreign-native"] == hints["elf"] + hints["pe"]
         and all(counts[k] == hints[k] for k in ("shell", "zip", "jmod"))
         and counts["opaque"] == hints[None], "fresh-outer-format-inverse")
    need(expanded <= TOTAL_LIMIT and reads <= 768 * 1024 * 1024, "fresh-component-inner-aggregate")
    return expanded, reads


def _fresh_non_jdk(label, value):
    need(type(label) is str and label in LABELS[1:], "fresh-non-jdk-component")
    complete = label in ("gradle", "sdk-platform", "sdk-build-tools")
    base = ("schemaVersion", "kind", "target", "component", "archiveBytes", "archiveSha256", "columns", "outer", "rows",
            "completeOuterMemberHashes", "formatCounts", "nativeMembers", "unknownMembers", "uninspectedInnerArchives",
            "uninspectedInnerArchiveCount", "innerInspectionScope", "remainingObligations", "nativeExecuted",
            "nativeClosure", "supplierAuthority", *_FRESH_RESOURCE_KEYS)
    extra = ("completeInnerCoverage", "directoryMembers", "foreignNativeMembers", "innerArchives") if complete else ("selectedInnerArchives",)
    keys(value, (*base, *extra), "fresh-non-jdk-shape")
    _fresh_archive(value, label)
    need(value["kind"] == ("mrk-intel-complete-non-jdk-observation-data-v1" if complete
                           else "mrk-intel-non-jdk-observation-data-v1")
         and value["component"] == label and value["columns"] == list(COLUMNS)
         and value["completeOuterMemberHashes"] is True and value["uninspectedInnerArchives"] == []
         and type(value["uninspectedInnerArchiveCount"]) is int and value["uninspectedInnerArchiveCount"] == 0,
         "fresh-non-jdk-completion")
    outer = _fresh_outer(label, value["outer"], value["rows"])
    if complete:
        need(value["completeInnerCoverage"] is True
             and integer(value["directoryMembers"]) == len(outer.members) - value["outer"]["files"]
             and value["innerInspectionScope"] == "all-complete-outer-zip-or-jmod"
             and value["remainingObligations"] == _FRESH_COMPLETE_OBLIGATIONS, "fresh-complete-scope")
        archives = value["innerArchives"]
    else:
        need(value["selectedInnerArchives"] == []
             and value["innerInspectionScope"] == "fixed-selected-outer-jars-only"
             and value["remainingObligations"] == _FRESH_SELECTED_OBLIGATIONS, "fresh-selected-scope")
        archives = value["selectedInnerArchives"]
    expanded, reads = _fresh_outer_observation(value, outer, archives, complete=complete)
    _fresh_resources(value, reads + value["outer"]["issuedReadBytes"], expanded)
    return outer


def _fresh_jdk_counterparts(direct, archives):
    names = {item["name"]: item for item in direct}
    compared = ("bytes", "sha256", "prefixBytes", "prefixSha256", "prefixBase64", "selectedCpu",
                "sliceOffset", "sliceBytes", "commandsBytes", "commandsSha256", "commandsBase64")
    for archive in archives:
        if archive["format"] != "jmod":
            continue
        for item in archive["nativeMembers"]:
            claim = keys(item["counterpart"], ("candidate", "matched", "status"), "fresh-counterpart-shape")
            name = item["name"]
            candidate = JDK_ROOT + "/Contents/Home/" + name if name.startswith(("bin/", "lib/")) else None
            other = names.get(candidate)
            exact = other is not None and all(item[key] == other[key] for key in compared)
            template = (archive["name"] == JDK_ROOT + "/Contents/Home/jmods/jdk.jpackage.jmod"
                        and name == "classes/jdk/jpackage/internal/resources/jpackageapplauncher")
            status = ("exact-byte-and-snapshot-match" if exact else "different-bytes-or-snapshot" if other is not None
                      else "embedded-jpackage-template-observed" if template else "unmatched")
            need(claim["candidate"] == candidate and claim["matched"] is exact and claim["status"] == status,
                 "fresh-counterpart-observation-join")
            # SOURCE comparison DATA only, not a new executable/template role.
            template_pin = (188160, "2fc0206e6e6fb80c90d2b1893d2e145e1b9a6162fa1ce5b0349307566b75d7fd",
                            "b5c98cf8727e50ecd11f3547c321188ad93b9642720be069959b59a261d354d8",
                            "7a39418a30571af042282559035c16b41a57d56bee960a48a45c8e6400aeab9e")
            need(exact or template and (item["bytes"], item["sha256"], item["prefixSha256"], item["commandsSha256"])
                 == template_pin, "fresh-unmatched-jdk-native")


def _fresh_jdk(outer_raw, value):
    need(type(outer_raw) is bytes and (len(outer_raw), hashlib.sha256(outer_raw).hexdigest())
         == _FRESH_INTEL_CORRESPONDENCE, "fresh-jdk-correspondence-original")
    document = decode(outer_raw)
    keys(document, ("schemaVersion", "kind", "label", "archiveBytes", "archiveSha256", "completeMemberHashes",
                    "supplierAuthority", "nativeClosure", "entryHeaders", "members", "files", "aliases",
                    "expandedBytes", "columns", "rows"), "fresh-jdk-correspondence-shape")
    need(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
         and document["kind"] == "offline-official-archive-correspondence-data" and document["label"] == "jdk"
         and (integer(document["archiveBytes"], 1), sha(document["archiveSha256"])) == _FRESH_INTEL_JDK
         and document["completeMemberHashes"] is True and document["supplierAuthority"] is False
         and document["nativeClosure"] is False and document["columns"] == list(COLUMNS), "fresh-jdk-correspondence-header")
    keys(value, ("schemaVersion", "kind", "target", "archiveBytes", "archiveSha256", "correspondenceSha256", "outer",
                 "formatCounts", "nativeMembers", "unknownMembers", "jvmMembers", "nativeExecuted", "nativeClosure",
                 "supplierAuthority", *_FRESH_RESOURCE_KEYS), "fresh-jdk-shape")
    _fresh_archive(value, "jdk")
    need(value["kind"] == "mrk-intel-jdk-native-jvm-data-v1"
         and sha(value["correspondenceSha256"]) == hashlib.sha256(outer_raw).hexdigest(), "fresh-jdk-raw-correspondence-join")
    outer = _fresh_outer("jdk", value["outer"], document["rows"])
    for key in ("entryHeaders", "members", "files", "aliases", "expandedBytes"):
        need(integer(document[key]) == value["outer"][key], "fresh-jdk-complete-outer-join")
    need((document["members"], document["files"], document["aliases"], document["expandedBytes"])
         == (549, 457, 0, 299747655), "fresh-jdk-census")
    expanded, reads = _fresh_outer_observation(value, outer, value["jvmMembers"], complete=False, jdk=True)
    need(len(value["nativeMembers"]) == 71 and len(value["jvmMembers"]) == 74
         and sum(item["format"] == "jmod" for item in value["jvmMembers"]) == 70, "fresh-jdk-selected-census")
    _fresh_jdk_counterparts(value["nativeMembers"], value["jvmMembers"])
    _fresh_resources(value, reads + value["outer"]["issuedReadBytes"], expanded)
    return outer


def _fresh_selected_bytes(inputs, outer):
    selected = []
    for role, name, size, digest in _FRESH_INTEL_SELECTED:
        raw = inputs.raw(role)
        member = outer.by_name.get(name)
        need(type(raw) is bytes and member is not None and member.tuple()
             == {"name": name, "kind": "file", "mode": 0o100644, "size": size, "sha256": digest}
             and (len(raw), hashlib.sha256(raw).hexdigest()) == (size, digest), "fresh-selected-original-bytes")
        selected.append((name, raw))
    return tuple(selected)


@dataclass(frozen=True, slots=True)
class _FreshIntelData:
    # Private schema/correspondence DATA, deliberately lacking emit/Reference/
    # authority methods. Runtime role/provider review remains wholly separate.
    originals: tuple[tuple[str, bytes], ...]
    commitments: tuple[tuple[str, int, str], ...]
    outers: tuple[_FreshOuter, ...]
    observations: tuple[dict, ...]
    selected_bytes: tuple[tuple[str, bytes], ...]


def _fresh_intel_data(documents):
    return _fresh_intel_read(_FreshIntelInputs(documents))


def _fresh_intel_read(inputs):
    need(type(inputs) is _FreshIntelInputs, "fresh-input-book")
    outer_raw = inputs.raw("jdk-correspondence.json")
    jdk = inputs.document("jdk-inspection.json")
    outers, observations = [_fresh_jdk(outer_raw, jdk)], [jdk]
    for label in LABELS[1:]:
        value = inputs.document(label + "-inspection.json")
        outers.append(_fresh_non_jdk(label, value)); observations.append(value)
    selected = _fresh_selected_bytes(inputs, outers[0])
    commitments = inputs.finish()
    # No SOURCE sink exists on this route. A caller still needs the separately
    # pinned complete projection, and real runtime custody/role admission.
    return _FreshIntelData(tuple((name, inputs.documents[name]) for name in _FRESH_INTEL_ROLES),
                           commitments, tuple(outers), tuple(observations), selected)


_INTEL_INPUT_COMMITMENTS = (('jdk-correspondence.json', 100949, 'fd4287337be6dc07ebb3576e1790a2c708487899637ed945d60d5197e8d30e46'),
 ('jdk-inspection.json', 1290358, '2c47970095d5ef969fc51bf688fcf2aac30899c68bd1c82d14a621e95debb246'),
 ('gradle-inspection.json', 1272954, '918398b9ad0e63b1c8fc109a79aeac34c7aca77886de71ddea6296d6952f7c08'),
 ('sdk-platform-inspection.json', 2231680, '49197e87a4accfa69b28ef4e898b2fcaad61bf576dae182839b8e9fa6701c315'),
 ('sdk-build-tools-inspection.json', 322435, '0de11cf169df014f73fdde1b78065ae56aefb4cea56e3f2d3aea62eca16d1013'),
 ('aapt2-inspection.json', 11261, '0b3cba2d81005bbc08fc50eb596aec51027e20b6e1a3ae689be7cecd72881aa8'),
 ('bundletool-inspection.json', 2958475, '14398d557aef3777fd3f7049e54b8a4542dac1990b8edf3cbae5a14bda670797'),
 ('jdk-release.bytes', 1637, 'edbe3a2e6b6a3186010a3b75257685d943a8baa013a92174c9a48b8c1a73886b'),
 ('jdk-jvm-cfg.bytes', 29, 'aa9efb969444c1484e29adecab55a122458090616e766b2f1230ef05bc3867e0'))


# Fixed fresh-observation SOURCE proposal only. These commitments do not grant
# runtime custody or a native phase; the separately reviewed Rust reference does.
_INTEL_ARCHIVES = {**ARCHIVES, "jdk": (*_FRESH_INTEL_JDK,
    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_mac_hotspot_17.0.20.1_1.tar.gz",
    "jdk-17.0.20.1+1")}
_INTEL_GRADLE_LAUNCHER = ("gradle-8.14.5/bin/gradle.bat", 3018,
    "d20e9ded0291e1ed6552d1df30022d2e5952ad493f9d3380f6a32b97f0cc80c7", 0o100755)
_INTEL_KOTLIN_I386 = ("org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86/libjansi.jnilib",
    14748, "ea7ceaf2b63f95ac34822fed2f4cdfd436599c682e04383fac3736dd4c4a41a6", 0,
    "7cc4e324aee6f2555b8a2b9c4e3988b5638d14d60e8ccb3e75066479c5ec08ea")
# Exact containing tuple, unresolved-row count, observed format, class version,
# required versioned path (None for historical classes), and full canonical row
# commitment. Original unknown/count/negative fields are NEVER rewritten.
_INTEL_GRADLE_RESOURCES = {
    "gradle-8.14.5/lib/jackson-core-2.18.6.jar": (589904,
        "e7e1bfa50f0a79db37e6aa37db111cf03aebf4a484b359d21127ab43ab2398c6", 2,
        "ambiguous-native", (65, 0), "META-INF/versions/21/",
        "1272a46b0599dd250638ee512b011d1dfe8bbfd54dcf4db8385e57af217921a2"),
    "gradle-8.14.5/lib/plugins/bcprov-jdk18on-1.84.jar": (8919063,
        "64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731", 24,
        "ambiguous-native", (69, 0), "META-INF/versions/25/",
        "07eae1913819bb60ffc0e17d7c642bd7881e945b6f76c3cb4b519dd7744f33b3"),
    "gradle-8.14.5/lib/xml-apis-1.4.01.jar": (220536,
        "a840968176645684bb01aed376e067ab39614885f9eee44abe35a5f20ebe7fad", 346,
        "ambiguous-native", (45, 3), None,
        "7287ab3a8414dc3609d88acb090654103001cb5a2f43572e4fe6f361b952dac4"),
    "gradle-8.14.5/lib/kotlin-compiler-embeddable-2.0.21.jar": (58272093,
        "9fa8cdd1de0dccffe154c997d423ec6b5f53cd6d9177e3a77a9b0de03fb1bc81", 1,
        "unsupported-native", None, None,
        "6db635559b82d6a2630ce9da705852f80bb632b7482ccacd1211aaacf0888497"),
}
_INTEL_CURRENT_NATIVE = (
    ("bundletool/bundletool.jar", "com/sun/jna/darwin/libjnidispatch.jnilib"),
    ("bundletool/bundletool.jar", "macos/aapt2"),
    ("gradle/lib/gradle-fileevents-0.2.7.jar", "net/rubygrapefruit/platform/x86_64-macos/libgradle-fileevents.dylib"),
    ("gradle/lib/jansi-1.18.jar", "META-INF/native/osx/libjansi.jnilib"),
    ("gradle/lib/kotlin-compiler-embeddable-2.0.21.jar",
     "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/x86_64/libjansi.jnilib"),
    ("gradle/lib/native-platform-osx-amd64-0.22-milestone-28.jar", "net/rubygrapefruit/platform/osx-amd64/libnative-platform-curses.dylib"),
    ("gradle/lib/native-platform-osx-amd64-0.22-milestone-28.jar", "net/rubygrapefruit/platform/osx-amd64/libnative-platform.dylib"),
)
_INTEL_NONHOST_ARM = (
    ("gradle/lib/gradle-fileevents-0.2.7.jar", "net/rubygrapefruit/platform/aarch64-macos/libgradle-fileevents.dylib"),
    ("gradle/lib/kotlin-compiler-embeddable-2.0.21.jar",
     "org/jetbrains/kotlin/org/fusesource/jansi/internal/native/Mac/arm64/libjansi.jnilib"),
    ("gradle/lib/native-platform-osx-aarch64-0.22-milestone-28.jar", "net/rubygrapefruit/platform/osx-aarch64/libnative-platform-curses.dylib"),
    ("gradle/lib/native-platform-osx-aarch64-0.22-milestone-28.jar", "net/rubygrapefruit/platform/osx-aarch64/libnative-platform.dylib"),
)


def _projection_profile(profile):
    need(type(profile) is str and profile in ("arm64", "x86_64"), "closed-projection-profile")
    return ARCHIVES if profile == "arm64" else _INTEL_ARCHIVES


def _fresh_gradle_context(container, containing):
    if type(container) is not _FreshOuter or container.label != "gradle" or type(containing) is not Member:
        return None
    pin = _INTEL_GRADLE_RESOURCES.get(containing.name)
    if pin is None:
        return None
    need(container.by_name.get(containing.name) is containing
         and (containing.kind, containing.hint, containing.mode, containing.size, containing.sha256)
         == ("file", "zip", 0o100644, pin[0], pin[1]), "fresh-gradle-containing-original")
    return pin


def _fresh_inner_counts(value, files, container, containing):
    pin = _fresh_gradle_context(container, containing)
    if pin is None:
        return _fresh_counts(value["formatCounts"], files)
    counts = keys(value["formatCounts"], _FRESH_FORMATS, "fresh-format-counts")
    need(sum(integer(n, 0, files) for n in counts.values()) == files, "fresh-file-format-census")
    need(all(counts[k] == (pin[2] if k == pin[3] else 0)
             for k in ("unsupported-native", "ambiguous-native", "unsupported-jmod")),
         "fresh-gradle-fixed-unresolved-census")
    return counts


def _fresh_unknown_prefix(item):
    keys(item, ("name", "bytes", "mode", "sha256", "format", "prefixBytes", "prefixSha256",
                "prefixBase64", "reason"), "fresh-fixed-unknown-shape")
    _fresh_file(item)
    prefix = base64_bytes(item["prefixBase64"], item["prefixBytes"], item["prefixSha256"], 4096)
    need(len(prefix) == min(item["bytes"], 4096), "fresh-fixed-unknown-prefix-extent")
    if len(prefix) == item["bytes"]:
        need(item["prefixSha256"] == item["sha256"], "fresh-fixed-unknown-whole-prefix")
    return prefix


def _fresh_class_header(prefix, size, version):
    """Finite header DATA, not class verification/loading or an MR manifest.

    JVMS25 4.1 admits these versions. Independently rule OUT FAT32 using
    necessary original-size constraints, never the project's slice-count cap.
    """
    need(type(prefix) is bytes and type(size) is int and 11 <= len(prefix) <= min(size, 4096)
         and type(version) is tuple and all(type(value) is int for value in version)
         and version in ((45, 3), (65, 0), (69, 0)), "fresh-fixed-class-input")
    need(prefix[:4] == b"\xca\xfe\xba\xbe"
         and (int.from_bytes(prefix[6:8], "big"), int.from_bytes(prefix[4:6], "big")) == version,
         "fresh-fixed-class-version")
    tags = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) if version[0] == 45 else (
        1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20)
    need(int.from_bytes(prefix[8:10], "big") > 1 and prefix[10] in tags,
         "fresh-fixed-class-initial-pool-header")
    table_end = 8 + 20 * int.from_bytes(prefix[4:8], "big")
    impossible = table_end > size
    if not impossible:
        need(len(prefix) >= 28, "fresh-fixed-class-fat-evidence-missing")
        offset = int.from_bytes(prefix[16:20], "big")
        extent = int.from_bytes(prefix[20:24], "big")
        impossible = offset < table_end or offset + extent > size
    need(impossible, "fresh-fixed-class-fat-not-excluded")


def _fresh_kotlin_i386(item, prefix):
    name, size, digest, mode, prefix_digest = _INTEL_KOTLIN_I386
    need((item["name"], item["bytes"], item["sha256"], item["mode"], item["prefixSha256"])
         == (name, size, digest, mode, prefix_digest)
         and item["format"] == item["reason"] == "unsupported-native"
         and len(prefix) == 4096 and prefix[:4] == b"\xce\xfa\xed\xfe"
         and tuple(int.from_bytes(prefix[n:n + 4], "little") for n in (4, 8, 12)) == (7, 3, 6),
         "fresh-fixed-kotlin-i386-original")


def _fresh_gradle_specials(value, counts, container, containing):
    pin = _fresh_gradle_context(container, containing)
    need(pin is not None and (value["name"], value["bytes"], value["sha256"], value["mode"])
         == (containing.name, pin[0], pin[1], 0o100644)
         and value["format"] == "zip" and value["zipViewOffset"] == 0,
         "fresh-fixed-gradle-resource-parent")
    rows = value["unknownMembers"]
    need(type(rows) is list and len(rows) == counts[pin[3]] == pin[2]
         and hashlib.sha256(canonical(rows)).hexdigest() == pin[6], "fresh-fixed-gradle-resource-roster")
    names, previous = set(), None
    for item in rows:
        prefix = _fresh_unknown_prefix(item)
        name = item["name"]
        need(name not in names and (previous is None or previous < name)
             and item["format"] == item["reason"] == pin[3], "fresh-fixed-gradle-resource-order")
        names.add(name); previous = name
        if pin[4] is None:
            _fresh_kotlin_i386(item, prefix)
        else:
            need(name.endswith(".class") and (pin[5] is None or name.startswith(pin[5])),
                 "fresh-fixed-versioned-class-path")
            _fresh_class_header(prefix, item["bytes"], pin[4])
    return names


def _fresh_gradle_launcher(value, outer):
    need(type(outer) is _FreshOuter and outer.label == "gradle", "fresh-fixed-launcher-component")
    unknown = value["unknownMembers"]
    need(len(unknown) == 1, "fresh-fixed-launcher-roster")
    item = unknown[0]
    prefix = _fresh_unknown_prefix(item)
    member = outer.by_name.get(_INTEL_GRADLE_LAUNCHER[0])
    need(member is not None and member.kind == "file" and member.hint is None
         and (member.name, member.size, member.sha256, member.mode) == _INTEL_GRADLE_LAUNCHER
         and (item["name"], item["bytes"], item["sha256"], item["mode"]) == _INTEL_GRADLE_LAUNCHER
         and item["format"] == "opaque" and item["reason"] == "executable-opaque"
         and len(prefix) == member.size, "fresh-fixed-launcher-original")
    return member.name


def _intel_native_rows(value):
    rows = list(value["nativeMembers"])
    if "foreignNativeMembers" in value:
        rows.extend(value["foreignNativeMembers"])
        if value.get("name") == "gradle-8.14.5/lib/kotlin-compiler-embeddable-2.0.21.jar":
            rows.extend(value["unknownMembers"])
    else:
        # In the legacy outer-only Bundletool schema these are explicit ELF/PE
        # records, not complete-mode unknown class/native dispositions.
        rows.extend(value["unknownMembers"])
    return rows


def _intel_native_kind(path, expected):
    name, _, _, _, kind = expected
    key = (path, name)
    if key in _INTEL_CURRENT_NATIVE:
        need(kind in ("Arm64", "GradleIntelPlatform", "GradlePlainJansiIntel", "BundletoolDarwinI386X64"),
             "intel-current-native-source-kind")
        return "CurrentX64"
    if key in _INTEL_NONHOST_ARM:
        need(kind == "Arm64", "intel-nonhost-arm-source-kind")
        return "OtherPlatformArm64"
    if key == ("gradle/lib/kotlin-compiler-embeddable-2.0.21.jar", _INTEL_KOTLIN_I386[0]):
        need(kind == "GradleIntelPlatform", "intel-i386-source-kind")
        return "OtherPlatformI386"
    need(kind in ("OtherPlatformElf", "OtherPlatformPe"), "intel-native-unassigned-role")
    return kind


def _intel_finite_native(path, archive, rows):
    pin = NATIVE_PINS.get(path)
    ordered = sorted(rows, key=lambda row: row["name"].lower())
    if pin is None:
        need(not ordered, "unlisted-native-resource")
        return ()
    need(archive == pin[:2] and len(ordered) == len(pin[2]), "native-archive-pin")
    result = []
    for row, expected in zip(ordered, pin[2]):
        need((row["name"], row["bytes"], row["sha256"], row["mode"]) == expected[:4], "native-resource-pin")
        kind, snapshot = _intel_native_kind(path, expected), None
        if kind in ("CurrentX64", "OtherPlatformArm64"):
            prefix, commands = _fresh_native(row)
            if kind == "CurrentX64":
                need(commands is not None, "intel-current-native-snapshot")
                snapshot = (prefix, commands, 0x01000007)
            else:
                need(commands is None and prefix[:4] == b"\xcf\xfa\xed\xfe"
                     and int.from_bytes(prefix[4:8], "little") == ARM64, "intel-finite-nonhost-arm")
        elif kind == "OtherPlatformI386":
            _fresh_kotlin_i386(row, _fresh_unknown_prefix(row))
        else:
            actual = _fresh_foreign(row, None, complete=row["format"] in ("ELF", "PE"))
            need(actual == ("ELF" if kind == "OtherPlatformElf" else "PE"), "intel-finite-foreign-format")
        result.append((row, kind, snapshot))
    return tuple(result)


def _intel_jdk_members(value):
    result = []
    for row in sorted(value["nativeMembers"], key=lambda row: row["name"].lower()):
        prefix, commands = _fresh_native(row, counterpart=value["format"] == "jmod")
        need(commands is not None, "intel-jdk-selected-native")
        counterpart = row.get("counterpart")
        need(counterpart is not None, "intel-jdk-native-requires-counterpart-claim")
        kind = "JdkInstalledCounterpart" if counterpart["matched"] else "JdkJpackageTemplate"
        # _fresh_jdk_counterparts already joined all full originals, prefixes,
        # commands and the one exact no-counterpart jpackage template.
        result.append((row, kind, (prefix, commands, 0x01000007)))
    return tuple(result)


def _classify_intel(member, label, path, proofs):
    key = (label, member.name)
    if member.name.endswith((".jar", ".jmod")):
        value = proofs.jvms.get(key)
        need(value is not None, "jvm-complete-observation-missing")
        native = (_intel_jdk_members(value) if label == "jdk" else
                  _intel_finite_native(path, (member.size, member.sha256), _intel_native_rows(value)))
        return 0o444, ("JvmArchive", native)
    if label == "sdk-build-tools" and member.name in SDK_PINS:
        kind, expected_path, size, digest, mode = SDK_PINS[member.name]
        need((path, member.size, member.sha256, member.mode) == (expected_path, size, digest, 0o100000 | mode), "sdk-special-pin")
        if kind in ("D8", "Apksigner", "LldShell"):
            need(member.hint == "shell", "sdk-script-prefix")
            return mode & ~0o222, ("SdkBash", kind)
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] == 0x01000007, "sdk-legacy-intel-snapshot")
        return mode & ~0o222, ("SdkLegacyIntel", kind, snapshot)
    if member.hint == "elf":
        pin = ELF_PINS.get(member.name) if label == "sdk-build-tools" else None
        need(pin is not None and (path, member.size, member.sha256, member.mode)
             == (pin[0], pin[1], pin[2], 0o100000 | pin[3]), "unlisted-target-elf")
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] is None and snapshot[0].startswith(pin[4]), "target-elf-header-pin")
        return 0o444, ("AndroidTargetElf",)
    if member.hint in ("macho", "fat-macho-or-java-class"):
        snapshot = proofs.direct.get(key)
        need(snapshot is not None and snapshot[2] == 0x01000007 and label in ("jdk", "sdk-build-tools"),
             "intel-direct-native-snapshot")
        mode = (member.mode & 0o777) & ~0o222
        need(mode in (0o444, 0o555), "direct-installed-mode")
        return mode, ("MachO", snapshot)
    # The remaining fixed script/foreign launcher/license/data rules are
    # architecture-independent and unchanged. No JVM/native case falls here.
    return classify(member, label, path, proofs)


class _IntelProofs:
    """Direct typed adapter over authentic fresh DATA, not a legacy report."""
    def __init__(self, data):
        need(type(data) is _FreshIntelData and data.commitments == _INTEL_INPUT_COMMITMENTS,
             "intel-projection-fresh-originals")
        self.direct, self.jvms, self.negatives = {}, {}, {}
        self.selected = dict(data.selected_bytes)
        self.bundle = data.observations[LABELS.index("bundletool")]
        for label, value in zip(LABELS, data.observations):
            for row in value["nativeMembers"]:
                prefix, commands = _fresh_native(row)
                need(commands is not None, "intel-direct-selected-snapshot")
                self.direct[(label, row["name"])] = (prefix, commands, 0x01000007)
            if label == "sdk-build-tools":
                for row in value["foreignNativeMembers"]:
                    kind = _fresh_foreign(row, None, complete=True)
                    need(kind == "ELF", "intel-sdk-foreign-kind")
                    self.direct[(label, row["name"])] = (
                        base64_bytes(row["prefixBase64"], row["prefixBytes"], row["prefixSha256"], 4096), b"", None)
            if label not in LABELS[:4]:
                continue
            for row in value["jvmMembers"] if label == "jdk" else value["innerArchives"]:
                key = (label, row["name"])
                need(key not in self.jvms and key not in self.negatives, "intel-duplicate-jvm-proof")
                if row["name"].endswith((".jar", ".jmod")):
                    self.jvms[key] = row
                else:
                    need(not row["nativeMembers"] and not row["unknownMembers"] and not row["nestedArchives"]
                         and all(n == 0 for kind, n in row["formatCounts"].items()
                                 if kind not in ("java-class-header", "opaque")), "intel-non-jvm-interior")
                    # Retain the original, fully admitted record. No invented
                    # negativeEvidence field or rewritten enum/counts.
                    self.negatives[key] = row
        for label, expected in SDK_NEGATIVE.items():
            need({name for group, name in self.jvms.keys() | self.negatives.keys() if group == label}
                 == expected, "intel-sdk-inner-inverse")

    def release(self):
        # Reuse the exact existing release grammar on the actual selected bytes.
        # The path is the same; neither the old ARM size/hash nor a JSON wrapper
        # substitutes for the independently admitted Intel release original.
        return Proofs.release(self)


def generate_intel(documents: Mapping[str, bytes], sink: Callable[[bytes], None]):
    """Propose Intel SOURCE from the exact fresh nine; no runtime authority."""
    inputs = _FreshIntelInputs(documents)
    need(inputs.commitments == _INTEL_INPUT_COMMITMENTS, "intel-emission-input-commitments")
    data = _fresh_intel_read(inputs)
    proofs = _IntelProofs(data)
    projection = Projection(dict(zip(LABELS, data.outers)), proofs, profile="x86_64")
    summary = projection.summary()
    summary["profile"] = "android-registered-macos-x86_64-v1"
    summary["inputs"] = [{"path": name, "bytes": size, "sha256": digest} for name, size, digest in data.commitments]
    summary["output"] = render(projection, sink, profile="x86_64")
    return summary
