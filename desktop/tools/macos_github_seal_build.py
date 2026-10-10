"""Fixed, credential-free Darwin build of the canonical sealed-box helper.

This is a separate hosted verification context, not a CPython producer or a
Desktop capability. Ordinary23 calls and the fixed provider-only3 probes use
the existing MRK process owner.
Public output remains provisional until this original entry actually returns.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import stat
import struct
import sys
import tarfile
import time
import types
import zlib

MIB = 1024 * 1024
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REFERENCE = "refs/heads/verify/desktop-macos-github-seal"
WORKFLOW = ".github/workflows/desktop-macos-github-seal.yml"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
DEVELOPER = Path("/Library/Developer/CommandLineTools")
HELPER = "desktop/helpers/macos-github-seal"
INVENTORY = "desktop/github-seal-inputs/libsodium-1.0.22.json"
INVENTORY_PIN = (189190, "451eff5b5ead60459e0631bf790d6e19f985cf57d58031b0c0eaa29256028e67")
ARCHIVE = "desktop/github-seal-inputs/libsodium-1.0.22.tar.gz"
ARCHIVE_PIN = (2008529, "adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349")
RAW_PIN = (9676800, "2f78c3e629fbe938b3b99297d6d5fb02307ea5458c12744554e4377603d5fdb8")
# Official Makefile.am:243-254 static convenience archives plus libsodium.
# ltmain.sh:11301 emits one .libs/<name> -> ../<name> per .la link.
LIBTOOL_ARCHIVES = (
    "libsodium.la", "libaesni.la", "libarmcrypto.la", "libsse2.la",
    "libssse3.la", "libsse41.la", "libavx2.la", "libavx512f.la", "librdrand.la",
)
LIBTOOL_MAKEFILE_PIN = (13770, "a3fd526d03210d2a0262ee1ef360167259a1923089be80cb5b040cc88168bef8")
WORK_SECONDS, CLEANUP_SECONDS = 900, 60
WORK_ENTRIES, WORK_BYTES, PUBLIC_BYTES = 8192, 512 * MIB, 96 * MIB
OUTPUT_LIMIT, QUERY_LIMIT = MIB, 65536
NATIVE_TEST = "macos::tests::canonical_return_paths_wipe_input_and_refuse_low_order_key"
NATIVE_PHASE_ENV = "MRK_SEAL_TEST_PHASE"
NATIVE_PHASES = (("helper-native-test", "ordinary6", 6), ("helper-entropy-test", "denied2", 2))
NATIVE_DENIED_POLICY = '(version 1)(allow default)(deny network*)(deny file-read-data (literal "/dev/urandom") (literal "/dev/random"))'
TARGETS = {
    "aarch64-apple-darwin": ("arm64", "ARM64", "1.98.1", 0x0100000C, 0),
    "x86_64-apple-darwin": ("x86_64", "X64", "1.98.0", 0x01000007, 3),
}
# These are the existing callable owners/parsers, not a new source-build owner.
REUSE_PINS = {
    "macos_cpython_source_build.py": (91537, "70c7552f2b9eaace61ddc316da7482575692e4d3715eadfdef572b1aa0e44de6"),
    "macos_cpython_orchestrator.py": (105771, "963555122a18aa1a123b033becbb53a67e44b55c8f2d26f0554f79c29b07f296"),
    "macos_cpython_source_probe.py": (28617, "721b3adebde7925dbb6ee6e7c39ad4ae9aebe8f6c99f11b880378792595088c4"),
    "macos_aqua_qualification.py": (455054, "352b73c1e95c2c13c778592ceb392caef3d4769e9ef7fd6eaf248ff3c73b8dba"),
}
HELPER_PINS = {
    'Cargo.lock': (141, 'bed5621628fafce21707d508559b97d4563a3b464af0e1a8054877a0b75ff0a3'),
    'Cargo.toml': (476, '7917d02fe12b37f2c5ea502bdf1315d7ce6aa6df04a69431aaf71df3c6c3c2fe'),
    'LICENSE.libsodium': (823, '508a76d186356c0dd807a670ef510964f8724557024796a2c426c6c0e19ab683'),
    'README.md': (11005, '87b43178941661882cb4940969cf313f68c14b9d6dc82b9435ada6e6885e303b'),
    'abi-check.c': (2489, '27c123f6e433b6608d2989add703cb7602b16d22d06938c552003b7eb1335868'),
    'src/macos.rs': (9898, 'a50d8977991a273ccaf1c50a8d6629361a5b05fcff32aac97121ef165258dc62'),
    'src/macos_tests.rs': (19853, 'fa3288176e0a031e0791496b6deb4e3396408dff1db96e24307713ac9191056d'),
    'src/main.rs': (1344, '14392210ce19e06e91da0a93ad6ac5a6ac142bc658cf0d25a838f9cec3261310'),
    'src/protocol.rs': (3239, '5441b4fd3d1eae80cb7f8d70ee79341eb8a47123177d8a72e152c6f7109b0c71'),
    'src/protocol_tests.rs': (5602, 'a87b33d4743c1db9e8209baf171dae12a7ac6a8fa017896ef43498e6810be47d'),
}
ROLE_LIMITS = (
    ("sdk-path", 30, QUERY_LIMIT), ("sdk-version", 30, QUERY_LIMIT),
    ("tool-path-clang", 30, QUERY_LIMIT), ("tool-path-ar", 30, QUERY_LIMIT),
    ("tool-path-ranlib", 30, QUERY_LIMIT), ("tool-path-ld", 30, QUERY_LIMIT),
    ("tool-path-nm", 30, QUERY_LIMIT), ("compiler-version", 30, QUERY_LIMIT),
    ("rustc-version", 30, QUERY_LIMIT), ("cargo-version", 30, QUERY_LIMIT),
    ("network-denial", 15, QUERY_LIMIT), ("physical-memory", 15, QUERY_LIMIT),
    ("sodium-configure", 180, OUTPUT_LIMIT), ("sodium-build", 300, OUTPUT_LIMIT),
    ("sodium-install", 60, OUTPUT_LIMIT), ("header-abi", 30, OUTPUT_LIMIT),
    ("static-four-symbols", 30, OUTPUT_LIMIT), ("canonical-box-build", 60, OUTPUT_LIMIT),
    ("canonical-box-test", 10, QUERY_LIMIT), ("helper-release", 120, OUTPUT_LIMIT),
    ("helper-native-test-build", 120, OUTPUT_LIMIT), ("helper-native-test", 10, QUERY_LIMIT),
    ("helper-entropy-test", 10, QUERY_LIMIT),
)
def _static_symbol_argv(target, nm, library):
    """Intel LLVM nm suppresses only empty-member diagnostics; ARM stays exact."""
    return [nm, *(["--quiet"] if target == "x86_64-apple-darwin" else []), "-gU", str(library)]


# Verification-only public inputs. Never a shipping/provider nomination.
PROVIDER_REFERENCE = "refs/heads/verify/desktop-macos-history-provider-probe"
PROVIDER_INPUT_ROOT = "desktop/history-provider-inputs"
PROVIDER_SOURCE = PROVIDER_INPUT_ROOT + "/source-manifest.json"
PROVIDER_CROSSBUILD = PROVIDER_INPUT_ROOT + "/crossbuild.json"
PROVIDER_SOURCE_PIN = (212713, "d7587f1290e72781bd65cfce96c397e1e37850c62b50d2cb4259ca006e9332dd")
PROVIDER_CROSSBUILD_PIN = (9544, "4f52eddccf96170bf27d6f217e820279a893e4dd711b49cafae783387bc4016f")
PROVIDER_PINS = {
    "aarch64-apple-darwin": (37471938, "a704813e4e64f8814e5fa21677f7dab51d9b77d045ded75dd11bcdc1a53d5516"),
    "x86_64-apple-darwin": (39889552, "aca3bcfd4fc35d9bcd800f06fe09f7d6c50ab4d2428f04c4ba081a32bfebbe4e"),
}
PROVIDER_NOTICE_PINS = {
    "aarch64-apple-darwin": (1552072, "3dc7d2cd021d654387e5be71603869a039a3d2adf8b97a6fd0dda4ef3743a44d"),
    "x86_64-apple-darwin": (1552072, "087592d4d366fcf2c49851571542959bb91607408c6e677ffdc2484fd7293c2e"),
}
PROVIDER_ROLES = (("network-denial", 15, QUERY_LIMIT), ("provider-version", 15, QUERY_LIMIT),
                  ("provider-invalid-controls", 15, QUERY_LIMIT))
PROVIDER_LOADS = ("/usr/lib/libSystem.B.dylib", "/usr/lib/libresolv.9.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/Security.framework/Versions/A/Security")
PROVIDER_VERSION = (b"gh version 2.88.1-mrk-history.1 (2026-10-09)\n"
    b"https://github.com/cli/cli/releases/latest\n")
PROVIDER_REFUSAL = b"managed history provider: controls\n"
CAPSULE_MODIFIER = "--publish-build-capsule"
CAPSULE_RECEIPT_LIMIT = 16384
CAPSULE_PURPOSES = {"history-provider": ("gh", 64 * MIB), "github-seal": ("mrk-github-seal", 16 * MIB)}
# Bound only to the actual reviewed LOCAL normalization output. Raw local
# results/inventories never become hosted inputs or a caller-supplied receipt.
PROVIDER_FACTS_PINS = {'aarch64-apple-darwin': (1623, 'b143103ca6928e2e900c0c648f406742080d4e4b87dadb72e30b418cef0d30e5'), 'x86_64-apple-darwin': (1622, '472ee0a35943f1395bc25d14db4d87b328d2c24e6600b29b9f2899e596a34373')}
PROVIDER_NOTICE_MANIFEST = "ed34b914139709ddccdedc1d3cd779b28eab05c55f7575266a479af858235294"


def probe_mode(argv, reference):
    """No permissive flag/ref fallback; old seal entry remains zero-argument."""
    need(type(argv) is list and type(reference) is str, "fixed-seal-workflow-context")
    if argv == [] and reference == REFERENCE:
        return False
    need(argv == ["--history-provider-probe"] and reference == PROVIDER_REFERENCE,
         "fixed-seal-workflow-context")
    return True


def capsule_mode(argv, reference):
    """Only a literal modifier of either existing, independently checked mode."""
    need(type(argv) is list, "fixed-seal-workflow-context")
    if argv[-1:] == [CAPSULE_MODIFIER]:
        probe_mode(argv[:-1], reference)
        return True
    probe_mode(argv, reference)
    return False


def provider_fact_records():
    rows = []
    for target in TARGETS:
        pin = PROVIDER_FACTS_PINS[target]
        need(type(pin) is tuple and len(pin) == 2 and type(pin[0]) is int
             and 0 < pin[0] <= CAPSULE_RECEIPT_LIMIT and type(pin[1]) is str
             and re.fullmatch(r"[0-9a-f]{64}", pin[1]) and pin[1] != "0" * 64,
             "capsule-facts-unbound")
        rows.append((PROVIDER_INPUT_ROOT + "/" + target + "/build-facts.json", pin))
    return tuple(rows)


def capsule_origin(value):
    """Closed DATA grammar; exact whole prepared SOURCE bytes are the anchor."""
    refs = {"result": 256 * 1024, "closedSummary": 16384, "crossbuild": 65536, "buildInfo": 65536}
    yes = {"allJoinedZeroAndPipesClosed", "sourcePost", "dependencyPost", "toolchainPost", "embeddedNoticesComplete"}
    no = {"noticeContentRuntimeExecuted", "nativeExecuted", "developerIdSigned", "notarized"}
    need(type(value) is dict and set(value) == set(refs) | yes | no | {"kind", "sourceInventory",
         "dependencyInventorySha256", "toolchainInventorySha256", "childOriginals", "namespaceOriginals"}
         and value["kind"] == "offline-owned-crossbuild"
         and type(value["childOriginals"]) is int and value["childOriginals"] == 5
         and type(value["namespaceOriginals"]) is int and value["namespaceOriginals"] == 1
         and all(value[k] is True for k in yes) and all(value[k] is False for k in no), "capsule-build-origin")
    for key in ("dependencyInventorySha256", "toolchainInventorySha256"):
        need(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key])
             and value[key] != "0" * 64, "capsule-build-origin")
    for key, limit in refs.items():
        row = value[key]
        need(type(row) is dict and set(row) == {"bytes", "sha256"}
             and type(row["bytes"]) is int and 0 < row["bytes"] <= limit
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
             and row["sha256"] != "0" * 64, "capsule-build-reference")
    row = value["sourceInventory"]
    need(type(row) is dict and set(row) == {"bytes", "sha256", "fileCount", "fileBytes"}
         and all(type(row[k]) is int for k in ("bytes", "fileCount", "fileBytes"))
         and 0 < row["bytes"] <= MIB and 0 < row["fileCount"] <= 2048 and 0 < row["fileBytes"] <= 32 * MIB
         and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
         and row["sha256"] != "0" * 64, "capsule-build-reference")


def capsule_prepared(body, target):
    records = dict(provider_fact_records())
    need(target in TARGETS, "capsule-facts-target")
    name = PROVIDER_INPUT_ROOT + "/" + target + "/build-facts.json"
    need(type(body) is bytes and (len(body), B.digest(body)) == records[name], "capsule-facts-pin")
    value = B.decode(body)
    need(type(value) is dict and set(value) == {"schemaVersion", "state", "facts", "nativeAuthority", "uploadAuthorized"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["state"] == "unconfigured-publication" and value["nativeAuthority"] is False
         and value["uploadAuthorized"] is False and B.canonical(value) + b"\n" == body, "capsule-facts-shape")
    facts = value["facts"]
    need(type(facts) is dict and set(facts) == {"target", "sourceManifestSha256", "binary", "notices", "buildOrigin"}
         and facts["target"] == target and facts["sourceManifestSha256"] == PROVIDER_SOURCE_PIN[1]
         and type(facts["binary"]) is dict and type(facts["binary"].get("bytes")) is int
         and facts["binary"] == {"bytes": PROVIDER_PINS[target][0], "sha256": PROVIDER_PINS[target][1]},
         "capsule-facts-product")
    notices = facts["notices"]
    need(type(notices) is dict and all(type(notices.get(k)) is int for k in ("files", "modules"))
         and notices == {"manifestSha256": PROVIDER_NOTICE_MANIFEST,
            "contentSha256": PROVIDER_NOTICE_PINS[target][1], "files": 333, "modules": 162}, "capsule-facts-notices")
    capsule_origin(facts["buildOrigin"])
    return facts


def provider_output(role, returncode, stdout, stderr):
    """Returned DATA only. The caller still proves actual original settlement."""
    if type(returncode) is not int or type(stdout) is not bytes or type(stderr) is not bytes:
        return False
    if role == "provider-version":
        return returncode == 0 and stdout == PROVIDER_VERSION and stderr == b""
    if role == "provider-invalid-controls":
        return returncode == 1 and stdout == b"" and stderr == PROVIDER_REFUSAL
    return role == "network-denial" and returncode == 0 and stderr == b""


def provider_macho_data(prefix, total, target, orchestration):
    """Same load-table parser over a bounded prefix of a separately hashed file."""
    need(target in TARGETS and type(prefix) is bytes and 32 <= len(prefix) <= QUERY_LIMIT
         and type(total) is int and len(prefix) <= total <= 128 * MIB
         and prefix[:4] == b"\xcf\xfa\xed\xfe", "provider-thin-header")
    machine, _, _, cpu, subtype = TARGETS[target]
    header = struct.unpack_from("<8I", prefix)
    need(header[1:4] == (cpu, subtype, 2) and header[7] == 0
         and header[5] <= QUERY_LIMIT - 32, "provider-thin-header")
    need(orchestration.native_slice(prefix, machine) == prefix, "provider-thin-header")
    rows = orchestration.macho_records(prefix, machine)
    loads, dyld, builds, signatures = [], [], [], []
    for row in rows:
        command, offset, size = row["command"], row["offset"], row["size"]
        need(command not in {0x6, 0x7, 0xD, 0xF, 0x10, 0x12, 0x13, 0x14, 0x15,
             0x1C, 0x8000001C, 0x27}, "provider-loader-override")
        if command == 0x32:
            need(size == 24 and struct.unpack_from("<4I", prefix, offset + 8)
                 == (1, 0x000C0000, 0x000C0000, 0), "provider-minimum-sdk")
            builds.append(command)
        elif command == 0xE:
            dyld.append(row["text"])
        elif command in {0xC, 0x18, 0x80000018, 0x1F, 0x8000001F, 0x20, 0x23, 0x80000023}:
            need(command == 0xC and row["text"] in PROVIDER_LOADS, "provider-system-load")
            loads.append(row["text"])
        elif command == 0x1D:
            need(size == 16, "provider-signature-command")
            start, length = struct.unpack_from("<II", prefix, offset + 8)
            need(start >= 32 + header[5] and length > 0 and start + length == total,
                 "provider-signature-command")
            signatures.append(command)
    need(len(builds) == 1 and dyld == ["/usr/lib/dyld"] and tuple(loads) == PROVIDER_LOADS
         and len(signatures) == (1 if target == "aarch64-apple-darwin" else 0), "provider-loader-roster")
    return {"thin": True, "minimumMacOS": "12.0", "sdk": "12.0", "loadDylibs": loads,
            "GoAdHocSignatureCommand": bool(signatures), "DeveloperIdQualified": False}


B = None


# Failure-only observations; never an admission, cleanup or publication grant.
_DIAGNOSTIC_STAGE = "entry"
_DIAGNOSTIC_BUILD = None
_DIAGNOSTIC_STAGES = frozenset((
    "entry", "target", "host", "run", "context", "python-entry", "bootstrap",
    "detached", "limits", "source-snapshot", "macho-load", "probe-load",
    "qualification-load", "owner-load", "cancellation-load", "build-init", "build-execute",
))
# Fixed source-defined reason vocabulary; no runtime source parsing or raw text.
_DIAGNOSTIC_REASONS = frozenset((
    'Apple-compiler-version',
    'Cargo-exact-two-original-names',
    'Cargo-release-original',
    'Cargo-returned-alias',
    'actual-direct-Rust-version',
    'actual-setup-python-entry',
    'bounded-canonical-tar',
    'bounded-original-roster',
    'build-capacity',
    'provider-thin-header',
    'provider-loader-override',
    'provider-minimum-sdk',
    'provider-system-load',
    'provider-signature-command',
    'provider-loader-roster',
    'provider-input-pin',
    'provider-input-original',
    'provider-input-short',
    'provider-copy-short',
    'provider-input-post',
    'provider-copy-original',
    'provider-copy-post',
    'provider-parent-post',
    'provider-parent-original',
    'provider-input-roster',
    'provider-record-post',
    'provider-record-unbound',
    'provider-record-pin',
    'provider-output-contract',
    'provider-evidence-bound',
    'capsule-binary-bound',
    'capsule-binary-mode',
    'capsule-build-origin',
    'capsule-build-reference',
    'capsule-cleanup-member',
    'capsule-combined-bound',
    'capsule-directory-original',
    'capsule-entry-bound',
    'capsule-export-original',
    'capsule-export-path',
    'capsule-facts-notices',
    'capsule-facts-pin',
    'capsule-facts-product',
    'capsule-facts-shape',
    'capsule-facts-target',
    'capsule-facts-unbound',
    'capsule-finality',
    'capsule-full-source-binding',
    'capsule-helper-byte-binding',
    'capsule-helper-parent-original',
    'capsule-member-roster',
    'capsule-mode',
    'capsule-original-finality',
    'capsule-output-collision',
    'capsule-publication-context',
    'capsule-quote-data',
    'capsule-receipt-bound',
    'capsule-receipt-original',
    'capsule-storage',
    'capsule-task-original',
    'capsule-work-finality',
    'build-input-original-post',
    'builder-already-loaded',
    'builder-source-hash',
    'builder-source-kind',
    'builder-source-original',
    'builder-source-post',
    'builder-source-short',
    'canonical-body-extent',
    'canonical-body-hash',
    'canonical-complete-roster',
    'canonical-compression-eof',
    'canonical-decoded-hash',
    'canonical-directory-body',
    'canonical-four-symbol-definition',
    'canonical-generated-version-header',
    'canonical-installed-build-library',
    'canonical-installed-public-header',
    'canonical-inventory',
    'canonical-normal-static-archive',
    'canonical-padding',
    'canonical-pkgconfig-version',
    'canonical-public-header-roster',
    'canonical-relative-name',
    'canonical-source-directory-roster',
    'canonical-source-file-roster',
    'canonical-source-final-post',
    'canonical-source-pin',
    'canonical-source-readback',
    'canonical-tar-row',
    'canonical-tar-type',
    'canonical-test-original-output',
    'canonical-test-result-collision',
    'canonical-test-returned-readback',
    'cargo-build-finished',
    'cargo-complete-records',
    'cargo-exact-target',
    'cargo-executable-location',
    'cargo-executable-original',
    'cargo-fresh-single-package',
    'cargo-nonerror-message',
    'cargo-output-framing',
    'cargo-record-cap',
    'cargo-record-terminal-order',
    'common-deadline-exhausted',
    'complete-build-original-finality',
    'deadline-shape',
    'descriptor-capacity',
    'direct-rust-root',
    'existing-owner-source-pin',
    'existing-parser-unbound',
    'fixed-Apple-sdk',
    'fixed-detached-source',
    'fixed-recipe-complete',
    'fixed-role-order',
    'fixed-seal-native-host',
    'fixed-seal-run',
    'fixed-seal-target',
    'fixed-seal-workflow-context',
    'fixed-tool-role',
    'fresh-task-directory',
    'fresh-task-directory-collision',
    'generated-alias-changed',
    'generated-alias-original',
    'generated-alias-parent',
    'generated-alias-parent-post',
    'generated-alias-post',
    'generated-alias-pre',
    'generated-alias-retirement-post',
    'generated-alias-unsettled',
    'generated-alias-unrecorded',
    'canonical-libtool-archive-roster',
    'helper-exact-native-test',
    'native-pair-admission',
    'native-pair-capture',
    'helper-fixed-roster',
    'helper-no-build-discovery',
    'helper-source-directory-post',
    'helper-source-final-post',
    'helper-source-pin',
    'hosted-python-preparation-alias',
    'hosted-python-preparation-bytes',
    'hosted-python-preparation-context',
    'hosted-python-preparation-deadline',
    'hosted-python-preparation-mode',
    'hosted-python-preparation-open',
    'hosted-python-preparation-original',
    'hosted-python-preparation-post',
    'hosted-python-preparation-short',
    'input-byte-binding',
    'input-open-correspondence',
    'input-post-correspondence',
    'input-short-read',
    'network-denial',
    'non-Apple-tool-route',
    'non-absolute-tool-route',
    'ordinary-canonical-test-mode',
    'ordinary-input-kind',
    'ordinary-input-links',
    'ordinary-input-size',
    'original-command-failed',
    'original-command-finality-unknown',
    'original-command-return-contract',
    'original-data-or-task-finality-unknown',
    'original-generated-configuration-changed',
    'original-private-root-changed',
    'original-static-header-changed',
    'original-static-library-changed',
    'original-task-root-changed',
    'original-tool-parent-changed',
    'owner-already-imported',
    'owner-source-pin',
    'owner-source-route',
    'private-Cargo-configuration',
    'produced-Cargo-alias-post',
    'produced-build-version-extent',
    'produced-executable-original',
    'produced-loader-build-version',
    'produced-native-execute-header',
    'produced-native-minimum-sdk',
    'produced-no-dynamic-sodium',
    'produced-no-loader-override',
    'produced-original-post',
    'produced-system-only-link',
    'produced-thin-native-MachO',
    'public-and-scratch-finality',
    'public-export-bound',
    'public-export-collision',
    'report-bound',
    'resource-capacity',
    'resource-limit-post',
    'retained-helper-source-original',
    'retained-original-content',
    'retained-original-identity',
    'retained-product-limit',
    'retained-static-header-original',
    'retained-static-library-original',
    'rust-runtime-alias-escape',
    'rust-runtime-complete-native-selection',
    'rust-runtime-directory',
    'rust-runtime-read-bound',
    'rust-runtime-roster-changed',
    'rust-runtime-subdirectory',
    'sdk-version',
    'seal-original-cancellation-owner',
    'single-query-line',
    'source-count',
    'source-directories',
    'source-directory',
    'source-leaf',
    'source-module-already-imported',
    'source-module-route',
    'static-install-roster',
    'static-libtool-metadata',
    'static-symbol-query',
    'tool-diagnostic-scalar',
    'tool-original-count',
    'tool-parent-changed',
    'tool-readmission-changed',
    'unadmitted-Cargo-configuration',
    'unadmitted-generated-alias',
    'unadmitted-task-custody',
    'unexpected-generated-alias',
    'unprotected-selected-tool',
    'unprotected-tool-parent',
    'verification-source-final-post',
    'work-directory',
    'work-entry',
    'work-extent',
    'work-file',
    'work-pending',
))


def failure_diagnostic(error):
    """One closed, non-atomic failed-entry line; no exception string conversion."""
    stage = _DIAGNOSTIC_STAGE if type(_DIAGNOSTIC_STAGE) is str and _DIAGNOSTIC_STAGE in _DIAGNOSTIC_STAGES else "unknown"
    refusal = type(error) is ValueError or (B is not None and type(error) is B.BuildRefused)
    reason = "unclassified"
    if refusal and type(error.args) is tuple and len(error.args) == 1:
        candidate = error.args[0]
        if type(candidate) is str and candidate in _DIAGNOSTIC_REASONS:
            reason = candidate
    category = ("refused" if refusal else "io" if isinstance(error, OSError) else
                "import" if isinstance(error, ImportError) else
                "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "other")
    phase, calls, data = "unavailable", "unavailable", "unavailable"
    last_rc = inflight = scratch = source_post = "unavailable"
    if B is not None and type(B.DATA) is B.DataFinality:
        data = "known" if B.DATA.known else "unknown"
    build = _DIAGNOSTIC_BUILD
    if type(build) is SealBuild:
        observed = build.phase
        allowed = {"admission", "canonical-source-extraction", "source-and-native-final-post"}
        allowed.update(role for role, _, _ in ROLE_LIMITS)
        if getattr(build, "provider_mode", False):
            allowed.update(role for role, _, _ in PROVIDER_ROLES)
        phase = observed if type(observed) is str and observed in allowed else "unknown"
        entered, returned = build.entered, build.returned
        if type(entered) is int and type(returned) is int and 0 <= returned <= entered <= 23:
            calls = f"{entered}/{returned}"
        # These are only retained observations, not an aggregate finality proof.
        observed_fields = vars(build)
        def closed_bool(name):
            value = observed_fields.get(name)
            return ("true" if value else "false") if type(value) is bool else "unavailable"
        inflight = closed_bool("inflight")
        scratch = closed_bool("scratch_retired")
        source_post = closed_bool("source_post")
        commands = observed_fields.get("commands")
        if type(commands) is list and len(commands) <= 23:
            for row in reversed(commands):
                if type(row) is dict and row.get("returned") is True:
                    value = row.get("returncode")
                    if type(value) is int and -(2 ** 31) <= value < 2 ** 31:
                        last_rc = str(value)
                    break
    line = (f"MRK_SEAL_DIAGNOSTIC_V1 stage={stage} reason={reason} category={category} "
            f"phase={phase} calls={calls} data={data} lastRc={last_rc} "
            f"inflight={inflight} scratchRetired={scratch} sourcePost={source_post} nonAtomic=true")
    # Fixed literal alphabets and two decimal counters fit comfortably. No
    # truncation of arbitrary input or fallback to its representation is used.
    if len(line.encode("ascii")) > 512:
        return "MRK_SEAL_DIAGNOSTIC_V1 stage=unknown reason=unclassified category=other phase=unknown calls=unavailable data=unavailable lastRc=unavailable inflight=unavailable scratchRetired=unavailable sourcePost=unavailable nonAtomic=true"
    return line


def need(value, reason):
    if not value:
        raise ValueError(reason)


def python_entry_binding(selected, reported):
    """Named action entry and CPython report must designate ONE actual file.

    setup-python publishes bin/python; CPython's macOS launcher may clean its
    directory spelling. This accepts aliases, never a different launcher or
    interpreter. The same named routes are admitted/read/POSTed by the owner.
    """
    for value in (selected, reported):
        need(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096
             and value.startswith("/") and "\0" not in value
             and len(value.split("/")) <= 128
             and all(part not in {".", ".."} for part in value.split("/")),
             "actual-setup-python-entry")
    paths = (Path(selected), Path(reported))
    resolved = tuple(path.resolve(strict=True) for path in paths)
    need(resolved[0] == resolved[1], "actual-setup-python-entry")
    original = resolved[0].lstat()
    need(stat.S_ISREG(original.st_mode) and original.st_mode & 0o111,
         "actual-setup-python-entry")
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    fixed = identity(original)
    need(all(identity(path.stat()) == fixed for path in paths)
         and identity(resolved[0].lstat()) == fixed, "actual-setup-python-entry")
    return ((selected, reported), str(resolved[0]), fixed)



def prepare_hosted_python(selected):
    """Remove only the observed group-write bit from this hosted interpreter.

    This separate explicit root preparation never enters the build/core owner.
    It does not copy/relocate Python, change libraries or relax tool admission.
    """
    need(B is None and sys.platform == "darwin" and sys.version_info[:3] == (3, 14, 7)
         and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
         and os.getuid() == os.geteuid() == 0, "hosted-python-preparation-context")
    binding = python_entry_binding(selected, sys.executable)
    paths, resolved, before = binding
    need(before[3] == 0 and before[5] == 1 and 0 < before[6] <= 512 * MIB
         and stat.S_IMODE(before[2]) in (0o775, 0o755), "hosted-python-preparation-original")
    fields = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                          info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    deadline = time.monotonic() + 15
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(fields(os.fstat(fd)) == before, "hosted-python-preparation-open")
        def digest(expected):
            os.lseek(fd, 0, os.SEEK_SET)
            total = 0; value = hashlib.sha256()
            while total < before[6]:
                need(time.monotonic() < deadline, "hosted-python-preparation-deadline")
                block = os.read(fd, min(MIB, before[6] - total))
                need(bool(block), "hosted-python-preparation-short")
                total += len(block); value.update(block)
            need(not os.read(fd, 1) and fields(os.fstat(fd)) == expected,
                 "hosted-python-preparation-post")
            return value.digest()
        original_hash = digest(before)
        need(python_entry_binding(*paths) == binding, "hosted-python-preparation-alias")
        if stat.S_IMODE(before[2]) == 0o775:
            os.fchmod(fd, 0o755)
        after = fields(os.fstat(fd))
        need(after[:2] == before[:2] and after[2] == stat.S_IFREG | 0o755
             and after[3:8] == before[3:8], "hosted-python-preparation-mode")
        need(digest(after) == original_hash, "hosted-python-preparation-bytes")
        need(python_entry_binding(*paths) == (paths, resolved, after)
             and time.monotonic() < deadline, "hosted-python-preparation-alias")
    finally:
        os.close(fd)  # One consuming close. Any failure stops preparation.


def bootstrap_builder():
    """The one pre-owner SOURCE read; a lost/failed close ends this entry."""
    global B
    path = CHECKOUT / "desktop/tools/macos_cpython_source_build.py"
    before = path.lstat()
    expected = REUSE_PINS[path.name]
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_size == expected[0], "builder-source-kind")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        # No helper/import/working directory is entered before this closes.
        observed = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(fields(before) == fields(observed), "builder-source-original")
        blocks, count = [], 0
        while count < expected[0]:
            block = os.read(fd, min(65536, expected[0] - count))
            need(block, "builder-source-short")
            blocks.append(block)
            count += len(block)
        need(not os.read(fd, 1) and fields(os.fstat(fd)) == fields(before)
             and fields(path.lstat()) == fields(before), "builder-source-post")
    finally:
        os.close(fd)  # Consuming, no EINTR retry or guessed descriptor cleanup.
    body = b"".join(blocks)
    need(hashlib.sha256(body).hexdigest() == expected[1], "builder-source-hash")
    name = "_mrk_seal_existing_build"
    need(name not in sys.modules, "builder-already-loaded")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(body, str(path), "exec"), module.__dict__)
    B = module


def names(path, maximum, check):
    """Same DataFinality/scandir pattern; check bounds before retaining names."""
    result, folded = [], set()
    with B.DATA.acquiring(os.scandir, lambda it: it.close(), path) as entries:
        for entry in entries:
            check()
            name = entry.name
            B.need(len(result) < maximum and all(32 <= ord(c) < 127 for c in name) and 0 < len(name) <= 255
                   and name not in {".", ".."} and not any(c in name for c in "/\\\0\n\r")
                   and name.casefold() not in folded, "bounded-original-roster")
            result.append(name)
            folded.add(name.casefold())
    return sorted(result)


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def source_snapshot(check, *, provider=False, capsule=False):
    fixed = {WORKFLOW, "desktop/tools/macos_github_seal_build.py", INVENTORY, ARCHIVE,
             "desktop/github-seal-inputs/README.md"}
    fixed.update("desktop/tools/" + name for name in REUSE_PINS)
    fixed.update(HELPER + "/" + name for name in HELPER_PINS)
    if provider:
        if capsule:
            records = provider_fact_records()
        else:
            B.need(type(PROVIDER_CROSSBUILD_PIN) is tuple and len(PROVIDER_CROSSBUILD_PIN) == 2
                   and type(PROVIDER_CROSSBUILD_PIN[0]) is int and 0 < PROVIDER_CROSSBUILD_PIN[0] <= QUERY_LIMIT
                   and type(PROVIDER_CROSSBUILD_PIN[1]) is str
                   and re.fullmatch(r"[0-9a-f]{64}", PROVIDER_CROSSBUILD_PIN[1]), "provider-record-unbound")
            records = ((PROVIDER_SOURCE, PROVIDER_SOURCE_PIN), (PROVIDER_CROSSBUILD, PROVIDER_CROSSBUILD_PIN))
        fixed = {WORKFLOW, "desktop/tools/macos_github_seal_build.py", *(name for name, _ in records)}
        fixed.update("desktop/tools/" + name for name in REUSE_PINS)
    pending = [CHECKOUT / "src/mobile_release"]
    directories = 0
    while pending:
        check()
        directory = pending.pop()
        info = directory.lstat()
        B.need(stat.S_ISDIR(info.st_mode) and not directory.is_symlink(), "source-directory")
        directories += 1
        B.need(directories <= 64, "source-directories")
        for name in names(directory, 1024, check):
            path = directory / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif name.endswith(".py"):
                B.need(stat.S_ISREG(info.st_mode), "source-leaf")
                fixed.add(path.relative_to(CHECKOUT).as_posix())
            B.need(len(fixed) <= 1024 and len(pending) <= 64, "source-count")
    rows = {}
    for name in sorted(fixed):
        check()
        path = CHECKOUT / name
        limit = (CAPSULE_RECEIPT_LIMIT if capsule else 2 * MIB) if provider and name in dict(records) else 2 * MIB
        if provider and not capsule and name == PROVIDER_CROSSBUILD:
            limit = QUERY_LIMIT
        body = B.read(path, limit)
        rows[name] = {"size": len(body), "sha256": B.digest(body), "identity": B.identity(path.lstat())}
    for name, pin in REUSE_PINS.items():
        row = rows["desktop/tools/" + name]
        B.need((row["size"], row["sha256"]) == pin, "existing-owner-source-pin")
    if provider:
        for name, pin in records:
            row = rows[name]
            B.need((row["size"], row["sha256"]) == pin, "provider-record-pin")
        return rows
    for name, pin in HELPER_PINS.items():
        row = rows[HELPER + "/" + name]
        B.need((row["size"], row["sha256"]) == pin, "helper-source-pin")
    for name, pin in ((INVENTORY, INVENTORY_PIN), (ARCHIVE, ARCHIVE_PIN)):
        row = rows[name]
        B.need((row["size"], row["sha256"]) == pin, "canonical-source-pin")
    return rows


def limits():
    result = {}
    for name, cap in (("CORE", 0), ("NOFILE", 1024), ("FSIZE", 128 * MIB), ("CPU", 900)):
        key = getattr(resource, "RLIMIT_" + name)
        original = resource.getrlimit(key)
        selected = tuple(cap if value == resource.RLIM_INFINITY else min(value, cap) for value in original)
        if name == "NOFILE":
            B.need(selected[0] >= 64, "descriptor-capacity")
        if name in {"FSIZE", "CPU"}:
            B.need(selected[0] > 0, "resource-capacity")
        resource.setrlimit(key, selected)
        B.need(resource.getrlimit(key) == selected, "resource-limit-post")
        result[name] = {"original": original, "selected": selected}
    return result


class SealBuild:
    """One fixed recipe around the already established MRK cancellation owner."""
    def __init__(self, *, target, source, run, attempt, owner, control, orchestration, probe, started, python_binding, provider=False, capsule=False):
        self.target, self.profile = target, TARGETS[target]
        self.source, self.run_id, self.attempt = source, run, attempt
        self.owner, self.control, self.orchestration, self.probe = owner, control, orchestration, probe
        self.started, self.deadline = started, started + WORK_SECONDS
        self.python_binding = python_binding
        B.need(type(provider) is bool and type(capsule) is bool, "fixed-seal-workflow-context")
        self.provider_mode, self.provider_ready = provider, False
        self.capsule_mode = capsule
        self.capsule_purpose = "history-provider" if provider else "github-seal"
        self.role_limits = PROVIDER_ROLES if provider else ROLE_LIMITS
        prefix = "mrk-history-provider" if provider else "mrk-github-seal"
        self.work = WORK_PARENT / f"{prefix}-{target}-{source}-{run}-{attempt}"
        self.private, self.public = self.work / "private", self.work / "public"
        self.capsule_pending, self.capsule_public = self.work / "capsule-pending", self.work / "capsule"
        self.capsule_identity = self.capsule_copy_identity = self.capsule_receipt_identity = None
        self.export_identity = self.export_helper_identity = None
        self.export_promoted = self.capsule_promoted = False
        self.provider_parents, self.provider_source_parents = {}, {}
        self.provider_private_retired = False
        self.work_identity = self.private_identity = None
        self.guard, owns = control.cancellation_owner(None, B.BuildRefused, "seal-handler-finality")
        B.need(owns, "seal-original-cancellation-owner")
        self.entered = self.returned = 0
        self.inflight = self.cleaning = False
        self.commands, self.tools, self.tool_parents, self.evidence = [], {}, {}, {}
        self.phase, self.failure, self.cleanup_errors = "admission", None, []
        self.scratch_retired = False
        self.environment, self.toolchain, self.generated = {}, {}, {}
        self.selected = {}
        self.native, self.export_rows = {}, {}
        self.success_ready = False
        self.source_post = False
        self.runtime_rosters = {}
        self.libtool_alias_originals = {}
        self.native_deadline = None
        self.native_capture_remaining = 0

    def check(self):
        if self.cleaning:
            B.remaining(self.cleanup_deadline, time.monotonic(), CLEANUP_SECONDS)
        else:
            self.guard.check()
            B.remaining(self.deadline, time.monotonic(), WORK_SECONDS)

    def final_check(self):
        B.need(B.DATA.known and B.custody(self.work.lstat()) == self.work_identity,
               "original-data-or-task-finality-unknown")
        B.remaining(self.deadline + CLEANUP_SECONDS, time.monotonic(), CLEANUP_SECONDS)

    def evidence_bytes(self, name, body):
        if getattr(self, "provider_mode", False):
            B.need(type(body) is bytes and sum(map(len, self.evidence.values())) + len(body) <= MIB - QUERY_LIMIT,
                   "provider-evidence-bound")
        return B.Build.evidence_bytes(self, name, body)

    def evidence_json(self, name, value):
        return B.Build.evidence_json(self, name, value)

    def mkdir(self, path):
        self.check()
        B.need(absent(path), "fresh-task-directory-collision")
        try:
            path.mkdir(mode=0o700)
            info = path.lstat()
            B.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                   and info.st_uid == os.getuid(), "fresh-task-directory")
        except BaseException:
            B.DATA.unknown()  # Never adopt an interrupted mkdir result by path.
            raise
        return B.custody(info)

    def protected_tool(self, path, *, role, system=True, executable=True):
        # Same protected_tool leaf/alias/original-read policy, with this fixed
        # role roster. No mutation of the CPython builder's role constants.
        self.check()
        B.need(role in {"sandbox", "xcrun", "shell", "make", "sysctl", "python", "sdk-settings",
                       "sdk-interface", "clang", "ar", "ranlib", "ld", "nm", "cargo", "rustc", "rust-library"},
               "fixed-tool-role")
        B.need(path.is_absolute(), "non-absolute-tool-route")
        resolved = path.resolve(strict=True)
        if system:
            allowed = ("/usr/", "/bin/", "/sbin/", "/System/", str(DEVELOPER) + "/")
            B.need(str(path).startswith(allowed) and str(resolved).startswith(allowed), "non-Apple-tool-route")
        for route in (path, resolved):
            for parent in (route.parent, *route.parent.parents):
                info = parent.stat()
                # Match the donor: Apple ancestors are protected; the action's
                # nonshipped interpreter/Rust cache has no same-UID isolation
                # claim. Still retain its actual parent custody for POST.
                B.need(stat.S_ISDIR(info.st_mode) and info.st_uid in ({0} if system else {0, os.getuid()})
                       and (not system or not info.st_mode & 0o022), "unprotected-tool-parent")
                facts = B.custody(info)
                previous = self.tool_parents.setdefault(str(parent), facts)
                B.need(previous == facts and len(self.tool_parents) <= 256, "tool-parent-changed")
        info = resolved.lstat()
        # Preserve the original admission order. Diagnostics do not turn a
        # failed predicate into an admitted tool or expose its filesystem path.
        condition = None
        if not stat.S_ISREG(info.st_mode):
            condition = "kind"
        elif info.st_uid not in ({0} if system else {0, os.getuid()}):
            condition = "owner"
        elif executable and not info.st_mode & 0o111:
            condition = "executable"
        elif info.st_mode & 0o022:
            condition = "mode"
        if condition is not None:
            scalars = {"uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode,
                       "nlink": info.st_nlink, "hostUid": os.getuid()}
            bounds = {"uid": 2**32, "gid": 2**32, "mode": 2**16, "nlink": 2**64, "hostUid": 2**32}
            B.need(all(type(value) is int and 0 <= value < bounds[name]
                     for name, value in scalars.items()), "tool-diagnostic-scalar")
            self.evidence_json("tool-admission-failure.json", {
                "schemaVersion": 1, "role": role, "condition": condition,
                "AppleSystem": bool(system), "executableRequired": bool(executable), **scalars})
            raise B.BuildRefused("unprotected-selected-tool")
        body = B.read(resolved, 512 * MIB, expected_links=info.st_nlink if system else 1)
        row = {"path": str(resolved), "selectedPath": str(path), "size": len(body), "sha256": B.digest(body),
               "identity": B.identity(info), "AppleSystem": system, "executable": executable, "role": role}
        previous = self.tools.get(str(path))
        B.need(previous is None or previous == row, "tool-readmission-changed")
        B.need(len(self.tools) < 1024 or previous is not None, "tool-original-count")
        self.tools[str(path)] = row
        self.check()
        return str(path)

    def python_tools(self):
        # Retain both exact named routes, with the same original/tool ledger.
        # Reads are sequential: no additional simultaneously live descriptor
        # or second retained binary body; the existing tool/parent caps apply.
        paths, resolved, original = self.python_binding
        B.need(python_entry_binding(*paths) == self.python_binding, "actual-setup-python-entry")
        for path in paths:
            self.protected_tool(Path(path), role="python", system=False)
            row = self.tools[path]
            B.need(row["path"] == resolved and tuple(row["identity"]) == original,
                   "actual-setup-python-entry")
        first, second = (self.tools[path] for path in paths)
        B.need(all(first[key] == second[key] for key in ("path", "identity", "size", "sha256"))
               and python_entry_binding(*paths) == self.python_binding, "actual-setup-python-entry")
        # This is the checked action-provided spelling, not an unchecked
        # canonical replacement. Existing recheck_tools covers both aliases.
        return paths[0]

    def recheck_tools(self, *, full=False):
        for path, facts in self.tool_parents.items():
            self.check()
            B.need(B.custody(Path(path).stat()) == facts, "original-tool-parent-changed")
        B.Build.recheck_tools(self, full=full)
        for path, roster in self.runtime_rosters.items():
            B.need(names(Path(path), 1024, self.check) == roster, "rust-runtime-roster-changed")

    def original_bytes(self, path, limit, *, expected=None):
        self.check()
        original = B.identity(path.lstat())
        body = B.read(path, limit, expected=expected)
        B.need(B.identity(path.lstat()) == original, "build-input-original-post")
        return body, original

    def libtool_alias(self, path, *, retire=False):
        # Fixed official archive names only; these generated aliases are never
        # admitted as our source, selected library, or public artifact inputs.
        parent_path = self.private / "build/src/libsodium/.libs"
        self.check()
        B.need(path.parent == parent_path and path.name in LIBTOOL_ARCHIVES,
               "unexpected-generated-alias")
        expected_target = "../" + path.name
        if retire:
            # DATA.known is the pre-acquisition baseline: our held parent below
            # is itself a pending original until its consuming close returns.
            verdict = self.guard.lifetime_ledger.verdict()
            B.need(self.cleaning and not self.inflight and B.DATA.known and verdict.complete
                   and not verdict.fatal and verdict.contained, "generated-alias-unsettled")
        before = path.lstat()
        B.need(stat.S_ISLNK(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(),
               "generated-alias-original")
        parent = path.parent.lstat()
        B.need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid(), "generated-alias-parent")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        with B.DATA.acquiring(os.open, os.close, path.parent, flags) as fd:
            B.need(B.identity(os.fstat(fd)) == B.identity(parent)
                   and B.identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)) == B.identity(before)
                   and os.readlink(path.name, dir_fd=fd) == expected_target, "generated-alias-pre")
            original = (B.identity(before), B.custody(parent))
            recorded = self.libtool_alias_originals.get(path.name)
            B.need(recorded is None or recorded == original, "generated-alias-changed")
            B.need(not retire or recorded == original, "generated-alias-unrecorded")
            B.need(B.identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)) == B.identity(before)
                   and os.readlink(path.name, dir_fd=fd) == expected_target
                   and B.identity(os.fstat(fd)) == B.identity(parent)
                   and B.identity(path.parent.lstat()) == B.identity(parent), "generated-alias-post")
            if retire:
                try:
                    os.unlink(path.name, dir_fd=fd)
                except BaseException:
                    B.DATA.unknown()  # No adoption of an interrupted unlink.
                    raise
                try:
                    os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise B.BuildRefused("generated-alias-retirement-post")
                B.need(B.custody(os.fstat(fd)) == B.custody(parent)
                       and B.custody(path.parent.lstat()) == B.custody(parent), "generated-alias-parent-post")
            else:
                self.libtool_alias_originals[path.name] = original
        self.check()

    def census(self):
        """Settled work bound, not a hard live quota or a descendant-FD claim."""
        if self.private_identity is None:
            return {"entries": 0, "bytes": 0}
        B.need(B.custody(self.private.lstat()) == self.private_identity, "original-private-root-changed")
        pending, count, total = [self.private], 0, 0
        while pending:
            self.check()
            directory = pending.pop()
            info = directory.lstat()
            B.need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "work-directory")
            for name in names(directory, WORK_ENTRIES - count, self.check):
                path = directory / name
                info = path.lstat()
                count += 1
                B.need(count <= WORK_ENTRIES and info.st_uid == os.getuid()
                       and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)),
                       "work-entry")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    B.need(len(pending) <= WORK_ENTRIES, "work-pending")
                elif stat.S_ISLNK(info.st_mode):
                    self.libtool_alias(path)
                    total += info.st_size
                    B.need(total <= WORK_BYTES, "work-extent")
                else:
                    # Generated Cargo/libtool aliases are ordinary build work,
                    # not admitted input/public originals. Selected artifacts
                    # receive their separate exact alias proof below.
                    B.need(info.st_nlink >= 1 and 0 <= info.st_size <= 128 * MIB, "work-file")
                    total += info.st_size
                    B.need(total <= WORK_BYTES, "work-extent")
        return {"entries": count, "bytes": total}

    def run(self, role, argv, *, cwd=None):
        self.check()
        roles = self.role_limits
        B.need(self.entered < len(roles) and role == roles[self.entered][0], "fixed-role-order")
        _, maximum, output_limit = roles[self.entered]
        native_phase = next((phase for phase in NATIVE_PHASES if role == phase[0]), None)
        deadline, environment, policy = self.deadline, self.environment, B.NETWORK_POLICY
        if native_phase is not None:
            B.need(not self.provider_mode and self.native_deadline is not None, "native-pair-admission")
            deadline = min(deadline, self.native_deadline)
            B.need(type(self.native_capture_remaining) is int and 0 < self.native_capture_remaining <= QUERY_LIMIT,
                   "native-pair-capture")
            output_limit = min(output_limit, self.native_capture_remaining)
            environment = {**self.environment, NATIVE_PHASE_ENV: native_phase[1]}
            if role == "helper-entropy-test":
                policy = NATIVE_DENIED_POLICY
        selected = [self.sandbox, "-p", policy, *argv]
        directory = cwd or self.private
        if self.provider_mode:
            self.provider_post()
        self.recheck_tools()
        if native_phase is not None:
            B.remaining(deadline, time.monotonic(), maximum)
        row = {"role": role, "argv": selected, "cwd": str(directory),
               "environmentSha256": B.digest(B.canonical(environment)),
               "started": time.monotonic(), "returned": False}
        self.phase = role
        self.commands.append(row)
        self.entered += 1
        self.inflight = True
        try:
            result = self.owner.run_owned(selected, environ=environment, cwd=directory,
                timeout=B.remaining(deadline, time.monotonic(), maximum), capture=True, text=False,
                output_limit=output_limit, cancellation=self.guard)
        except BaseException:
            verdict = self.guard.lifetime_ledger.verdict()
            self.inflight = not (verdict.complete and not verdict.fatal and verdict.contained)
            raise
        else:
            self.inflight = False
            self.returned += 1
            B.need(B.original_result(result, selected) and len(result.stdout) + len(result.stderr) <= output_limit,
                   "original-command-return-contract")
            if native_phase is not None:
                self.native_capture_remaining -= len(result.stdout) + len(result.stderr)
            row.update(returned=True, returncode=result.returncode, ended=time.monotonic(),
                stdoutSha256=self.evidence_bytes(role + ".stdout", result.stdout),
                stderrSha256=self.evidence_bytes(role + ".stderr", result.stderr))
            self.recheck_tools()
            if self.provider_mode:
                self.provider_post()
                B.need(provider_output(role, result.returncode, result.stdout, result.stderr), "provider-output-contract")
            else:
                B.need(result.returncode == 0 and b"(ignored)" not in result.stdout + result.stderr,
                       "original-command-failed")
            row["settledWork"] = self.census()
            self.check()
            if native_phase is not None:
                B.remaining(deadline, time.monotonic(), maximum)
            return result

    def line(self, result):
        B.need(result.stderr == b"" and re.fullmatch(rb"[^\x00-\x1f\x7f]+\n", result.stdout), "single-query-line")
        return result.stdout[:-1].decode("ascii", "strict")

    def rust_inputs(self, root):
        # Bind the installed compiler's dynamic libraries and the exact native
        # standard-library directory. Do not activate SDK/Gradle/build catalogs.
        total = 0
        for directory in (root / "lib", root / "lib/rustlib" / self.target / "lib"):
            self.check()
            info = directory.lstat()
            B.need(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, os.getuid()}
                   and not info.st_mode & 0o022, "rust-runtime-directory")
            roster = names(directory, 1024, self.check)
            self.runtime_rosters[str(directory)] = roster
            selected = []
            for name in roster:
                path = directory / name
                if directory == root / "lib" and not name.endswith(".dylib"):
                    continue
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    B.need(name == "self-contained" and not names(path, 1, self.check), "rust-runtime-subdirectory")
                    self.runtime_rosters[str(path)] = []
                    continue
                B.need(path.resolve(strict=True).is_relative_to(root), "rust-runtime-alias-escape")
                self.protected_tool(path, role="rust-library", system=False, executable=False)
                total += self.tools[str(path)]["size"]
                B.need(total <= 2 * 1024 * MIB, "rust-runtime-read-bound")
                selected.append(name)
            B.need(selected and (directory == root / "lib" or any(name.startswith("libstd-") for name in selected)),
                   "rust-runtime-complete-native-selection")
        return total

    def provider_parents_post(self):
        parents = self.provider_source_parents if self.provider_private_retired else self.provider_parents
        for path, original in parents.items():
            self.check()
            info = Path(path).lstat()
            B.need(stat.S_ISDIR(info.st_mode) and B.custody(info) == original,
                   "provider-parent-post")

    def provider_stream(self, path, pin, *, original=None, destination=None):
        # Large input reads remain separate from the existing2MiB SOURCE reader.
        # At most one64KiB block and one64KiB load table are retained, not the
        # full executable; the SAME original is checked before/after all bytes.
        self.check()
        B.need(type(pin) is tuple and len(pin) == 2 and type(pin[0]) is int
               and 0 < pin[0] <= 128 * MIB and type(pin[1]) is str
               and re.fullmatch(r"[0-9a-f]{64}", pin[1]), "provider-input-pin")
        info = path.lstat()
        identity = B.identity(info)
        B.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin[0]
               and (original is None or identity == original), "provider-input-original")
        self.provider_parents_post()
        copy_identity = None
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        with B.DATA.acquiring(os.open, os.close, path, flags) as fd:
            B.need(B.identity(os.fstat(fd)) == identity, "provider-input-original")
            def transfer(output):
                digest, count, prefix = hashlib.sha256(), 0, b""
                while count < pin[0]:
                    self.check()
                    block = os.read(fd, min(65536, pin[0] - count))
                    B.need(bool(block), "provider-input-short")
                    if len(prefix) < QUERY_LIMIT:
                        prefix += block[:QUERY_LIMIT - len(prefix)]
                    digest.update(block)
                    count += len(block)
                    if output is not None:
                        cursor = 0
                        while cursor < len(block):
                            self.check()
                            written = os.write(output, block[cursor:])
                            B.need(type(written) is int and 0 < written <= len(block) - cursor,
                                   "provider-copy-short")
                            cursor += written
                B.need(not os.read(fd, 1) and (count, digest.hexdigest()) == pin,
                       "provider-input-pin")
                B.need(B.identity(os.fstat(fd)) == identity and B.identity(path.lstat()) == identity,
                       "provider-input-post")
                return prefix
            if destination is None:
                prefix = transfer(None)
            else:
                # A failed open/close stays in the SAME DATA ledger. No retry,
                # guessed file adoption, or chmod of the checkout original.
                with B.DATA.acquiring(os.open, os.close, destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600) as output:
                    made = os.fstat(output)
                    B.need(stat.S_ISREG(made.st_mode) and made.st_nlink == 1 and made.st_uid == os.getuid(),
                           "provider-copy-original")
                    prefix = transfer(output)
                    os.fchmod(output, 0o555)
                    after = os.fstat(output)
                    B.need(B.custody(after)[:2] == B.custody(made)[:2] and B.custody(after)[3:] == B.custody(made)[3:]
                           and after.st_size == pin[0]
                           and stat.S_IMODE(after.st_mode) == 0o555 and after.st_nlink == 1
                           and B.identity(destination.lstat()) == B.identity(after), "provider-copy-post")
                    copy_identity = B.identity(after)
            self.provider_parents_post()
        self.check()
        return identity, prefix, copy_identity

    def provider_notices_post(self):
        # Fixed descriptive sidecars, never executable/source authority. Preserve
        # the exact initially observed originals across every subsequent read.
        B.need(type(self.provider_notice_originals) is dict
               and set(self.provider_notice_originals) == set(PROVIDER_NOTICE_PINS),
               "provider-notice-originals")
        for target, pin in PROVIDER_NOTICE_PINS.items():
            path = CHECKOUT / PROVIDER_INPUT_ROOT / target / "NOTICES.txt"
            self.provider_stream(path, pin, original=self.provider_notice_originals[target])

    def provider_input(self):
        self.provider_parents = {}
        input_root = CHECKOUT / PROVIDER_INPUT_ROOT
        path = input_root / self.target / "gh"
        # All named source ancestors are real directories; no symlink/alias
        # admission. Public checkout is not a same-UID isolation boundary.
        for parent in (path.parent, *path.parent.parents):
            self.check()
            info = parent.lstat()
            B.need(stat.S_ISDIR(info.st_mode) and not parent.is_symlink(), "provider-parent-original")
            self.provider_parents[str(parent)] = B.custody(info)
        B.need(len(self.provider_parents) <= 128, "provider-parent-original")
        expected_root = sorted(TARGETS) if self.capsule_mode else ["aarch64-apple-darwin", "crossbuild.json",
                         "source-manifest.json", "x86_64-apple-darwin"]
        B.need(names(input_root, len(expected_root), self.check) == expected_root, "provider-input-roster")
        for target in PROVIDER_PINS:
            self.check()
            directory = input_root / target
            info = directory.lstat()
            expected_names = ["NOTICES.txt", "build-facts.json", "gh"] if self.capsule_mode else ["NOTICES.txt", "gh"]
            B.need(stat.S_ISDIR(info.st_mode) and not directory.is_symlink()
                   and names(directory, len(expected_names), self.check) == expected_names, "provider-input-roster")
            B.need((str(directory) not in self.provider_parents and len(self.provider_parents) < 128)
                   or self.provider_parents.get(str(directory)) == B.custody(info),
                   "provider-parent-original")
            self.provider_parents[str(directory)] = B.custody(info)
        B.need(set(PROVIDER_NOTICE_PINS) == set(PROVIDER_PINS), "provider-notice-roster")
        self.provider_source_parents = dict(self.provider_parents)
        if self.capsule_mode:
            self.provider_prepared = {}
            for target, (name, pin) in zip(TARGETS, provider_fact_records()):
                body = B.read(CHECKOUT / name, CAPSULE_RECEIPT_LIMIT, expected=pin)
                B.need(B.identity((CHECKOUT / name).lstat()) == self.source_binding[name]["identity"], "provider-record-post")
                self.provider_prepared[target] = capsule_prepared(body, target)
        self.provider_notice_originals = {}
        for target, pin in PROVIDER_NOTICE_PINS.items():
            notice = input_root / target / "NOTICES.txt"
            identity, _, _ = self.provider_stream(notice, pin)
            self.provider_notice_originals[target] = identity
        B.need(B.custody((self.private / "provider").lstat()) == self.provider_directory_identity,
               "provider-parent-post")
        self.provider_original = path
        self.provider_pin = PROVIDER_PINS[self.target]
        self.provider_identity, prefix, _ = self.provider_stream(path, self.provider_pin)
        self.provider_facts = provider_macho_data(prefix, self.provider_pin[0], self.target, self.orchestration)
        self.provider_binary = self.private / "provider/gh"
        for parent in (self.provider_binary.parent, self.private, self.work):
            info = parent.lstat()
            B.need((str(parent) not in self.provider_parents and len(self.provider_parents) < 128)
                   or self.provider_parents.get(str(parent)) == B.custody(info),
                   "provider-parent-original")
            self.provider_parents[str(parent)] = B.custody(info)
        B.need(len(self.provider_parents) <= 128, "provider-parent-original")
        _, _, self.provider_copy_identity = self.provider_stream(path, self.provider_pin,
            original=self.provider_identity, destination=self.provider_binary)
        _, copied_prefix, _ = self.provider_stream(self.provider_binary, self.provider_pin,
                                                   original=self.provider_copy_identity)
        B.need(provider_macho_data(copied_prefix, self.provider_pin[0], self.target, self.orchestration)
               == self.provider_facts, "provider-copy-post")
        self.provider_ready = True
        self.provider_post()

    def provider_post(self, *, private=True):
        B.need(private or (self.capsule_mode and self.provider_private_retired and self.scratch_retired
                          and absent(self.private)), "provider-private-retirement")
        self.provider_parents_post()
        pairs = ((self.provider_original, self.provider_identity),)
        if private:
            pairs += ((self.provider_binary, self.provider_copy_identity),)
        for path, original in pairs:
            self.provider_stream(path, self.provider_pin, original=original)
        self.provider_notices_post()
        records = provider_fact_records() if self.capsule_mode else (
            (PROVIDER_SOURCE, PROVIDER_SOURCE_PIN), (PROVIDER_CROSSBUILD, PROVIDER_CROSSBUILD_PIN))
        for name, pin in records:
            self.check()
            before = self.source_binding[name]
            B.need(B.identity((CHECKOUT / name).lstat()) == before["identity"], "provider-record-post")
            B.read(CHECKOUT / name, pin[0], expected=pin)
            B.need(B.identity((CHECKOUT / name).lstat()) == before["identity"], "provider-record-post")
        self.check()

    def prepare_provider(self):
        self.work_identity = self.mkdir(self.work)
        self.private_identity = self.mkdir(self.private)
        for name in ("home", "tmp", "gh-config", "provider"):
            made = self.mkdir(self.private / name)
            if name == "provider":
                self.provider_directory_identity = made
        self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.private / "home"),
            "TMPDIR": str(self.private / "tmp") + "/", "GH_CONFIG_DIR": str(self.private / "gh-config"),
            "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "GH_HOST": "github.com", "NO_COLOR": "1",
            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
            "GH_TOKEN": "mrk-history-native-probe-not-a-credential"}
        self.sandbox = self.protected_tool(Path("/usr/bin/sandbox-exec"), role="sandbox")
        self.python = self.python_tools()
        self.provider_input()
        network = self.run("network-denial", [self.python, "-I", "-S", "-B",
            str(CHECKOUT / "desktop/tools/macos_cpython_source_probe.py"), "network", self.target])
        facts = B.probe_result(network.stdout, "network", self.target, self.probe)
        B.need(network.stderr == b"" and type(facts.get("errno")) is int and facts["errno"] in {1, 13}, "network-denial")
        self.toolchain.update(nativeHost=facts["nativeHost"], target=self.target,
            pythonVersion=sys.version, pythonShipped=False, resourceLimits=self.resource_limits)
        self.run("provider-version", [str(self.provider_binary), "--version"])
        # gh reads private startup Config/KnownHosts BEFORE the apiRun guard.
        # The explicit PUBLIC inert token satisfies CheckAuth; no secret token,
        # user config, successful API client or real network request is tested.
        self.environment["MRK_HISTORY_PROVIDER_V1"] = "1"
        self.run("provider-invalid-controls", [str(self.provider_binary), "api", "--hostname", "github.com",
                                               "--method", "GET", "user"])
        self.provider_post()
        self.recheck_tools(full=True)
        B.need(source_snapshot(self.check, provider=True, capsule=self.capsule_mode) == self.source_binding,
               "verification-source-final-post")
        self.source_post = True
        provider_inputs = {"binary": {"bytes": self.provider_pin[0], "sha256": self.provider_pin[1]},
            "sourceManifest": PROVIDER_SOURCE_PIN,
            "facts": self.provider_facts, "embeddedNoticesComplete": True,
            "noticeContentRuntimeExecuted": False, "notices": PROVIDER_NOTICE_PINS,
            "copiedIdentity": self.provider_copy_identity, "inputIdentity": self.provider_identity}
        if self.capsule_mode:
            provider_inputs["preparedFacts"] = PROVIDER_FACTS_PINS
        else:
            provider_inputs["crossbuild"] = PROVIDER_CROSSBUILD_PIN
            self.evidence_bytes("crossbuild.json", B.read(CHECKOUT / PROVIDER_CROSSBUILD, QUERY_LIMIT, expected=PROVIDER_CROSSBUILD_PIN))
        self.evidence_json("provider-inputs.json", provider_inputs)
        self.evidence_json("toolchain.json", {**self.toolchain, "tools": list(self.tools.values()), "sameUidAdversaryIsolation": False})
        self.evidence_json("source-binding.json", {"sourceCommit": self.source, "rows": self.source_binding})
        self.check()
        B.need(self.entered == self.returned == 3, "fixed-recipe-complete")
        self.success_ready = True

    def prepare(self):
        self.work_identity = self.mkdir(self.work)
        self.private_identity = self.mkdir(self.private)
        for name in ("home", "tmp", "sources", "build", "prefix", "cargo", "target"):
            self.mkdir(self.private / name)
        self.environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.private / "home"),
            "TMPDIR": str(self.private / "tmp") + "/", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
            # Apple ranlib refreshes archive TOC dates during make install.
            # Its documented deterministic mode preserves strict build/install byte identity.
            "ZERO_AR_DATE": "1",
            "DEVELOPER_DIR": str(DEVELOPER), "CONFIG_SITE": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1"}
        self.sandbox = self.protected_tool(Path("/usr/bin/sandbox-exec"), role="sandbox")
        self.xcrun = self.protected_tool(Path("/usr/bin/xcrun"), role="xcrun")
        self.shell = self.protected_tool(Path("/bin/sh"), role="shell")
        self.make = self.protected_tool(Path("/usr/bin/make"), role="make")
        self.sysctl = self.protected_tool(Path("/usr/sbin/sysctl"), role="sysctl")
        self.python = self.python_tools()
        rust = Path("/Users/runner/.rustup/toolchains") / ("stable-" + self.target)
        B.need(rust.resolve(strict=True) == rust, "direct-rust-root")
        self.rustc = self.protected_tool(rust / "bin/rustc", role="rustc", system=False)
        self.cargo = self.protected_tool(rust / "bin/cargo", role="cargo", system=False)
        self.toolchain["rustInputBytes"] = self.rust_inputs(rust)
        sdk = self.line(self.run("sdk-path", [self.xcrun, "--sdk", "macosx", "--show-sdk-path"]))
        self.sdk = Path(sdk).resolve(strict=True)
        B.need(self.sdk.is_relative_to(DEVELOPER / "SDKs") and " " not in str(self.sdk), "fixed-Apple-sdk")
        self.protected_tool(self.sdk / "SDKSettings.json", role="sdk-settings", executable=False)
        sdk_version = self.line(self.run("sdk-version", [self.xcrun, "--sdk", "macosx", "--show-sdk-version"]))
        B.need(re.fullmatch(r"26\.[0-9]+(?:\.[0-9]+)?", sdk_version), "sdk-version")
        for name in ("clang", "ar", "ranlib", "ld", "nm"):
            path = self.line(self.run("tool-path-" + name, [self.xcrun, "--sdk", "macosx", "--find", name]))
            setattr(self, name, self.protected_tool(Path(path), role=name))
        for name in B.SDK_INTERFACE_PATHS:
            self.protected_tool(self.sdk / name, role="sdk-interface", executable=False)
        compiler = self.run("compiler-version", [self.clang, "--version"])
        B.need(compiler.stderr == b"" and compiler.stdout.startswith(b"Apple clang version "), "Apple-compiler-version")
        rust_version = self.run("rustc-version", [self.rustc, "-vV"])
        cargo_version = self.line(self.run("cargo-version", [self.cargo, "--version"]))
        rust_lines = rust_version.stdout.decode("ascii", "strict").splitlines()
        B.need(rust_version.stderr == b"" and len(rust_lines) <= 16
               and rust_lines[0].startswith("rustc " + self.profile[2] + " (")
               and rust_lines.count("host: " + self.target) == 1
               and rust_lines.count("release: " + self.profile[2]) == 1
               and re.fullmatch(r"cargo " + re.escape(self.profile[2]) + r" \([0-9a-f]{7,40} [0-9-]{10}\)", cargo_version),
               "actual-direct-Rust-version")
        self.environment.update(SDKROOT=str(self.sdk), MACOSX_DEPLOYMENT_TARGET="26.0",
            CC=self.clang, AR=self.ar, RANLIB=self.ranlib, LD=self.ld, MAKE=self.make, CONFIG_SHELL=self.shell,
            CFLAGS=B.compiler_flags(self.sdk, self.target), CPPFLAGS="", LDFLAGS=B.linker_flags(self.sdk, self.target),
            RUSTC=self.rustc, RUSTUP_AUTO_INSTALL="0", CARGO_HOME=str(self.private / "cargo"),
            CARGO_TARGET_DIR=str(self.private / "target"), CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0",
            CARGO_BUILD_JOBS="1", CARGO_ENCODED_RUSTFLAGS="\x1f".join(("-L", "native=" + str(self.private / "prefix/lib"),
                                                                    "-C", "linker=" + self.clang)))
        network = self.run("network-denial", [self.python, "-I", "-S", "-B",
            str(CHECKOUT / "desktop/tools/macos_cpython_source_probe.py"), "network", self.target])
        facts = B.probe_result(network.stdout, "network", self.target, self.probe)
        B.need(network.stderr == b"" and type(facts.get("errno")) is int and facts["errno"] in {1, 13}, "network-denial")
        memory = self.run("physical-memory", [self.sysctl, "-n", "hw.memsize"])
        B.need(memory.stderr == b"" and re.fullmatch(rb"[1-9][0-9]{0,19}\n", memory.stdout)
               and int(memory.stdout) >= 4 * 1024 * MIB and shutil.disk_usage(self.private).free >= 4 * 1024 * MIB,
               "build-capacity")
        self.toolchain.update(sdk=str(self.sdk), sdkVersion=sdk_version, compilerVersion=compiler.stdout.decode("ascii"),
            rustVersion=rust_version.stdout.decode("ascii"), cargoVersion=cargo_version, nativeHost=facts["nativeHost"],
            pythonVersion=sys.version, pythonShipped=False, physicalMemoryBytes=int(memory.stdout),
            physicalMemoryIsAvailableMemory=False, target=self.target, resourceLimits=self.resource_limits)

    def sources(self):
        self.phase = "canonical-source-extraction"
        self.inventory = B.decode(B.read(CHECKOUT / INVENTORY, INVENTORY_PIN[0], expected=INVENTORY_PIN))
        rows = self.inventory["rows"]
        B.need(self.inventory["schemaVersion"] == 1 and self.inventory["version"] == "1.0.22"
               and self.inventory["root"] == "libsodium-1.0.22" and self.inventory["signatureVerified"] is False
               and len(rows) == 814, "canonical-inventory")
        compressed = B.read(CHECKOUT / ARCHIVE, ARCHIVE_PIN[0], expected=ARCHIVE_PIN)
        decoder, parts, count = zlib.decompressobj(31), [], 0
        # A decoder ceiling BELOW the tar reader also bounds headers/PAX/GNU
        # metadata/padding/trailing bytes. No tar getmembers or extraction API.
        for offset in range(0, len(compressed), 65536):
            pending = compressed[offset:offset + 65536]
            while pending:
                self.check()
                raw = decoder.decompress(pending, min(65536, RAW_PIN[0] - count + 1))
                pending = decoder.unconsumed_tail
                count += len(raw)
                B.need(count <= RAW_PIN[0] and not decoder.unused_data, "bounded-canonical-tar")
                parts.append(raw)
        B.need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
               and count == RAW_PIN[0], "canonical-compression-eof")
        raw = b"".join(parts)
        B.need(B.digest(raw) == RAW_PIN[1], "canonical-decoded-hash")
        self.sodium = self.private / "sources/libsodium-1.0.22"
        cursor, payload, directories = 0, 0, []
        for row in rows:
            self.check()
            header = raw[cursor:cursor + 512]
            B.need(len(header) == 512 and header[156:157] in {b"0", b"\0", b"5"}, "canonical-tar-type")
            item = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            wanted = "libsodium-1.0.22" + ("/" + row["path"] if row["path"] else "")
            B.need(item.name.rstrip("/") == wanted and not item.linkname and not item.pax_headers
                   and item.size == row["bytes"] and item.mode == row["mode"] and item.mtime == row["mtime"]
                   and (item.isdir() if row["kind"] == "directory" else item.isreg()), "canonical-tar-row")
            relative = row["path"]
            if relative:
                B.need(B.source_name(relative) == relative, "canonical-relative-name")
            path = self.sodium / relative
            cursor += 512
            body = raw[cursor:cursor + item.size]
            B.need(len(body) == item.size, "canonical-body-extent")
            if row["kind"] == "directory":
                B.need(item.size == 0, "canonical-directory-body")
                self.mkdir(path)
                directories.append((path, row["mtime"]))
            else:
                B.need(B.digest(body) == row["sha256"], "canonical-body-hash")
                B.write(path, body, 0o555 if row["mode"] & 0o111 else 0o444)
                os.utime(path, (row["mtime"], row["mtime"]), follow_symlinks=False)
                payload += len(body)
            padding = (-item.size) % 512
            B.need(not any(raw[cursor + item.size:cursor + item.size + padding]), "canonical-padding")
            cursor += item.size + padding
        B.need(payload == 9072098 and len(raw) - cursor == 5120 and not any(raw[cursor:]), "canonical-complete-roster")
        for path, mtime in reversed(directories):
            self.check()
            os.chmod(path, 0o555)
            os.utime(path, (mtime, mtime), follow_symlinks=False)
        del raw, parts, compressed
        self.sodium_source = self.original_source()
        makefile = self.sodium_source["src/libsodium/Makefile.am"]
        B.need((makefile["size"], makefile["sha256"]) == LIBTOOL_MAKEFILE_PIN,
               "canonical-libtool-archive-roster")
        self.helper = self.private / "sources/macos-github-seal"
        self.mkdir(self.helper)
        self.mkdir(self.helper / "src")
        for name, pin in HELPER_PINS.items():
            self.check()
            B.write(self.helper / name, B.read(CHECKOUT / HELPER / name, pin[0], expected=pin), 0o444)
        os.chmod(self.helper / "src", 0o555)
        os.chmod(self.helper, 0o555)
        self.helper_source = B.tree_rows(self.helper, maximum=MIB, max_files=10, source=True, deadline=self.deadline)
        B.need(set(self.helper_source) == set(HELPER_PINS), "helper-fixed-roster")
        self.cargo_absence()
        self.evidence_json("canonical-source.json", {"archive": self.inventory["archive"], "decodedTar": self.inventory["decodedTar"],
            "inventorySha256": INVENTORY_PIN[1], "sourceRowsSha256": B.digest(B.canonical(self.sodium_source)),
            "regularFiles": 678, "directories": 136, "officialSignatureVerified": False,
            "priorOptionalBundledComparisonQualified": False, "helperSourceSha256": B.digest(B.canonical(self.helper_source))})

    def original_source(self):
        actual = B.tree_rows(self.sodium, maximum=10 * MIB, max_files=678, source=True, deadline=self.deadline)
        expected = {row["path"]: row for row in self.inventory["rows"] if row["kind"] == "file"}
        B.need(set(actual) == set(expected), "canonical-source-file-roster")
        for name, row in actual.items():
            self.check()
            wanted = expected[name]
            info = (self.sodium / name).lstat()
            B.need((row["size"], row["sha256"], row["mode"], info.st_mtime_ns)
                   == (wanted["bytes"], wanted["sha256"], 0o555 if wanted["mode"] & 0o111 else 0o444,
                       wanted["mtime"] * 10**9), "canonical-source-readback")
        for row in self.inventory["rows"]:
            if row["kind"] == "directory":
                self.check()
                path = self.sodium / row["path"]
                info = path.lstat()
                wanted_names = sorted(PurePosixPath(other["path"]).name for other in self.inventory["rows"]
                    if other["path"] and str(PurePosixPath(other["path"]).parent) == (row["path"] or "."))
                B.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555
                       and info.st_mtime_ns == row["mtime"] * 10**9
                       and names(path, 814, self.check) == wanted_names, "canonical-source-directory-roster")
        return actual

    def cargo_absence(self):
        for directory in (self.helper, *self.helper.parents):
            self.check()
            for name in (".cargo/config", ".cargo/config.toml", ".cargo/credentials", ".cargo/credentials.toml"):
                B.need(absent(directory / name), "unadmitted-Cargo-configuration")
        for name in ("config", "config.toml", "credentials", "credentials.toml"):
            B.need(absent(self.private / "cargo" / name), "private-Cargo-configuration")
        B.need(absent(self.helper / "build.rs") and absent(self.helper / "rust-toolchain")
               and absent(self.helper / "rust-toolchain.toml"), "helper-no-build-discovery")

    def build_sodium(self):
        build, prefix = self.private / "build", self.private / "prefix"
        self.run("sodium-configure", [self.shell, str(self.sodium / "configure"), "--disable-shared",
            "--enable-static", "--disable-dependency-tracking", "--prefix=" + str(prefix)], cwd=build)
        for name in ("config.log", "config.status", "Makefile", "src/Makefile", "src/libsodium/Makefile",
                     "src/libsodium/include/Makefile", "src/libsodium/include/sodium/version.h", "test/default/Makefile"):
            self.check()
            body, original = self.original_bytes(build / name, 2 * MIB)
            B.need(b"-DBENCHMARKS" not in body and b"-DBROWSER_TESTS" not in body, "ordinary-canonical-test-mode")
            self.generated[name] = {"bytes": len(body), "sha256": B.digest(body), "identity": original}
        self.run("sodium-build", [self.make, "-j1"], cwd=build)
        self.run("sodium-install", [self.make, "-j1", "install"], cwd=build)
        self.library = prefix / "lib/libsodium.a"
        archive, self.library_identity = self.original_bytes(self.library, 64 * MIB)
        B.need(archive.startswith(b"!<arch>\n") and len(archive) > 8, "canonical-normal-static-archive")
        B.need(B.read(build / "src/libsodium/.libs/libsodium.a", 64 * MIB) == archive, "canonical-installed-build-library")
        self.library_pin = (len(archive), B.digest(archive))
        B.need(names(prefix, 4, self.check) == ["include", "lib"]
               and names(prefix / "lib", 4, self.check) == ["libsodium.a", "libsodium.la", "pkgconfig"]
               and names(prefix / "lib/pkgconfig", 2, self.check) == ["libsodium.pc"], "static-install-roster")
        la = B.read(prefix / "lib/libsodium.la", 65536).decode("ascii", "strict")
        for key, value in (("dlname", ""), ("library_names", ""), ("old_library", "libsodium.a")):
            B.need(re.findall(r"(?m)^" + key + r"='([^'\n]*)'$", la) == [value], "static-libtool-metadata")
        pc = B.read(prefix / "lib/pkgconfig/libsodium.pc", 65536).decode("ascii", "strict")
        B.need(re.findall(r"(?m)^Version: ([^\n]+)$", pc) == ["1.0.22"], "canonical-pkgconfig-version")
        self.headers = {}
        wanted = set(self.inventory["publicHeaders"]) | {"sodium/version.h"}
        B.need(len(wanted) == 77 and names(prefix / "include", 3, self.check) == ["sodium", "sodium.h"]
               and names(prefix / "include/sodium", 77, self.check)
               == sorted(PurePosixPath(name).name for name in wanted if name.startswith("sodium/")), "canonical-public-header-roster")
        generated = B.read(build / "src/libsodium/include/sodium/version.h", MIB)
        template = B.read(self.sodium / "src/libsodium/include/sodium/version.h.in", MIB)
        version = template.replace(b"@VERSION@", b"1.0.22").replace(b"@SODIUM_LIBRARY_VERSION_MAJOR@", b"26")
        version = version.replace(b"@SODIUM_LIBRARY_VERSION_MINOR@", b"4").replace(b"@SODIUM_LIBRARY_MINIMAL_DEF@", b"")
        B.need(generated == version, "canonical-generated-version-header")
        for name in sorted(wanted):
            self.check()
            body, original = self.original_bytes(prefix / "include" / name, MIB)
            expected = version if name == "sodium/version.h" else B.read(self.sodium / "src/libsodium/include" / name, MIB)
            B.need(body == expected, "canonical-installed-public-header")
            self.headers[name] = {"bytes": len(body), "sha256": B.digest(body), "identity": original}
        self.run("header-abi", [self.clang, "-arch", self.profile[0], "-isysroot", str(self.sdk),
            "-mmacosx-version-min=26.0", "-I", str(prefix / "include"), "-std=c11", "-fsyntax-only",
            "-Werror=incompatible-function-pointer-types", "-Werror=incompatible-pointer-types", str(self.helper / "abi-check.c")])
        symbols = self.run("static-four-symbols", _static_symbol_argv(self.target, self.nm, self.library))
        B.need(symbols.stderr == b"", "static-symbol-query")
        lines = symbols.stdout.decode("ascii", "strict").splitlines()
        for name in ("_sodium_init", "_crypto_box_seal", "_sodium_memzero", "_randombytes_close"):
            B.need(sum(bool(re.fullmatch(r"[0-9a-fA-F]+ [A-Z] " + re.escape(name), line.strip())) for line in lines) == 1,
                   "canonical-four-symbol-definition")
        self.evidence_json("canonical-static-link-inputs.json", {"libraryBytes": len(archive), "librarySha256": B.digest(archive),
            "headers": self.headers, "generated": self.generated, "fourRequiredDefinitions": True,
            "matchingHeaderTranslationUnit": True, "minimal": False, "releaseSignatureVerified": False})

    def macho(self, path, *, limit, cargo_release=False):
        self.check()
        info = path.lstat()
        B.need(stat.S_ISREG(info.st_mode) and info.st_nlink in ({1, 2} if cargo_release else {1}) and info.st_uid == os.getuid()
               and info.st_mode & 0o111 and not info.st_mode & 0o022, "produced-executable-original")
        alias = None
        if info.st_nlink == 2:
            B.need(path == self.private / "target" / self.target / "release/mrk-github-seal", "Cargo-release-original")
            deps = path.parent / "deps"
            matches = []
            for name in names(deps, 1024, self.check):
                candidate = deps / name
                observed = candidate.lstat()
                if (observed.st_dev, observed.st_ino) == (info.st_dev, info.st_ino):
                    B.need(re.fullmatch(r"mrk_github_seal-[0-9a-f]{16}", name)
                           and B.identity(observed) == B.identity(info), "Cargo-returned-alias")
                    matches.append(candidate)
            B.need(len(matches) == 1, "Cargo-exact-two-original-names")
            alias = str(matches[0])
            B.read(matches[0], limit, expected_links=2)
        body = B.read(path, limit, expected_links=info.st_nlink)
        cpu, subtype = self.profile[3:]
        B.need(len(body) >= 32 and body[:4] == b"\xcf\xfa\xed\xfe"
               and self.orchestration.native_slice(body, self.profile[0]) == body, "produced-thin-native-MachO")
        header = struct.unpack_from("<8I", body)
        B.need(header[1:4] == (cpu, subtype, 2), "produced-native-execute-header")
        rows = self.orchestration.macho_records(body, self.profile[0])
        load, dyld, build = [], [], []
        for row in rows:
            command, offset, size = row["command"], row["offset"], row["size"]
            B.need(command not in {0x6, 0x7, 0xD, 0xF, 0x10, 0x12, 0x13, 0x14, 0x15, 0x1C, 0x8000001C, 0x27},
                   "produced-no-loader-override")
            if command == 0x32:
                B.need(size >= 24, "produced-build-version-extent")
                platform_id, minimum, sdk, tool_count = struct.unpack_from("<4I", body, offset + 8)
                B.need(platform_id == 1 and minimum == 0x001A0000 and sdk >> 16 == 26
                       and tool_count <= 16 and size == 24 + 8 * tool_count, "produced-native-minimum-sdk")
                build.append((minimum, sdk))
            if command == 0xE:
                dyld.append(row["text"])
            if command in {0xC, 0x18, 0x80000018, 0x1F, 0x8000001F, 0x20, 0x23, 0x80000023}:
                value = row["text"]
                B.need(value in {"/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib", "/usr/lib/libc++.1.dylib", "/usr/lib/libiconv.2.dylib"}
                       or value.startswith("/System/Library/Frameworks/") and "/../" not in value,
                       "produced-system-only-link")
                B.need("sodium" not in value.lower(), "produced-no-dynamic-sodium")
                load.append(value)
        B.need(len(build) == 1 and dyld == ["/usr/lib/dyld"] and "/usr/lib/libSystem.B.dylib" in load,
               "produced-loader-build-version")
        B.need(B.identity(path.lstat()) == B.identity(info), "produced-original-post")
        row = {"bytes": len(body), "sha256": B.digest(body), "identity": B.identity(info), "cargoAlias": alias,
               "loadDylibs": load, "minimumMacOS": "26.0", "sdkMajor": 26,
               "thin": True, "signedReleaseQualification": False}
        self.selected[str(path)] = row
        return row

    def selected_post(self):
        for value, row in self.selected.items():
            self.check()
            path = Path(value)
            B.need(B.identity(path.lstat()) == row["identity"]
                   and B.digest(B.read(path, row["bytes"], expected_links=row["identity"][5])) == row["sha256"],
                   "produced-original-post")
            if row["cargoAlias"] is not None:
                alias = Path(row["cargoAlias"])
                B.need(B.identity(alias.lstat()) == row["identity"]
                       and B.digest(B.read(alias, row["bytes"], expected_links=2)) == row["sha256"],
                       "produced-Cargo-alias-post")
        _, original = self.original_bytes(self.library, self.library_pin[0], expected=self.library_pin)
        B.need(original == self.library_identity, "original-static-library-changed")
        for name, row in self.headers.items():
            self.check()
            _, original = self.original_bytes(self.private / "prefix/include" / name, row["bytes"],
                                               expected=(row["bytes"], row["sha256"]))
            B.need(original == row["identity"], "original-static-header-changed")

    def cargo_artifact(self, result, *, test):
        B.need(result.stdout.endswith(b"\n") and len(result.stdout) <= MIB, "cargo-output-framing")
        records = result.stdout.splitlines()
        B.need(len(records) <= 32 and all(0 < len(line) <= QUERY_LIMIT for line in records), "cargo-record-cap")
        artifacts, finished = [], []
        package = "path+" + self.helper.as_uri() + "#mrk-github-seal@0.1.0"
        for line in records:
            row = B.decode(line)
            B.need(type(row) is dict and not finished, "cargo-record-terminal-order")
            if row.get("reason") == "compiler-message":
                B.need(row.get("package_id") == package and type(row.get("message")) is dict
                       and row["message"].get("level") in {"warning", "note", "help"}, "cargo-nonerror-message")
                continue
            if row.get("reason") == "build-finished":
                B.need(row == {"reason": "build-finished", "success": True}, "cargo-build-finished")
                finished.append(row)
                continue
            B.need(row.get("reason") == "compiler-artifact" and row.get("package_id") == package
                   and row.get("manifest_path") == str(self.helper / "Cargo.toml") and row.get("features") == []
                   and row.get("fresh") is False and type(row.get("profile")) is dict
                   and row["profile"].get("test") is test and row["profile"].get("opt_level") == "3",
                   "cargo-fresh-single-package")
            target = row.get("target")
            B.need(type(target) is dict and target.get("kind") == ["bin"] and target.get("crate_types") == ["bin"]
                   and target.get("name") == "mrk-github-seal" and target.get("src_path") == str(self.helper / "src/main.rs")
                   and target.get("edition") == "2021", "cargo-exact-target")
            executable = row.get("executable")
            B.need(type(executable) is str and row.get("filenames") == [executable], "cargo-executable-original")
            path = Path(executable)
            parent = self.private / "target" / self.target / "release"
            B.need(path.is_absolute() and path.resolve(strict=True) == path
                   and (path == parent / "mrk-github-seal" if not test else path.parent == parent / "deps"
                        and re.fullmatch(r"mrk_github_seal-[0-9a-f]{16}", path.name)), "cargo-executable-location")
            artifacts.append(path)
        B.need(len(artifacts) == len(finished) == 1 and B.decode(records[-1]) == finished[0], "cargo-complete-records")
        return artifacts[0]

    def probes_and_helper(self):
        build = self.private / "build"
        self.run("canonical-box-build", [self.make, "-j1", "-C", "test/default", "box_seal"], cwd=build)
        box = build / "test/default/box_seal"
        self.native["canonicalBoxExecutable"] = self.macho(box, limit=64 * MIB)
        B.need(absent(build / "test/default/box_seal.res"), "canonical-test-result-collision")
        returned = self.run("canonical-box-test", [str(box)], cwd=build / "test/default")
        B.need(returned.stdout == returned.stderr == b"", "canonical-test-original-output")
        expected = B.read(self.sodium / "test/default/box_seal.exp", 22,
                          expected=(22, "23eed69ea51943ee68301bdd6e5d773ed42dfb0ae51bb4582f9dfd0756d52fe7"))
        B.need(B.read(build / "test/default/box_seal.res", 22) == expected, "canonical-test-returned-readback")
        self.native["canonicalBox"] = {"returnedZero": True, "resultMatchesOfficialExpected": True,
            "canonicalRoundTripAndNegativeCases": True, "perHandleCleanupClaim": False}
        self.cargo_absence()
        common = ["--frozen", "--offline", "--release", "--target", self.target, "--jobs", "1", "--bin", "mrk-github-seal"]
        release = self.run("helper-release", [self.cargo, "rustc", *common, "--message-format=json"], cwd=self.helper)
        self.binary = self.cargo_artifact(release, test=False)
        self.native["helperExecutable"] = self.macho(self.binary, limit=16 * MIB, cargo_release=True)
        self.cargo_absence()
        test = self.run("helper-native-test-build", [self.cargo, "test", *common, "--no-run", "--message-format=json"], cwd=self.helper)
        executable = self.cargo_artifact(test, test=True)
        self.native["helperTestExecutable"] = self.macho(executable, limit=64 * MIB)
        self.native_tests(executable)

    def native_tests(self, executable):
        # One epoch/capture pool for both separately owned process trees. Never
        # renew it for the denied-policy phase, even after a known first return.
        B.need(not self.provider_mode and self.native_deadline is None
               and self.entered == self.returned == len(ROLE_LIMITS) - 2, "native-pair-admission")
        self.native_deadline = min(self.deadline, time.monotonic() + 10)
        self.native_capture_remaining = QUERY_LIMIT
        phases = []
        for role, phase, closed in NATIVE_PHASES:
            B.remaining(self.native_deadline, time.monotonic(), 10)
            test = self.run(role, [str(executable), NATIVE_TEST, "--exact", "--test-threads=1"])
            text = test.stdout.decode("ascii", "strict")
            lines = [line for line in text.split("\n") if line]
            B.need(test.stderr == b"" and "\r" not in text and len(lines) == 3 and lines[0] == "running 1 test"
                   and lines[1] == "test " + NATIVE_TEST + " ... ok"
                   and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in [0-9]+\.[0-9]+s", lines[2]),
                   "helper-exact-native-test")
            B.remaining(self.native_deadline, time.monotonic(), 10)
            phases.append({"phase": phase, "passed": 1, "nestedOriginalsClosed": closed})
        self.native["helperNativeTest"] = {"passed": 2, "selectedInvocations": 2,
            "failed": 0, "ignored": 0, "filteredUncredited": 4, "phases": phases,
            "returnedWipePaths": True, "framedParentRoundTrip": False,
            "framedBuildParentRoundTrip": True, "nestedOriginalsClosed": 8,
            "positiveFrameSizes": [0, 3, 49152], "actualFrameRefusals": 2,
            "entropyDeviceControlOriginals": 2, "entropyDeviceDenialObserved": True,
            "entropyHelperSignal": 6, "abortReturnedWipeClaim": False,
            "installedDesktopParentQualified": False, "entropyFailureInjected": True}

    def final_sources(self):
        self.phase = "source-and-native-final-post"
        self.selected_post()
        B.need(self.original_source() == self.sodium_source, "canonical-source-final-post")
        B.need(B.tree_rows(self.helper, maximum=MIB, max_files=10, source=True, deadline=self.deadline) == self.helper_source,
               "helper-source-final-post")
        B.need(names(self.helper, 11, self.check) == sorted([name for name in HELPER_PINS if "/" not in name] + ["src"])
               and names(self.helper / "src", 10, self.check) == sorted(name[4:] for name in HELPER_PINS if name.startswith("src/")),
               "helper-source-directory-post")
        self.cargo_absence()
        for name, row in self.generated.items():
            _, original = self.original_bytes(self.private / "build" / name, row["bytes"],
                                               expected=(row["bytes"], row["sha256"]))
            B.need(original == row["identity"], "original-generated-configuration-changed")
        self.recheck_tools(full=True)
        B.need(source_snapshot(self.check) == self.source_binding, "verification-source-final-post")
        self.source_post = True
        self.evidence_json("toolchain.json", {**self.toolchain, "tools": list(self.tools.values()),
            "rustDirectoryRosters": self.runtime_rosters, "sameUidAdversaryIsolation": False})
        self.evidence_json("source-binding.json", {"sourceCommit": self.source, "rows": self.source_binding})
        self.evidence_json("native-tests.json", self.native)
        self.check()
        B.need(self.entered == self.returned == 23, "fixed-recipe-complete")
        self.success_ready = True

    def retain_products(self):
        # Only after all command originals have settled, before retiring their
        # work. Copy through same actual read/write/close/readback primitives.
        self.export = self.work / "export-pending"
        self.export_identity = self.mkdir(self.export)
        helper = self.export / "helper"
        self.export_helper_identity = self.mkdir(helper)
        include = self.export / "include"
        self.mkdir(include)
        self.mkdir(include / "sodium")
        sources = [("helper/mrk-github-seal", self.binary, self.native["helperExecutable"]["bytes"], 0o555),
                   ("libsodium.a", self.library, self.library_pin[0], 0o444),
                   ("LICENSE.libsodium", self.helper / "LICENSE.libsodium", 823, 0o444),
                   ("abi-check.c", self.helper / "abi-check.c", HELPER_PINS["abi-check.c"][0], 0o444)]
        sources.extend(("include/" + name, self.private / "prefix/include" / name, row["bytes"], 0o444)
                       for name, row in self.headers.items())
        total = 0
        for name, path, limit, mode in sources:
            self.check()
            selected = self.selected.get(str(path))
            links = selected["identity"][5] if selected is not None else 1
            if selected is not None:
                B.need(B.identity(path.lstat()) == selected["identity"], "retained-original-identity")
            body = B.read(path, limit, expected_links=links)
            if selected is not None:
                B.need(B.digest(body) == selected["sha256"], "retained-original-content")
            elif path == self.library:
                B.need(B.identity(path.lstat()) == self.library_identity
                       and (len(body), B.digest(body)) == self.library_pin, "retained-static-library-original")
            elif name.startswith("include/"):
                header = self.headers[name[8:]]
                B.need(B.identity(path.lstat()) == header["identity"]
                       and (len(body), B.digest(body)) == (header["bytes"], header["sha256"]),
                       "retained-static-header-original")
            else:
                B.need((len(body), B.digest(body)) == HELPER_PINS[path.relative_to(self.helper).as_posix()],
                       "retained-helper-source-original")
            total += len(body)
            B.need(total <= PUBLIC_BYTES - 32 * MIB, "retained-product-limit")
            self.export_rows[name] = B.write(self.export / name, body, mode)

    def capsule_reserve(self):
        """Prospective SAME-task/output totals, not a second pool or live quota."""
        B.need(self.capsule_mode and self.capsule_purpose in CAPSULE_PURPOSES, "capsule-mode")
        _, limit = CAPSULE_PURPOSES[self.capsule_purpose]
        private = self.census()
        B.need(type(private) is dict and set(private) == {"entries", "bytes"}
               and all(type(private[k]) is int and private[k] >= 0 for k in private)
               and all(type(row) is dict and type(row.get("size")) is int and row["size"] >= 0
                       for row in self.export_rows.values()), "capsule-quote-data")
        # This is the SAME bounded command evidence the old publish path emits.
        # Form it once now so the new copy quote includes its actual bytes.
        self.evidence_json("commands.json", self.commands)
        B.need(len(self.export_rows) + len(self.evidence) + 10 <= WORK_ENTRIES, "capsule-entry-bound")
        parents = {".", "evidence"}
        for name in self.export_rows:
            parts = PurePosixPath(name).parts
            B.need(1 <= len(parts) <= 4 and all(part not in {"", ".", ".."} for part in parts), "capsule-export-path")
            parents.update("/".join(parts[:n]) for n in range(1, len(parts)))
        products = sum(row["size"] for row in self.export_rows.values())
        # All current evidence bodies already exist; leave the full old report
        # bound rather than estimating its yet-unwritten serialization.
        pending_evidence = sum(map(len, self.evidence.values())) + QUERY_LIMIT
        capsule = limit + CAPSULE_RECEIPT_LIMIT
        output = products + pending_evidence + capsule
        entries = private["entries"] + len(self.export_rows) + len(self.evidence) + len(parents) + 6
        B.need(output <= PUBLIC_BYTES and private["bytes"] + output <= WORK_BYTES
               and entries <= WORK_ENTRIES, "capsule-combined-bound")
        B.need(shutil.disk_usage(self.work).free >= pending_evidence + capsule, "capsule-storage")
        self.capsule_reservation = {"bytes": capsule, "combinedBytes": output, "combinedEntries": entries}

    def capsule_parents_post(self):
        self.check()
        B.need(B.custody(self.work.lstat()) == self.work_identity, "capsule-task-original")
        export = self.public if self.export_promoted else self.export
        B.need(B.custody(export.lstat()) == self.export_identity, "capsule-export-original")
        if not self.provider_mode:
            B.need(B.custody((export / "helper").lstat()) == self.export_helper_identity,
                   "capsule-helper-parent-original")
        if self.capsule_identity is not None:
            root = self.capsule_public if self.capsule_promoted else self.capsule_pending
            B.need(B.custody(root.lstat()) == self.capsule_identity, "capsule-directory-original")

    def capsule_products_post(self, *, receipt=False):
        self.capsule_parents_post()
        root = self.capsule_public if self.capsule_promoted else self.capsule_pending
        name, limit = CAPSULE_PURPOSES[self.capsule_purpose]
        wanted = sorted([name, "tool-build-receipt.json"] if receipt else [name])
        B.need(names(root, 2, self.check) == wanted and 0 < self.capsule_pin[0] <= limit,
               "capsule-member-roster")
        path = root / name
        B.need(stat.S_IMODE(path.lstat().st_mode) == 0o555, "capsule-binary-mode")
        self.provider_stream(path, self.capsule_pin, original=self.capsule_copy_identity)
        if receipt:
            path = root / "tool-build-receipt.json"
            B.need(B.identity(path.lstat()) == self.capsule_receipt_identity
                   and stat.S_IMODE(path.lstat().st_mode) == 0o444, "capsule-receipt-original")
            B.read(path, CAPSULE_RECEIPT_LIMIT, expected=self.capsule_receipt_pin)
            B.need(B.identity(path.lstat()) == self.capsule_receipt_identity, "capsule-receipt-original")
        self.capsule_parents_post()

    def capsule_source_post(self):
        self.capsule_parents_post()
        if self.provider_mode:
            self.provider_post(private=not self.provider_private_retired)
        else:
            export = self.public if self.export_promoted else self.export
            self.provider_stream(export / "helper/mrk-github-seal", self.capsule_pin,
                                 original=self.capsule_source_identity)
        B.need(source_snapshot(self.check, provider=self.provider_mode, capsule=True) == self.source_binding,
               "verification-source-final-post")
        self.capsule_parents_post()

    def prepare_capsule(self):
        B.need(self.capsule_mode and self.success_ready and self.failure is None and self.source_post
               and B.DATA.known and not self.inflight, "capsule-work-finality")
        B.need(self.capsule_identity is None and absent(self.capsule_pending) and absent(self.capsule_public),
               "capsule-output-collision")
        self.capsule_reserve()
        name, limit = CAPSULE_PURPOSES[self.capsule_purpose]
        if self.provider_mode:
            path, pin, original = self.provider_original, self.provider_pin, self.provider_identity
        else:
            path = self.export / "helper/mrk-github-seal"
            row = self.export_rows["helper/mrk-github-seal"]
            pin = (row["size"], row["sha256"])
            native = self.native["helperExecutable"]
            B.need(pin == (native["bytes"], native["sha256"]), "capsule-helper-byte-binding")
            original = B.identity(path.lstat())
            self.capsule_source_identity = original
        B.need(type(pin[0]) is int and 0 < pin[0] <= limit, "capsule-binary-bound")
        self.capsule_pin = pin
        self.capsule_identity = self.mkdir(self.capsule_pending)
        self.capsule_parents_post()
        _, _, self.capsule_copy_identity = self.provider_stream(path, pin, original=original,
                                                              destination=self.capsule_pending / name)
        self.capsule_products_post()
        self.capsule_source_post()

    def capsule_receipt(self):
        # These are the checked entry's actual publication identifiers, NOT a
        # claim that the offline provider compiler ran in this GitHub job.
        B.need(self.target in TARGETS and type(self.source) is str
               and re.fullmatch(r"[0-9a-f]{40}", self.source) and self.source != "0" * 40
               and all(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,15}", value)
                       and int(value) <= 9007199254740991
                       for value in (self.run_id, self.attempt)), "capsule-publication-context")
        source = self.evidence["source-binding.json"]
        B.need(source == B.canonical({"sourceCommit": self.source, "rows": self.source_binding}),
               "capsule-full-source-binding")
        value = {"schemaVersion": 1, "kind": "current-tool-build-capsule", "purpose": self.capsule_purpose,
            "target": self.target, "sourceCommit": self.source, "sourceManifestSha256": B.digest(source),
            "binary": {"bytes": self.capsule_pin[0], "sha256": self.capsule_pin[1]}, "notices": None,
            "runId": self.run_id, "runAttempt": self.attempt,
            "sourcePost": True, "originalsClosed": True, "productsFinal": True}
        if self.provider_mode:
            prepared = self.provider_prepared[self.target]
            B.need(prepared["binary"] == value["binary"], "capsule-facts-product")
            capsule_origin(prepared["buildOrigin"])
            value.update(sourceManifestSha256=prepared["sourceManifestSha256"], notices=prepared["notices"],
                         buildOrigin=prepared["buildOrigin"])
        body = B.canonical(value)
        B.need(len(body) <= CAPSULE_RECEIPT_LIMIT, "capsule-receipt-bound")
        return body

    def retire_capsule(self):
        # This path is cleanup of OUR acquired directory only, never discovery
        # of a lost mkdir result or adoption after an unknown close/rename.
        if self.capsule_identity is None or not B.DATA.known:
            return
        self.final_check()
        root = self.capsule_public if self.capsule_promoted else self.capsule_pending
        B.need(B.custody(root.lstat()) == self.capsule_identity, "capsule-directory-original")
        name, limit = CAPSULE_PURPOSES[self.capsule_purpose]
        for member in names(root, 2, self.check):
            B.need(member in {name, "tool-build-receipt.json"}, "capsule-member-roster")
            info = (root / member).lstat()
            B.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                   and 0 <= info.st_size <= (limit if member == name else CAPSULE_RECEIPT_LIMIT),
                   "capsule-cleanup-member")
        B.retire_tree(root, self.cleanup_deadline)
        self.capsule_identity = None

    def publish_capsule(self, passed):
        verdict = self.guard.lifetime_ledger.verdict()
        B.need(passed is True and self.success_ready and self.source_post and not self.inflight
               and self.entered == self.returned == len(self.role_limits)
               and B.public_eligible(failure=self.failure, entered=self.entered, returned=self.returned,
                   ledger={"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained},
                   handlers=self.guard.handler_state, scratch_retired=self.scratch_retired, data_finality=B.DATA.known),
               "capsule-original-finality")
        self.capsule_source_post()
        self.capsule_products_post()
        body = self.capsule_receipt()
        path = self.capsule_pending / "tool-build-receipt.json"
        row = B.write(path, body, 0o444)
        self.capsule_receipt_pin = (row["size"], row["sha256"])
        self.capsule_receipt_identity = B.identity(path.lstat())
        self.capsule_products_post(receipt=True)
        self.capsule_source_post()
        B.need(sum(row["size"] for row in self.export_rows.values()) + self.capsule_pin[0] + len(body) <= PUBLIC_BYTES,
               "capsule-combined-bound")
        self.final_check()
        B.need(absent(self.capsule_public), "capsule-output-collision")
        try:
            self.capsule_pending.rename(self.capsule_public)
        except BaseException:
            B.DATA.unknown()
            raise
        self.capsule_promoted = True
        self.capsule_products_post(receipt=True)
        self.capsule_source_post()
        self.final_check()
        B.need(absent(self.capsule_pending) and absent(self.private), "capsule-finality")

    def cleanup(self):
        verdict = self.guard.lifetime_ledger.verdict()
        B.need(B.DATA.known and not self.inflight and verdict.complete and not verdict.fatal and verdict.contained,
               "original-command-finality-unknown")
        self.cleaning = True
        self.cleanup_deadline = min(self.deadline + CLEANUP_SECONDS, time.monotonic() + CLEANUP_SECONDS)
        if self.work_identity is None:
            # No admitted mkdir means no path lookup can acquire a cleanup grant.
            B.need(absent(self.work), "unadmitted-task-custody")
            self.scratch_retired = True
            return
        B.need(B.custody(self.work.lstat()) == self.work_identity, "original-task-root-changed")
        if self.provider_mode and self.provider_ready:
            self.provider_post()
        capsule_error = None
        if self.failure is None and self.success_ready:
            if self.provider_mode:
                self.export = self.work / "export-pending"
                self.export_identity = self.mkdir(self.export)  # Evidence only; capsule is a separate sibling.
            else:
                self.retain_products()
            if self.capsule_mode:
                try:
                    self.prepare_capsule()
                except BaseException as error:
                    capsule_error = error
                    if not B.DATA.known:
                        raise  # Unknown copy/open/close grants no further retirement.
        try:
            if self.private_identity is not None:
                self.census()  # Enforce our tighter 8192/512MiB before the donor retire.
                for name in (() if self.provider_mode else LIBTOOL_ARCHIVES):
                    alias = self.private / "build/src/libsodium/.libs" / name
                    if name in self.libtool_alias_originals:
                        self.libtool_alias(alias, retire=True)
                    else:
                        B.need(absent(alias), "unadmitted-generated-alias")
                B.retire_tree(self.private, self.cleanup_deadline)
            self.scratch_retired = True
            if self.capsule_mode and self.provider_mode and self.provider_ready:
                self.provider_private_retired = True  # Only after the actual retire_tree returned and its POST passed.
            if capsule_error is not None:
                self.retire_capsule()
                # This export was positively acquired before capsule work. It
                # cannot remain at the old failed-report destination, nor may
                # a path lookup adopt an interrupted/unreturned mkdir result.
                B.need(B.DATA.known and not self.export_promoted and self.export_identity is not None
                       and B.custody(self.export.lstat()) == self.export_identity,
                       "capsule-export-original")
                B.retire_tree(self.export, self.cleanup_deadline)
                self.export_identity = self.export_helper_identity = None
                self.export_rows.clear()
        except BaseException as cleanup_error:
            if capsule_error is not None:
                raise capsule_error from cleanup_error
            raise
        if capsule_error is not None:
            raise capsule_error

    def publish(self, verdict):
        self.final_check()
        if not self.success_ready or self.failure is not None:
            self.export = self.work / "export-pending"
            self.export_identity = self.mkdir(self.export)
        evidence = self.export / "evidence"
        self.mkdir(evidence)
        if not (self.capsule_mode and "commands.json" in self.evidence):
            self.evidence_json("commands.json", self.commands)
        passed = B.public_eligible(failure=self.failure, entered=self.entered, returned=self.returned,
            ledger={"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained},
            handlers=self.guard.handler_state, scratch_retired=self.scratch_retired, data_finality=B.DATA.known)
        passed = passed and self.success_ready and self.entered == len(self.role_limits)
        report = {"schemaVersion": 1, "kind": "macos-github-seal-build-v1", "sourceCommit": self.source,
            "runId": self.run_id, "runAttempt": self.attempt, "target": self.target,
            "status": "passed" if passed else "failed", "transportState": "pending-original-entry-exit",
            "originalCallsEntered": self.entered, "originalCallsReturned": self.returned,
            "originalLedger": {"complete": verdict.complete, "fatal": verdict.fatal, "contained": verdict.contained},
            "handlers": self.guard.handler_state, "dataFinalityKnown": B.DATA.known,
            "scratchRetired": self.scratch_retired, "failure": self.failure, "cleanupErrors": self.cleanup_errors,
            "sourcePost": self.source_post,
            "sourceSha256": B.digest(B.canonical(self.source_binding)), "sourceCount": len(self.source_binding),
            "products": self.export_rows, "officialArchiveSha256": ARCHIVE_PIN[1],
            "officialSignatureVerified": False, "packagedHelperQualified": False,
            "framedParentRoundTripQualified": False, "nativeTests": self.native if passed else None,
            "evidence": {name: {"bytes": len(body), "sha256": B.digest(body)} for name, body in self.evidence.items()}}
        if self.provider_mode:
            report.update(kind="macos-history-provider-probe-v1", packagedProviderQualified=False,
                authenticatedHistoryQualified=False, embeddedNoticesComplete=True,
                noticeContentRuntimeExecuted=False, providerNotices=PROVIDER_NOTICE_PINS,
                providerBinary={"bytes": PROVIDER_PINS[self.target][0], "sha256": PROVIDER_PINS[self.target][1]},
                crossbuildRecord=PROVIDER_CROSSBUILD_PIN, sourceManifest=PROVIDER_SOURCE_PIN)
            if self.capsule_mode:
                del report["crossbuildRecord"]
                report["preparedFacts"] = PROVIDER_FACTS_PINS
            for name in ("officialArchiveSha256", "officialSignatureVerified", "packagedHelperQualified",
                         "framedParentRoundTripQualified", "nativeTests"):
                del report[name]
        body = B.canonical(report)
        B.need(len(body) <= QUERY_LIMIT, "report-bound")
        self.export_rows["report.json"] = B.write(self.export / "report.json", body, 0o444)
        for name, data in self.evidence.items():
            self.final_check()
            self.export_rows["evidence/" + name] = B.write(evidence / name, data, 0o444)
        B.need(sum(row["size"] for row in self.export_rows.values()) <= (MIB if self.provider_mode else PUBLIC_BYTES),
               "public-export-bound")
        for name, row in self.export_rows.items():
            self.final_check()
            B.read(self.export / name, row["size"], expected=(row["size"], row["sha256"]))
        self.final_check()
        B.need(absent(self.public), "public-export-collision")
        try:
            self.export.rename(self.public)
        except BaseException:
            B.DATA.unknown()
            raise
        self.export_promoted = True
        self.final_check()
        B.need(absent(self.export) and absent(self.private), "public-and-scratch-finality")
        if self.capsule_mode and passed:
            self.publish_capsule(passed)

    def execute(self):
        scope = self.control.CleanupScope(self.guard, self.cleanup, owns_cancellation=True, first_primary=True)
        caught = capsule_cleanup_error = None
        try:
            try:
                with scope:
                    self.guard.install()
                    self.guard.activate()
                    try:
                        if self.provider_mode:
                            self.prepare_provider()
                        else:
                            self.prepare()
                            self.sources()
                            self.build_sodium()
                            self.probes_and_helper()
                            self.final_sources()
                    except BaseException as error:
                        self.failure = {"phase": self.phase, "type": type(error).__name__,
                            "reason": str(error) if type(error) is B.BuildRefused else "original-operation-failed"}
                        raise
            finally:
                scope.__exit__(*sys.exc_info())
        except BaseException as error:
            caught = error
            if self.failure is None:
                self.failure = {"phase": "cleanup", "type": type(error).__name__, "reason": "original-cleanup-failed"}
        self.cleanup_errors = [type(error).__name__ for error in scope._cleanup_errors]
        if caught is not None and self.capsule_mode:
            try:
                self.retire_capsule()
            except BaseException as error:
                capsule_cleanup_error = error
                self.cleanup_errors.append(type(error).__name__)
        verdict = self.guard.lifetime_ledger.verdict()
        settled = B.DATA.known and not self.inflight and verdict.complete and not verdict.fatal and verdict.contained
        settled = settled and self.guard.handler_state == "RESTORED" and self.scratch_retired
        # No guessed/adopted cleanup and no publication while custody is unknown.
        if settled and self.work_identity is not None:
            try:
                self.publish(verdict)
            except BaseException as publication_error:
                if self.capsule_mode:
                    try:
                        self.retire_capsule()
                    except BaseException as retirement_error:
                        if caught is not None:
                            raise caught from retirement_error
                        raise publication_error from retirement_error
                if caught is not None:
                    raise caught from publication_error
                raise
        if caught is not None:
            if capsule_cleanup_error is not None:
                raise caught from capsule_cleanup_error
            raise caught
        B.need(settled and self.success_ready, "complete-build-original-finality")


def main():
    global _DIAGNOSTIC_STAGE, _DIAGNOSTIC_BUILD
    started = time.monotonic()
    _DIAGNOSTIC_STAGE = "target"
    target = os.environ.get("MRK_SEAL_TARGET", "")
    argv, reference = sys.argv[1:], os.environ.get("GITHUB_REF", "")
    capsule = capsule_mode(argv, reference)
    provider = probe_mode(argv[:-1] if capsule else argv, reference)
    need(target in TARGETS, "fixed-seal-target")
    machine, runner_arch, _, _, _ = TARGETS[target]
    _DIAGNOSTIC_STAGE = "host"
    need(sys.platform == "darwin" and os.uname().machine == machine and platform.mac_ver()[0].startswith("26.")
         and sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(), "fixed-seal-native-host")
    _DIAGNOSTIC_STAGE = "run"
    source, run, attempt = (os.environ.get(key, "") for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    need(re.fullmatch(r"[0-9a-f]{40}", source) and source != "0" * 40
         and all(re.fullmatch(r"[1-9][0-9]{0,15}" if capsule else r"[1-9][0-9]{0,19}", value)
                 and (not capsule or int(value) <= 9007199254740991)
                 for value in (run, attempt)), "fixed-seal-run")
    _DIAGNOSTIC_STAGE = "context"
    reference = PROVIDER_REFERENCE if provider else REFERENCE
    route = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": runner_arch, "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": reference, "GITHUB_WORKFLOW_SHA": source, "GITHUB_JOB": "seal-build",
        "GITHUB_WORKFLOW_REF": REPOSITORY + "/" + WORKFLOW + "@" + reference,
        "GITHUB_WORKSPACE": str(CHECKOUT), "RUNNER_TEMP": str(WORK_PARENT), "DEVELOPER_DIR": str(DEVELOPER)}
    need(all(os.environ.get(key) == value for key, value in route.items()), "fixed-seal-workflow-context")
    _DIAGNOSTIC_STAGE = "python-entry"
    python_binding = python_entry_binding(os.environ.get("MRK_SEAL_PYTHON"), sys.executable)
    _DIAGNOSTIC_STAGE = "bootstrap"
    bootstrap_builder()
    _DIAGNOSTIC_STAGE = "detached"
    B.need(B.read(CHECKOUT / ".git/HEAD", 41) == source.encode("ascii") + b"\n", "fixed-detached-source")
    _DIAGNOSTIC_STAGE = "limits"
    resource_limits = limits()
    os.umask(0o077)
    check = lambda: B.remaining(started + WORK_SECONDS, time.monotonic(), WORK_SECONDS)
    _DIAGNOSTIC_STAGE = "source-snapshot"
    before = source_snapshot(check, provider=provider, capsule=capsule)
    tools = CHECKOUT / "desktop/tools"
    _DIAGNOSTIC_STAGE = "macho-load"
    orchestration = B.load_module("_mrk_seal_existing_macho", tools / "macos_cpython_orchestrator.py")
    B.need(orchestration._BUILD is None, "existing-parser-unbound")
    orchestration._BUILD = B  # SAME actual DATA ledger; no CPython context call.
    _DIAGNOSTIC_STAGE = "probe-load"
    probe = B.load_module("_mrk_seal_existing_probe", tools / "macos_cpython_source_probe.py")
    _DIAGNOSTIC_STAGE = "qualification-load"
    qualification = B.load_module("_mrk_seal_existing_qualification", tools / "macos_aqua_qualification.py")
    _DIAGNOSTIC_STAGE = "owner-load"
    owner = qualification.load_owner(CHECKOUT)
    _DIAGNOSTIC_STAGE = "cancellation-load"
    from mobile_release import cancellation
    _DIAGNOSTIC_STAGE = "build-init"
    build = SealBuild(target=target, source=source, run=run, attempt=attempt, owner=owner,
        control=cancellation, orchestration=orchestration, probe=probe, started=started,
        python_binding=python_binding, provider=provider, capsule=capsule)
    build.resource_limits, build.source_binding = resource_limits, before
    _DIAGNOSTIC_BUILD = build
    _DIAGNOSTIC_STAGE = "build-execute"
    build.execute()


if __name__ == "__main__":
    preparing = len(sys.argv) == 3 and sys.argv[1] == "--prepare-hosted-python"
    try:
        if preparing:
            prepare_hosted_python(sys.argv[2])
        else:
            main()
    except BaseException as error:
        # No exception payload, environment, path or secret material is printed.
        print(failure_diagnostic(error), file=sys.stderr)
        print("Canonical seal build refused; only finalized public evidence is eligible for retention.", file=sys.stderr)
        raise SystemExit(1) from None
    print("Hosted Python executable mode prepared; native build remains unexecuted." if preparing else
          "History provider probes returned; packaging and authenticated History remain separate."
          if sys.argv[1:] in (["--history-provider-probe"], ["--history-provider-probe", CAPSULE_MODIFIER]) else
          "Canonical seal native tests returned; packaging and the framed parent integration remain separate.")
