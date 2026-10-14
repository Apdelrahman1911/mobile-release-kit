#!/usr/bin/env python3
"""Closed DATA projection for verification artifacts, never native acceptance.

Original receipts/captures remain local and authoritative to their existing
validators. This script reads only the fixed roster below. Bounded exceptions
to tool-output exclusion are the <=128-byte compile-fixed producer refusal token
and two <=65536-byte original pkgutil preambles, joined to their failed original
calls and projected only to finite diagnostics. Two fixed <=256KiB Installer
log metadata/selected originals are joined to the failed original and projected
only to fixed markers/hashes, never line text. No raw output fallback,
source-binding.json, private native reports, credentials or directory listings
are read.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
import time

OUTPUT = "public-verification-evidence.json"
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
PHASES = (
    "prepare", "verify-before", "verify-after", "sign-vault-helper", "sign-desktop-image",
    "sign-desktop-payload", "sign-root-app", "sign-root-installer", "sign-remover",
    "notarize-payload", "finalize-package", "package-install", "finalize-image",
    "finalize-remove-package", "package-remove", "finalize-remove-image",
    "prepare-removal-observers", "package-removal-fixture", "same-package-noop", "update-baseline",
)
PHASE_STATUS = {
    "update-baseline": "update-baseline.status",
    "same-package-noop": "same-package-noop.status",
    "finalize-package": "package-finalization.status", "package-install": "package-install.status",
    "finalize-image": "image-finalization.status", "finalize-remove-package": "remove-package-finalization.status",
    "package-remove": "package-remove.status", "finalize-remove-image": "remove-image-finalization.status",
    "prepare-removal-observers": "removal-observers.status", "package-removal-fixture": "package-removal-fixture.status",
}
# These are scalar original statuses, not transcript/JSONL/suffix discovery.
STATUS_FILES = (
    "vault-helper-build.status", "android-helper-build.status", "normal-build.status", "observer-build.status",
    "remover-build.status", "removal-observer-build.status", "package-format-tar.status", "package-format-xar.status",
    "package-tar.status", "package-xar.status", "remove-package-tar.status", "remove-package-xar.status",
    "installer-output.status", "installer-log-cursor.status", "installer-log-capture.status",
    *PHASE_STATUS.values(), "normal-ui/build.status", "normal-ui/test.status", "normal-ui/summary.status",
    "normal-ui/android-inputs.status", "normal-ui/android-signed-build-test.status",
    "normal-ui/android-signed-build-summary.status", "normal-ui/android-signed-build-result.status",
    "normal-ui/ios-unsigned-archive-test.status", "normal-ui/ios-unsigned-archive-summary.status",
    "normal-ui/ios-pending-recovery-test.status", "normal-ui/ios-pending-recovery-summary.status",
    *("normal-ui/" + role + suffix for role in ("project", "persistence", "diagnostics", "saved-checks",
      "saved-version-recovery", "github-local-bundle", "removal-ordinary") for suffix in ("-test.status", "-summary.status")),
    "normal-ui/workflow-refusal-test.status", "normal-ui/workflow-refusal-summary.status",
    "normal-ui/release-evidence-test.status", "normal-ui/release-evidence-summary.status",
    *("aqua-" + role + ".status" for role in ("project-fields", "android-inputs", "local-edits3", "doctor-preflight2",
      "vault-helper", "installation-inspection", "project-recovery", "ios-account")), "aqua.status",
    "headless-build.status", "headless-tests.status", "headless-native-tests.status",
    "data-contracts/mount.status", "data-contracts/apfs.status", "data-contracts/build.status",
    "data-contracts/rust.status", "data-contracts/python.status",
    *("wrapping-" + role + "-build.status" for role in ("codec", "normal", "observer", "qualification", "reader")),
)
REMOVAL_ROLE_PREFIX = ("removal-target-attach", "removal-observers-attach", "removal-observer-before")
REMOVAL_ROLE_SUFFIX = ("removal-observer-terminal", "removal-observers-detach", "removal-target-detach")
REMOVAL_ROLES = {case: REMOVAL_ROLE_PREFIX + middle + REMOVAL_ROLE_SUFFIX for case, middle in (
    ("ordinary", ("removal-live-cancel", "removal-observer-after-cancel", "removal-live-continue")),
    ("abrupt", ("removal-live-cut", "removal-observer-after-cut", "removal-resume")))}
REMOVAL_METHODS = {"ordinary": "testInstalledRemovalCancelThenContinue", "abrupt": "testInstalledRemovalContinueBeforeInterruption"}
REMOVAL_RELEASE = "macos26-arm64-desktop-01"
NATIVE_ROLES = frozenset((
    "update-baseline-attach", "update-baseline-installer", "update-baseline-detach",
    *REMOVAL_ROLES["ordinary"], *REMOVAL_ROLES["abrupt"],
    "resident-fetch", "build", "resident-image-sign", "resident-image-verify-signed", "entry-build", "desktop-facade-build",
    "resident-facade-build", "sign", "verify-signed", "verify-before", "verify-after",
    "verify-before-resident-image", "verify-after-resident-image", "verify-before-history-provider", "verify-before-github-seal",
    "verify-after-history-provider", "verify-after-github-seal", "resolve-notarytool", "resolve-stapler",
    "verify-inner-before", "verify-outer-before", "payload-zip", "payload-submit", "payload-log",
    "staple-inner", "validate-inner", "staple-outer", "validate-outer", "verify-inner-after", "verify-outer-after",
    "producer-tests", "producer-build", "producer-emitter", "distribution-create", "distribution-sign", "distribution-verify-signature",
    "distribution-verify-image", "observation-create", "observation-sign", "observation-verify-signature",
    "observation-verify-image", "distribution-attach", "installer-log-cursor", "installer", "installer-log-capture",
    "distribution-detach", "final-package-productbuild",
    *(phase + suffix for phase in PHASES if phase.startswith("sign-") for suffix in ("", "-verify")),
    *("final-image-" + role for role in ("resolve-notarytool", "resolve-stapler", "signature-before", "submit", "log",
      "staple", "validate", "signature-after", "verify", "attach", "detach", "policy-status", "policy-assess")),
    *("final-package-" + role for role in ("resolve-notarytool", "resolve-stapler", "sign", "signature-before", "submit",
      "log", "staple", "validate", "signature-after")),
))
CREDENTIAL_ROLES = frozenset((
    "search-before", "default-before", "create", "search-created", "settings", "unlock", "import", "partitions",
    "identity", "certificates", "search-admit", "restrict", "search-restricted", "search-after-callback", "restore",
    "search-restored", "delete", "default-after", "search-final", "producer-adhoc", "producer-adhoc-verify",
    "producer-cdhash", "installer-chain",
))
PURPOSES = frozenset((*PHASES, "installer", "producer", "distribution-image", "observation-image",
    "python", "resident-image", "helper", "observer-program"))
OWNER_REASONS = frozenset(("output-bound", "deadline", "protocol-or-original-ownership", "original-parent-ended",
    "cleanup-unconfirmed", "failed-timeout-or-incomplete-output", "exec-rejected", "stopped-before-execution",
    "incomplete-output", "unclassified"))
FAILURE_TYPES = frozenset(("Refused", "OSError", "ValueError", "TypeError", "RuntimeError", "AssertionError",
    "MemoryError", "RecursionError", "UnicodeError", "JSONDecodeError", "KeyboardInterrupt", "SystemExit",
    "ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown", "Incomplete"))

# Fixed first-failing post-staple facts only; never native/finality authority.
FINAL_IMAGE_UNLINK_FLAGS = ('retainedPreIdentityExpected', 'retainedPreLinkUnlinked', 'namedExists', 'namedSameDevice', 'namedRegular', 'namedModeExpected', 'namedOwnerExpected', 'namedGroupExpected', 'namedSingleLink', 'namedSizeBounded', 'namedGrowthBounded', 'namedInodeDifferent', 'heldNameIdentityDifferent', 'parentStable', 'censusStable', 'retainedPreBytesUnchanged', 'namedPostStable')
FINAL_IMAGE_STAPLE_STAGES = ('final-image-staple-clock', 'final-image-staple-parent', 'final-image-staple-held-stat', 'final-image-staple-held-device', 'final-image-staple-held-inode', 'final-image-staple-held-mode', 'final-image-staple-held-links', 'final-image-staple-held-links-unlinked', 'final-image-staple-held-links-other', 'final-image-staple-held-uid', 'final-image-staple-held-gid', 'final-image-staple-size', 'final-image-staple-growth', 'final-image-staple-name-stat', 'final-image-staple-binding', 'final-image-staple-xattr-query', 'final-image-staple-xattrs-present', 'final-image-staple-stream', 'final-image-staple-post', 'final-image-staple-returned-input', 'final-image-staple-returned-preimage', 'final-image-staple-returned-name', 'final-image-staple-returned-acquire', 'final-image-staple-returned-stream', 'final-image-staple-returned-commit')
FINAL_IMAGE_STAPLE_REASONS = frozenset(('final-image-stapled-original', 'file-extended-attributes-query', 'file-extended-attributes', 'notary-monotonic-clock', 'directory-original-unavailable', 'directory-parent-changed', 'directory-original-unbound', 'directory-original-changed', 'notary-zip-original', 'notary-zip-short-read', 'notary-zip-post', 'final-image-directory-census', 'final-image-input-changed', 'final-image-output-changed', 'final-image-target-census', 'final-package-preimage-unavailable', 'final-package-preimage-metadata', 'final-package-preimage-short-read', 'final-package-preimage-content', 'final-package-preimage-post'))

FINAL_IMAGE_INPUT_STAGES = (
    'final-image-original-inputs',
    'final-image-package-owner',
    'final-image-original-readback',
    'final-image-package-audit',
    'final-image-producer',
    'final-image-source-profiles',
    'final-image-original-image',
)
FINAL_IMAGE_INPUT_STAGER_REASONS = frozenset((
    'build-release-identity',
    'build-release-shape',
    'build-release-size',
    'build-release-version',
    'build-target',
    'duplicate-json-key',
    'installer-export-byte-bound',
    'json-byte-bound',
    'json-constant',
    'json-shape-bound',
    'maintenance-export-action',
    'maintenance-export-binding',
    'maintenance-export-shape',
    'maintenance-policy-binding',
    'maintenance-policy-digest-or-order',
    'maintenance-policy-membership',
    'maintenance-policy-row',
    'maintenance-policy-shape',
    'maintenance-predecessor-order',
    'maintenance-producer-binding',
    'maintenance-producer-shape',
    'maintenance-record-byte-bound',
    'maintenance-record-encoding-or-shape',
    'maintenance-record-map',
    'maintenance-release-binding',
    'maintenance-release-set-bound',
    'maintenance-release-set-shape',
    'maintenance-release-shape',
    'maintenance-request-id',
    'maintenance-reused-release-identity',
    'maintenance-signing-policies-bound',
    'maintenance-write-accounting',
    'producer-emitter-original',
    'producer-emitter-package-binding',
    'producer-emitter-summary',
    'registration-reservation-creation-incomplete',
    'registration-reservation-not-predecessor-creation',
    'registration-reservation-parent-not-settled',
    'registration-reservation-result',
    'registration-reservation-reuse-not-observed',
    'registration-reservation-unentered',
    'source-producer-correspondence',
    'source-producer-profile',
    'source-producer-unconfigured',
    'source-service-profile',
))

# Closed first-failed metadata attribution; no dynamic role/path rendering.
FINAL_IMAGE_VERIFY_FIELDS = ("device", "inode", "mode", "links", "uid", "gid", "size", "mtime", "ctime")
FINAL_IMAGE_VERIFY_OBJECTS = ("output", *("input-%02d" % index for index in range(14)))
FINAL_IMAGE_VERIFY_STAGES = frozenset(
    "final-image-verify-%s-%s-%s" % (object_label, boundary, field)
    for object_label in FINAL_IMAGE_VERIFY_OBJECTS for boundary in ("held", "named")
    for field in FINAL_IMAGE_VERIFY_FIELDS)

STAGES = frozenset((*FINAL_IMAGE_VERIFY_STAGES, "final-image-readonly-seal", *FINAL_IMAGE_STAPLE_STAGES, *PHASES, *NATIVE_ROLES, *FINAL_IMAGE_INPUT_STAGES, "owned-directory-admission", "source-image-binding",
    "resident-dependency-fetch", "separate-resident-image-compiler", "compiler-original-copy", "resident-image-source-selected-signing",
    "fixed-installed-entry-compiler", "desktop-facade-compiler", "resident-facade-compiler",
    "helper-source-selected-signing", "notary-preflight-input", "notary-known-private-retirement", "final-image-owned-publication",
    "final-package-signed-output", "final-package-mode-and-publication", "install-product-original-adoption",
    "final-package-original-audit",
    "package-final-audit", "package-producer-tests", "package-explicit-producer-compiler", "package-producer-emission",
    "package-readonly-attach", "standard-original-installer", "package-nonroot-v2-readback"))
# Fixed current pre-first-original notary guards; never a dynamic reason prefix.
NOTARY_ADMISSION_REASONS = frozenset((
    'notary-copy-failed-rename-post',
    'notary-copy-parent-mode',
    'notary-copy-parent-original',
    'notary-copy-parent-restore',
    'notary-copy-post',
    'notary-copy-rename-original',
    'notary-copy-rename-post',
    'notary-copy-sealed-directories',
    'notary-fixed-tool',
    'notary-io-unknown',
    'notary-key-original-changed',
    'notary-original-close-unknown',
    'notary-original-depth',
    'notary-original-directory-post',
    'notary-original-file',
    'notary-original-node-bound',
    'notary-original-open-changed',
    'notary-original-path',
    'notary-payload-post',
    'notary-post-unknown',
    'notary-selected-tool-ancestry',
    'notary-selected-tool-changed',
    'notary-selected-tool-original',
    'notary-selected-tool-path',
    'notary-source-post',
    'notary-stager-original-correspondence',
    'notary-stager-original-roster',
    'notary-work-volume-reserve',
    'notary-zip-sha256-changed',
))
INSTALL_PRODUCT_AUDIT_REASONS = frozenset((
    'complete-root-owned-scripts-correspondence',
    'fixed-install-product-purpose',
    'install-product-component',
    'install-product-distribution',
    'install-product-readme',
    'install-product-source-bound',
    'install-product-source-version',
    'install-product-xar-bound',
    'install-product-xar-checksum',
    'install-product-xar-count',
    'install-product-xar-data',
    'install-product-xar-directory',
    'install-product-xar-duplicate',
    'install-product-xar-encoding',
    'install-product-xar-file',
    'install-product-xar-header',
    'install-product-xar-id',
    'install-product-xar-member-checksum',
    'install-product-xar-metadata',
    'install-product-xar-metadata-tags',
    'install-product-xar-finder-shape',
    'install-product-xar-finder-time',
    'install-product-xar-finder-nanoseconds',
    'install-product-xar-scalar-shape',
    'install-product-xar-inode-value',
    'install-product-xar-deviceno-value',
    'install-product-xar-name',
    'install-product-xar-range',
    'install-product-xar-roster',
    'install-product-xar-size',
    'install-product-xar-toc',
    'install-product-xml',
))


FINAL_PACKAGE_POST_REASONS = frozenset((
    'final-package-ticket-transition-state',
    'final-package-preimage-unavailable',
    'final-package-preimage-metadata',
    'final-package-preimage-short-read',
    'final-package-preimage-content',
    'final-package-preimage-post',
    'final-package-preimage-transition',
    'final-package-returned-shape',
    'final-package-returned-acquisition',
    'final-package-returned-binding',
    'final-package-ticket-binding',
    'final-package-ticket-metadata',
    'final-package-ticket-growth',
    'final-package-ticket-short-read',
    'final-package-signed-prefix-changed',
    'final-package-ticket-eof',
    'final-package-ticket-fd-post',
    'final-package-ticket-name-post',
    'final-package-directory-census',
    'final-package-input-changed',
    'final-package-output-changed',
    'final-package-target-census',
    'final-package-original-settlement-reserve',
    'final-package-fixed-role-order',
    'final-package-private-role',
    'final-package-original-bound',
))


DISTRIBUTION_STAGER_REASONS = frozenset(('distribution-attach-original', 'distribution-attach-plist', 'distribution-attach-entity', 'distribution-attach-mount', 'distribution-attach-single-mount', 'distribution-package-name', 'distribution-three-file-roster', 'distribution-original-byte-mode'))

REASONS = frozenset((*FINAL_IMAGE_STAPLE_REASONS, *DISTRIBUTION_STAGER_REASONS, *FINAL_IMAGE_INPUT_STAGER_REASONS,"producer-tests-bound", "producer-tests-framing", "producer-tests-roster", "producer-tests-result",
    "original-nonzero-producer-tests", *FINAL_PACKAGE_POST_REASONS, *INSTALL_PRODUCT_AUDIT_REASONS, "notary-key-purpose", "notary-key-input", "notary-key-base64", "notary-key-pem-shape",
    *NOTARY_ADMISSION_REASONS, "notary-submission-invalid", "notary-authentication-not-retired", "notary-group-deadline",
    "notary-group-hard-deadline", "notary-final-input-result", "notary-private-key-retained", "original-return-contract",
    "original-operation-refused", "helper-package-incomplete", "package-finality-incomplete",
    "package-signature-bound", "package-signature-utf8", "package-signature-format", "package-signature-header",
    "package-signature-trust-timestamp", "package-signature-chain-order", "package-signature-chain-format",
    "package-signature-fingerprint-repeated", "package-signature-fingerprint-position", "package-signature-fingerprint-bound",
    "package-signature-expiry-repeated", "package-signature-source-chain", "package-signature-source-fingerprint",
    "notary-submit-terminal", "notary-submit-metadata", "notary-submit-archive", "notary-uuid",
    # Fixed transport/held-parent SOURCE guards; diagnostic observations only.
    'package-mount-host-admission', 'package-mount-host-source', 'package-mount-host-source-post',
    'package-transport-automounted', 'package-transport-context', 'package-transport-detach-original',
    'package-transport-host-original', 'package-transport-host-unavailable', 'package-transport-mounted-namespace',
    'package-transport-one-admission', 'package-transport-original-device', 'package-transport-original-mount',
    'removal-bounded-roster', 'removal-directory-facts-changed', 'removal-directory-flags',
    'removal-directory-named-held', 'removal-directory-original', 'removal-directory-post',
    'removal-fixed-name-collision', 'removal-local-filesystem', 'removal-original-control-pool',
    'removal-original-empty-acl', 'removal-original-headroom', 'removal-protected-apfs',
    'removal-protected-owner', 'removal-readonly-filesystem', 'removal-roster-original',
    'removal-roster-post', 'removal-roster-previous-unknown',
))
REASON_CATEGORIES = (
    ("notary-key-", "notary-authentication"), ("notary-profile-", "notary-profile"),
    ("notary-json-", "notary-schema"), ("notary-log-", "notary-log"),
    ("notary-submission-", "notary-submission"), ("notary-submit-", "notary-submission"),
    ("notary-ticket-", "notary-ticket"), ("notary-tool-", "notary-tool"),
    ("notary-", "notary-refused"), ("final-package-", "final-package-refused"),
    ("final-image-", "final-image-refused"), ("credential-", "credential-refused"),
)
BOOL_FIELDS = ("targetRetired", "originalClosesKnown", "outerFinalityRequired")
CALL_BOOLS = ("entered", "returned", "capturesSettled", "dispatched", "contained", "cleanup_complete", "settled")
FINAL_BOOLS = ("sha256Compared", "strictVerificationBeforeAndAfter", "actualStaplerValidation",
    "trustedSignatureBeforeAndAfter", "trustedTimestampBeforeAndAfter", "signedPrefixUnchanged", "completeScriptsAudited",
    "strictSignatureBeforeAndAfter", "actualImageVerification", "finalMountReadOnly", "finalMountOriginalsMatch",
    "originalMountDetached", "assessmentSubsystemEnabledBefore", "actualDiskImagePolicyAssessment")
FINAL_HASHES = ("logSha256", "archiveSha256", "inventorySha256", "runtimeManifestSha256", "unsignedSha256",
    "signedSha256", "packageSha256", "originalPackageSha256", "packageInfoSha256", "installerProfileSha256",
    "notaryProfileSha256", "descriptorSha256", "signatureSha256", "producerProfileSha256", "serviceProfileSha256",
    "originalImageSha256", "submittedSha256", "imageSha256", "packageInstallReceiptSha256", "packageRemoveReceiptSha256",
    "finalPackageReceiptSha256")
FINAL_SIZES = ("archiveBytes", "unsignedBytes", "signedBytes", "packageBytes", "descriptorBytes", "signatureBytes",
    "originalImageBytes", "imageBytes")
SUMMARY_HASHES = ("packageSha256", "runtimeManifestSha256", "distributionSha256", "descriptorSha256", "signatureSha256",
    "finalImageReceiptSha256", "originalDistributionSha256", "installerInventorySha256", "normalBinaryBeforeSigningSha256",
    "desktopImageBeforeSigningSha256", "signedDesktopImageSha256", "signedResidentImageSha256", "signedAppBinarySha256",
    "signedEntryBinarySha256", "installedProducerSha256", "inventorySha256", "removerExecutableSha256",
    "finalPackageReceiptSha256", "packageRemoveReceiptSha256")
SUMMARY_BOOLS = ("originalInstallerReturnedZero", "originalPackageGroupReturnedZero", "originalObservationMountDetached",
    "originalImageFinalizationReturnedZero", "originalFinalImageMountDetached", "finalImageScopedNotarizationObserved",
    "originalPackageFinalizationReturnedZero", "originalPackageRemoveReturnedZero", "removalExecuted",
    "installedAppLaunchedByRemovalRoute", "distributionQualified", "productReady")
IOS_UNSIGNED_DIAGNOSTIC = "normal-ui/ios-unsigned-archive-test.failure-diagnostics.json"
IOS_UNSIGNED_SELECTION = "ios-unsigned-archive-test.xcresult"
IOS_PENDING_DIAGNOSTIC = "normal-ui/ios-pending-recovery-test.failure-diagnostics.json"
IOS_PENDING_SELECTION = "ios-pending-recovery-test.xcresult"
IOS_PENDING_METHOD = "testInstalledIOSPendingAccountRecoveryThroughUI"
IOS_UNSIGNED_METHOD = "testSyntheticProjectUnsignedIOSArchive"
IOS_UNSIGNED_STAGES = ("ios-unsigned-fixture", "ios-unsigned-launch", "ios-unsigned-project",
    "ios-unsigned-review", "ios-unsigned-original-result", "ios-unsigned-close")
UI_DIAGNOSTICS = (("build", "normal-ui/build.failure-diagnostics.json"),
    ("toolchain", "normal-ui/toolchain.failure-diagnostics.json"),
    ("admission", "normal-ui/build.admission-diagnostics.json"))
UI_ERROR_DOMAINS = frozenset(("NSCocoaErrorDomain", "NSPOSIXErrorDomain", "NSOSStatusErrorDomain", "NSMachErrorDomain",
    "XCTestErrorDomain", "XCTRunnerErrorDomain", "com.apple.dt.xctest.error", "IDETestOperationsObserverErrorDomain",
    "IDEFoundationErrorDomain", "RBSRequestErrorDomain", "RBSServiceErrorDomain", "FBSOpenApplicationServiceErrorDomain",
    "FBSOpenApplicationErrorDomain", "IXUserPresentableErrorDomain"))
UI_COMPILER_REASONS = frozenset(("type-mismatch", "missing-member", "missing-name", "inaccessible", "missing-argument",
    "extra-argument", "inference", "ambiguous-overload", "initialization", "throwing", "actor-isolation",
    "sendability", "syntax", "redeclaration"))
UI_ADMISSION_STAGES = frozenset(("request", "context", "loader", "phase", "execute", "diagnostic", "publication", "finalize"))
UI_ADMISSION_EXCEPTIONS = frozenset(("Refused", "AttributeError", "TypeError", "ValueError", "ImportError",
    "ModuleNotFoundError", "OSError", "FileNotFoundError", "PermissionError", "RuntimeError", "KeyError",
    "AssertionError", "KeyboardInterrupt", "SystemExit", "ProcessError", "ProcessInterrupted", "other"))
UI_ADMISSION_SOURCES = frozenset(("macos_normal_ui_runner.py", "macos_aqua_qualification.py", "owned_process.py",
                                   "_command_process.py"))
UI_OWNER_REASONS = frozenset(("incomplete-output", "original-deadline", "output-bound", "protocol-or-ownership",
    "command-failed-or-incomplete", "cleanup-unconfirmed", "exec-rejected", "stopped-before-exec",
    "parent-ended", "observer-ended", "fence-collision", "unknown"))
UI_ADMISSION_ROLES = frozenset(("normal-ui-source-roster", "normal-ui-build", "normal-ui-summary", "normal-build-settings",
    "saved-version-source-roster", "saved-version-core-interrupt", "verify-generated-runner", "generated-runner-entitlements",
    "one-admitted-ui-test", "normal-ui-test-tree", "normal-toolchain-xcode", "normal-toolchain-sdkPath",
    "normal-toolchain-sdkVersion", "normal-toolchain-sdkBuild"))
BUILD_SETTINGS = ("ARCHS", "VALID_ARCHS", "EXCLUDED_ARCHS", "NATIVE_ARCH_ACTUAL",
    "NATIVE_ARCH_64_BIT", "SUPPORTED_PLATFORMS", "ONLY_ACTIVE_ARCH", "MACOSX_DEPLOYMENT_TARGET", "SDK_VERSION")
BUILD_ARCHITECTURES = ("arm64", "arm64e", "x86_64", "x86_64h", "i386")
BUILD_PLATFORMS = ("macosx", "iphoneos", "iphonesimulator", "appletvos", "appletvsimulator",
    "watchos", "watchsimulator", "xros", "xrsimulator", "driverkit")
DESTINATION_REJECTIONS = ("non-ascii-or-control", "row-envelope", "field-count", "field-format",
    "duplicate-key", "missing-required-field")
INPUT_LIMIT = 3 * 1024 * 1024
OUTPUT_LIMIT = 128 * 1024
JSON_NODE_LIMIT = 250000
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


# Public SOURCE-selected IDs and exact guard codes, not diagnostic prose.
DATA_CONTRACT_PHASES = ("mount", "apfs", "build", "rust", "python")
DATA_CONTRACT_TEST_IDS = (
    'test_workflow_transaction_profile.WorkflowUpdateFilesystemTests.test_failure_after_first_real_replacement_restores_originals_and_primary',
    'test_workflow_transaction_profile.WorkflowUpdateFilesystemTests.test_mixed_update_create_preserve_commits_and_cleans_original_backups',
    'test_candidate_evidence.CandidateEvidenceAdmissionTests.test_platform_and_posix_prerequisites_control_both_methods_without_io',
    'test_candidate_evidence.CandidateEvidenceAdmissionTests.test_darwin_requires_every_original_posix_descriptor_primitive',
    'test_candidate_evidence.CandidateEvidenceAdmissionTests.test_unsupported_profiles_are_closed_without_io',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_darwin_route_uses_the_original_host_reader_without_more_authority',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_android_and_ios_use_real_validators_and_exact_redacted_contract',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_declared_decimal_precision_and_distinct_manifest_run_roles',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_forged_self_consistency_never_claims_provenance_or_artifact_authority',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_artifact_projection_has_stable_role_order_not_document_order',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_only_three_fixed_documents_are_opened_no_publishers_or_payloads',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_missing_is_incomplete_and_present_invalid_dominates_missing',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_malformed_json_duplicates_floats_nonfinite_and_schema_stage_self_digest',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_actual_candidate_intent_receipt_cross_bindings_not_only_self_digests',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_private_or_legacy_validator_messages_are_never_forwarded',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_byte_integer_node_depth_and_projection_limits_are_not_policy_invalid',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_exact_two_mib_each_and_six_mib_total_are_admitted_without_extra_files',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_unrepresentable_valid_identifiers_and_large_run_text_are_limits',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_utf8_and_unsafe_root_refusals_are_constant',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_read_io_refusal_does_not_reflect_path_or_native_exception',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_original_root_identity_is_checked_before_any_document_read',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_root_parent_leaf_links_and_portable_aliases_are_not_followed',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_special_foreign_owner_and_foreign_device_refuse_before_leaf_open',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_changed_leaf_absence_and_ancestor_veto_even_nonconsistent_results',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_one_cooperative_deadline_includes_pure_validation_and_final_checks',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_descriptor_close_uncertainty_attempts_all_original_closes_once',
    'test_candidate_evidence.CandidateEvidenceObservationTests.test_original_iterator_close_uncertainty_is_not_incomplete',
    'test_lifecycle_evidence.LifecycleLayoutTests.test_closed_params_and_platform_before_io',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_darwin_routes_every_stage_through_the_original_shared_reader',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_three_real_layouts_reuse_policy_and_never_upgrade_authority',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_shared_fixtures_and_core_blocker_parity',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_platform_stage_intent_and_predecessor_disagreement_export_no_partial_history',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_missing_invalid_and_inconsistent_never_export_history',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_repeated_candidate_bytes_must_match_without_claiming_bundle_inventory',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_exact_document_and_aggregate_limits_require_real_eof',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_zero_remaining_refuses_next_nonempty_file_even_after_invalid_values',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_rejected_arrays_are_charged_before_top_level_kind_rejection',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_symlink_changed_and_original_cleanup_failures_withhold_results',
    'test_lifecycle_evidence.LifecycleEvidenceTests.test_observation_does_not_write_launch_or_contact_services',
    'test_metadata_images_edit.MetadataImagesEditTests.test_changed_sibling_target_or_saved_configuration_is_not_a_second_preview_or_write',
    'test_metadata_images_edit.MetadataImagesEditTests.test_directory_move_lost_return_preserves_owned_transition_for_original_and_restart_rollback',
    'test_metadata_images_edit.MetadataImagesEditTests.test_failure_after_committed_marker_never_retries_import_or_claims_false_success',
    'test_metadata_images_edit.MetadataImagesEditTests.test_image_only_limit_accepts_a_header_checked_image_larger_than_unchanged_global_limit',
    'test_metadata_images_edit.MetadataImagesEditTests.test_new_directory_import_is_one_shot_and_preserves_original_sources_and_saved_inputs',
    'test_metadata_images_edit.MetadataImagesEditTests.test_private_original_object_exclusions_protect_a_target_even_without_a_relative_source_name',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_00_actual_mixed_ready_rollback_preserves_old_identity_and_readonly_facts',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_actual_committed_target_is_checked_again_before_last_backup_cleanup',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_changed_saved_dependencies_targets_and_portable_alias_refuse_without_public_effects',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_cleanup_failure_after_owned_deletion_is_not_retried_and_new_inspection_can_finish',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_committed_and_rolled_back_cleanup_accept_only_complete_controls_and_admitted_data_subset',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_complete_preparing_between_and_owned_new_directory_states',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_current_revision_rechecks_config_siblings_targets_and_journal_identity_before_apply',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_idle_and_unreadable_configuration_never_manufacture_usable_baseline_or_recovery',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_incomplete_contradictory_or_foreign_control_proof_is_conflict_not_cleanup_authority',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_one_shot_consent_immutable_authority_and_discard_do_not_erase_inspected_commit',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_original_stop_after_owned_rollback_move_preserves_failure_and_requires_new_recovery',
    'test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_terminal_fsync_failure_keeps_rolled_back_fact_without_cleanup_or_false_success',
    'test_github_preflight_frames.GitHubPreflightBootstrapTests.test_exact_linux_and_darwin_admit_only_the_fixed_engine_family',
    'test_github_preflight_frames.GitHubPreflightBootstrapTests.test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry',
    'test_github_release.GitHubReleaseBootstrapTests.test_exact_linux_and_darwin_admit_only_the_fixed_engine_family',
    'test_github_release.GitHubReleaseBootstrapTests.test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_intent_and_run_are_exact_canonical_noncredential_records',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_intent_rejects_broadened_authority_and_modified_caller',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_initial_contains_no_credential_and_binds_exact_ready_digest',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_initial_and_go_frames_reject_extra_pipelined_duplicate_or_unbound_input',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_pending_is_fresh_native_scope_only_and_go_contains_no_token',
    'test_github_preflight_frames.GitHubPreflightFrameTests.test_final_result_preserves_accepted_uncertain_and_observed_distinctions',
    'test_github_release.GitHubReleaseFrameTests.test_full64_maximum_retained_records_fit_the_private_result_without_truncation',
    'test_github_release.GitHubReleaseFrameTests.test_protocol_journal_and_go_cannot_cross_preflight_family',
    'test_github_release.GitHubReleaseFrameTests.test_original_helper_waits_for_durable_intent_and_closes_before_final',
    'test_github_release.GitHubReleaseTransportTests.test_only_release_config_role_can_read_base64_overhead_in_all_framing_modes',
    'test_github_release.GitHubReleaseTransportTests.test_release_aggregate_and_original_deadline_are_never_renewed',
    'test_github_preflight.GitHubPreflightPolicyTests.test_caller_source_and_identity_fail_before_any_dispatch',
    'test_github_preflight.GitHubPreflightPolicyTests.test_dispatch_is_one_post_and_returned_id_is_not_workflow_success',
    'test_github_preflight.GitHubPreflightPolicyTests.test_changed_branch_during_consent_is_not_sent',
    'test_github_preflight.GitHubPreflightPolicyTests.test_lost_response_204_and_invalid_run_url_never_retry_or_claim_no_effect',
    'test_github_release.GitHubReleasePolicyTests.test_selection_is_closed_original_data_never_current_version_substitution',
    'test_github_release.GitHubReleasePolicyTests.test_single_dispatch_latches_uncertainty_and_refuses_replacement_source',
    'test_github_release.GitHubReleasePolicyTests.test_original_attempt_observation_requires_stage_jobs_not_build_repetition',
    'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_observes_original_complete_report_and_settled_projection',
    'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_workflow_has_one_bounded_original_result',
    'test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_saved_offline_and_empty_recovery_use_original_gui_only',
    'test_android_build_tools.MacToolAdmissionDataTests.test_mac_commands_use_exact_contents_home_private_environment_and_inspection_only',
    'test_android_build_tools.OwnerAndCommandDataTests.test_bundletool_requires_original_native_borrow_and_exact_snapshot',
)
DATA_CONTRACT_GUARDS = frozenset(('cargo-artifact-eof', 'cargo-artifact-original', 'cargo-artifact-path', 'cargo-artifact-postimage', 'cargo-artifact-shape', 'cargo-build-finished', 'cargo-debug-artifact', 'command-not-complete', 'filesystem-header', 'filesystem-native-volume', 'filesystem-row', 'filesystem-volume', 'fixed-input-changed', 'fixed-input-shape', 'output-bound', 'output-changed', 'python-counts', 'rust-aggregate-marker', 'source-post', 'temporary-nonempty', 'temporary-post', 'unclassified'))


PRODUCER_REFUSAL_TOKENS = {
    b"package-producer-refused:arguments\n": "arguments",
    b"package-producer-refused:clock\n": "clock",
    b"package-producer-refused:completed-package-magic\n": "completed-package-magic",
    b"package-producer-refused:created-root-original\n": "created-root-original",
    b"package-producer-refused:deadline\n": "deadline",
    b"package-producer-refused:descriptor-data\n": "descriptor-data",
    b"package-producer-refused:descriptor-name\n": "descriptor-name",
    b"package-producer-refused:descriptor-outside-package-root\n": "descriptor-outside-package-root",
    b"package-producer-refused:emission-binding\n": "emission-binding",
    b"package-producer-refused:file-finality\n": "file-finality",
    b"package-producer-refused:final-input-post\n": "final-input-post",
    b"package-producer-refused:final-report-bound\n": "final-report-bound",
    b"package-producer-refused:final-report-deadline\n": "final-report-deadline",
    b"package-producer-refused:final-report-flush\n": "final-report-flush",
    b"package-producer-refused:final-report-write\n": "final-report-write",
    b"package-producer-refused:observer-input-roster\n": "observer-input-roster",
    b"package-producer-refused:ordinary-user\n": "ordinary-user",
    b"package-producer-refused:original-limit\n": "original-limit",
    b"package-producer-refused:original-name\n": "original-name",
    b"package-producer-refused:original-no-handle\n": "original-no-handle",
    b"package-producer-refused:original-not-owned\n": "original-not-owned",
    b"package-producer-refused:original-open\n": "original-open",
    b"package-producer-refused:original-pending\n": "original-pending",
    b"package-producer-refused:original-post\n": "original-post",
    b"package-producer-refused:original-slot\n": "original-slot",
    b"package-producer-refused:original-stat\n": "original-stat",
    b"package-producer-refused:original-type\n": "original-type",
    b"package-producer-refused:original-unbound\n": "original-unbound",
    b"package-producer-refused:original-unknown\n": "original-unknown",
    b"package-producer-refused:parent-protection\n": "parent-protection",
    b"package-producer-refused:path-components\n": "path-components",
    b"package-producer-refused:path-encoding\n": "path-encoding",
    b"package-producer-refused:path-shape\n": "path-shape",
    b"package-producer-refused:platform\n": "platform",
    b"package-producer-refused:private-acl\n": "private-acl",
    b"package-producer-refused:private-attributes\n": "private-attributes",
    b"package-producer-refused:private-file\n": "private-file",
    b"package-producer-refused:private-program\n": "private-program",
    b"package-producer-refused:private-root\n": "private-root",
    b"package-producer-refused:read-budget\n": "read-budget",
    b"package-producer-refused:read-extent\n": "read-extent",
    b"package-producer-refused:read-limit\n": "read-limit",
    b"package-producer-refused:read-original\n": "read-original",
    b"package-producer-refused:read-short\n": "read-short",
    b"package-producer-refused:read-size\n": "read-size",
    b"package-producer-refused:root-roster\n": "root-roster",
    b"package-producer-refused:root-roster-bound\n": "root-roster-bound",
    b"package-producer-refused:root-roster-close\n": "root-roster-close",
    b"package-producer-refused:root-roster-eof\n": "root-roster-eof",
    b"package-producer-refused:root-roster-member\n": "root-roster-member",
    b"package-producer-refused:root-roster-name\n": "root-roster-name",
    b"package-producer-refused:root-roster-record\n": "root-roster-record",
    b"package-producer-refused:roster-original\n": "roster-original",
    b"package-producer-refused:sidecar-created\n": "sidecar-created",
    b"package-producer-refused:sidecar-mode\n": "sidecar-mode",
    b"package-producer-refused:sidecar-persist\n": "sidecar-persist",
    b"package-producer-refused:sidecar-readback\n": "sidecar-readback",
    b"package-producer-refused:sidecar-root-persist\n": "sidecar-root-persist",
    b"package-producer-refused:sidecar-sealed-original\n": "sidecar-sealed-original",
    b"package-producer-refused:sidecar-shape\n": "sidecar-shape",
    b"package-producer-refused:sidecar-write\n": "sidecar-write",
    b"package-producer-refused:sidecar-write-bound\n": "sidecar-write-bound",
    b"package-producer-refused:sidecar-written-original\n": "sidecar-written-original",
    b"package-producer-refused:signature-not-created\n": "signature-not-created",
    b"package-producer-refused:signature-verification\n": "signature-verification",
    b"package-producer-refused:signed-input-post\n": "signed-input-post",
    b"package-producer-refused:signer-finality\n": "signer-finality",
    b"package-producer-refused:source-current-unavailable\n": "source-current-unavailable",
    b"package-producer-refused:source-inventory-unavailable\n": "source-inventory-unavailable",
    b"package-producer-refused:source-runtime-unavailable\n": "source-runtime-unavailable",
    b"package-producer-refused:source-signer-unavailable\n": "source-signer-unavailable",
    b"package-producer-refused:verification-finality\n": "verification-finality",
}

class Refused(ValueError):
    """Fixed refusal only; no input text is ever included."""


def need(condition):
    if not condition:
        raise Refused("public-evidence-refused")


def clock(budget):
    need(time.monotonic_ns() <= budget["deadline"])


def hex_value(value, width=64):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % width, value) is not None
         and value != "0" * width)
    return value


def integer(value, maximum=1000000, minimum=0):
    need(type(value) is int and minimum <= value <= maximum)
    return value


def boolean(value):
    need(type(value) is bool)
    return value


def identifier(value):
    need(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None)
    return value


def uuid_value(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value)
         and value != "00000000-0000-0000-0000-000000000000")
    return value


def optional(row, name, validator):
    return None if name not in row or row[name] is None else validator(row[name])


def token(value, choices):
    return value if type(value) is str and value in choices else "unclassified"


def project_ios_unsigned_stages(value):
    need(type(value) is dict and set(value) == {"state", "events"}
         and type(value["state"]) is str and value["state"] in ("unavailable", "absent", "refused", "observed")
         and type(value["events"]) is list and len(value["events"]) <= 12)
    if value["state"] != "observed":
        need(value["events"] == [])
        return dict(value)
    need(bool(value["events"]))
    index, active, finished, seen = 0, None, False, set()
    for row in value["events"]:
        need(type(row) is dict and set(row) == {"stage", "result"}
             and type(row["stage"]) is str and row["stage"] in IOS_UNSIGNED_STAGES
             and type(row["result"]) is str and row["result"] in ("started", "passed", "failed"))
        stage, result = row["stage"], row["result"]
        key = (stage, result)
        need(key not in seen and not finished and index < len(IOS_UNSIGNED_STAGES)
             and stage == IOS_UNSIGNED_STAGES[index]
             and ((result == "started" and active is None) or (result != "started" and active == stage)))
        seen.add(key)
        if result == "started": active = stage
        else:
            active = None
            if result == "passed": index += 1
            else: finished = True
    return dict(value)


def project_ui_failure(value, phase):
    """Existing build/query or two exact nonzero iOS cases; no general test reader."""
    fields = {"schemaVersion", "scope", "phase", "selection", "originalReturncode", "stdoutBytes", "stdoutSha256",
        "stderrBytes", "stderrSha256", "status", "findingsTruncated", "errorCodes", "sourceFailures",
        "queryObservations", "requireObservations", "dashboardReadiness", "markers"}
    unsigned = phase == "test"
    build_fields = {"compilerDiagnostics"} if phase == "build" else set()
    if unsigned and "iosUnsignedStages" in value:
        need(value.get("selection") == IOS_UNSIGNED_SELECTION)
        build_fields.add("iosUnsignedStages")
    if phase == "build" and "buildFailureReasons" in value:
        build_fields.add("buildFailureReasons")  # Backward-compatible absence remains unproven, not empty.
    if phase == "build" and "destinationTable" in value:
        build_fields.add("destinationTable")  # Optional absence is not an empty table observation.
    need(phase in ("build", "query", "test") and set(value) == fields | build_fields
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "normal-macos-ui-failure-diagnostic-only" and value["phase"] == phase
          and ((not unsigned and value["selection"] is None) or (unsigned and type(value["selection"]) is str
               and value["selection"] in (IOS_UNSIGNED_SELECTION, IOS_PENDING_SELECTION)))
          and value["status"] in ("unavailable", "classified", "unclassified"))
    integer(value["originalReturncode"], 255, 1)
    cap = 4096 if phase == "query" else 1024 * 1024
    size = integer(value["stdoutBytes"], cap)
    integer(value["stderrBytes"], cap - size)
    hex_value(value["stdoutSha256"]); hex_value(value["stderrSha256"])
    boolean(value["findingsTruncated"])
    failures = value["sourceFailures"]
    need(type(failures) is list and (len(failures) <= 4 if unsigned else failures == [])
         and type(value["requireObservations"]) is list
         and (len(value["requireObservations"]) <= 1 if unsigned else value["requireObservations"] == [])
         and value["dashboardReadiness"] is None)
    if unsigned:
        selected_method = IOS_UNSIGNED_METHOD if value["selection"] == IOS_UNSIGNED_SELECTION else IOS_PENDING_METHOD
        for row in value["requireObservations"]:
            need(type(row) is dict and set(row) == {"source", "line", "check"}
                 and type(row["source"]) is str and row["source"] == "NormalAppUITests.swift"
                 and type(row["check"]) is str and row["check"] in ("condition", "singleton", "actionable"))
            integer(row["line"], 65535, 1)
        sites = []
        for row in failures:
            need(type(row) is dict and set(row) == {"stream", "source", "method", "line", "column"}
                 and type(row["stream"]) is str and row["stream"] in ("stdout", "stderr")
                 and type(row["source"]) is str and row["source"] == "NormalAppUITests.swift"
                 and type(row["method"]) is str and row["method"] == selected_method)
            integer(row["line"], 65535, 1)
            if row["column"] is not None: integer(row["column"], 4096, 1)
            sites.append((row["stream"], row["source"], row["method"], row["line"], row["column"]))
        need(len(set(sites)) == len(sites))
        if "iosUnsignedStages" in value: project_ios_unsigned_stages(value["iosUnsignedStages"])
    markers = value["markers"]
    need(type(markers) is dict and set(markers) == {"selectedCaseStarted", "selectedCaseFailed",
         "testExecuteFailed", "testingFailed", "xcodebuildError"} | ({"buildFailed"} if phase == "build" else set())
         and all(type(item) is bool for item in markers.values()))
    errors, queries = value["errorCodes"], value["queryObservations"]
    need(type(errors) is list and len(errors) <= 8 and type(queries) is list and len(queries) <= 4)
    for row in errors:
        need(type(row) is dict and set(row) == {"stream", "domain", "code"}
             and row["stream"] in ("stdout", "stderr") and type(row["domain"]) is str and row["domain"] in UI_ERROR_DOMAINS)
        integer(row["code"], 2147483647, -2147483648)
    for row in queries:
        need(type(row) is dict and set(row) == {"stream", "kind", "observation", "matches", "exceedsFour", "nonAtomic"}
             and row["stream"] in ("stdout", "stderr") and row["kind"] in ("renderer", "dashboard")
             and row["observation"] in ("initial", "identifier", "title", "label", "value", "placeholderValue", "containingSameStaticText")
             and row["nonAtomic"] is True and (row["kind"] != "renderer" or row["observation"] == "initial"))
        count = integer(row["matches"], 5)
        need(boolean(row["exceedsFour"]) == (count == 5) and (row["observation"] != "initial" or count != 1))
    if phase == "build":
        rows = value["compilerDiagnostics"]
        need(type(rows) is list and len(rows) <= 4)
        for row in rows:
            need(type(row) is dict and set(row) == {"stream", "source", "line", "column", "severity", "reasonCodes"}
                 and row["stream"] in ("stdout", "stderr") and row["source"] == "NormalAppUITests.swift"
                 and row["severity"] in ("error", "note"))
            integer(row["line"], 65535, 1); integer(row["column"], 4096, 1)
            reasons = row["reasonCodes"]
            need(type(reasons) is list and len(reasons) <= 3
                 and all(type(reason) is str and reason in UI_COMPILER_REASONS for reason in reasons)
                 and len(set(reasons)) == len(reasons))
        if "buildFailureReasons" in value:
            rows = value["buildFailureReasons"]
            need(type(rows) is list and len(rows) <= 4)
            for row in rows:
                need(type(row) is dict and set(row) == {"stream", "code"}
                     and row["stream"] in ("stdout", "stderr")
                     and row["code"] in ("destination-not-found", "no-eligible-destination"))
            need(len({(row["stream"], row["code"]) for row in rows}) == len(rows))
        if "destinationTable" in value:
            table = value["destinationTable"]
            fields = {"state", "unknownRowObserved", "malformedRowObserved", "rowsTruncated", "rows"}
            need(type(table) is dict and fields <= set(table) <= fields | {
                 "rejections", "rejectionDetailsTruncated", "unknownRows", "unknownRowsTruncated"}
                 and ("rejections" in table) == ("rejectionDetailsTruncated" in table)
                 and ("unknownRows" in table) == ("unknownRowsTruncated" in table)
                 and table["state"] in ("unavailable", "absent", "observed"))
            for name in ("unknownRowObserved", "malformedRowObserved", "rowsTruncated"):
                boolean(table[name])
            rows = table["rows"]
            need(type(rows) is list and len(rows) <= 8
                 and (not table["rowsTruncated"] or value["findingsTruncated"])
                 and (table["state"] == "observed" or not (rows or table["unknownRowObserved"]
                      or table["malformedRowObserved"] or table["rowsTruncated"])))
            if "rejections" in table:
                rejections = table["rejections"]
                need(table["state"] == "observed" and table["malformedRowObserved"]
                     and type(rejections) is list and len(rejections) <= 8)
                boolean(table["rejectionDetailsTruncated"])
                keys = []
                for rejection in rejections:
                    need(type(rejection) is dict and set(rejection) == {"stream", "section", "reason"}
                         and rejection["stream"] in ("stdout", "stderr")
                         and rejection["section"] in ("available", "ineligible")
                         and type(rejection["reason"]) is str and rejection["reason"] in DESTINATION_REJECTIONS)
                    keys.append((rejection["stream"], rejection["section"], rejection["reason"]))
                need(len(set(keys)) == len(keys) and (bool(keys) or table["rejectionDetailsTruncated"]))
            if "unknownRows" in table:
                unknown = table["unknownRows"]
                need(table["state"] == "observed" and table["unknownRowObserved"]
                     and type(unknown) is list and len(unknown) <= 8)
                boolean(table["unknownRowsTruncated"])
                need((bool(unknown) or table["unknownRowsTruncated"])
                     and (not table["unknownRowsTruncated"] or value["findingsTruncated"]))
                for row in unknown:
                    need(type(row) is dict and set(row) == {"stream", "section", "platform", "architecture",
                         "unsupportedKeyPresent", "errorPresent"}
                         and row["stream"] in ("stdout", "stderr") and row["section"] in ("available", "ineligible")
                         and row["platform"] in ("macos", "unrecognized")
                         and row["architecture"] in (None, "arm64", "arm64e", "x86_64", "x86_64h", "i386", "unrecognized"))
                    boolean(row["unsupportedKeyPresent"]); boolean(row["errorPresent"])
                    need(row["unsupportedKeyPresent"] or row["platform"] == "unrecognized"
                         or row["architecture"] == "unrecognized")
            for row in rows:
                fields = {"stream", "section", "platform", "architecture", "errorPresent"}
                need(type(row) is dict and fields <= set(row) <= fields | {"errorTerms"}
                     and row["stream"] in ("stdout", "stderr") and row["section"] in ("available", "ineligible")
                     and row["platform"] == "macos" and row["architecture"] in (None, "arm64", "arm64e", "x86_64", "x86_64h", "i386"))
                boolean(row["errorPresent"])
                if "errorTerms" in row:
                    # Closed lexical presence, not a platform/architecture failure classification.
                    vocabulary = ("architecture", "platform", "macos", "xcode", "sdk", "deployment", "version", "support", "install")
                    terms = row["errorTerms"]
                    need(row["errorPresent"] and type(terms) is list and len(terms) <= len(vocabulary)
                         and all(type(term) is str and term in vocabulary for term in terms)
                         and terms == [term for term in vocabulary if term in terms])
    return dict(value)


def project_ui_admission(value):
    """No raw exception record: only the wrapper's finite admission projection."""
    fields = {"schemaVersion", "scope", "status", "nativeSuccessInferred", "productReady", "unknownStateRetained"}
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "normal-macos-ui-admission-diagnostic-only"
         and value["nativeSuccessInferred"] is False and value["productReady"] is False
         and value["unknownStateRetained"] is True)
    if value["status"] == "unavailable":
        need(set(value) == fields)
        return dict(value)
    fields |= {"stage", "exceptionClass", "sourceFrames", "ownerFailure", "commands"}
    need(value["status"] == "observed-exception-only"
         and fields <= set(value) <= fields | {"ownerDiagnostic", "sourceFramesTruncated"}
         and type(value["stage"]) is str and value["stage"] in UI_ADMISSION_STAGES
         and type(value["exceptionClass"]) is str and value["exceptionClass"] in UI_ADMISSION_EXCEPTIONS)
    frames, owner, commands = value["sourceFrames"], value["ownerFailure"], value["commands"]
    need(type(frames) is list and len(frames) <= 4 and type(commands) is list and len(commands) <= 16
         and type(owner) is dict and set(owner) == {"dispatched", "contained", "cleanupComplete"}
         and all(item is None or type(item) is bool for item in owner.values()))
    if "ownerDiagnostic" in value and (diagnostic := value["ownerDiagnostic"]) is not None:
        need(value["exceptionClass"] == "ProcessError" and type(diagnostic) is dict
             and set(diagnostic) == {"reason", "failureMask"}
             and type(diagnostic["reason"]) is str and diagnostic["reason"] in UI_OWNER_REASONS
             and (diagnostic["failureMask"] is None or type(diagnostic["failureMask"]) is int
                  and (diagnostic["failureMask"] == 32 or 48 <= diagnostic["failureMask"] <= 63)))
    if "sourceFramesTruncated" in value:
        boolean(value["sourceFramesTruncated"])
    for frame in frames:
        need(type(frame) is dict and set(frame) == {"source", "line"}
             and type(frame["source"]) is str and frame["source"] in UI_ADMISSION_SOURCES)
        integer(frame["line"], 1000000, 1)
    for command in commands:
        need(type(command) is dict and set(command) == {"role", "returncode", "stdoutBytes", "stderrBytes"}
             and type(command["role"]) is str and command["role"] in UI_ADMISSION_ROLES)
        integer(command["returncode"], 255)
        size = integer(command["stdoutBytes"], 1024 * 1024)
        integer(command["stderrBytes"], 1024 * 1024 - size)
    return dict(value)


def project_ui_diagnostic(value, role, caller_status):
    need(type(value) is dict and role in ("build", "toolchain", "admission", "ios-unsigned-test", "ios-pending-test")
         and type(caller_status) is dict and caller_status.get("receiptState") == "observed")
    status = integer(caller_status.get("returncode"), 255, 1)
    # Writers have no embedded source/run tuple. This is only parent-context
    # attribution from the fixed fresh work root, never independent attestation.
    try:
        if role in ("ios-unsigned-test", "ios-pending-test"):
            if value.get("scope") == "normal-macos-ui-admission-diagnostic-only":
                row = project_ui_admission(value)
                row["originalCallerReturncode"] = status  # Scalar attribution, not a native-command outcome.
            else:
                row = project_ui_failure(value, "test")
                need(row["selection"] == (IOS_UNSIGNED_SELECTION if role == "ios-unsigned-test" else IOS_PENDING_SELECTION))
        else:
            row = project_ui_admission(value) if role == "admission" else project_ui_failure(value, "build" if role == "build" else "query")
    except KeyError:
        raise Refused("public-evidence-refused") from None
    if role != "admission" and not (role in ("ios-unsigned-test", "ios-pending-test") and value.get("scope") == "normal-macos-ui-admission-diagnostic-only"):
        need(row["originalReturncode"] == status)
    return {**row, "receiptState": "observed", "binding": "same-work-root-parent-context-only", "nativeSuccessInferred": False}


def project_build_settings(value, context, status, build):
    """A later query is not the failed build or independent source/phase proof."""
    fields = {"schemaVersion", "scope", "target", "sourceCommit", "originalBuildReturncode",
        "originalBuildStdoutSha256", "originalBuildStderrSha256", "hostVersion", "queryRole", "queryState",
        "queryReturncode", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256", "settingsState", "settings",
        "sourceBinding", "phaseFinality", "nativeSuccessInferred", "productReady"}
    need(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["scope"] == "normal-macos-build-settings-diagnostic-only"
         and value["target"] == context["target"] == "x86_64-apple-darwin"
         and value["sourceCommit"] == context["source"]
         and value["queryRole"] == "normal-build-settings"
         and value["sourceBinding"] == "prior-build-source-pre-post-only" and value["phaseFinality"] == "not-asserted"
         and value["nativeSuccessInferred"] is False and value["productReady"] is False
         and type(status) is dict and status.get("receiptState") == "observed"
         and type(build) is dict and build.get("receiptState") == "observed" and build.get("phase") == "build")
    code = integer(value["originalBuildReturncode"], 255, 1)
    need(code == integer(status.get("returncode"), 255, 1) == integer(build.get("originalReturncode"), 255, 1))
    for stream in ("Stdout", "Stderr"):
        need(hex_value(value["originalBuild" + stream + "Sha256"]) == hex_value(build.get(stream.lower() + "Sha256")))
    host = value["hostVersion"]
    need(host is None or type(host) is str and len(host) <= 16 and re.fullmatch(r"26(?:\.[0-9]{1,3}){1,3}", host))
    need(value["queryState"] in ("not-returned", "returned")
         and value["settingsState"] in ("unavailable", "nonzero", "malformed", "observed"))
    capture = ("queryReturncode", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256")
    if value["queryState"] == "not-returned":
        need(all(value[key] is None for key in capture) and value["settingsState"] == "unavailable" and value["settings"] is None)
    else:
        query_code = integer(value["queryReturncode"], 255)
        size = integer(value["stdoutBytes"], 262144)
        integer(value["stderrBytes"], 262144 - size)
        hex_value(value["stdoutSha256"]); hex_value(value["stderrSha256"])
        need(value["settingsState"] in (("malformed", "observed") if query_code == 0 else ("nonzero",)))
        if value["settingsState"] != "observed":
            need(value["settings"] is None)
    if value["settingsState"] == "observed":
        need(value["stdoutBytes"] > 0)  # The genuine parser never admits empty input.
        settings = value["settings"]
        need(type(settings) is dict and set(settings) == set(BUILD_SETTINGS))
        for name in BUILD_SETTINGS:
            row = settings[name]
            need(type(row) is dict and set(row) == {"state", "value"} and row["state"] in ("absent", "unsupported", "observed"))
            item = row["value"]
            if row["state"] != "observed":
                need(item is None)
            elif name in ("ARCHS", "VALID_ARCHS", "EXCLUDED_ARCHS", "SUPPORTED_PLATFORMS"):
                choices = BUILD_PLATFORMS if name == "SUPPORTED_PLATFORMS" else BUILD_ARCHITECTURES
                need(type(item) is list and len(item) <= (8 if name == "SUPPORTED_PLATFORMS" else 5)
                     and all(type(word) is str and word in choices for word in item) and len(set(item)) == len(item))
            elif name in ("NATIVE_ARCH_ACTUAL", "NATIVE_ARCH_64_BIT"):
                need(type(item) is str and item in ("x86_64", "x86_64h", "arm64", "arm64e"))
            elif name == "ONLY_ACTIVE_ARCH":
                boolean(item)
            else:
                need(type(item) is str and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}", item))
    return {**value, "receiptState": "observed", "binding": "same-work-root-parent-context-and-failed-build-captures"}


def project_data_contract_failure(value, context, statuses, inventory_paths):
    """Failure-only sidecar observations; no raw captures or native acceptance."""
    fields = {"schemaVersion", "kind", "source", "workflowSource", "runId", "runAttempt", "target", "phase",
        "originalReturncode", "originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow",
        "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256", "guardCode", "python", "cargo",
        "diagnosticOnly", "productReady"}
    need(type(value) is dict and fields <= set(value) <= fields | {"rustPanic", "rustPanicDiagnostic"}
         and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["kind"] == "mrk-native-data-contract-failure-diagnostics-v1"
         and value["diagnosticOnly"] is True and value["productReady"] is False
         and all(value[name] == context[name] for name in ("source", "workflowSource", "runId", "runAttempt", "target"))
         and value["phase"] in DATA_CONTRACT_PHASES
         and type(value["guardCode"]) is str and value["guardCode"] in DATA_CONTRACT_GUARDS)
    for name in ("originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow"):
        boolean(value[name])
    code = value["originalReturncode"]
    if code is not None:
        integer(code, 65535, -65536)
    need(not value["originalReturned"] or code is not None)
    for stream in ("stdout", "stderr"):
        integer(value[stream + "Bytes"], 4 * 1024 * 1024)
        hex_value(value[stream + "Sha256"])
    caller = statuses.get("data-contracts/" + value["phase"] + ".status", {"receiptState": "absent"})
    need(type(caller) is dict and caller.get("receiptState") in ("observed", "absent", "refused")
         and set(caller) == ({"receiptState", "returncode"} if caller["receiptState"] == "observed" else {"receiptState"}))
    matched = None
    if caller["receiptState"] == "observed":
        need(value["originalReturned"] and code == integer(caller["returncode"], 65535, -65536))
        matched = True  # Equality alone, including zero, is not a phase pass.
    closed = (value["originalReturned"] and value["outputComplete"] and value["captureClosed"]
              and not value["timedOut"] and not value["outputOverflow"])
    python = value["python"]
    if python is not None:
        counts = ("testsRun", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")
        need(closed and value["phase"] == "python" and type(python) is dict and set(python) == set(counts) | {
            "actualHostBeforeAndAfter", "failureTests", "classifiedTestCount", "omittedTestCount", "unclassifiedTestCount"})
        for name in counts:
            integer(python[name], 84 if name == "testsRun" else 65535)
        boolean(python["actualHostBeforeAndAfter"])
        rows = python["failureTests"]
        need(type(rows) is list and len(rows) <= 16)
        keys = []
        for row in rows:
            need(type(row) is dict and set(row) == {"kind", "id"} and row["kind"] in ("failure", "error")
                 and type(row["id"]) is str and row["id"] in DATA_CONTRACT_TEST_IDS)
            keys.append((row["kind"], row["id"]))
        need(len(set(keys)) == len(keys) and keys == [(kind, name) for name in DATA_CONTRACT_TEST_IDS
             for kind in ("failure", "error") if (kind, name) in keys])
        classified = integer(python["classifiedTestCount"], 168)
        omitted = integer(python["omittedTestCount"], 152)
        unknown = integer(python["unclassifiedTestCount"], 65535)
        need(classified == len(rows) + omitted and classified + unknown <= python["failures"] + python["errors"]
             and all(sum(row["kind"] == kind for row in rows) <= python[field]
                     for kind, field in (("failure", "failures"), ("error", "errors"))))
    cargo = value["cargo"]
    result = dict(value)
    if cargo is not None:
        need(closed and value["phase"] == "build" and type(cargo) is dict
             and set(cargo) == {"errors", "unclassifiedErrors", "omittedErrors"})
        integer(cargo["unclassifiedErrors"], 4096); integer(cargo["omittedErrors"], 4096)
        rows = cargo["errors"]
        need(type(rows) is list and len(rows) <= 8)
        seen, projected = set(), []
        for row in rows:
            need(type(row) is dict and set(row) == {"code", "source", "line", "column"}
                 and type(row["code"]) is str and re.fullmatch(r"E[0-9]{4}", row["code"]) is not None)
            source, line, column = row["source"], row["line"], row["column"]
            if source is None:
                need(line is None and column is None)
            else:
                need(type(source) is str and 0 < len(source) <= 240 and re.fullmatch(r"[A-Za-z0-9_./-]+", source)
                     and all(part not in ("", ".", "..") for part in source.split("/")))
                integer(line, 1000000, 1); integer(column, 1000000, 1)
            key = (row["code"], source, line, column)
            need(key not in seen)
            seen.add(key)  # Validate genuine original uniqueness BEFORE source redaction.
            if source not in inventory_paths:
                source = line = column = None
            projected.append({"code": row["code"], "source": source, "line": line, "column": column})
        # Distinct original rows may project equally; do not invent count changes.
        result["cargo"] = {**cargo, "errors": projected}
    panic = value.get("rustPanic")  # Legacy absence remains an unknown site.
    result["rustPanic"] = None
    if panic is not None:
        need(closed and value["phase"] == "rust" and code == 101 and value["stderrBytes"] > 0
             and type(panic) is dict and set(panic) == {"source", "line", "column"})
        source = panic["source"]
        need(type(source) is str and 0 < len(source) <= 240 and re.fullmatch(r"[A-Za-z0-9_./-]+", source)
             and source.endswith(".rs") and all(part not in ("", ".", "..") for part in source.split("/"))
             and (source.startswith("desktop/src-tauri/src/")
                  or source == "desktop/src-tauri/tests/installed_shell_observation.rs"))
        integer(panic["line"], 1000000, 1); integer(panic["column"], 1000000, 1)
        if source in inventory_paths:
            result["rustPanic"] = dict(panic)
    diagnostic = value.get("rustPanicDiagnostic")
    result["rustPanicDiagnostic"] = None
    if diagnostic is not None:
        need(closed and value["phase"] == "rust" and code == 101
             and type(diagnostic) is dict and set(diagnostic) == {"parseState", "spellingSha256", "line", "column"})
        state = diagnostic["parseState"]
        need(type(state) is str and state in ("input-invalid", "empty", "bounds", "header-missing",
            "header-multiple", "header-format", "coordinate-range", "unmapped-source", "observed"))
        if state in ("unmapped-source", "observed"):
            need(type(diagnostic["spellingSha256"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", diagnostic["spellingSha256"]) is not None)
            integer(diagnostic["line"], 1000000, 1); integer(diagnostic["column"], 1000000, 1)
        else:
            need(all(diagnostic[name] is None for name in ("spellingSha256", "line", "column")))
        if state == "observed":
            # Crossjoin the original before the existing inventory redaction.
            need(panic is not None and diagnostic["line"] == panic["line"] and diagnostic["column"] == panic["column"])
            if result["rustPanic"] is not None:
                result["rustPanicDiagnostic"] = dict(diagnostic)
        else:
            need(panic is None)
            # An opaque lexical spelling is not source membership or cause.
            result["rustPanicDiagnostic"] = dict(diagnostic)
    return {**result, "receiptState": "observed", "binding": "same-source-run-target-context",
            "callerStatus": dict(caller), "statusMatched": matched, "nativeSuccessInferred": False}


def decode(body, budget, *, inventory=False, ui_admission=False):
    # Byte bounds precede stdlib parsing. Graph bounds are post-parse checks,
    # not a prospective allocation or hard-RSS guarantee.
    need(type(ui_admission) is bool and not (inventory and ui_admission))
    need(type(body) is bytes and 0 < len(body) <= (2 * 1024 * 1024 if inventory else 32768 if ui_admission else 16384))
    def pairs(rows):
        need(len(rows) <= 128 and len({key for key, _ in rows}) == len(rows))
        return dict(rows)
    def number(raw):
        need(len(raw) <= 20)
        return int(raw)
    def no_float(_raw):
        raise Refused("public-evidence-refused")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_int=number,
                           parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("public-evidence-refused") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        budget["nodes"] += 1
        need(depth <= 16 and count <= (131072 if inventory else 8192) and budget["nodes"] <= JSON_NODE_LIMIT)
        if type(item) is dict:
            need(len(item) <= 128)
            pending.extend((part, depth + 1) for pair in item.items() for part in pair)
        elif type(item) is list:
            need(len(item) <= (4095 if inventory else 128))
            pending.extend((part, depth + 1) for part in item)
    need(type(value) is dict)
    clock(budget)
    return value


def project_owner_finality(value):
    """Finite post-publication DATA, not completion, cleanup or target authority."""
    if value is None:
        return {"available": False}
    need(type(value) is list and len(value) == 5 and all(type(part) is int for part in value[:4]))
    version, branch, outer, cleanup, terminal = value
    need(version == 1 and branch in (0, 1) and 0 <= outer <= (1023 if branch == 0 else 1048575)
         and 0 <= cleanup <= 15)
    need(terminal is None or type(terminal) is int and branch == 1
         and (terminal in (0, 32) or 48 <= terminal <= 63))
    if branch == 1:
        # No child observations may be invented for a missing parent record.
        need(not (outer & (1 << 3) and outer & ((1 << 4) | (1 << 5) | (1 << 6))))
        need(not (outer & (1 << 7) and outer & ((1 << 8) | (1 << 18) | (1 << 19))))
        need(not (outer & (1 << 10) and outer & ((1 << 11) | (1 << 12))))
        need(terminal is None or not outer & ((1 << 7) | (1 << 8) | (1 << 9)))
    return {"available": True, "branch": "no-child" if branch == 0 else "child",
            "predicateMask": outer, "cleanupMask": cleanup, "terminalFailureMask": terminal}


NOTARY_SUBMIT_CLASSES = {"http-401": "http-authentication", "http-403": "http-permission",
    "http-429": "http-rate-limit", **{f"http-{code}": "http-service" for code in (500, 502, 503, 504)},
    "url-1001": "network-timeout", "url-1003": "network-dns", "url-1004": "network-connection",
    "url-1005": "network-connection", "url-1006": "network-dns", "url-1009": "network-connection",
    "url-1200": "network-tls", "url-1202": "network-tls"}


def project_notary_submit_diagnostic(value, row):
    """Closed same-original lexical facts, not a service or authentication verdict."""
    fields = {"schemaVersion", "kind", "diagnosticOnly", "nativeSuccessInferred", "policyUnchanged",
        "stderrBytes", "stderrSha256", "formatClass", "lexicalState", "errorClass", "matches", "matchesTruncated"}
    need(type(value) is dict and set(value) == fields and row.get("role") == "payload-submit"
         and all(row.get(name) is True for name in ("entered", "returned", "capturesSettled"))
         and type(row.get("returncode")) is int and -65536 <= row["returncode"] <= 65535 and row["returncode"] != 0)
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["kind"] == "failure-only-notary-submit" and value["diagnosticOnly"] is True
         and value["nativeSuccessInferred"] is False and value["policyUnchanged"] is True)
    size = integer(value["stderrBytes"], 65536)
    need(hex_value(value["stderrSha256"]) == hex_value(row.get("stderrSha256")))
    form, state, error = value["formatClass"], value["lexicalState"], value["errorClass"]
    need(form in ("empty", "bounded-utf8", "invalid-utf8") and (form == "empty") == (size == 0))
    matches, truncated = value["matches"], value["matchesTruncated"]
    need(type(matches) is list and len(matches) <= 16 and type(truncated) is bool
         and all(type(key) is str and key in (*NOTARY_SUBMIT_CLASSES, "unsupported-http", "unsupported-url") for key in matches)
         and (not truncated or len(matches) == 16)
         and (form == "bounded-utf8" or not matches and not truncated))
    expected_state, expected_error = "none", "unclassified"
    if form == "invalid-utf8" or any(key.startswith("unsupported-") for key in matches):
        expected_state = "unrecognized"
    elif truncated or len(matches) > 1:
        expected_state = "multiple-or-conflicting"
    elif matches:
        expected_state, expected_error = "single-known", NOTARY_SUBMIT_CLASSES[matches[0]]
    need(state == expected_state and error == expected_error)
    return dict(value)


def project_calls(rows, *, credential=False):
    if rows is None:
        return None
    need(type(rows) is list and len(rows) <= 128)
    projected, unknown = [], 0
    for row in rows:
        need(type(row) is dict)
        role = token(row.get("role"), CREDENTIAL_ROLES if credential else NATIVE_ROLES)
        if role == "unclassified":
            unknown += 1
            continue
        # Absence is unproven, not false. Do not inflate genuine original rows
        # with fields their writer never recorded (notably credential captures).
        item = {"role": role, **{name: optional(row, name, boolean) for name in CALL_BOOLS if name in row}}
        item["status" if credential else "returncode"] = optional(row, "status" if credential else "returncode",
            lambda value: integer(value, 65535, -65536))
        if not credential:
            item.update({name: optional(row, name, hex_value) for name in ("stdoutSha256", "stderrSha256") if name in row})
            if "notarySubmitDiagnostic" in row:
                try:
                    item["notarySubmitDiagnostic"] = project_notary_submit_diagnostic(row["notarySubmitDiagnostic"], row)
                except Refused:
                    item["notarySubmitDiagnostic"] = {"receiptState": "refused", "diagnosticOnly": True,
                        "nativeSuccessInferred": False, "policyUnchanged": True}
            failure = row.get("originalFailure")
            need(failure is None or type(failure) is dict)
            if failure is not None:
                item["originalFailure"] = {
                    "available": optional(failure, "available", boolean),
                    "ownerErrorType": token(failure.get("ownerErrorType"),
                        ("ProcessError", "ProcessCleanupError", "ProcessOutcomeUnknown", "other")),
                    "classification": token(failure.get("classification"), OWNER_REASONS),
                    "timeoutSeconds": optional(failure, "timeoutSeconds", lambda value: integer(value, 2**31 - 1)),
                    "outputLimitBytes": optional(failure, "outputLimitBytes", lambda value: integer(value, 2**31 - 1)),
                }
                if "ownerFinality" in failure:
                    item["originalFailure"]["ownerFinality"] = project_owner_finality(failure["ownerFinality"])
        projected.append(item)
    return {"recordedCount": len(rows), "unclassifiedCount": unknown, "calls": projected}


def project_failure(row):
    if row is None:
        return None
    need(type(row) is dict)
    reason = row.get("reason")
    safe = token(reason, REASONS)
    if type(reason) is str and safe == "unclassified":
        if reason.startswith("original-nonzero-") and reason[len("original-nonzero-"):] in NATIVE_ROLES:
            safe = reason
        else:
            for prefix, category in REASON_CATEGORIES:
                if reason.startswith(prefix):
                    safe = category
                    break
    return {"stage": token(row.get("stage"), STAGES), "type": token(row.get("type"), FAILURE_TYPES), "reason": safe,
            "errno": optional(row, "errno", lambda value: integer(value, 65535, 1))}


def project_final(row):
    if row is None:
        return None
    need(type(row) is dict)
    result = {name: optional(row, name, boolean) for name in FINAL_BOOLS if name in row}
    result.update({name: optional(row, name, hex_value) for name in FINAL_HASHES if name in row})
    result.update({name: optional(row, name, lambda value: integer(value, 2**40)) for name in FINAL_SIZES if name in row})
    result.update({name: optional(row, name, lambda value: integer(value, 2048))
                   for name in ("errorCount", "warningCount", "ticketRowCount") if name in row})
    if "scriptFileCount" in row:
        result["scriptFileCount"] = optional(row, "scriptFileCount", lambda value: integer(value, 4096))
    if "submissionId" in row:
        result["submissionId"] = optional(row, "submissionId", uuid_value)
    if "status" in row:
        need(type(row["status"]) is str and row["status"] in ("Accepted", "Invalid"))
        result["status"] = row["status"]
    return result


def project_removal_fixture(value, context, calls):
    if value is None:
        return None
    case = context.get("expectedRemovalCase", "disabled")
    need(case in ("ordinary", "abrupt") and context.get("profile") == "installed"
         and context["target"] == "aarch64-apple-darwin" and type(value) is dict)
    true_fields = ("allPayloadAbsent", "ordinaryOriginalFinalityRequired", "originalUIJoined",
        "requestsDirectoryNamedOnly", "mountedInputsDetached", "sourcePrePostMatched", "firstOriginalErrorPreserved")
    abrupt_fields = ("abruptProcessCutObserved", "samePackageLinkedResumeObserved", "appRootLastReturnedEffectObserved")
    need(set(value) == {"schemaVersion", "case", "targetBinding", "archives", "qualification", "uiObservation",
         "outputs", "outputsSha256", "powerLossQualified", "productReady", *true_fields, *abrupt_fields}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["case"] == case
         and value["qualification"] == "pending-original-owner-finality"
         and value["powerLossQualified"] is False and value["productReady"] is False
         and all(value[name] is True for name in true_fields)
         and all(value[name] is (case == "abrupt") for name in abrupt_fields))
    need(integer(value["archives"], 2, 1) == (1 if case == "ordinary" else 2)
         and integer(value["outputs"], 6, 3) == (3 if case == "ordinary" else 6))
    hex_value(value["outputsSha256"])
    binding = value["targetBinding"]
    hashes = ("inventorySha256", "packageSha256", "removeDescriptorSha256", "removeSignatureSha256")
    need(type(binding) is dict and set(binding) == {"sourceCommit", "target", "release", *hashes}
         and binding["sourceCommit"] == context["source"] and binding["target"] == context["target"]
         and binding["release"] == REMOVAL_RELEASE)
    for name in hashes:
        hex_value(binding[name])
    ui = value["uiObservation"]
    ui_true = ("oneOriginalAttemptObserved", "originalAppTerminated", "uiGateClosed", "uiChannelClosed")
    need(type(ui) is dict and set(ui) == {"case", "testIdentifier", "testCounts", "nativeSummarySha256",
         "nativeTestTreeSha256", "gateFree", "normalQuit", "productReady", *ui_true}
         and ui["case"] == case and ui["testIdentifier"] == "MRKNormalAppUITests/NormalAppUITests/" + REMOVAL_METHODS[case]
         and ui["gateFree"] == "unqualified" and ui["normalQuit"] is False and ui["productReady"] is False
         and all(ui[name] is True for name in ui_true))
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    need(type(ui["testCounts"]) is dict and set(ui["testCounts"]) == set(counts)
         and all(type(ui["testCounts"][name]) is int and ui["testCounts"][name] == count for name, count in counts.items()))
    hex_value(ui["nativeSummarySha256"]); hex_value(ui["nativeTestTreeSha256"])
    # Only case consistency, not a replacement for the owner's ordered/final
    # original validation. Expected cancellation/cut return1 remains unchanged.
    need(type(calls) is list and len(calls) <= 128 and all(type(row) is dict
         and row.get("role") in REMOVAL_ROLES[case] for row in calls))
    return dict(value)


def project_same_package(value, context):
    row = value.get("samePackageObservation")
    if row is None:
        need(value.get("passed") is False)
        return None
    hashes = ("finalImageReceiptSha256", "imageSha256", "packageSha256", "inventorySha256",
              "runtimeManifestSha256", "baselineResultSha256", "resultSha256")
    counts = {"beforeExportCount": 1, "afterExportCount": 2, "newExportCount": 1,
              "payloadWriteCount": 0, "payloadWriteBytes": 0}
    truths = ("samePackageNoopObserved", "immediatePredecessorMatched", "currentObjectsPreserved",
        "retainedGenerationsPreserved", "currentBytesVerified", "baselineExportUnchanged",
        "originalInstallerReturnedZero", "mountReadOnly", "mountOriginalsMatch", "originalMountDetached")
    need(context["profile"] == "installed" and type(row) is dict
         and set(row) == {"schemaVersion", "kind", "verifiedCurrentFiles", "systemServiceExitClaimed", "productReady",
                          *hashes, *counts, *truths}
         and type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
         and row["kind"] == "final-carrier-same-package-noop"
         and all(row[name] is True for name in truths)
         and row["systemServiceExitClaimed"] is False and row["productReady"] is False
         and all(type(row[name]) is int and row[name] == number for name, number in counts.items()))
    for name in hashes:
        hex_value(row[name])
    integer(row["verifiedCurrentFiles"], 2048, 1)
    need(row["baselineResultSha256"] != row["resultSha256"])
    calls = value.get("originalCalls")
    need(type(calls) is list and len(calls) == 3
         and tuple(call.get("role") for call in calls if type(call) is dict) ==
             ("distribution-attach", "installer", "distribution-detach")
         and all(all(call.get(key) is True for key in ("entered", "returned", "capturesSettled"))
                 and type(call.get("returncode")) is int and call["returncode"] == 0 for call in calls)
         and value.get("credentialOriginals") == [] and value.get("credentialContexts") == []
         and value.get("notarySubmission") is None and value.get("finalImage") is None
         and value.get("finalPackage") is None and value.get("payloadNotarization") is None
         and value.get("productReady") is False
         and value.get("notaryAuthentication") == {"created": False, "closed": False, "retired": False}
         and value.get("directStagerIOPending") is None and value.get("cleanupErrors") == []
         and all(value.get(key) is True for key in ("passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired")))
    mount = value.get("packageMount")
    need(type(mount) is dict and all(type(flag) is bool for flag in mount.values())
         and mount == {"attachEntered": True, "originalKnown": True, "detached": True, "retained": False,
         "installerEntered": True, "installerOriginalZero": True, "sameRequestV2Readback": True,
         "systemServiceExitClaimed": False})
    return dict(row)  # No request/instance identifiers, filesystem paths or raw native output.


APP_ABSENCE_REF = "refs/heads/verify/desktop-macos-app-absence-fixture"
APP_ABSENCE_PREPARE_ROLES = ("app-absence-build", "app-absence-data-tests", "app-absence-adhoc", "app-absence-verify-code", "app-absence-pkgbuild", "app-absence-tar", "app-absence-xar")
APP_ABSENCE_PACKAGE_ROLES = ("producer-tests", "producer-build", "producer-emitter", "app-absence-image-create", "app-absence-image-verify", "app-absence-baseline-attach",
    "distribution-create", "distribution-sign", "distribution-verify-signature", "distribution-verify-image", "observation-create", "observation-sign",
    "observation-verify-signature", "observation-verify-image", "distribution-attach", "installer-log-cursor", "app-absence-baseline", "installer",
    "installer-log-capture", "distribution-detach", "app-absence-baseline-detach")
APP_ABSENCE_RESTORE_ROLES = ("app-absence-restore-attach", "app-absence-withdraw", "app-absence-install", "app-absence-verify", "app-absence-restore-detach")
APP_ABSENCE_HASHES = ("packageSha256", "producerDescriptorSha256", "producerSignatureSha256", "fixtureExecutableSha256", "inventorySha256", "runtimeManifestSha256", "protocolSha256")
APP_ABSENCE_PROOFS = {
    "baseline": ("rootAbsent", "privateDirectoryCreated", "parentCensusMatched", "recordReadback"),
    "withdraw": ("initialFreshInstallRecorded", "createdRootMatchedPriorAbsence", "sameInstance", "reservationClosedUnderMaintenance", "renameKnownSuccess",
        "appAbsent", "runtimeUnchanged", "historyUnchanged", "withdrawnAppVerified", "recordReadback"),
    "verify": ("restoreFixedAppRecorded", "initialHistoryPreserved", "sameInstance", "runtimeUnchanged", "newAppOriginal", "currentAppVerified",
        "withdrawnAppVerified", "reservationClosedUnderMaintenance", "recordReadback", "retainedPrivateEvidence"),
}


def app_absence_binding(value, context):
    need(type(value) is dict and set(value) == set(APP_ABSENCE_HASHES) | {"fixtureSource", "productSource", "runId", "runAttempt", "target"}
         and value["fixtureSource"] == value["productSource"] == context["source"]
         and all(value[k] == context[k] for k in ("runId", "runAttempt", "target")))
    return {key: hex_value(value[key]) for key in APP_ABSENCE_HASHES}


def app_absence_owner(value, context, phase, roles):
    need(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
         and value.get("phase") == phase and value.get("packageRole") == "ordinary-image"
         and context["profile"] == "installed"
         and value.get("workflow") == "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@" + APP_ABSENCE_REF
         and all(value.get(k) == context[k] for k in ("source", "workflowSource", "runId", "runAttempt", "target"))
         and all(value.get(k) is True for k in ("passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired"))
         and value.get("cleanupErrors") == [] and value.get("directStagerIOPending", False) is None and "failure" not in value)
    calls = value.get("originalCalls")
    need(type(calls) is list and len(calls) == len(roles))
    for row, role in zip(calls, roles):
        need(type(row) is dict and row.get("role") == role and row.get("returned") is True and row.get("capturesSettled") is True
             and type(row.get("returncode")) is int and (row["returncode"] == 0 or phase == "package-install"
                 and role in ("installer-log-cursor", "installer-log-capture") and row["returncode"] == 1))
    if phase != "package-install":
        need(value.get("credentialOriginals") == value.get("credentialContexts") == [])


def app_absence_phase(value, context, phase, binding, baseline):
    need(type(value) is dict and set(value) == set(APP_ABSENCE_HASHES) | {"fixtureSource", "productSource", "runId", "runAttempt", "target",
        "schemaVersion", "kind", "phase", "baselineSha256", "recordSha256", "proof", "originalOuterExitRequired", "systemServiceExitClaimed", "productReady"}
        and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "app-absence-phase-observation"
        and value["phase"] == phase and value["originalOuterExitRequired"] is True
        and value["systemServiceExitClaimed"] is False and value["productReady"] is False)
    actual = app_absence_binding({k: value[k] for k in (*APP_ABSENCE_HASHES, "fixtureSource", "productSource", "runId", "runAttempt", "target")}, context)
    need(actual == binding and hex_value(value["baselineSha256"]) == baseline
         and type(value["proof"]) is dict and set(value["proof"]) == set(APP_ABSENCE_PROOFS[phase])
         and all(v is True for v in value["proof"].values()))
    record = hex_value(value["recordSha256"])
    need(phase != "baseline" or record == baseline)
    return {"recordSha256": record, "preExitObservation": True}


def project_app_absence_baseline(value, context):
    app_absence_owner(value, context, "package-install", APP_ABSENCE_PACKAGE_ROLES)
    need("appAbsenceBaseline" in value)
    row = value["appAbsenceBaseline"]
    need(type(row) is dict and set(row) == {"schemaVersion", "binding", "preparationReceiptSha256", "layout", "image", "baselineSha256",
        "baselineOriginal", "baselineObservation", "initial", "initialFreshInstall", "initialExportCount", "originalBaselineZero",
        "originalMountDetached", "systemServiceExitClaimed", "productReady"}
        and type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
        and row["initialFreshInstall"] is True and type(row["initialExportCount"]) is int and row["initialExportCount"] == 1
        and row["originalBaselineZero"] is True and row["originalMountDetached"] is True
        and row["systemServiceExitClaimed"] is False and row["productReady"] is False)
    binding = app_absence_binding(row["binding"], context)
    layout = row["layout"]
    names = ("Install.pkg", "producer.json", "producer.sig", "MRK-AppAbsence-Baseline.pkg", "MRK-AppAbsence-Withdraw.pkg", "MRK-AppAbsence-Verify.pkg")
    need(type(layout) is dict and set(layout) == set(names))
    for name in names:
        item = layout[name]
        need(type(item) is dict and set(item) == {"name", "bytes", "sha256", "mode", "links"}
             and item["name"] == name and type(item["mode"]) is int and item["mode"] == 0o444
             and type(item["links"]) is int and item["links"] == 1)
        integer(item["bytes"], 16384 if name == "producer.json" else 512 if name == "producer.sig" else 512*1024*1024,
                28 if name.endswith(".pkg") else 1)
        hex_value(item["sha256"])
    for name, key in zip(names[:3], ("packageSha256", "producerDescriptorSha256", "producerSignatureSha256")):
        need(layout[name]["sha256"] == binding[key])
    fixture = layout[names[3]]
    need(all(layout[name]["sha256"] == fixture["sha256"] and layout[name]["bytes"] == fixture["bytes"] for name in names[4:]))
    original = row["baselineOriginal"]
    need(type(original) is dict and set(original) == {"bytes", "sha256", "identity"}
         and type(original["identity"]) is list and len(original["identity"]) == 9
         and all(type(v) is int and 0 <= v < 2**64 for v in original["identity"]))
    integer(original["bytes"], 65536, 1)
    baseline = hex_value(row["baselineSha256"])
    need(hex_value(original["sha256"]) == baseline)
    app_absence_phase(row["baselineObservation"], context, "baseline", binding, baseline)
    image = row["image"]
    need(type(image) is dict and set(image) == {"bytes", "sha256"})
    size = integer(image["bytes"], 2560 * 1024 * 1024, 1)
    initial = row["initial"]
    need(type(initial) is dict and set(initial) == {"requestId", "invocation", "stateSha256", "resultSha256", "instance"})
    for key in ("requestId", "invocation", "instance"):
        hex_value(initial[key], 32)
    hex_value(initial["stateSha256"])
    return {"binding": binding, "preparationReceiptSha256": hex_value(row["preparationReceiptSha256"]),
        "baselineSha256": baseline, "initialResultSha256": hex_value(initial["resultSha256"]),
        "imageSha256": hex_value(image["sha256"]), "imageBytes": size, "initialFreshInstall": True,
        "originalBaselineZero": True, "originalMountDetached": True, "nativeCalls": len(APP_ABSENCE_PACKAGE_ROLES),
        "fixturePackageSha256": fixture["sha256"], "fixturePackageBytes": fixture["bytes"]}


def project_app_absence_receipt(value, context, phase, raw_sha):
    roles = APP_ABSENCE_PREPARE_ROLES if phase == "prepare-app-absence" else APP_ABSENCE_RESTORE_ROLES
    need(phase in ("prepare-app-absence", "app-absence-restore"))
    app_absence_owner(value, context, phase, roles)
    result = {"receiptState": "observed", "receiptSha256": raw_sha, "nativeCalls": len(roles),
              "originalClosesKnown": True, "originalCallerRequired": True, "productReady": False}
    if phase == "prepare-app-absence":
        need("appAbsencePreparation" in value)
        row = value["appAbsencePreparation"]
        need(type(row) is dict and set(row) == {"fixtureSource", "productSource", "runId", "runAttempt", "target",
             "fixtureExecutableSha256", "fixtureExecutableBytes", "fixturePackageSha256", "fixturePackageBytes", "inventorySha256",
             "runtimeManifestSha256", "protocolSha256", "cargoMessagesSha256", "pureDataTests", "archiveAudited", "adHocOnly", "productReady"}
             and all(row.get(k) == v for k, v in {"fixtureSource": context["source"], "productSource": context["source"],
            "runId": context["runId"], "runAttempt": context["runAttempt"], "target": context["target"]}.items())
            and row.get("archiveAudited") is True and row.get("adHocOnly") is True and row.get("productReady") is False)
        result.update({k: hex_value(row[k]) for k in ("fixtureExecutableSha256", "fixturePackageSha256", "inventorySha256", "runtimeManifestSha256", "protocolSha256")})
        result["fixtureExecutableBytes"] = integer(row["fixtureExecutableBytes"], 64*1024*1024, 1)
        result["fixturePackageBytes"] = integer(row["fixturePackageBytes"], 512*1024*1024, 28)
        tests = row["pureDataTests"]
        names = ("fixed_transport_and_same_source_bindings", "initial_fresh_install_and_same_gate_not_name_only",
                 "output_quote_and_original_exit_finality_are_separate", "actual_restore_requires_new_app_and_exact_initial_history",
                 "exclusive_rename_metadata_and_record_bounds_are_not_identity_reset",
                 "phase_observations_are_pending_outer_exit_and_keep_private_fields_private")
        need(type(tests) is dict and set(tests) == {"schemaVersion", "kind", "methodNames", "testCount", "passed", "failed", "ignored",
             "filteredCount", "stdoutSha256", "stderrSha256", "productReady"}
             and tests["kind"] == "fixture-rust-data-test-observation" and tests["productReady"] is False
             and tests["methodNames"] == ["installer::worker::app_absence_fixture::tests::" + name for name in names]
             and all(type(tests[k]) is int and tests[k] == v for k, v in (("schemaVersion", 1), ("testCount", 6), ("passed", 6), ("failed", 0), ("ignored", 0))))
        need(all(tests[k] == value["originalCalls"][1].get(k) for k in ("stdoutSha256", "stderrSha256")))
        result["pureDataTests"] = {"passed": 6, "failed": 0, "ignored": 0, "filteredCount": integer(tests["filteredCount"], 999999),
            "stdoutSha256": hex_value(tests["stdoutSha256"]), "stderrSha256": hex_value(tests["stderrSha256"])}
        return result
    need("appAbsenceRestore" in value)
    row = value["appAbsenceRestore"]
    need(type(row) is dict and set(row) == {"schemaVersion", "binding", "preparationReceiptSha256", "baselineOwnerReceiptSha256",
         "imageSha256", "baselineSha256", "initialResultSha256", "restoreResultSha256", "withdraw", "verify", "initialFreshInstall",
         "restoreFixedAppObserved", "immediatePredecessorMatched", "currentBytesVerified", "initialHistoryPreserved", "beforeExportCount",
         "afterExportCount", "newExportCount", "verifiedCurrentFiles", "originalInstallerReturnedZero", "originalMountDetached",
         "retainedPrivateEvidence", "systemServiceExitClaimed", "productReady"}
         and type(row.get("schemaVersion")) is int and row["schemaVersion"] == 1
         and all(row.get(k) is True for k in ("initialFreshInstall", "restoreFixedAppObserved", "immediatePredecessorMatched",
             "currentBytesVerified", "initialHistoryPreserved", "originalInstallerReturnedZero", "originalMountDetached", "retainedPrivateEvidence"))
         and row.get("systemServiceExitClaimed") is False and row.get("productReady") is False
         and all(type(row.get(k)) is int and row[k] == v for k, v in (("beforeExportCount", 1), ("afterExportCount", 2), ("newExportCount", 1))))
    binding = app_absence_binding(row["binding"], context)
    baseline = hex_value(row["baselineSha256"])
    for phase in ("withdraw", "verify"):
        app_absence_phase(row[phase], context, phase, binding, baseline)
    result.update(binding=binding, **{k: hex_value(row[k]) for k in ("preparationReceiptSha256", "baselineOwnerReceiptSha256", "imageSha256",
        "baselineSha256", "initialResultSha256", "restoreResultSha256")})
    result.update(verifiedCurrentFiles=integer(row["verifiedCurrentFiles"], 4096, 1), retainedPrivateEvidence=True)
    return result


def app_absence_join(prepare, restore, baseline, statuses):
    need(all(type(row) is dict and row.get("receiptState") == "observed" for row in (prepare, restore, baseline))
         and all(type(row) is dict and row.get("receiptState") == "observed" and type(row.get("returncode")) is int
                 and row["returncode"] == 0 for row in statuses))
    prior = baseline.get("appAbsenceBaseline")
    need(type(prior) is dict and prior["nativeCalls"] == len(APP_ABSENCE_PACKAGE_ROLES) and prepare["nativeCalls"] == 7 and restore["nativeCalls"] == 5
         and prior["preparationReceiptSha256"] == restore["preparationReceiptSha256"] == prepare["receiptSha256"]
         and restore["baselineOwnerReceiptSha256"] == baseline["receiptSha256"]
         and restore["binding"] == prior["binding"]
         and prepare["fixturePackageSha256"] == prior["fixturePackageSha256"]
         and prepare["fixturePackageBytes"] == prior["fixturePackageBytes"]
         and all(restore[k] == prior[k] for k in ("baselineSha256", "imageSha256", "initialResultSha256"))
         and all(prepare[k] == prior["binding"][k] for k in ("fixtureExecutableSha256", "inventorySha256", "runtimeManifestSha256", "protocolSha256")))
    return {"receiptState": "observed", "proofComplete": True, "nativeCalls": {"prepare": 7, "baseline": len(APP_ABSENCE_PACKAGE_ROLES), "restore": 5},
            **{k: prior["binding"][k] for k in ("packageSha256", "inventorySha256", "runtimeManifestSha256")},
            "initialResultSha256": prior["initialResultSha256"], "restoreResultSha256": restore["restoreResultSha256"],
            "retainedPrivateEvidence": True, "systemServiceExitClaimed": False, "downloadedLaunchQualified": False,
            "guiQualified": False, "productReady": False}


NATIVE_ROLES = NATIVE_ROLES | frozenset(APP_ABSENCE_PREPARE_ROLES + APP_ABSENCE_PACKAGE_ROLES + APP_ABSENCE_RESTORE_ROLES)


def project_update(value, context, phase):
    row = value.get("updateBaseline" if phase == "update-baseline" else "positiveUpdate")
    if row is None:
        return None
    need(phase in ("update-baseline", "package-install") and type(row) is dict
         and type(row.get("schemaVersion")) is int and row["schemaVersion"] == 1
         and value.get("passed") is True and value.get("originalClosesKnown") is True
         and value.get("targetRetired") is True and row.get("productReady") is False)
    for name in ("source", "workflowSource", "runId", "runAttempt", "target"):
        need(type(row.get(name)) is str and row[name] == context[name])
    predecessor = hex_value(row.get("predecessorSource"), 40)
    need(predecessor != context["source"])
    calls = value.get("originalCalls")
    need(type(calls) is list and all(type(v) is dict and v.get("entered") is True
         and v.get("returned") is True and v.get("capturesSettled") is True
         and type(v.get("returncode")) is int and (v["returncode"] == 0
         or phase == "package-install" and v.get("role") in ("installer-log-cursor", "installer-log-capture")
         and v["returncode"] == 1) for v in calls))
    common = {"predecessorSource": predecessor, "productReady": False}
    if phase == "update-baseline":
        need(tuple(v.get("role") for v in calls) == ("update-baseline-attach", "update-baseline-installer", "update-baseline-detach")
             and value.get("credentialOriginals") == [] and value.get("credentialContexts") == []
             and row.get("originalInstallerReturnedZero") is True and row.get("originalMountDetached") is True
             and row.get("freshCurrentBytesReadback") is True)
        readback = row.get("readback")
        need(type(readback) is dict and set(readback) == {"previous", "rootIdentity", "generation"})
        previous = readback["previous"]
        need(type(previous) is dict and set(previous) == {"invocation", "sha256"})
        return {**common, "invocation": hex_value(previous.get("invocation"), 32),
                "stateSha256": hex_value(previous.get("sha256")),
                "qualificationEvidenceSha256": hex_value(row.get("qualificationEvidenceSha256")),
                "expectedCurrentDescriptorSha256": hex_value(row.get("expectedCurrentDescriptorSha256")),
                "predecessorPackageSha256": hex_value(row.get("predecessorPackageSha256")),
                "freshCurrentBytesReadback": True, "originalMountDetached": True}
    required_true = ("rootIdentityPreserved", "generationInstancesDistinct", "previousExportUnchanged",
                     "testedAppDataOriginalPreserved", "originalCurrentInstallerReturnedZero", "originalMountDetached", "currentPayloadReadback")
    required_false = ("retainedPayloadRehashed", "downloadedLaunchQualified", "allUserDataCompatible", "productReady")
    need(all(row.get(k) is True for k in required_true) and all(row.get(k) is False for k in required_false)
         and type(row.get("exportCount")) is int and row["exportCount"] == 2
         and tuple(v.get("role") for v in calls) == ("producer-tests", "producer-build", "producer-emitter", "distribution-create", "distribution-sign",
             "distribution-verify-signature", "distribution-verify-image", "observation-create", "observation-sign",
             "observation-verify-signature", "observation-verify-image", "distribution-attach", "installer-log-cursor",
             "installer", "installer-log-capture", "distribution-detach"))
    old, new = hex_value(row.get("baselineInvocation"), 32), hex_value(row.get("currentInvocation"), 32)
    need(old != new)
    return {**common, "baselineInvocation": old, "currentInvocation": new,
            "predecessorPackageSha256": hex_value(row.get("predecessorPackageSha256")),
            "predecessorQualificationEvidenceSha256": hex_value(row.get("predecessorQualificationEvidenceSha256")),
            "currentDescriptorSha256": hex_value(row.get("currentDescriptorSha256")),
            **{k: True for k in required_true}, **{k: False for k in required_false}, "exportCount": 2}


def update_join(baseline, current):
    if baseline.get("updateObservation") is None and current.get("updateObservation") is None:
        return {"receiptState": "absent"}
    for phase in (baseline, current):
        status = phase.get("callerStatus")
        need(phase.get("receiptState") == "observed" and phase.get("recordedPassed") is True
             and type(status) is dict and status.get("receiptState") == "observed"
             and type(status.get("returncode")) is int and status["returncode"] == 0
             and type(phase.get("updateObservation")) is dict)
    old, new = baseline["updateObservation"], current["updateObservation"]
    need(old["predecessorSource"] == new["predecessorSource"] and old["invocation"] == new["baselineInvocation"]
         and old["qualificationEvidenceSha256"] == new["predecessorQualificationEvidenceSha256"]
         and old["predecessorPackageSha256"] == new["predecessorPackageSha256"]
         and old["expectedCurrentDescriptorSha256"] == new["currentDescriptorSha256"])
    return {"receiptState": "observed", "baseline": old, "current": new,
            "qualification": "two-generation-Installer-and-synthetic-app-data-observed-not-GUI-or-download-acceptance",
            "productReady": False}


def project_package_staple(value):
    flags = {"heldPreIdentityMatched", "namedPreIdentityMatched", "fdNameIdentityMatched",
             "fdNameMetadataMatched", "namedShapeExpected"}
    need(type(value) is dict and set(value) == flags | {"heldLinkState", "selectedBranch", "transitionComplete"}
         and all(value[key] is None or type(value[key]) is bool for key in flags)
         and type(value["transitionComplete"]) is bool
         and type(value["heldLinkState"]) is str and value["heldLinkState"] in ("unavailable", "single", "unlinked", "other")
         and type(value["selectedBranch"]) is str and value["selectedBranch"] in ("unavailable", "same-original", "returned-output"))
    need(not value["transitionComplete"] or all(type(value[key]) is bool for key in flags)
         and value["heldPreIdentityMatched"] and value["namedShapeExpected"]
         and ((value["selectedBranch"], value["heldLinkState"], value["namedPreIdentityMatched"],
               value["fdNameIdentityMatched"], value["fdNameMetadataMatched"])
              in (("same-original", "single", True, True, True),
                  ("returned-output", "unlinked", False, False, False))))
    return dict(value)



def project_final_image_unlink(value):
    need(type(value) is dict and set(value) == set(FINAL_IMAGE_UNLINK_FLAGS) | {"state", "outputAdopted", "transitionComplete"}
         and type(value["state"]) is str and value["state"] in ("observed", "refused")
         and value["outputAdopted"] is False and value["transitionComplete"] is False
         and all(value[name] is None or type(value[name]) is bool for name in FINAL_IMAGE_UNLINK_FLAGS))
    if value["state"] == "observed":
        need(all(type(value[name]) is bool for name in FINAL_IMAGE_UNLINK_FLAGS)
             and all(value[name] is True for name in ("retainedPreIdentityExpected", "retainedPreLinkUnlinked",
                 "namedExists", "parentStable", "censusStable", "retainedPreBytesUnchanged", "namedPostStable")))
    return dict(value)


def project_receipt(value, context, phase):
    need(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1)
    for name in ("source", "workflowSource", "runId", "runAttempt", "target"):
        need(type(value.get(name)) is str and value[name] == context[name])
    need(type(value.get("phase")) is str and value["phase"] == phase and type(value.get("passed")) is bool)
    need(not value["passed"] or value.get("failure") is None)
    need(phase == "prepare-removal-observers" or "originalCalls" in value
         and "credentialOriginals" in value and "credentialContexts" in value)
    result = {"receiptState": "observed", "recordedPassed": value["passed"], "correlationMatches": True,
              **{name: boolean(value.get(name)) for name in BOOL_FIELDS}}
    result["originalCalls"] = project_calls(value.get("originalCalls"))
    result["credentialOriginals"] = project_calls(value.get("credentialOriginals"), credential=True)
    contexts = value.get("credentialContexts")
    if type(contexts) is int:  # Existing closed removal-observer preparation projection.
        result["credentialContextCount"] = integer(contexts, 16)
        result["credentialContexts"] = None
    elif contexts is None:
        result["credentialContextCount"] = result["credentialContexts"] = None
    else:
        need(type(contexts) is list and len(contexts) <= 16)
        projected = []
        for row in contexts:
            need(type(row) is dict)
            projected.append({"purpose": token(row.get("purpose"), PURPOSES),
                **{name: optional(row, name, boolean) for name in ("retired", "closed", "searchRestored", "defaultUnchanged")}})
        result["credentialContextCount"], result["credentialContexts"] = len(contexts), projected
    result.update({name: optional(value, name, integer) for name in ("nativeCalls", "credentialCalls")})
    result.update({name: optional(value, name, hex_value) for name in
        ("nativeCallsSha256", "credentialCallsSha256", "observerProgramSha256", "finalPackageReceiptSha256")})
    auth = value.get("notaryAuthentication")
    need(auth is None or type(auth) is dict)
    result["notaryAuthentication"] = None if auth is None else {
        name: optional(auth, name, boolean) for name in ("created", "closed", "retired")}
    submission = value.get("notarySubmission")
    need(submission is None or type(submission) is dict)
    result["notarySubmission"] = None
    if submission is not None:
        need(type(submission.get("status")) is str and submission["status"] in ("Accepted", "Invalid"))
        result["notarySubmission"] = {"id": uuid_value(submission.get("id")), "status": submission["status"]}
    result["packageStapleObservation"] = None
    if "packageStapleObservation" in value:
        need(phase in ("finalize-package", "finalize-remove-package", "prepare-removal-observers"))
        result["packageStapleObservation"] = project_package_staple(value["packageStapleObservation"])
    for name in ("payloadNotarization", "finalPackage", "finalImage"):
        final = value.get(name)
        result[name] = project_final(final)
        if final is not None:
            if "target" in final:
                need(final["target"] == context["target"])
            if submission is not None:
                need(final.get("submissionId") == submission["id"] and final.get("status") == submission["status"])
            if name != "payloadNotarization":
                kind = (("mrk-final-remover-package" if "remove" in phase else "mrk-final-installer-package")
                        if name == "finalPackage" else
                        ("mrk-final-removal-image" if "remove" in phase else "mrk-final-user-image"))
                need(type(final.get("schemaVersion")) is int and final["schemaVersion"] == 1 and final.get("kind") == kind)
    mount = value.get("finalImageMount")
    need(mount is None or type(mount) is dict)
    result["finalImageMount"] = None if mount is None else {name: optional(mount, name, boolean) for name in
        ("attachEntered", "originalKnown", "detached", "retained", "installerEntered", "systemServiceExitClaimed")}
    if phase == "same-package-noop":
        result["samePackageObservation"] = project_same_package(value, context)
    else:
        need(value.get("samePackageObservation") is None)
    if value.get("appAbsenceBaseline") is not None:
        need(phase == "package-install")
        result["appAbsenceBaseline"] = project_app_absence_baseline(value, context)
    if phase in ("update-baseline", "package-install"):
        result["updateObservation"] = project_update(value, context, phase)
    else:
        need(value.get("updateBaseline") is None and value.get("positiveUpdate") is None)
    result["failure"] = project_failure(value.get("failure"))
    result["finalImageUnlinkObservation"] = None
    if "finalImageUnlinkObservation" in value:
        failure = result["failure"]
        calls = value.get("originalCalls")
        need(phase == "finalize-image" and value["passed"] is False
             and result["originalClosesKnown"] is False and result["targetRetired"] is False
             and result["finalImage"] is None and type(failure) is dict
             and failure["type"] == "Refused" and failure["reason"] == "final-image-stapled-original"
             and failure["stage"] == "final-image-staple-held-links-unlinked"
             and result["notarySubmission"] is not None and result["notarySubmission"]["status"] == "Accepted"
             and type(calls) is list and len(calls) == 6
             and all(type(row) is dict and row.get("returned") is True and row.get("capturesSettled") is True
                 and type(row.get("returncode")) is int and row["returncode"] == 0 for row in calls)
             and tuple(row.get("role") for row in calls) == ("final-image-resolve-notarytool", "final-image-resolve-stapler",
                 "final-image-signature-before", "final-image-submit", "final-image-log", "final-image-staple"))
        result["finalImageUnlinkObservation"] = project_final_image_unlink(value["finalImageUnlinkObservation"])
    removal = value.get("removalFixture")
    need(removal is None or phase == "package-removal-fixture")
    if phase == "package-removal-fixture":
        result["removalFixture"] = project_removal_fixture(removal, context, value.get("originalCalls"))
    return result


def project_inventory(value, body, context, *, collect_paths=None):
    need(set(value) == {"source", "tree", "files"} and value["source"] == context["source"])
    tree = hex_value(value["tree"], 40)
    rows = value["files"]
    need(type(rows) is list and 0 < len(rows) <= 4095)
    paths = set()
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "gitMode", "blob", "size", "sha256"})
        path = row["path"]
        need(type(path) is str and 0 < len(path) <= 4096 and not path.startswith("/")
             and all(part not in ("", ".", "..") for part in path.split("/")) and path not in paths
             and row["gitMode"] in ("100644", "100755"))
        paths.add(path)
        hex_value(row["blob"], 40); hex_value(row["sha256"]); integer(row["size"], 32 * 1024 * 1024)
    if collect_paths is not None:
        collect_paths.update(paths)  # Only after EVERY inventory row passed; no partial attribution.
    return {"receiptState": "observed", "tree": tree, "fileCount": len(rows), "sha256": hashlib.sha256(body).hexdigest()}


def project_summary(value, context, removal):
    need(value.get("sourceCommit") == context["source"] and value.get("runId") == context["runId"]
         and value.get("runAttempt") == context["runAttempt"])
    need(type(value.get("schemaVersion")) is int and value["schemaVersion"] == (1 if removal else 2))
    if removal:
        need(value.get("kind") == "mrk-removal-carrier-preview-v1" and value.get("target") == context["target"])
    else:
        need(value.get("scope") == "normal-macos-early-preview" and value.get("platform") ==
             ("macOS26-arm64" if context["target"] == TARGETS[0] else "macOS26-x86_64"))
    result = {"receiptState": "observed", "sourceTree": hex_value(value.get("sourceTree"), 40)}
    result.update({name: optional(value, name, hex_value) for name in SUMMARY_HASHES if name in value})
    result.update({name: optional(value, name, boolean) for name in SUMMARY_BOOLS if name in value})
    result.update({name: optional(value, name, lambda item: integer(item, 2**40))
                   for name in ("packageSize", "packageBytes", "distributionBytes") if name in value})
    return result


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def open_root(work):
    need(type(work) is str and work.startswith("/") and len(work) <= 4096
         and all(part not in ("", ".", "..") for part in work[1:].split("/")))
    fd = os.open("/", READ_FLAGS | os.O_DIRECTORY)
    try:
        for part in work[1:].split("/"):
            child = os.open(part, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
            old, fd = fd, child
            os.close(old)  # A failed close is fatal, never retried.
        value = os.fstat(fd)
        need(value.st_uid == os.geteuid() and not value.st_mode & 0o022)
        return fd
    except BaseException:
        os.close(fd)
        raise


PACKAGE_SIGNATURE_CAPTURES = (
    ("before", "android-helper-final-package-signature-before.stdout", "final-package-signature-before"),
    ("after", "android-helper-final-package-signature-after.stdout", "final-package-signature-after"),
)
PACKAGE_SIGNATURE_CAPTURE_LIMIT = 65536


def reserve_package_signature_reads(budget):
    """Precharge both fixed attempts and full raw bounds, even when absent."""
    clock(budget)
    need("packageSignatureReads" not in budget)
    charge = len(PACKAGE_SIGNATURE_CAPTURES) * (PACKAGE_SIGNATURE_CAPTURE_LIMIT + 1)
    need(budget["files"] + len(PACKAGE_SIGNATURE_CAPTURES) <= 128
         and budget["bytes"] + charge <= INPUT_LIMIT)
    budget["files"] += len(PACKAGE_SIGNATURE_CAPTURES)
    budget["bytes"] += charge
    budget["packageSignatureReads"] = {name: True for _, name, _ in PACKAGE_SIGNATURE_CAPTURES}


def package_signature_preamble(body):
    """Finite structural diagnostics only; never trust or chain acceptance."""
    need(type(body) is bytes and 0 < len(body) <= PACKAGE_SIGNATURE_CAPTURE_LIMIT and body.endswith(b"\n"))
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        raise Refused("public-evidence-refused") from None
    need(all(character in "\n\t" or character.isprintable() for character in text))
    lines = [line.strip(" \t") for line in text.splitlines() if line.strip(" \t")]
    need(0 < len(lines) <= 256 and all(len(line) <= 1024 for line in lines))
    trusted = {"Status: signed by a certificate trusted by macOS": "macOS",
               "Status: signed by a certificate trusted by Mac OS X": "macOSX",
               "Status: signed by a developer certificate issued by Apple for distribution": "appleDistribution"}
    statuses = [i for i, line in enumerate(lines) if line.startswith("Status: ")]
    timestamps = [i for i, line in enumerate(lines) if line.startswith("Signed with a trusted timestamp on: ")]
    chains = [i for i, line in enumerate(lines) if line == "Certificate Chain:"]
    notaries = [i for i, line in enumerate(lines) if line.startswith("Notarization: ")]
    return {"lineCount": len(lines), "formatBounded": True,
        "statusCount": len(statuses), "statusIndex": statuses[0] if statuses else -1,
        "statusClass": trusted.get(lines[statuses[0]], "other") if len(statuses) == 1 else "absent" if not statuses else "other",
        "statusAtIndex1Accepted": len(lines) > 1 and lines[1] in trusted,
        "trustedTimestampCount": len(timestamps), "trustedTimestampIndex": timestamps[0] if timestamps else -1,
        "trustedTimestampSuffixBounded": bool(timestamps) and all(0 < len(lines[i][len("Signed with a trusted timestamp on: "):]) <= 128 for i in timestamps),
        "trustedTimestampAtIndex2": 2 in timestamps,
        "chainMarkerCount": len(chains), "chainMarkerIndex": chains[0] if chains else -1, "chainMarkerAtIndex3": 3 in chains,
        "notarizationCount": len(notaries), "notarizationIndex": notaries[0] if notaries else -1,
        "notarizationClass": "trustedByMacOS" if len(notaries) == 1 and lines[notaries[0]] == "Notarization: trusted by macOS" else "absent" if not notaries else "other"}


def project_package_signature_diagnostic(captures, phase):
    need(type(captures) is dict and set(captures) == {key for key, _, _ in PACKAGE_SIGNATURE_CAPTURES}
         and type(phase) is dict and phase.get("receiptState") == "observed"
         and phase.get("correlationMatches") is True and phase.get("recordedPassed") is False)
    caller = phase.get("callerStatus")
    need(type(caller) is dict and caller.get("receiptState") == "observed"
         and type(caller.get("returncode")) is int and caller["returncode"] != 0)
    failure = phase.get("failure")
    need(type(failure) is dict and failure.get("type") == "Refused"
         and failure.get("stage") == "final-package-signature-after"
         and failure.get("reason") == "package-signature-trust-timestamp")
    originals = phase.get("originalCalls")
    need(type(originals) is dict and type(originals.get("unclassifiedCount")) is int
         and originals["unclassifiedCount"] == 0)
    calls = originals.get("calls")
    need(type(calls) is list and len(calls) <= 128 and all(type(row) is dict for row in calls)
         and type(originals.get("recordedCount")) is int and originals["recordedCount"] == len(calls))
    entered = [row for row in calls if row.get("entered") is True]
    result = {"receiptState": "observed", "diagnosticOnly": True, "nativeSuccessInferred": False,
              "policyUnchanged": True, "binding": "same-source-run-target-failed-original"}
    empty = hashlib.sha256(b"").hexdigest()
    for key, _, role in PACKAGE_SIGNATURE_CAPTURES:
        body = captures[key]
        need(type(body) is bytes and 0 < len(body) <= PACKAGE_SIGNATURE_CAPTURE_LIMIT)
        selected = [row for row in calls if row.get("role") == role]
        need(len(selected) == 1)
        call = selected[0]
        need(call.get("entered") is True and call.get("returned") is True and call.get("capturesSettled") is True
             and type(call.get("returncode")) is int and call["returncode"] == 0
             and call.get("stderrSha256") == empty and type(body) is bytes
             and call.get("stdoutSha256") == hashlib.sha256(body).hexdigest())
        if key == "after":
            need(entered and entered[-1] is call)
        result[key] = package_signature_preamble(body)
    return result


INSTALLER_DIAGNOSTIC_INPUTS = ("installer-log-capture.json", "installer-log-selected.txt")
INSTALLER_DIAGNOSTIC_LIMIT = 256 * 1024
INSTALLER_LOG_AUTHORITY = "project-correlated-diagnostics-not-package-pid-authentication-or-original-fd-custody"
INSTALLER_LOG_KEYS = ("package-identifier", "package-path", "native-executable", "fixture-result", "ordinary-result",
                      "postinstall-phase", "postinstall-refusal", "acl-diagnostic")
INSTALLER_PARENT_KEY = "completed-parent-diagnostic"
INSTALLER_DIAGNOSTIC_REFUSAL_STAGES = ('metadata-original-read', 'selected-original-read', 'original-caller', 'metadata-original-hash', 'metadata-decode', 'metadata-schema', 'preceding-originals', 'payload-originals', 'finalizer-caller', 'finalizer-receipt-hash', 'payload-acceptance', 'binding-schema', 'binding-context', 'binding-path', 'capture-unavailable-schema', 'captured-schema', 'log-identity', 'interval', 'row-list', 'selected-body-hash', 'selector-catalog', 'row-shape', 'row-bounds', 'row-hash', 'row-anchors', 'acl-row-bound', 'parent-row-bound', 'count-correspondence', 'result-state')
INSTALLER_LOG_REFUSALS = frozenset(("log-input-binding", "log-file-policy", "log-file-identity", "log-cursor-shape",
    "log-cursor-binding", "log-cursor-offset", "log-anchor-rewritten", "log-truncated", "log-incomplete-boundary",
    "log-interval-bound", "log-line-bound", "log-selected-bound", "log-metadata-bound", "log-no-project-lines",
    "log-read-incomplete", "log-output-readback", "original-close-unknown", "ancestor-close-unknown",
    "log-input-or-capture-unavailable", "log-output-unavailable"))


def reserve_installer_diagnostic_reads(budget):
    """Exactly two fixed attempts/full bounds, charged before any original read."""
    clock(budget)
    need("installerDiagnosticReads" not in budget)
    charge = len(INSTALLER_DIAGNOSTIC_INPUTS) * (INSTALLER_DIAGNOSTIC_LIMIT + 1)
    need(budget["files"] + 2 <= 128 and budget["bytes"] + charge <= INPUT_LIMIT)
    budget["files"] += 2
    budget["bytes"] += charge
    budget["installerDiagnosticReads"] = {name: True for name in INSTALLER_DIAGNOSTIC_INPUTS}


def decode_installer_diagnostic(body, budget):
    # Genuine log metadata can exceed generic16KiB/list128. This separate
    # fixed grammar does not broaden any other input or claim preparse RSS.
    need(type(body) is bytes and 0 < len(body) <= INSTALLER_DIAGNOSTIC_LIMIT)
    def pairs(rows):
        need(len(rows) <= 32 and len({key for key, _ in rows}) == len(rows))
        return dict(rows)
    def number(raw):
        need(len(raw) <= 20)
        return int(raw)
    def no_float(_raw):
        raise Refused("public-evidence-refused")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_int=number,
                           parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("public-evidence-refused") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1; budget["nodes"] += 1
        need(depth <= 16 and count <= 65536 and budget["nodes"] <= JSON_NODE_LIMIT)
        if type(item) is dict:
            need(len(item) <= 32)
            pending.extend((part, depth + 1) for pair in item.items() for part in pair)
        elif type(item) is list:
            need(len(item) <= 2048)
            pending.extend((part, depth + 1) for part in item)
        elif type(item) is str:
            need(len(item.encode("utf-8")) <= 4096)
        else:
            need(item is None or type(item) in (bool, int))
    need(type(value) is dict)
    clock(budget)
    return value


def installer_log_patterns(binding, *, completed_parent):
    """Exact selector SOURCE grammars; no arbitrary raw token rendering."""
    need(type(completed_parent) is bool)
    def bounded_token(value, path=False):
        chars = rb"A-Za-z0-9._+~%/-" if path else rb"A-Za-z0-9._+-"
        return re.compile(rb"(?<![" + chars + rb"])" + re.escape(value) + rb"(?![" + chars + rb"])")
    patterns = {
        "package-identifier": bounded_token(binding["packageIdentifier"].encode()),
        "package-path": bounded_token(binding["packagePath"].encode(), path=True),
        "native-executable": bounded_token(b"mrk-macos-install"),
        "fixture-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_FIXTURE_RESULT="),
        "ordinary-result": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_RESULT="),
        "postinstall-phase": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_PHASE=(?:entry|target-ok|relative-entry|absolute-entry|cwd-ok|pre-exec)(?![A-Za-z0-9_-])"),
        "postinstall-refusal": re.compile(rb"(?<![A-Za-z0-9_])MRK_MACOS_POSTINSTALL_REFUSED=(?:target|entry|cwd)(?![A-Za-z0-9_-])"),
        "acl-diagnostic": re.compile(
            rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role="
            rb"(?:input-directory|input-inventory|system-root|system-library|system-support|other-protected-object);phase="
            rb"(?:filesec-allocation|fstatx-snapshot|snapshot-owner|snapshot-group|snapshot-mode|acl-presence|acl-conversion|"
            rb"acl-object|acl-validation|acl-first-entry|acl-entry-present|acl-free|ffi-output)"
            rb";result=-?[0-9]{1,10};call=-?[0-9]{1,10};errno=-?[0-9]{1,10};freeCall=-?[0-9]{1,10};freeErrno=-?[0-9]{1,10}(?=\r?\n$)"),
    }
    if completed_parent:
        patterns[INSTALLER_PARENT_KEY] = re.compile(
            rb"(?<![A-Za-z0-9_])MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=[0-9a-f]{64};exit=(?:1|20)"
            rb";originals=[01];native=[01];timely=[01];unknown=[01](?=\r?\n$)")
    if completed_parent:
        # The genuine selector inserts this ninth anchor before postinstall/ACL.
        patterns = {key: patterns[key] for key in (*INSTALLER_LOG_KEYS[:5], INSTALLER_PARENT_KEY, *INSTALLER_LOG_KEYS[5:])}
    return patterns


def installer_failure_originals(phase, statuses):
    need(type(phase) is dict and phase.get("receiptState") == "observed"
         and phase.get("correlationMatches") is True and phase.get("recordedPassed") is False)
    caller = phase.get("callerStatus")
    need(type(caller) is dict and caller.get("receiptState") == "observed"
         and type(caller.get("returncode")) is int and caller["returncode"] != 0)
    failure = phase.get("failure")
    need(type(failure) is dict and failure.get("type") == "Refused"
         and failure.get("stage") == "standard-original-installer"
         and failure.get("reason") == "original-nonzero-installer")
    originals = phase.get("originalCalls")
    need(type(originals) is dict and type(originals.get("unclassifiedCount")) is int
         and originals["unclassifiedCount"] == 0)
    calls = originals.get("calls")
    need(type(calls) is list and len(calls) <= 128 and all(type(row) is dict for row in calls)
         and type(originals.get("recordedCount")) is int and originals["recordedCount"] == len(calls))
    roles = ("installer-log-cursor", "installer", "installer-log-capture")
    selected = []
    for role, allowed, name in zip(roles, ((0,), (1,), (0, 1)),
                                  ("installer-log-cursor.status", "installer-output.status", "installer-log-capture.status")):
        matches = [row for row in calls if row.get("role") == role]
        need(len(matches) == 1)
        row = matches[0]
        need(all(row.get(key) is True for key in ("entered", "returned", "capturesSettled"))
             and type(row.get("returncode")) is int and row["returncode"] in allowed)
        observed = statuses.get(name)
        need(type(observed) is dict and observed.get("receiptState") == "observed"
             and type(observed.get("returncode")) is int and observed["returncode"] == row["returncode"])
        hex_value(row.get("stdoutSha256")); hex_value(row.get("stderrSha256"))
        selected.append(row)
    entered = [row for row in calls if row.get("entered") is True]
    need(len(entered) >= 3 and all(entered[-3 + i] is row for i, row in enumerate(selected)))
    empty = hashlib.sha256(b"").hexdigest()
    need(selected[0]["stderrSha256"] == empty and selected[2]["stderrSha256"] == empty)
    return selected


def project_installer_failure_diagnostic(metadata_body, selected_body, phase, statuses, context, payload, finalized, budget):
    """Same failed original/project-correlated selection, never Installer success."""
    budget["installerDiagnosticStage"] = "original-caller"
    cursor, installer, capture = installer_failure_originals(phase, statuses)
    budget["installerDiagnosticStage"] = "metadata-original-hash"
    need(type(metadata_body) is bytes and capture["stdoutSha256"] == hashlib.sha256(metadata_body).hexdigest())
    budget["installerDiagnosticStage"] = "metadata-decode"
    metadata = decode_installer_diagnostic(metadata_body, budget)
    budget["installerDiagnosticStage"] = "metadata-schema"
    need(type(metadata.get("schemaVersion")) is int and metadata["schemaVersion"] == 1
         and metadata.get("kind") == "installer-log-capture" and metadata.get("authority") == INSTALLER_LOG_AUTHORITY
         and metadata.get("scriptOutputFinality") == "unestablished")
    # These are already-read original phase receipts. No self-derived anchor
    # or extra file opens; unavailable preceding facts refuse this diagnosis.
    budget["installerDiagnosticStage"] = "preceding-originals"
    for original in (payload, finalized):
        need(type(original) is dict and original.get("receiptState") == "observed"
             and original.get("correlationMatches") is True and original.get("recordedPassed") is True
             and original.get("originalClosesKnown") is True and original.get("targetRetired") is True)
    # notarize-payload has no scalar PHASE_STATUS in the existing workflow.
    # Require its actual closed successful originals, never invent a status0.
    budget["installerDiagnosticStage"] = "payload-originals"
    payload_calls = payload.get("originalCalls")
    need(type(payload_calls) is dict and type(payload_calls.get("unclassifiedCount")) is int
         and payload_calls["unclassifiedCount"] == 0 and type(payload_calls.get("calls")) is list
         and 0 < len(payload_calls["calls"]) <= 128 and type(payload_calls.get("recordedCount")) is int
         and payload_calls["recordedCount"] == len(payload_calls["calls"]))
    for call in payload_calls["calls"]:
        need(type(call) is dict and all(call.get(key) is True for key in ("entered", "returned", "capturesSettled"))
             and type(call.get("returncode")) is int and call["returncode"] == 0)
    budget["installerDiagnosticStage"] = "finalizer-caller"
    caller = finalized.get("callerStatus")
    need(type(caller) is dict and caller.get("receiptState") == "observed"
         and type(caller.get("returncode")) is int and caller["returncode"] == 0)
    budget["installerDiagnosticStage"] = "finalizer-receipt-hash"
    need(hex_value(finalized.get("receiptSha256")) == hex_value(phase.get("finalPackageReceiptSha256")))
    budget["installerDiagnosticStage"] = "payload-acceptance"
    notarized = payload.get("payloadNotarization")
    need(type(notarized) is dict and notarized.get("status") == "Accepted"
         and type(notarized.get("errorCount")) is int and notarized["errorCount"] == 0)
    inventory, manifest = hex_value(notarized.get("inventorySha256")), hex_value(notarized.get("runtimeManifestSha256"))
    budget["installerDiagnosticStage"] = "binding-schema"
    binding = metadata.get("binding")
    need(type(binding) is dict and set(binding) == {"packageKind", "packageIdentifier", "packagePath", "sourceCommit",
         "inventorySha256", "runtimeManifestSha256", "runId", "runAttempt", "requestId"})
    budget["installerDiagnosticStage"] = "binding-context"
    need(binding["packageKind"] == "ordinary" and binding["packageIdentifier"] == "dev.mobile-release-kit.desktop.installed"
         and type(binding["sourceCommit"]) is str and binding["sourceCommit"] == context["source"]
         and type(binding["runId"]) is str and binding["runId"] == context["runId"]
         and type(binding["runAttempt"]) is str and binding["runAttempt"] == context["runAttempt"]
         and binding["inventorySha256"] == inventory and binding["runtimeManifestSha256"] == manifest)
    budget["installerDiagnosticStage"] = "binding-path"
    request = hex_value(binding["requestId"], 32)
    path = binding["packagePath"]
    need(type(path) is str and path.startswith("/") and len(path.encode("utf-8")) <= 4096
         and all(ord(character) >= 32 and ord(character) != 127 for character in path)
         and all(part and part not in (".", "..") for part in path.split("/")[1:])
         and path.split("/")[-2:] == ["package-mount", "MobileReleaseKit-Request-" + request + ".pkg"])
    result = {"receiptState": "observed", "diagnosticOnly": True, "originalInstallerReturnedZero": False,
              "nativeSuccessInferred": False, "policyUnchanged": True,
              "binding": "same-source-run-target-failed-original-project-correlated",
              "metadataSha256": hashlib.sha256(metadata_body).hexdigest()}
    if capture["returncode"] == 1:
        budget["installerDiagnosticStage"] = "capture-unavailable-schema"
        need(set(metadata) == {"schemaVersion", "kind", "state", "reason", "binding", "authority",
             "scriptOutputFinality", "plannedSelectedData", "selectedOutputState"}
             and metadata["state"] == "unknown" and type(metadata["reason"]) is str
             and metadata["reason"] in INSTALLER_LOG_REFUSALS
             and metadata["selectedOutputState"] in ("not-created", "write-or-close-unknown-preserve-original"))
        planned = metadata["plannedSelectedData"]
        need(planned is None or type(planned) is dict and set(planned) == {"file", "bytes", "sha256"})
        if planned is not None:
            need(planned["file"] == INSTALLER_DIAGNOSTIC_INPUTS[1])
            integer(planned["bytes"], INSTALLER_DIAGNOSTIC_LIMIT, 1); hex_value(planned["sha256"])
        need(metadata["selectedOutputState"] != "not-created" or planned is None)
        return {**result, "captureState": "unavailable", "reason": metadata["reason"], "selectionOriginalAuthorized": False}
    budget["installerDiagnosticStage"] = "captured-schema"
    need(set(metadata) == {"schemaVersion", "kind", "state", "binding", "logPath", "identity", "cursorSha256",
         "startOffsetBytes", "endOffsetBytes", "growthBeyondSnapshotBytes", "intervalBytes", "intervalSha256",
         "linesObserved", "linesUnselected", "selectedLines", "markerCounts", "resultMarkerState", "selectedData",
         "authority", "scriptOutputFinality"} and metadata["state"] == "observed-project-correlated"
         and metadata["logPath"] == "/private/var/log/install.log" and metadata["cursorSha256"] == cursor["stdoutSha256"])
    budget["installerDiagnosticStage"] = "log-identity"
    log_id = metadata["identity"]
    need(type(log_id) is dict and set(log_id) == {"device", "inode", "mode", "uid", "gid", "links"}
         and all(type(value) is int and value >= 0 for value in log_id.values())
         and log_id["inode"] > 0 and stat.S_ISREG(log_id["mode"]) and log_id["uid"] == 0
         and log_id["links"] == 1 and not log_id["mode"] & 0o022)
    budget["installerDiagnosticStage"] = "interval"
    start = integer(metadata["startOffsetBytes"], 2**63 - 1)
    end = integer(metadata["endOffsetBytes"], 2**63 - 1, start)
    interval = integer(metadata["intervalBytes"], 1024 * 1024)
    need(end - start == interval)
    integer(metadata["growthBeyondSnapshotBytes"], 2**63 - 1); hex_value(metadata["intervalSha256"])
    observed = integer(metadata["linesObserved"], 1024 * 1024)
    unselected = integer(metadata["linesUnselected"], observed)
    budget["installerDiagnosticStage"] = "row-list"
    rows, counts, data = metadata["selectedLines"], metadata["markerCounts"], metadata["selectedData"]
    need(type(rows) is list and 0 < len(rows) <= 2048 and observed - unselected == len(rows)
         and type(counts) is dict and set(counts) in (set(INSTALLER_LOG_KEYS), set((*INSTALLER_LOG_KEYS, INSTALLER_PARENT_KEY)))
         and type(data) is dict and set(data) == {"file", "bytes", "sha256"} and data["file"] == INSTALLER_DIAGNOSTIC_INPUTS[1])
    budget["installerDiagnosticStage"] = "selected-body-hash"
    need(type(selected_body) is bytes and 0 < len(selected_body) <= INSTALLER_DIAGNOSTIC_LIMIT
         and integer(data["bytes"], INSTALLER_DIAGNOSTIC_LIMIT, 1) == len(selected_body)
         and hex_value(data["sha256"]) == hashlib.sha256(selected_body).hexdigest())
    budget["installerDiagnosticStage"] = "selector-catalog"
    parent_catalog = INSTALLER_PARENT_KEY in counts
    patterns = installer_log_patterns(binding, completed_parent=parent_catalog)
    need(tuple(patterns) == ((*INSTALLER_LOG_KEYS[:5], INSTALLER_PARENT_KEY, *INSTALLER_LOG_KEYS[5:])
         if parent_catalog else INSTALLER_LOG_KEYS))
    actual_counts = {key: 0 for key in patterns}
    for count in counts.values(): integer(count, 1024 * 1024)
    retained, last_end, acl_rows, parent_rows = 0, 0, [], []
    phase_counts = {key: 0 for key in ("entry", "target-ok", "relative-entry", "absolute-entry", "cwd-ok", "pre-exec")}
    refusal_counts = {key: 0 for key in ("target", "entry", "cwd")}
    for row in rows:
        clock(budget)
        budget["installerDiagnosticStage"] = "row-shape"
        need(type(row) is dict and set(row) == {"relativeOffsetBytes", "retainedOffsetBytes", "bytes", "sha256", "anchors"})
        budget["installerDiagnosticStage"] = "row-bounds"
        offset = integer(row["relativeOffsetBytes"], interval)
        length = integer(row["bytes"], 128 * 1024, 1)
        need(offset >= last_end and offset + length <= interval and row["retainedOffsetBytes"] == retained
             and type(row["retainedOffsetBytes"]) is int and retained + length <= len(selected_body))
        budget["installerDiagnosticStage"] = "row-hash"
        line = selected_body[retained:retained + length]
        need(line.endswith(b"\n") and b"\n" not in line[:-1] and hex_value(row["sha256"]) == hashlib.sha256(line).hexdigest())
        budget["installerDiagnosticStage"] = "row-anchors"
        matches = {key: list(pattern.finditer(line)) for key, pattern in patterns.items()}
        anchors = [key for key, matched in matches.items() if matched]
        need(type(row["anchors"]) is list and row["anchors"] == anchors and bool(anchors))
        for key, matched in matches.items(): actual_counts[key] += len(matched)
        for key, prefix, catalog in (("postinstall-phase", b"MRK_MACOS_POSTINSTALL_PHASE=", phase_counts),
                                     ("postinstall-refusal", b"MRK_MACOS_POSTINSTALL_REFUSED=", refusal_counts)):
            for match in matches[key]: catalog[match.group()[len(prefix):].decode("ascii")] += 1
        for match in matches["acl-diagnostic"]:
            budget["installerDiagnosticStage"] = "acl-row-bound"
            need(len(acl_rows) < 32)
            fields = match.group()[len(b"MRK_MACOS_INSTALL_ACL_DIAGNOSTIC="):].decode("ascii").split(";")
            values = dict(field.split("=", 1) for field in fields)
            acl_rows.append({"role": values["role"], "phase": values["phase"],
                **{key: integer(int(values[key]), 9999999999, -9999999999) for key in ("result", "call", "errno", "freeCall", "freeErrno")}})
        if parent_catalog:
            for match in matches[INSTALLER_PARENT_KEY]:
                budget["installerDiagnosticStage"] = "parent-row-bound"
                fields = match.group()[len(b"MRK_MACOS_INSTALL_COMPLETED_REFUSED="):].decode("ascii").split(";")
                parent_rows.append(dict(field.split("=", 1) for field in fields))
                need(len(parent_rows) <= 2048)
        retained += length; last_end = offset + length
    budget["installerDiagnosticStage"] = "count-correspondence"
    need(retained == len(selected_body) and actual_counts == counts)
    budget["installerDiagnosticStage"] = "result-state"
    state = "mixed" if counts["fixture-result"] else "duplicate" if counts["ordinary-result"] > 1 else "unbound" if counts["ordinary-result"] == 1 else "missing"
    need(type(metadata["resultMarkerState"]) is str and metadata["resultMarkerState"] == state)
    parent = {"state": "missing", "markerCount": len(parent_rows)}
    if len(parent_rows) == 1:
        item = parent_rows[0]
        parent.update(state="observed", reasonSha256=hex_value(item["reasonSha256"]), exit=int(item["exit"]),
                      **{key: item[key] == "1" for key in ("originals", "native", "timely", "unknown")})
    elif parent_rows:
        parent["state"] = "duplicate" if all(row == parent_rows[0] for row in parent_rows) else "conflicting"
    # Counts and fixed labels only; original-selected bytes and hidden binding
    # paths never enter the public object. Duplicates never pick a convenient row.
    return {**result, "captureState": "observed-project-correlated", "selectionOriginalAuthorized": True,
        "selectedBytes": len(selected_body), "selectedLineCount": len(rows), "selectedSha256": data["sha256"],
        "selectorCatalog": "fixed9" if parent_catalog else "fixed8", "markerCounts": dict(counts),
        "resultMarkerState": state, "postinstallPhaseCounts": phase_counts, "postinstallRefusalCounts": refusal_counts,
        "aclDiagnostics": acl_rows, "completedParentDiagnostic": parent}


def read_input(root, name, limit, budget, *, package_signature_reserved=False, installer_diagnostic_reserved=False, ordinary_ui_reserved=False):
    clock(budget)
    need(all(type(flag) is bool for flag in (package_signature_reserved, installer_diagnostic_reserved, ordinary_ui_reserved))
         and sum((package_signature_reserved, installer_diagnostic_reserved, ordinary_ui_reserved)) <= 1)
    if ordinary_ui_reserved:
        need(limit == ORDINARY_UI_LIMIT and name in {row[1] for row in ORDINARY_UI_INPUTS})
        reserved = budget.get("ordinaryUiReads")
        need(type(reserved) is dict and reserved.get(name) is True)
        reserved[name] = False
    elif installer_diagnostic_reserved:
        need(limit == INSTALLER_DIAGNOSTIC_LIMIT and name in INSTALLER_DIAGNOSTIC_INPUTS)
        reserved = budget.get("installerDiagnosticReads")
        need(type(reserved) is dict and reserved.get(name) is True)
        reserved[name] = False
    elif package_signature_reserved:
        need(type(package_signature_reserved) is bool and limit == PACKAGE_SIGNATURE_CAPTURE_LIMIT
             and name in {path for _, path, _ in PACKAGE_SIGNATURE_CAPTURES})
        reserved = budget.get("packageSignatureReads")
        need(type(reserved) is dict and reserved.get(name) is True)
        reserved[name] = False  # Consume before original open; absent attempts are not reusable.
    else:
        budget["files"] += 1
        need(budget["files"] <= 128)
    parents, directory = [], root
    try:
        parts = name.split("/")  # name is from the fixed SOURCE roster only.
        for part in parts[:-1]:
            child = os.open(part, READ_FLAGS | os.O_DIRECTORY, dir_fd=directory)
            parents.append((child, directory, part, directory_identity(os.fstat(child))))
            directory = child
            need(os.fstat(child).st_uid == os.geteuid())
        try:
            fd = os.open(parts[-1], READ_FLAGS, dir_fd=directory)
        except OSError as error:
            if error.errno == errno.ELOOP:  # No descriptor was returned.
                raise Refused("public-evidence-refused") from None
            raise
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                 and 0 < before.st_size <= limit)
            if not (package_signature_reserved or installer_diagnostic_reserved or ordinary_ui_reserved):
                budget["bytes"] += before.st_size + 1
            need(budget["bytes"] <= INPUT_LIMIT)
            body = os.pread(fd, before.st_size + 1, 0)
            need(len(body) == before.st_size and identity(before) == identity(os.fstat(fd))
                 == identity(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)))
        finally:
            os.close(fd)
        for child, parent, part, original in parents:
            need(directory_identity(os.fstat(child)) == original
                 == directory_identity(os.stat(part, dir_fd=parent, follow_symlinks=False)))
        clock(budget)
        return body
    finally:
        for child, _parent, _part, _original in reversed(parents):
            os.close(child)


# Fixed positive observations, not activation or a replacement native verifier.
POSITIVE_UI_INPUTS = (
    ("android", "normal-ui/android-signed-build-result.json", 16384, False),
    ("iosFacts", "normal-ui/ios-unsigned-archive.facts.json", 16384, False),
    ("iosTest", "normal-ui/ios-unsigned-archive-test.runner-admission.json", 32768, True),
    ("iosSummary", "normal-ui/ios-unsigned-archive-summary.command-admission.json", 32768, True),
    ("iosRecoveryFacts", "normal-ui/ios-pending-recovery.facts.json", 16384, False),
    ("iosRecoveryTest", "normal-ui/ios-pending-recovery-test.runner-admission.json", 32768, True),
    ("iosRecoverySummary", "normal-ui/ios-pending-recovery-summary.command-admission.json", 32768, True),
)
POSITIVE_UI_COUNTS = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
POSITIVE_UI_STATUSES = {
    "android": ("normal-ui/android-inputs.status", "normal-ui/android-signed-build-test.status",
                "normal-ui/android-signed-build-summary.status", "normal-ui/android-signed-build-result.status"),
    "ios": ("normal-ui/ios-unsigned-archive-test.status", "normal-ui/ios-unsigned-archive-summary.status"),
    "iosRecovery": ("normal-ui/ios-pending-recovery-test.status", "normal-ui/ios-pending-recovery-summary.status"),
}


def positive_ui_fixed(value, fixed, extra=()):
    need(type(value) is dict and set(value) == set(fixed) | set(extra)
         and all(type(value[key]) is type(item) and value[key] == item for key, item in fixed.items()))


def positive_ui_counts(value):
    positive_ui_fixed(value, POSITIVE_UI_COUNTS)
    return dict(value)


def positive_ui_facts(value, context, *, android):
    if android:
        fixed = dict(schemaVersion=1, scope="one-ordinary-local-signed-android-build", sourceCommit=context["source"],
            target=context["target"], runId=context["runId"], runAttempt=context["runAttempt"], sourceRegistrationObserved=True,
            serviceEnabledObserved=True, vendorAcknowledgementAutomated=True,
            nativeSigningVerified=True, privateOriginalsClosed=True, memorySessionDiscarded=True, parentReturncodeRequired=0,
            outputPostMatched=True, normalQuitObserved=True, releaseQualified=False)
        sizes = {"artifactBytes": 64 << 20, "outputEntries": 100000, "outputNameBytes": 2 << 20,
                 "outputLogicalBytes": 2 << 30, "moduleLogicalBytes": 1 << 30}
        hashes = ("publicCertificateSha256", "artifactSha256", "outputCensusSha256")
    else:
        fixed = dict(schemaVersion=1, scope="one-ordinary-local-unsigned-ios-archive", sourceCommit=context["source"],
            savedVersion="1.2.3", savedBuild=7, inputFiles=9, inputBytes=7264, topLevelDirectories=4,
            archiveDescendantsObserved=False, nativeResultDisplayed=True, outputPostMatched=True,
            originalsClosed=True, normalQuitObserved=True, successBeforeCutoff=True, signed=False,
            ipaExported=False, releaseQualified=False, parentReturncodeRequired=0)
        sizes = {"originalEntries": 100000, "originalBytes": 8 << 30}
        hashes = ()
    extra = {"serviceRegistrationRequested", "protectedCopyInstance"} if android else set()
    positive_ui_fixed(value, fixed, {"operationId", "ownerGeneration", *sizes, *hashes} | extra)
    for key in ("operationId", "ownerGeneration"):
        hex_value(value[key], 32)
    for key in hashes:
        hex_value(value[key])
    for key, cap in sizes.items():
        integer(value[key], cap, 1)
    if android:
        need(type(value["serviceRegistrationRequested"]) is bool)
        hex_value(value["protectedCopyInstance"], 32)
        need(value["outputLogicalBytes"] >= value["moduleLogicalBytes"] + value["artifactBytes"])
    return dict(value)


def positive_ui_admission(value, context, *, summary):
    """Only finite recorded DATA; private runner paths/rosters are never exported."""
    common = dict(target=context["target"], sourceCommit=context["source"], sourcePrePostMatched=True,
        originalCommandReturned=True, receiptPolicy="exclusive0600-readback-consuming-close",
        resultBundle="ios-unsigned-archive-test.xcresult")
    extra = {"sourceRosterSha256", "commands", "fileLimitBytes", "phaseClock"}
    runner_extra = {"runnerPath", "xctestrunPath", "runnerExecutable", "testExecutable", "xctestrun",
                    "productEntryCount", "productRosterSha256", "entitlementsSha256", "appSandboxEntitlement"}
    if summary:
        fixed = dict(common, schemaVersion=1, scope="normal-ui-original-command-admission-only", phase="summary",
                     originalCommandRole="normal-ui-summary", originalReturncode=0)
        extra.add("iosUnsignedTestCounts")
    else:
        fixed = dict(common, schemaVersion=1, scope="actual-generated-xctrunner-admission-only",
                     strictCodesignOriginalZero=True, reSignedOrRepaired=False,
                     originalProductsPrePostMatched=True, originalClosesCompleted=True,
                     originalTestReturncode=0, normalPhase="test")
        extra.update(runner_extra | {"iosUnsignedObservation"})
    positive_ui_fixed(value, fixed, extra)
    hex_value(value["sourceRosterSha256"])
    need(type(value["fileLimitBytes"]) is list and len(value["fileLimitBytes"]) == 2
         and all(type(item) is int and item == 1024**3 for item in value["fileLimitBytes"]))
    clock_row = value["phaseClock"]
    positive_ui_fixed(clock_row, {"postCloseDeadlineRequired": True}, ("startNs", "deadlineNs", "beforePublicationNs"))
    for key in ("startNs", "deadlineNs", "beforePublicationNs"):
        need(type(clock_row[key]) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", clock_row[key]) is not None)
    start, end, before = (int(clock_row[key]) for key in ("startNs", "deadlineNs", "beforePublicationNs"))
    need(start <= before < end and end - start == (90 if summary else 1245) * 10**9)
    source_role = ("normal-ui-source-roster", 15, 1048576)
    roles = (source_role, ("normal-ui-summary", 30, 262144), source_role) if summary else (
        source_role, ("verify-generated-runner", 30, 1048576),
        ("generated-runner-entitlements", 30, 1048576), ("one-admitted-ui-test", 1020, 1048576), source_role)
    rows = value["commands"]
    need(type(rows) is list and len(rows) == len(roles))
    commands = []
    for row, (role, cap, limit) in zip(rows, roles):
        positive_ui_fixed(row, dict(role=role, returncode=0, roleCapSeconds=cap, outputLimitBytes=limit),
            ("timeoutSeconds", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"))
        integer(row["timeoutSeconds"], cap, 1)
        integer(row["stdoutBytes"], limit); integer(row["stderrBytes"], limit)
        need(row["stdoutBytes"] + row["stderrBytes"] <= limit)
        for key in ("argvSha256", "stdoutSha256", "stderrSha256"):
            hex_value(row[key])
        commands.append({key: row[key] for key in ("role", "returncode", "stdoutBytes", "stderrBytes")})
    if summary:
        positive_ui_counts(value["iosUnsignedTestCounts"])
    else:
        # Shape only, not a new path/identity authentication. All these private
        # fields disappear from the projection; the original owner is authority.
        for key in ("runnerPath", "xctestrunPath"):
            need(type(value[key]) is str and 0 < len(value[key]) <= 4096
                 and not any(ord(char) < 32 or ord(char) == 127 for char in value[key]))
        integer(value["productEntryCount"], 4096, 5)
        for key in ("productRosterSha256", "entitlementsSha256"):
            hex_value(value[key])
        need(type(value["appSandboxEntitlement"]) is str and value["appSandboxEntitlement"] in ("absent", "false"))
        for key in ("runnerExecutable", "testExecutable", "xctestrun"):
            item = value[key]
            need(type(item) is list and len(item) == 3 and item[0] == "file" and type(item[1]) is list
                 and len(item[1]) == 9 and all(type(part) is str and re.fullmatch(r"[0-9]{1,20}", part) for part in item[1]))
            need(stat.S_ISREG(int(item[1][2])) and int(item[1][5]) == 1 and 0 < int(item[1][6]) <= 256 << 20)
            hex_value(item[2])
        positive_ui_facts(value["iosUnsignedObservation"], context, android=False)
    return commands


def positive_ui_prerequisites(context, statuses, phases, inventory, kind):
    need(context["profile"] == "installed" and inventory.get("receiptState") == "observed")
    required = ("package-install.status", "normal-ui/build.status", *POSITIVE_UI_STATUSES[kind])
    for name in required:
        row = statuses.get(name)
        positive_ui_fixed(row, {"receiptState": "observed", "returncode": 0})
    # Simultaneous positive scopes are not admitted by the actual workflow.
    need(not any(statuses.get(name, {}).get("receiptState") == "observed"
                 and statuses[name].get("returncode") == 0
                 for other, names in POSITIVE_UI_STATUSES.items() if other != kind for name in names))
    installed = phases.get("package-install", {})
    need(installed.get("receiptState") == "observed" and installed.get("recordedPassed") is True
         and installed.get("originalClosesKnown") is True and installed.get("targetRetired") is True)


def project_android_positive(value, context, statuses, phases, inventory):
    positive_ui_prerequisites(context, statuses, phases, inventory, "android")
    need(context["target"] in TARGETS)
    fixed = dict(schemaVersion=1, scope="ordinary-installed-one-android-signed-build-ui", target=context["target"],
        applicationSourceCommit=context["source"], harnessSourceCommit=context["source"], sourceTree=inventory["tree"],
        workflow=".github/workflows/desktop-macos-installed.yml", runId=context["runId"], runAttempt=context["runAttempt"],
        testIdentifier="MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectAndroidSignedBuild",
        resultOriginalReturncodeRequired=0, privateInputsPublished=False, vendorAcknowledgementAutomated=True,
        newProtectedCopyRegistered=True, cleanExitStatus=None, allWorkerFinality="not-established-by-XCTest-UI-state",
        fullUIQualified=False, distributionQualified=False, productReady=False)
    extra = {"packageSha256", "packageBytes", "runtimeManifestSha256", "installerInventorySha256",
             "originalCommandStatuses", "testCounts", "observation"}
    positive_ui_fixed(value, fixed, extra)
    for key in ("packageSha256", "runtimeManifestSha256", "installerInventorySha256"):
        hex_value(value[key])
    integer(value["packageBytes"], 2**40, 1)
    positive_ui_fixed(value["originalCommandStatuses"], dict(packageInstall=0, installer=0, supplier=0, build=0, test=0, summary=0))
    positive_ui_counts(value["testCounts"])
    facts = positive_ui_facts(value["observation"], context, android=True)
    need(value["vendorAcknowledgementAutomated"] is facts["vendorAcknowledgementAutomated"]
         and value["newProtectedCopyRegistered"] is facts["sourceRegistrationObserved"])
    return {"receiptState": "observed", "binding": "source-run-target-fields-and-current-statuses",
            "nativeSuccessInferred": False, "recordedResult": dict(value)}


def project_ios_positive(facts, test, summary, context, statuses, phases, inventory):
    positive_ui_prerequisites(context, statuses, phases, inventory, "ios")
    observation = positive_ui_facts(facts, context, android=False)
    test_commands = positive_ui_admission(test, context, summary=False)
    summary_commands = positive_ui_admission(summary, context, summary=True)
    need(test["iosUnsignedObservation"] == observation and test["sourceRosterSha256"] == summary["sourceRosterSha256"])
    return {"receiptState": "observed", "binding": "same-work-root-parent-context-only", "nativeSuccessInferred": False,
            "observation": observation, "testCounts": positive_ui_counts(summary["iosUnsignedTestCounts"]),
            "sourceRosterSha256": test["sourceRosterSha256"], "sourceAndTargetMatched": True,
            "callerStatusesMatched": True, "recordedRunnerOriginalsClosed": True,
            "commands": {"test": test_commands, "summary": summary_commands},
            "cleanExitStatus": None, "allWorkerFinality": "not-established-by-XCTest-UI-state",
            "fullUIQualified": False, "distributionQualified": False, "productReady": False}


def ios_pending_recovery_facts(value, context):
    """Closed observations and independent account readback, never UI-only success."""
    positive_ui_fixed(value, dict(schemaVersion=1, scope="normal-ui-pending-account-recovery-v1",
                                 originalClosesCompleted=True), ("observation", "account"))
    observation = value["observation"]
    fixture = (f"/private/tmp/mrk-macos-aqua-{context['source']}-{context['runId']}-"
               f"{context['runAttempt']}/ios-recovery-pending")
    positive_ui_fixed(observation, dict(schemaVersion=1, sourceCommit=context["source"], target=context["target"],
        runId=context["runId"], runAttempt=context["runAttempt"], fixtureSha256=hashlib.sha256(fixture.encode("utf-8")).hexdigest(),
        inspectUnchecked=True, recoverUnchecked=True, ordinaryQuit=True), ("inspect", "recover", "sessionSha256"))
    hex_value(observation["sessionSha256"])
    for key, status in (("inspect", "pending"), ("recover", "recovered")):
        row = observation[key]
        positive_ui_fixed(row, dict(phase="terminal", outcome="complete", reason="none", accountStatus=status),
                          ("operationId", "ownerGeneration"))
        hex_value(row["operationId"], 32); hex_value(row["ownerGeneration"], 32)
    need(all(observation["inspect"][key] != observation["recover"][key] for key in ("operationId", "ownerGeneration")))
    account = value["account"]
    positive_ui_fixed(account, dict(exactPendingSessionRecovered=True, originalOwnedNativeAndControlsRemoved=True,
        persistentOriginalLeaseRetained=True, baselineIdentitiesMatched=True, baselinePreferencesMatched=True,
        projectMarkerUnchanged=True, privateContentsExported=False, foreignPreferenceConflictInjected=False,
        appleSigningMaterialUsed=False, signedExportQualified=False), ("producer", "nativeReadback", "nativeBaselineMembers"))
    integer(account["nativeBaselineMembers"], 8, 1)
    common = dict(schemaVersion=1, case="ios-recovery-pending", profileCalls=0, commandFinalities=True,
        leaseClosed=True, sessionClosed=True, handlersRestored=True, fixtureDescriptorsClosed=True,
        originalDeadlineMet=True, keychainContentsRead=False)
    positive_ui_fixed(account["producer"], dict(common, scope="real-core-pending-account-fixture-v1", pendingLeft=True),
                      ("commands",))
    integer(account["producer"]["commands"], 64, 3)
    positive_ui_fixed(account["nativeReadback"], dict(common, scope="real-core-account-baseline-readback-v1", commands=2,
        pendingAbsent=True, baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True))
    return dict(value)


def ios_pending_recovery_admission(value, context, *, summary):
    """Separate fixed recovery contract; never reinterpret an unsigned admission."""
    common = dict(target=context["target"], sourceCommit=context["source"], sourcePrePostMatched=True,
        originalCommandReturned=True, receiptPolicy="exclusive0600-readback-consuming-close",
        resultBundle="ios-pending-recovery-test.xcresult")
    extra = {"sourceRosterSha256", "commands", "fileLimitBytes", "phaseClock"}
    if summary:
        fixed = dict(common, schemaVersion=1, scope="normal-ui-original-command-admission-only", phase="summary",
                     originalCommandRole="normal-ui-summary", originalReturncode=0)
        extra.add("iosPendingRecoveryTestCounts")
    else:
        fixed = dict(common, schemaVersion=1, scope="actual-generated-xctrunner-admission-only",
            strictCodesignOriginalZero=True, reSignedOrRepaired=False, originalProductsPrePostMatched=True,
            originalClosesCompleted=True, originalTestReturncode=0, normalPhase="test")
        extra.update(("runnerPath", "xctestrunPath", "runnerExecutable", "testExecutable", "xctestrun",
                      "productEntryCount", "productRosterSha256", "entitlementsSha256", "appSandboxEntitlement", "iosPendingRecovery"))
    positive_ui_fixed(value, fixed, extra)
    hex_value(value["sourceRosterSha256"])
    need(type(value["fileLimitBytes"]) is list and len(value["fileLimitBytes"]) == 2
         and all(type(item) is int and item == 1024**3 for item in value["fileLimitBytes"]))
    clock_row = value["phaseClock"]
    positive_ui_fixed(clock_row, {"postCloseDeadlineRequired": True}, ("startNs", "deadlineNs", "beforePublicationNs"))
    for key in ("startNs", "deadlineNs", "beforePublicationNs"):
        need(type(clock_row[key]) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", clock_row[key]) is not None)
    start, end, before = (int(clock_row[key]) for key in ("startNs", "deadlineNs", "beforePublicationNs"))
    need(start <= before < end and end - start == (90 if summary else 1080) * 10**9)
    source_role = ("normal-ui-source-roster", 15, 1048576)
    roles = (source_role, ("normal-ui-summary", 30, 262144), source_role) if summary else (
        source_role, ("verify-generated-runner", 30, 1048576), ("generated-runner-entitlements", 30, 1048576),
        ("ios-account-produce", 180, 16384), ("one-admitted-ui-test", 645, 1048576),
        ("ios-account-observe", 90, 2048), source_role)
    rows = value["commands"]
    need(type(rows) is list and len(rows) == len(roles))
    commands = []
    for row, (role, cap, limit) in zip(rows, roles):
        positive_ui_fixed(row, dict(role=role, returncode=0, roleCapSeconds=cap, outputLimitBytes=limit),
            ("timeoutSeconds", "argvSha256", "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256"))
        integer(row["timeoutSeconds"], cap, 1)
        integer(row["stdoutBytes"], limit); integer(row["stderrBytes"], limit)
        need(row["stdoutBytes"] + row["stderrBytes"] <= limit)
        for key in ("argvSha256", "stdoutSha256", "stderrSha256"):
            hex_value(row[key])
        commands.append({key: row[key] for key in ("role", "returncode", "stdoutBytes", "stderrBytes")})
    if summary:
        positive_ui_counts(value["iosPendingRecoveryTestCounts"])
    else:
        # Private identities are shape-checked, not exported or treated as new
        # authentication. The actual runner remains the original's authority.
        for key in ("runnerPath", "xctestrunPath"):
            need(type(value[key]) is str and 0 < len(value[key]) <= 4096
                 and not any(ord(char) < 32 or ord(char) == 127 for char in value[key]))
        integer(value["productEntryCount"], 4096, 5)
        for key in ("productRosterSha256", "entitlementsSha256"):
            hex_value(value[key])
        need(type(value["appSandboxEntitlement"]) is str and value["appSandboxEntitlement"] in ("absent", "false"))
        for key in ("runnerExecutable", "testExecutable", "xctestrun"):
            item = value[key]
            need(type(item) is list and len(item) == 3 and item[0] == "file" and type(item[1]) is list
                 and len(item[1]) == 9 and all(type(part) is str and re.fullmatch(r"[0-9]{1,20}", part) for part in item[1]))
            need(stat.S_ISREG(int(item[1][2])) and int(item[1][5]) == 1 and 0 < int(item[1][6]) <= 256 << 20)
            hex_value(item[2])
        ios_pending_recovery_facts(value["iosPendingRecovery"], context)
    return commands


def project_ios_pending_recovery(facts, test, summary, context, statuses, phases, inventory):
    positive_ui_prerequisites(context, statuses, phases, inventory, "iosRecovery")
    need(context["target"] in TARGETS)
    checked = ios_pending_recovery_facts(facts, context)
    test_commands = ios_pending_recovery_admission(test, context, summary=False)
    summary_commands = ios_pending_recovery_admission(summary, context, summary=True)
    need(test["iosPendingRecovery"] == checked and test["sourceRosterSha256"] == summary["sourceRosterSha256"])
    return {"receiptState": "observed", "binding": "same-work-root-parent-context-only", "nativeSuccessInferred": False,
        "observation": checked["observation"], "account": checked["account"],
        "testCounts": positive_ui_counts(summary["iosPendingRecoveryTestCounts"]),
        "sourceRosterSha256": test["sourceRosterSha256"], "sourceAndTargetMatched": True, "runContextMatched": True,
        "callerStatusesMatched": True, "recordedRunnerOriginalsClosed": True,
        "commands": {"test": test_commands, "summary": summary_commands}, "cleanExitStatus": None,
        "allWorkerFinality": "not-established-by-XCTest-UI-state", "appleSigningMaterialUsed": False,
        "signedExportQualified": False, "fullUIQualified": False, "distributionQualified": False, "productReady": False}


# Ordinary receipts are UI-only observations; their writers have separate finality.
ORDINARY_UI_LIMIT = 16384
ORDINARY_UI_OUTPUT_LIMIT = 8192
ORDINARY_UI_COMMON = {'schemaVersion': 1,
 'workflow': '.github/workflows/desktop-macos-installed.yml',
 'cleanExitStatus': None,
 'allWorkerFinality': 'not-established-by-XCTest-UI-state',
 'fullUIQualified': False,
 'distributionQualified': False,
 'productReady': False}
ORDINARY_UI_BINDINGS = ('applicationSourceCommit',
 'harnessSourceCommit',
 'sourceTree',
 'runId',
 'runAttempt',
 'target',
 'platform',
 'packageSha256',
 'packageSize',
 'runtimeManifestSha256',
 'installerInventorySha256',
 'normalBinaryBeforeSigningSha256',
 'signedAppBinarySha256')
ORDINARY_UI_HASHES = ('generatedRunnerAdmissionSha256',
 'buildCommandAdmissionSha256',
 'summaryCommandAdmissionSha256',
 'nativeSummarySha256')
# key, fixed path, count, methods, prerequisites, exact producer literals, extra fields
ORDINARY_UI_INPUTS = (('launch',
  'normal-ui/result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit',),
  (),
  {'scope': 'normal-app-launch-cancel-navigation-quit-ui-only',
   'sameOriginalApplicationTerminationAndGateClose': 'observed',
   'ordinaryEntryPayloadPickerQuitAndGateExclusion': 'observed',
   'gateProbeIsAuthentication': False,
   'directPayloadPreMain': 'unqualified',
   'fullM2Qualified': False,
   'maintenanceQualified': False,
   'originalCommandStatuses': {'build': 0, 'test': 0, 'summary': 0},
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit',
   'launchRenderCancelNavigationQuitUI': 'passed',
   'applicationStateAfterNormalQuit': 'notRunning'},
  ('entryBundleIdentifier', 'payloadBundleIdentifier', 'signedEntryBinarySha256')),
 ('project',
  'normal-ui/project-result.json',
  2,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages',
   'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectPathFields'),
  ('launch',),
  {'scope': 'normal-app-project-config-workflows-text-version-images-ui',
   'originalCommandStatuses': {'sharedBuild': 0, 'projectTest': 0, 'projectSummary': 0},
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages',
   'testIdentifiers': ['MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectLocalEditsAndImages',
                       'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectPathFields'],
   'projectRelativeFieldBrowseUI': 'passed',
   'fieldBrowseSavedConfiguration': False,
   'androidToolSourceBrowseUI': 'passed',
   'androidToolSourceBrowseTestIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectPathFields',
   'androidToolSourceBrowseScope': 'selection-only-three-roles-native-cancel-reselect-backend-source-refused',
   'supplierInspectionQualified': False,
   'protectedToolCopyQualified': False,
   'androidBuildQualified': False,
   'localProjectEditsAndImagesUI': 'passed',
   'applicationStateAfterNormalQuit': 'notRunning'},
  ()),
 ('persistence',
  'normal-ui/persistence-result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticPersistentCredentials',),
  ('launch',),
  {'scope': 'normal-app-synthetic-persistent-credentials-ui',
   'originalCommandStatuses': {'sharedBuild': 0, 'persistenceTest': 0, 'persistenceSummary': 0},
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticPersistentCredentials',
   'normalPersistenceSelected': True,
   'syntheticPersistenceCRUDUI': 'passed',
   'applicationStateAfterNormalQuit': 'notRunning',
   'applicationRestart': 'passed',
   'ordinaryApplicationLifetimes': 2,
   'originalReferenceAndGateTerminalObserved': True,
   'signingOrStoreValidated': False},
  ('vaultHelperBytes', 'vaultHelperSha256')),
 ('diagnostics',
  'normal-ui/diagnostics-result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectBuildToolDiagnostics',),
  ('launch', 'project', 'persistence'),
  {'scope': 'ordinary-ui-observed-original-diagnostics-report-and-settled-projection',
   'originalCommandStatuses': {'sharedBuild': 0,
                               'diagnosticsTestFileLimit': 0,
                               'diagnosticsTestFileBudget': 0,
                               'diagnosticsTest': 0,
                               'diagnosticsSummary': 0},
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectBuildToolDiagnostics',
   'diagnosticsReportAndSettledProjectionUI': 'passed',
   'originalStartProvenance': 'acknowledged-current-context',
   'diagnosticsPlatform': 'android',
   'diagnosticsCoreHost': 'macos',
   'coreOutcomeObserved': 'complete',
   'coreCommandsAttemptedAssertion': 'one-through-four',
   'nativeProjectionObserved': {'phase': 'settled', 'finality': 'settled'},
   'applicationStateAfterNormalQuit': 'notRunning',
   'independentOwnerResourceProof': False,
   'fullDoctorExecuted': False,
   'offlinePreflightExecuted': False,
   'projectRecoveryExecuted': False,
   'allToolVersionsMatched': None,
   'releaseReadinessEstablished': False},
  ('fileBudgetSha256', 'priorResultSha256', 'safeFactsSha256')),
 ('savedChecks',
  'normal-ui/saved-checks-result.json',
  2,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedOfflineChecks',
   'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectEmptyBuildInputInspection'),
  ('launch', 'project', 'persistence', 'diagnostics'),
  {'scope': 'ordinary-ui-observed-saved-offline-and-empty-build-input-inspection',
   'originalCommandStatuses': {'sharedBuild': 0,
                               'savedChecksTestFileLimit': 0,
                               'savedChecksTestFileBudget': 0,
                               'savedChecksTest': 0,
                               'savedChecksSummary': 0},
   'testIdentifiers': ['MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedOfflineChecks',
                       'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectEmptyBuildInputInspection'],
   'journeys': {'savedOfflineChecks': {'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedOfflineChecks',
                                       'scope': 'ordinary-ui-observed-saved-offline-report-and-settled-projection',
                                       'savedOfflineReportAndSettledProjectionUI': 'passed',
                                       'originalStartProvenance': 'acknowledged-current-saved-config',
                                       'coreOutcomeObserved': 'complete',
                                       'negativeFindingsAssertion': {'missingAtLeast': 2,
                                                                     'skippedAtLeast': 1,
                                                                     'moduleWrapperAndEarlyExitObserved': True},
                                       'nativeProjectionObserved': {'phase': 'settled',
                                                                    'finality': 'settled'},
                                       'fixtureReadback': 'unchanged-before-and-after-normal-quit',
                                       'applicationStateAfterNormalQuit': 'notRunning'},
                'emptyBuildInputInspection': {'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectEmptyBuildInputInspection',
                                              'scope': 'ordinary-ui-observed-empty-build-input-inspection-and-settled-projection',
                                              'emptyBuildInputInspectionAndSettledProjectionUI': 'passed',
                                              'coreOutcomeObserved': 'complete',
                                              'inspectionStatusObserved': 'idle',
                                              'nativeProjectionObserved': {'phase': 'settled',
                                                                           'finality': 'settled'},
                                              'mutationRecoveryExecuted': False,
                                              'projectCleanlinessEstablished': False,
                                              'fixtureReadback': 'unchanged-before-and-after-normal-quit',
                                              'applicationStateAfterNormalQuit': 'notRunning'}},
   'applicationStateAfterBothNormalQuits': 'notRunning',
   'independentOwnerResourceProof': False,
   'fullDoctorExecuted': False,
   'offlinePreflightExecuted': True,
   'projectRecoveryInspectionExecuted': True,
   'mutationRecoveryExecuted': False,
   'zeroCommandEvidence': False,
   'networkIsolationEstablished': False,
   'releaseReadinessEstablished': False},
  ('fileBudgetSha256', 'priorResultSha256', 'safeFactsSha256')),
 ('workflowRefusal',
  'normal-ui/workflow-refusal-result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectManagedWorkflowRefusal',),
  ('diagnostics',),
  {'applicationStateAfterNormalQuit': 'notRunning',
   'originalReferenceAndGateTerminalObserved': True,
   'independentOwnerResourceProof': False,
   'savedOfflineAndEmptyBuildInputCohortObserved': False,
   'scope': 'ordinary-ui-observed-original-managed-workflow-refusal',
   'managedWorkflowRefusalUI': 'passed',
   'managedWorkflowBundleRefused': True,
   'fixtureOriginalsPreserved': True,
   'workflowMutationObserved': False,
   'remoteGitHubOperationObserved': False,
   'releasePromotionObserved': False,
   'coreOutcomeObserved': {'effect': 'not_started', 'journal': 'not_created', 'resources': 'settled'},
   'nativeProjectionObserved': {'finality': 'settled'},
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectManagedWorkflowRefusal',
   'selectedSavedFileScope': 'workflow-refusal'},
  ('priorResultSha256',)),
 ('releaseEvidence',
  'normal-ui/release-evidence-result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedReleaseEvidence',),
  ('diagnostics',),
  {'applicationStateAfterNormalQuit': 'notRunning',
   'originalReferenceAndGateTerminalObserved': True,
   'independentOwnerResourceProof': False,
   'savedOfflineAndEmptyBuildInputCohortObserved': False,
   'scope': 'ordinary-ui-observed-original-saved-release-evidence-documents-only',
   'savedReleaseEvidenceUI': 'passed',
   'nativeEvidencePickerObserved': True,
   'candidateDocumentsAgreeObserved': True,
   'sharedCandidateGuidanceObserved': True,
   'stageChangeRetainsCandidateObserved': True,
   'replacementCancelStaleObserved': True,
   'releaseInputsUnpopulatedObserved': True,
   'fixtureOriginalsPreserved': True,
   'remoteGitHubOperationObserved': False,
   'releasePromotionObserved': False,
   'artifactBytesVerified': False,
   'signingAuthenticated': False,
   'githubAuthenticityEstablished': False,
   'storeStateEstablished': False,
   'releaseReadinessEstablished': False,
   'recoverySafetyEstablished': False,
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedReleaseEvidence',
   'selectedSavedFileScope': 'release-evidence'},
  ('priorResultSha256',)),
 ('savedVersion',
  'normal-ui/saved-version-recovery-result.json',
  1,
  ('MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedVersionRecovery',),
  ('diagnostics',),
  {'applicationStateAfterNormalQuit': 'notRunning',
   'originalReferenceAndGateTerminalObserved': True,
   'independentOwnerResourceProof': False,
   'savedOfflineAndEmptyBuildInputCohortObserved': False,
   'scope': 'ordinary-ui-observed-original-saved-version-rollback-and-fresh-load',
   'savedVersionRecoveryUI': 'passed',
   'coreOutcomeObserved': {'effect': 'rolled_back',
                           'journal': 'clean',
                           'resources': 'settled',
                           'reason': 'none'},
   'nativeProjectionObserved': {'finality': 'settled', 'reason': 'none'},
   'freshSavedVersionObserved': {'name': '1.2.3', 'build': '7'},
   'inspectionClosedWithoutApply': True,
   'explicitFreshRecoveryConfirmation': True,
   'interruptedGuiSaveObserved': False,
   'configurationTextImagesRecoveryObserved': False,
   'testIdentifier': 'MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectSavedVersionRecovery',
   'selectedSavedFileScope': 'saved-version-recovery'},
  ('priorResultSha256', 'savedVersionRecovery')))


def reserve_ordinary_ui_reads(budget):
    clock(budget)
    need("ordinaryUiReads" not in budget)
    charge = len(ORDINARY_UI_INPUTS) * (ORDINARY_UI_LIMIT + 1)
    need(budget["files"] + len(ORDINARY_UI_INPUTS) <= 128
         and budget["bytes"] + charge <= INPUT_LIMIT
         and budget["outputBytes"] + ORDINARY_UI_OUTPUT_LIMIT <= OUTPUT_LIMIT)
    budget["files"] += len(ORDINARY_UI_INPUTS)
    budget["bytes"] += charge
    budget["outputBytes"] += ORDINARY_UI_OUTPUT_LIMIT
    budget["ordinaryUiOutputReserved"] = True
    budget["ordinaryUiReads"] = {row[1]: True for row in ORDINARY_UI_INPUTS}


def ordinary_ui_literal(value, expected):
    # Exact finite producer literals, including nested bool/int distinctions.
    if type(expected) is dict:
        positive_ui_fixed(value, {}, expected)
        for key, item in expected.items(): ordinary_ui_literal(value[key], item)
    elif type(expected) is list:
        need(type(value) is list and len(value) == len(expected))
        for item, fixed in zip(value, expected): ordinary_ui_literal(item, fixed)
    else:
        need(type(value) is type(expected) and value == expected)


def ordinary_ui_result(value, definition, context, statuses, phases, inventory, preview, prior, build_admission):
    key, _path, count, methods, prerequisites, fixed, extra = definition
    need(context["profile"] == "installed" and context["workflowSource"] == context["source"]
         and inventory.get("receiptState") == "observed" and preview.get("receiptState") == "observed"
         and preview.get("sourceTree") == inventory["tree"])
    installed = phases.get("package-install", {})
    need(installed.get("receiptState") == "observed" and installed.get("correlationMatches") is True
         and installed.get("recordedPassed") is True and installed.get("originalClosesKnown") is True
         and installed.get("targetRetired") is True)
    role = {"launch": None, "savedChecks": "saved-checks", "savedVersion": "saved-version-recovery",
            "workflowRefusal": "workflow-refusal", "releaseEvidence": "release-evidence"}.get(key, key)
    required = ("package-install.status", "normal-ui/build.status") + (
        ("normal-ui/test.status", "normal-ui/summary.status") if role is None else
        ("normal-ui/" + role + "-test.status", "normal-ui/" + role + "-summary.status"))
    for name in required: positive_ui_fixed(statuses.get(name), {"receiptState": "observed", "returncode": 0})
    bindings = dict(applicationSourceCommit=context["source"], harnessSourceCommit=context["source"],
        sourceTree=inventory["tree"], runId=context["runId"], runAttempt=context["runAttempt"], target=context["target"],
        platform="macOS26-arm64" if context["target"] == TARGETS[0] else "macOS26-x86_64")
    for name in ORDINARY_UI_BINDINGS[7:]:
        bindings[name] = integer(preview.get(name), 2**40, 1) if name == "packageSize" else hex_value(preview.get(name))
    expected = dict(ORDINARY_UI_COMMON, **fixed, **bindings)
    positive_ui_fixed(value, {}, set(expected) | set(ORDINARY_UI_HASHES) | {"toolchain", "testCounts"} | set(extra))
    for name, item in expected.items(): ordinary_ui_literal(value[name], item)
    ordinary_ui_literal(value["testCounts"], dict(POSITIVE_UI_COUNTS, totalTestCount=count, passedTests=count))
    hashes = {name: hex_value(value[name]) for name in ORDINARY_UI_HASHES}
    toolchain = value["toolchain"]
    positive_ui_fixed(toolchain, {}, ("xcode", "sdkPath", "sdkVersion", "sdkBuild"))
    need(all(type(item) is str and 0 < len(item) <= 4096 and item.isascii() for item in toolchain.values()))
    need(all(prior.get(name, {}).get("receiptState") == "observed" for name in prerequisites))
    need(build_admission is None or hashes["buildCommandAdmissionSha256"] == build_admission)
    if key in ("diagnostics", "savedChecks"):
        ordinary_ui_literal(value["priorResultSha256"], {next(row[1].split("/")[-1] for row in ORDINARY_UI_INPUTS if row[0] == name): prior[name]["resultSha256"] for name in prerequisites})
        for name in ("fileBudgetSha256", "safeFactsSha256"): hex_value(value[name])
    elif key in ("workflowRefusal", "releaseEvidence", "savedVersion"):
        need(hex_value(value["priorResultSha256"]) == prior["diagnostics"]["resultSha256"])
    if key == "launch":
        hex_value(value["signedEntryBinarySha256"])
        need(value["signedEntryBinarySha256"] == hex_value(preview.get("signedEntryBinarySha256"))
             and value["entryBundleIdentifier"] == "dev.mobile-release-kit.desktop.entry"
             and value["payloadBundleIdentifier"] == "dev.mobile-release-kit.desktop")
    if key == "persistence":
        hex_value(value["vaultHelperSha256"]); integer(value["vaultHelperBytes"], 32 * 1024 * 1024, 1)
    recovery = None
    if key == "savedVersion":
        recovery = value["savedVersionRecovery"]
        digests = ("sourceInputsSha256", "runtimeManifestSha256", "runtimeResultSha256", "sourceClosureSha256",
            "fixtureDataSha256", "producerSha256", "producerFramesSha256", "handoffSha256")
        positives = ("originalFixtureRestored", "unrelatedOriginalsUnchanged", "readyJournalRemoved",
            "sourcePrePostMatched", "uiOriginalMarkersObserved", "originalClosesCompleted")
        expected_recovery = dict.fromkeys(positives, True)
        expected_recovery.update(producerReturncode=86, publicOriginalCount=13, readyJournalFileCount=6,
                                 interruptedGuiSaveObserved=False)
        positive_ui_fixed(recovery, {}, set(digests) | set(expected_recovery))
        for name in digests: hex_value(recovery[name])
        for name, item in expected_recovery.items(): ordinary_ui_literal(recovery[name], item)
        need(recovery["runtimeManifestSha256"] == bindings["runtimeManifestSha256"])
    result = {"receiptState": "observed", "scope": fixed["scope"], "testIdentifiers": list(methods),
        "testCounts": [value["testCounts"][name] for name in POSITIVE_UI_COUNTS], "admissionSha256": [hashes[name] for name in
            ("generatedRunnerAdmissionSha256", "summaryCommandAdmissionSha256", "nativeSummarySha256")],
        "resultWriterFinalityEstablished": False, "cleanExitStatus": None,
        "allWorkerFinality": "not-established-by-XCTest-UI-state", "nativeSuccessInferred": False,
        "fullUIQualified": False, "distributionQualified": False, "productReady": False}
    if "originalCommandStatuses" in value: result["originalCommandStatuses"] = dict(value["originalCommandStatuses"])
    if recovery is not None:
        result["producerReturncode"] = recovery["producerReturncode"]
        result["recordedOriginalClosesCompleted"] = True
    return result, bindings, hashes["buildCommandAdmissionSha256"]


def ordinary_ui_observations(root, context, statuses, phases, inventory, preview, budget):
    if "ordinaryUiReads" not in budget: reserve_ordinary_ui_reads(budget)
    rows, bindings, build_admission = {}, None, None
    for definition in ORDINARY_UI_INPUTS:
        key, path = definition[:2]
        try:
            body = read_input(root, path, ORDINARY_UI_LIMIT, budget, ordinary_ui_reserved=True)
            document = decode(body, budget)
            row, current_bindings, current_build = ordinary_ui_result(document, definition, context, statuses, phases, inventory, preview, rows, build_admission)
            row.update(resultSha256=hashlib.sha256(body).hexdigest(), resultBytes=len(body))
            if bindings is None: bindings, build_admission = current_bindings, current_build
            else: need(current_bindings == bindings)
            rows[key] = row
            del body, document
        except FileNotFoundError: rows[key] = {"receiptState": "absent"}
        except Refused: rows[key] = {"receiptState": "refused"}
    result = {"receiptState": "absent" if all(row["receiptState"] == "absent" for row in rows.values()) else "recorded",
        "results": rows, "binding": bindings, "buildCommandAdmissionSha256": build_admission,
        "testCountOrder": list(POSITIVE_UI_COUNTS), "admissionHashOrder":
        ["generatedRunnerAdmissionSha256", "summaryCommandAdmissionSha256", "nativeSummarySha256"]}
    need(len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)) <= ORDINARY_UI_OUTPUT_LIMIT)
    return result


def positive_ui_observations(root, context, statuses, phases, inventory, budget, deliveries=None):
    inputs = {}
    ios_status = statuses.get("normal-ui/ios-unsigned-archive-test.status", {})
    ios_failed = (type(ios_status) is dict and ios_status.get("receiptState") == "observed"
        and type(ios_status.get("returncode")) is int and 1 <= ios_status["returncode"] <= 255)
    ios_failure = None
    recovery_status = statuses.get("normal-ui/ios-pending-recovery-test.status", {})
    recovery_failed = (type(recovery_status) is dict and recovery_status.get("receiptState") == "observed"
        and type(recovery_status.get("returncode")) is int and 1 <= recovery_status["returncode"] <= 255)
    recovery_failure = None
    for key, path, limit, admission in POSITIVE_UI_INPUTS:
        if key == "iosFacts" and ios_failed:
            try:
                ios_failure = project_ui_diagnostic(decode(read_input(root, IOS_UNSIGNED_DIAGNOSTIC, 4096, budget), budget),
                    "ios-unsigned-test", ios_status)
            except FileNotFoundError:
                ios_failure = {"receiptState": "absent"}
            except Refused:
                ios_failure = {"receiptState": "refused"}
            inputs[key] = ("absent", None)  # One alternative attempt, never a fallback facts read.
            continue
        if key == "iosRecoveryFacts" and recovery_failed:
            try:
                recovery_failure = project_ui_diagnostic(decode(read_input(root, IOS_PENDING_DIAGNOSTIC, 4096, budget), budget),
                    "ios-pending-test", recovery_status)
            except FileNotFoundError:
                recovery_failure = {"receiptState": "absent"}
            except Refused:
                recovery_failure = {"receiptState": "refused"}
            inputs[key] = ("absent", None)  # One alternative attempt, never a fallback facts read.
            continue
        try:
            inputs[key] = ("observed", decode(read_input(root, path, limit, budget), budget, ui_admission=admission))
        except FileNotFoundError:
            inputs[key] = ("absent", None)
        except Refused:
            inputs[key] = ("refused", None)
    result = {}
    for name, kind, keys in (("androidSignedBuild", "android", ("android",)),
                             ("iosUnsignedArchive", "ios", ("iosFacts", "iosTest", "iosSummary")),
                             ("iosPendingRecovery", "iosRecovery", ("iosRecoveryFacts", "iosRecoveryTest", "iosRecoverySummary"))):
        states = [inputs[key][0] for key in keys]
        if all(state == "absent" for state in states):
            result[name] = {"receiptState": "absent"}
            continue
        try:
            need(all(state == "observed" for state in states))
            values = [inputs[key][1] for key in keys]
            projector = {"android": project_android_positive, "ios": project_ios_positive,
                         "iosRecovery": project_ios_pending_recovery}[kind]
            result[name] = projector(*values, context, statuses, phases, inventory)
        except Refused:
            result[name] = {"receiptState": "refused"}
    if ios_failed:
        result["iosUnsignedArchive"] = {"receiptState": "refused", "failureDiagnostic": ios_failure}
    if recovery_failed:
        result["iosPendingRecovery"] = {"receiptState": "refused", "failureDiagnostic": recovery_failure}
    result["ordinary"] = ordinary_ui_observations(root, context, statuses, phases, inventory,
        (deliveries or {}).get("preview", {}), budget)
    size = len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    need(budget.get("ordinaryUiOutputReserved") is True
         and budget["outputBytes"] >= ORDINARY_UI_OUTPUT_LIMIT)
    budget["ordinaryUiOutputReserved"] = False  # Consume once, never reusable after refusal.
    budget["outputBytes"] -= ORDINARY_UI_OUTPUT_LIMIT
    need(size <= 16384 and budget["outputBytes"] + size <= OUTPUT_LIMIT)
    budget["outputBytes"] += size
    return result


def project_producer_refusal(body, phase):
    """One finite token is a diagnostic observation, never producer finality."""
    need(type(body) is bytes and 0 < len(body) <= 128 and body in PRODUCER_REFUSAL_TOKENS
         and type(phase) is dict and phase.get("receiptState") == "observed"
         and phase.get("correlationMatches") is True and phase.get("recordedPassed") is False)
    caller = phase.get("callerStatus")
    need(type(caller) is dict and caller.get("receiptState") == "observed"
         and type(caller.get("returncode")) is int and caller["returncode"] != 0)
    failure = phase.get("failure")
    need(type(failure) is dict and failure.get("type") == "Refused"
         and failure.get("stage") == "package-producer-emission"
         and failure.get("reason") == "original-nonzero-producer-emitter")
    originals = phase.get("originalCalls")
    need(type(originals) is dict and originals.get("unclassifiedCount") == 0)
    calls = originals.get("calls")
    need(type(calls) is list and originals.get("recordedCount") == len(calls))
    emitters = [row for row in calls if row.get("role") == "producer-emitter"]
    entered = [row for row in calls if row.get("entered") is True]
    need(len(emitters) == 1 and entered and entered[-1] is emitters[0])
    call = emitters[0]
    need(call.get("entered") is True and call.get("returned") is True and call.get("capturesSettled") is True
         and type(call.get("returncode")) is int and call["returncode"] == 78
         and call.get("stdoutSha256") == hashlib.sha256(b"").hexdigest()
         and call.get("stderrSha256") == hashlib.sha256(body).hexdigest())
    return {"receiptState": "observed", "reason": PRODUCER_REFUSAL_TOKENS[body],
            "binding": "same-source-run-target-failed-original", "nativeSuccessInferred": False}


def project(work, *, profile, source, workflow_source, run_id, run_attempt, target, removal_case="disabled"):
    need(profile in ("installed", "aqua") and target in TARGETS)
    need(removal_case in ("disabled", "ordinary", "abrupt")
         and (removal_case == "disabled" or profile == "installed" and target == "aarch64-apple-darwin"))
    context = {"profile": profile, "source": hex_value(source, 40), "workflowSource": hex_value(workflow_source, 40),
               "runId": identifier(run_id), "runAttempt": identifier(run_attempt), "target": target,
               "expectedRemovalCase": removal_case}
    need(source == workflow_source and len(PHASES) <= 20 and len(STATUS_FILES) <= 100
         and len(set(STATUS_FILES)) == len(STATUS_FILES))
    # All fixed attempts count, including absent originals, before any read.
    need(len(STATUS_FILES) + len(PHASES) + 4 + len(PACKAGE_SIGNATURE_CAPTURES) + len(INSTALLER_DIAGNOSTIC_INPUTS)
         + (len(UI_DIAGNOSTICS) + 6 + len(POSITIVE_UI_INPUTS) + len(ORDINARY_UI_INPUTS) if profile == "installed" else 0) <= 128)
    budget = {"deadline": time.monotonic_ns() + 45_000_000_000, "files": 0, "bytes": 0, "nodes": 0,
              "outputBytes": 16384}  # Reserve the fixed roster keys/envelope/caller-status duplicates.
    reserve_package_signature_reads(budget)
    reserve_installer_diagnostic_reads(budget)
    if profile == "installed": reserve_ordinary_ui_reads(budget)
    root = open_root(work)
    try:
        root_id = directory_identity(os.fstat(root))
        def observe(name, limit, convert):
            try:
                row = convert(read_input(root, name, limit, budget))
            except FileNotFoundError:
                row = {"receiptState": "absent"}
            except Refused:
                row = {"receiptState": "refused"}
            # List bounds precede projection loops; aggregate output admission
            # precedes adding each bounded projection to the report. No raw fallback.
            budget["outputBytes"] += len(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
            need(budget["outputBytes"] <= OUTPUT_LIMIT)
            return row
        statuses = {}
        def status(body):
            need(re.fullmatch(rb"(?:0|[1-9][0-9]{0,4}|-[1-9][0-9]{0,4})\n", body) is not None)
            return {"receiptState": "observed", "returncode": integer(int(body), 65535, -65536)}
        for name in STATUS_FILES:
            statuses[name] = observe(name, 16, status)
        phases = {}
        def phase_receipt(body, phase):
            result = project_receipt(decode(body, budget), context, phase)
            if "appAbsenceBaseline" in result or phase == "finalize-package":
                result["receiptSha256"] = hashlib.sha256(body).hexdigest()
            return result
        for phase in PHASES:
            row = observe("android-helper-" + phase + ".json", 16384,
                          lambda body, phase=phase: phase_receipt(body, phase))
            row["callerStatus"] = statuses.get(PHASE_STATUS.get(phase))
            if phase == "same-package-noop" and row.get("samePackageObservation") is not None:
                caller = row["callerStatus"]
                if type(caller) is not dict or caller.get("receiptState") != "observed" or caller.get("returncode") != 0:
                    row = {"receiptState": "refused", "callerStatus": caller}
            phases[phase] = row
        producer_refusal = observe("android-helper-producer-emitter.stderr", 128,
            lambda body: project_producer_refusal(body, phases["package-install"]))
        signature_captures, signature_states = {}, []
        for key, name, _ in PACKAGE_SIGNATURE_CAPTURES:
            try:
                signature_captures[key] = read_input(root, name, PACKAGE_SIGNATURE_CAPTURE_LIMIT, budget,
                    package_signature_reserved=True)
                signature_states.append("observed")
            except FileNotFoundError:
                signature_states.append("absent")
            except Refused:
                signature_states.append("refused")
        try:
            need(all(state == "observed" for state in signature_states))
            package_signature = project_package_signature_diagnostic(signature_captures, phases["finalize-package"])
        except Refused:
            package_signature = {"receiptState": "absent" if all(state == "absent" for state in signature_states) else "refused",
                                 "diagnosticOnly": True, "nativeSuccessInferred": False, "policyUnchanged": True}
        del signature_captures
        budget["outputBytes"] += len(json.dumps(package_signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        need(budget["outputBytes"] <= OUTPUT_LIMIT)
        installer_inputs, installer_states = {}, {}
        for name in INSTALLER_DIAGNOSTIC_INPUTS:
            try:
                installer_inputs[name] = read_input(root, name, INSTALLER_DIAGNOSTIC_LIMIT, budget,
                    installer_diagnostic_reserved=True)
                installer_states[name] = "observed"
            except FileNotFoundError:
                installer_states[name] = "absent"
            except Refused:
                installer_states[name] = "refused"
        try:
            budget["installerDiagnosticStage"] = "metadata-original-read"
            need(installer_states[INSTALLER_DIAGNOSTIC_INPUTS[0]] == "observed")
            installer_diagnostic = project_installer_failure_diagnostic(installer_inputs[INSTALLER_DIAGNOSTIC_INPUTS[0]],
                installer_inputs.get(INSTALLER_DIAGNOSTIC_INPUTS[1]), phases["package-install"], statuses, context,
                phases["notarize-payload"], phases["finalize-package"], budget)
            budget["installerDiagnosticStage"] = "selected-original-read"
            need(installer_diagnostic.get("captureState") != "observed-project-correlated"
                 or installer_states[INSTALLER_DIAGNOSTIC_INPUTS[1]] == "observed")
        except Refused as error:
            stage = budget.get("installerDiagnosticStage")
            installer_diagnostic = {"receiptState": "absent" if all(state == "absent" for state in installer_states.values()) else "refused",
                "diagnosticOnly": True, "originalInstallerReturnedZero": False, "nativeSuccessInferred": False, "policyUnchanged": True,
                "inputStates": {"metadata": installer_states[INSTALLER_DIAGNOSTIC_INPUTS[0]],
                                "selected": installer_states[INSTALLER_DIAGNOSTIC_INPUTS[1]]},
                "refusalStage": stage if type(error) is Refused and type(stage) is str
                    and stage in INSTALLER_DIAGNOSTIC_REFUSAL_STAGES
                    and time.monotonic_ns() <= budget["deadline"] else "unclassified"}
        del installer_inputs
        budget["outputBytes"] += len(json.dumps(installer_diagnostic, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        need(budget["outputBytes"] <= OUTPUT_LIMIT)
        try:
            update = update_join(phases["update-baseline"], phases["package-install"])
        except Refused:
            update = {"receiptState": "refused"}
        inventory_paths = set()
        inventory = observe("source-inventory.json", 2 * 1024 * 1024,
            lambda body: project_inventory(decode(body, budget, inventory=True), body, context, collect_paths=inventory_paths))
        deliveries = {name: observe(path, 16384, lambda body, removal=removal:
            project_summary(decode(body, budget), context, removal)) for name, path, removal in
            (("preview", "preview/PREVIEW.json", False), ("removal", "remove-preview/REMOVAL.json", True))}
        ui_diagnostics = {role: observe(path, 4096, lambda body, role=role:
            project_ui_diagnostic(decode(body, budget), role, statuses["normal-ui/build.status"]))
            for role, path in UI_DIAGNOSTICS} if profile == "installed" else {}
        settings_diagnostic = observe("normal-ui/build.settings-diagnostics.json", 4096,
            lambda body: project_build_settings(decode(body, budget), context, statuses["normal-ui/build.status"],
                ui_diagnostics["build"])) if profile == "installed" else None
        data_failure = observe("data-contracts/failure-diagnostics.json", 16384,
            lambda body: project_data_contract_failure(decode(body, budget), context, statuses, inventory_paths)) if profile == "installed" else None
        app_absence = None
        if profile == "installed":
            app_status = [observe(name, 16, status) for name in ("app-absence-preparation.status", "app-absence-restore.status")]
            app_rows = [observe("android-helper-" + phase + ".json", 16384,
                lambda body, phase=phase: project_app_absence_receipt(decode(body, budget), context, phase, hashlib.sha256(body).hexdigest()))
                for phase in ("prepare-app-absence", "app-absence-restore")]
            try:
                app_absence = app_absence_join(*app_rows, phases["package-install"], app_status + [statuses["package-install.status"]])
            except Refused:
                app_absence = {"receiptState": "absent" if all(row.get("receiptState") == "absent" for row in app_rows + app_status)
                               else "incomplete", "proofComplete": False}
            app_absence.update(prepare=app_rows[0], restore=app_rows[1], callerStatuses=app_status)
        value = {"schemaVersion": 1, "kind": "mrk-public-verification-evidence-v1", **context,
                 "diagnosticOnly": True, "productReady": False, "sourceInventory": inventory,
                 "phases": phases, "statuses": statuses, "deliveries": deliveries, "normalUiBuildDiagnostics": ui_diagnostics,
                 "producerFailureDiagnostic": producer_refusal, "packageSignatureDiagnostic": package_signature,
                 "installerFailureDiagnostic": installer_diagnostic,
                 "dataContractFailure": data_failure, "buildSettingsDiagnostic": settings_diagnostic, "appAbsence": app_absence, "positiveUpdate": update}
        if profile == "installed":
            value["positiveUiObservations"] = positive_ui_observations(root, context, statuses, phases, inventory, budget, deliveries)
        body = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        need(len(body) <= OUTPUT_LIMIT and directory_identity(os.fstat(root)) == root_id
             == directory_identity(os.stat(work, follow_symlinks=False)))
        clock(budget)
        fd = os.open(OUTPUT, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        try:
            need(os.write(fd, body) == len(body))
            os.fsync(fd)
            need(os.pread(fd, len(body) + 1, 0) == body)
            final = os.fstat(fd)
            need(stat.S_ISREG(final.st_mode) and final.st_nlink == 1 and stat.S_IMODE(final.st_mode) == 0o600
                 and final.st_uid == os.geteuid() and final.st_size == len(body)
                 and identity(final) == identity(os.stat(OUTPUT, dir_fd=root, follow_symlinks=False)))
        finally:
            os.close(fd)
        need(directory_identity(os.fstat(root)) == root_id == directory_identity(os.stat(work, follow_symlinks=False)))
        clock(budget)
    finally:
        os.close(root)
    return value


def main(arguments):
    try:
        need(len(arguments) in (14, 16) and tuple(arguments[:14:2]) ==
             ("--profile", "--work", "--target", "--source", "--workflow-source", "--run-id", "--run-attempt"))
        need(len(arguments) == 14 or arguments[14] == "--removal-case")
        removal_case = "disabled" if len(arguments) == 14 else arguments[15]
        profile, work, target, source, workflow_source, run_id, run_attempt = arguments[1:14:2]
        project(work, profile=profile, source=source, workflow_source=workflow_source,
                run_id=run_id, run_attempt=run_attempt, target=target, removal_case=removal_case)
    except Exception:
        print("Public evidence projection refused; originals remain local.", file=sys.stderr)
        return 1
    print("Closed public verification facts projected; native acceptance is not inferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
