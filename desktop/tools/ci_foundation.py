"""Fixed desktop compiler/native boundary checks on disposable hosted runners only.

Not the release-kit verification controller, a release workflow, an installer,
or a general command runner. Never invoke this on a shared development machine.
Compiler completion is not proof of desktop/native-child finality; the ignored
Rust test owns and reports those original-child observations separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import TextIO
import zipfile

RUST = "1.98.0"
PYTHON = "3.14.7"
NODE = "v24.20.0"
BOUNDARY_SCOPE = "passive-v1"
COMPILE_SCOPE = "shell-compile-v1"
COMPILE_EVIDENCE_SCOPE = "desktop-shell-compile-only-v1"
COMPILE_WORKFLOW = ".github/workflows/desktop-session-compile.yml"
COMPILE_REF = "refs/heads/verify/desktop-session-compile"
COMPILE_PHASES = ("prepare", "acquire", "compile", "clean")
COMPILE_CHECKS = {
    "acquire": ("rust-toolchain-install", "rust-version-target", "locked-platform-metadata",
                "node-version", "npm-locked-no-scripts"),
    "compile": ("rust-version-target", "headless-test-compile-only", "node-version",
                "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"),
}
GTK_COMPILE_SCOPE = "session-gtk-compile-v1"
GTK_COMPILE_EVIDENCE_SCOPE = "desktop-session-gtk-compile-only-v1"
GTK_COMPILE_WORKFLOW = ".github/workflows/desktop-session-gtk-compile.yml"
GTK_COMPILE_REF = "refs/heads/verify/desktop-session-gtk-compile"
GTK_COMPILE_FEATURES = ("desktop-shell", "development-runtime")
GTK_COMPILE_CHECKS = {
    "acquire": COMPILE_CHECKS["acquire"],
    "compile": ("rust-version-target", "node-version", "gtk-python-syntax-only",
                "gtk-js-syntax-only", "gtk-c-pkg-config", "gtk-c-compile-only",
                "vite-assets", "gtk-integration-compile-only"),
}
COMPILE_PROFILES = {
    COMPILE_SCOPE: {"workflow": COMPILE_WORKFLOW, "ref": COMPILE_REF,
                    "evidence": COMPILE_EVIDENCE_SCOPE, "checks": COMPILE_CHECKS},
    GTK_COMPILE_SCOPE: {"workflow": GTK_COMPILE_WORKFLOW, "ref": GTK_COMPILE_REF,
                        "evidence": GTK_COMPILE_EVIDENCE_SCOPE, "checks": GTK_COMPILE_CHECKS},
}
WORKFLOW_NATIVE_SCOPE = "github-workflow-apply-native-v1"
WORKFLOW_NATIVE_EVIDENCE_SCOPE = "desktop-github-workflow-apply-native-only-v1"
WORKFLOW_NATIVE_WORKFLOW = ".github/workflows/desktop-github-workflow-apply-native.yml"
WORKFLOW_NATIVE_REF = "refs/heads/verify/desktop-github-workflow-apply-native"
WORKFLOW_NATIVE_PHASES = ("prepare", "acquire", "compile", "workflow-owner", "workflow-transaction-eof", "workflow-core", "clean")
WORKFLOW_NATIVE_CHECKS = {
    "acquire": ("rust-toolchain-install", "rust-version-target", "workflow-locked-headless-metadata"),
    "compile": ("rust-version-target", "headless-test-compile-only"),
    "workflow-owner": ("rust-version-target", "workflow-owner-source-native-contract", "workflow-owner-source-receipt",
                       "workflow-owner-zip-native-contract", "workflow-owner-zip-receipt"),
    "workflow-transaction-eof": ("rust-version-target", "workflow-transaction-eof-native-contract", "workflow-eof-receipt"),
    "workflow-core": ("workflow-core-ordinary", "workflow-core-ordinary-receipt",
                      "workflow-core-committed-fsync", "workflow-core-committed-fsync-receipt",
                      "workflow-core-committed-close", "workflow-core-committed-close-receipt"),
}
WORKFLOW_NATIVE_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target",
                               "workflow-owner-source", "workflow-owner-zip", "workflow-transaction-eof")
WORKFLOW_OWNER_TEST = "edit_owner::hosted_tests::hosted_workflow_edit_owner_original_resources"
WORKFLOW_TRANSACTION_EOF_TEST = "edit_owner::hosted_tests::hosted_workflow_transaction_eof_original_resources"
WORKFLOW_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
BOUNDARY_PHASES = ("prepare", "acquire", "compile", "native", "config-owner", "config-task-loss",
                   "config-owner-delta", "config-transaction-eof", "config-core", "clean")
GTK_COMPILE_SOURCES = (
    "desktop/github_connection_bootstrap.py",
    "desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
    "desktop/src-tauri/src/asset_session.rs", "desktop/src-tauri/src/asset_source.rs",
    "desktop/src-tauri/src/edit_owner.rs", "desktop/src-tauri/src/hosted_tests.rs",
    "desktop/src-tauri/src/github_workflow_edit_protocol.rs",
    "desktop/src-tauri/src/github_connection_protocol.rs",
    "desktop/src-tauri/src/github_connection_session.rs",
    "desktop/src-tauri/src/runtime.rs",
    "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/src/supervisor.rs",
    "desktop/src-tauri/src/session_gtk_qualification.rs",
    "desktop/src-tauri/src/session_gtk_qualification/native_contract.rs",
    "desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py",
    # cfg(test) hosted_tests embeds these bytes in the same Linux libtest. This
    # is compiler-input accounting, never permission to execute the TLS entry.
    ".github/workflows/desktop-github-connection-tls.yml",
    "desktop/src-tauri/tests/fixtures/github_tls_peer.py",
    "desktop/src-tauri/tests/fixtures/github_tls_namespace.sh",
    "desktop/src-tauri/tests/fixtures/github_tls/root-ca.pem",
    "desktop/src-tauri/tests/fixtures/github_tls/other-root-ca.pem",
    "desktop/src-tauri/tests/fixtures/github_tls/api-valid.pem",
    "desktop/src-tauri/tests/fixtures/github_tls/wrong-san.pem",
    "desktop/src-tauri/tests/fixtures/github_tls/api-expired.pem",
    "desktop/src-tauri/tests/fixtures/github_tls/server-key.pem",
    "desktop/src-tauri/tests/session_gtk_qualification.rs",
    "desktop/src-tauri/tests/session_gtk_recipe.js",
    "desktop/native/session_gtk_input_linux.c", "desktop/tools/qualify_session_gtk.py",
    "desktop/tools/ci_foundation.py", GTK_COMPILE_WORKFLOW,
)
# Reviewed package-member DATA, not a roster inferred from the candidate zip or
# an import of the native qualification driver. Keep aligned with its SOURCES.
GTK_CORE_PATHS = (
    "mobile_release/__init__.py",
    "mobile_release/__main__.py",
    "mobile_release/_command_process.py",
    "mobile_release/_desktop_edit_control.py",
    "mobile_release/_desktop_edit_engine.py",
    "mobile_release/_desktop_edit_protocol.py",
    "mobile_release/_desktop_engine.py",
    "mobile_release/_desktop_github_engine.py",
    "mobile_release/_github_connection_transport.py",
    "mobile_release/_lifetime_evidence.py",
    "mobile_release/_native_process.py",
    "mobile_release/_profile_callers.py",
    "mobile_release/_profile_process.py",
    "mobile_release/_store_lane_contract.py",
    "mobile_release/_store_lane_evidence.py",
    "mobile_release/_store_lane_files.py",
    "mobile_release/android.py",
    "mobile_release/android_upload_validation.py",
    "mobile_release/api/__init__.py",
    "mobile_release/api/_catalog.py",
    "mobile_release/api/_credential_assessment.py",
    "mobile_release/api/_credential_guide.py",
    "mobile_release/api/_github_connection.py",
    "mobile_release/api/_github_setup.py",
    "mobile_release/api/_json.py",
    "mobile_release/api/_preview.py",
    "mobile_release/api/_snapshot.py",
    "mobile_release/api/_snapshot_windows.py",
    "mobile_release/api/_snapshot_windows_native.py",
    "mobile_release/api/contracts.py",
    "mobile_release/api/data/credential-guide-v1.json",
    "mobile_release/api/data/field-help.json",
    "mobile_release/api/data/github-connection-v1.json",
    "mobile_release/api/data/github-setup-v1.json",
    "mobile_release/api/data/project.schema.json",
    "mobile_release/build_inputs.py",
    "mobile_release/cancellation.py",
    "mobile_release/checked_files.py",
    "mobile_release/cli.py",
    "mobile_release/config.py",
    "mobile_release/config_edit.py",
    "mobile_release/config_payloads.py",
    "mobile_release/credential_policy.py",
    "mobile_release/credential_requirements.py",
    "mobile_release/credentials.py",
    "mobile_release/data/apple-profile-roots.pem",
    "mobile_release/discovery.py",
    "mobile_release/errors.py",
    "mobile_release/github_workflow_edit.py",
    "mobile_release/init_transaction.py",
    "mobile_release/init_workspace_custody.py",
    "mobile_release/inspection.py",
    "mobile_release/ios.py",
    "mobile_release/ios_artifacts.py",
    "mobile_release/ios_der.py",
    "mobile_release/ios_entitlements.py",
    "mobile_release/ios_plist_binary.py",
    "mobile_release/ios_profile_auth.py",
    "mobile_release/ios_profile_trust.py",
    "mobile_release/ios_profiles.py",
    "mobile_release/ios_upload_validation.py",
    "mobile_release/local_signing.py",
    "mobile_release/macho.py",
    "mobile_release/metadata.py",
    "mobile_release/owned_process.py",
    "mobile_release/preflight.py",
    "mobile_release/provenance.py",
    "mobile_release/reporting.py",
    "mobile_release/stores.py",
    "mobile_release/tooling.py",
    "mobile_release/workflow.py",
    "mobile_release/workflow_payloads.py",
)
EMPTY_NATIVE_DIRECTORIES = (
    "native", "config-owner", "config-driver-loss", "config-watchdog-loss", "config-stop",
    "config-terminal-deadline", "config-startup-stop", "config-transaction-eof",
)
COMPILER_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target", "appdata", "localappdata", "npm-cache")
COMPILER_PRIVATE_FILES = ("context.json", "core.zip", "metadata.json", "npmrc-user", "npmrc-global", "gitconfig-empty")
COMPILE_PUBLIC_FILES = ("public-bindings.json", "acquire-checks.json", "compile-checks.json")
NATIVE_TEST = "supervisor::hosted_tests::passive_hosted_contract"
WINDOWS_SNAPSHOT_TEST = "supervisor::hosted_tests::windows_static_snapshot_hosted_contract"
FOUNDATION_SCOPE = "passive-v1"
WINDOWS_SNAPSHOT_SCOPE = "windows-snapshot-v1"
WINDOWS_SNAPSHOT_PUBLIC_SCOPE = "windows-static-snapshot-native-only-not-desktop-enablement"
WINDOWS_SNAPSHOT_PHASES = frozenset({"prepare", "acquire", "compile", "windows-snapshot", "clean"})
WINDOWS_SNAPSHOT_RECEIPT_SCOPE = "windows-static-snapshot-native-v1"
WINDOWS_SDK_VERSION = "10.0.26100.0"
WINDOWS_SDK_HEADERS = tuple(sorted((
    "shared/ntdef.h", "shared/ntstatus.h", "shared/winerror.h", "um/winternl.h", "um/winnt.h",
    "um/minwinbase.h", "um/WinBase.h", "um/winioctl.h", "um/ioapiset.h", "um/fileapi.h",
    "um/securitybaseapi.h", "um/aclapi.h",
)))
WINDOWS_SNAPSHOT_SOURCES = tuple(sorted((
    "src/mobile_release/api/_snapshot_windows_native.py", "src/mobile_release/api/_snapshot_windows.py",
    "src/mobile_release/api/_snapshot.py", "src/mobile_release/api/__init__.py",
    "tests/desktop/test_windows_snapshot.py", "tests/desktop/test_api.py", "docs/desktop.md",
    "desktop/src-tauri/runtime-contract.md", "tests/native_desktop_snapshot_windows.py",
    "desktop/src-tauri/src/hosted_tests.rs", "desktop/src-tauri/src/supervisor.rs",
    "desktop/tools/ci_foundation.py", ".github/workflows/desktop-foundation.yml",
    "tests/desktop/test_ci_foundation_contract.py", "src/mobile_release/__init__.py",
    "src/mobile_release/_desktop_engine.py", "src/mobile_release/api/contracts.py",
    "src/mobile_release/api/_json.py", "src/mobile_release/config.py", "src/mobile_release/discovery.py",
    "src/mobile_release/init_transaction.py", "src/mobile_release/errors.py", "desktop/engine_bootstrap.py",
    "desktop/src-tauri/src/runtime.rs", "desktop/src-tauri/src/protocol.rs", "desktop/src-tauri/src/error.rs",
    "desktop/src-tauri/src/bridge.rs", "desktop/src-tauri/src/lib.rs", "desktop/src-tauri/build.rs",
    "desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
)))
WINDOWS_SNAPSHOT_GROUPS = (
    ("W1", ("ordinary-source", "ordinary-zip", "closed-gate")),
    ("W2", ("link-children", "reparse-root", "reparse-ancestor", "short-alias", "case-alias", "case-collision",
            "subst-drive", "unc", "device", "ads")),
    ("W3", ("root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race")),
    ("W4", ("acl-type", "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit")),
    ("W5", ("replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change")),
    ("W6", ("oplock-release", "oplock-withhold", "pending-failstop")),
)
WINDOWS_SNAPSHOT_NOT_VERIFIED = (
    "production-windows-enablement", "production-runtime-custody", "stateful-or-descendant-backends",
    "configuration-saving", "native-gui", "installers", "mobile-builds", "stores", "atomic-snapshot",
)
WINDOWS_READER_APIS = (
    "GetCurrentProcess", "IsWow64Process2", "QueryDosDeviceW", "NtCreateFile", "GetHandleInformation",
    "GetFileType", "GetFileInformationByHandleEx", "GetVolumeInformationByHandleW", "GetFinalPathNameByHandleW",
    "ReadFile", "CloseHandle", "DeviceIoControl",
)
WINDOWS_READER_COUNTERS = (
    "acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxBufferBytes",
    "rootOpens", "relativeOpens", "metadataChecks", "identitiesMatched", "readCalls", "readBytes", "readEof",
    "directoryCalls", "directoryRecords", "directoryEof", "outsideAcquired", "outsideReads", "outsideDescent",
    "aliasMetadataAcquired", "violations", "eventCount",
)
WINDOWS_ORIGINAL_FLAGS = (
    "inspectionJoined", "acquisitionJoined", "spawned", "waited", "writerJoined", "writerComplete",
    "stdoutEof", "stderrEof", "stdoutJoined", "stderrJoined", "driverReturned", "watchdogReturned",
    "observerReturned", "terminal", "permitReleased", "registryEmpty",
)
WINDOWS_FIXTURE_COUNTERS = ("acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxArenaBytes")
WINDOWS_SNAPSHOT_ISSUES = frozenset({
    "config.missing", "config.invalid", "snapshot.scan-stopped", "snapshot.entry-limit", "snapshot.changed",
    "snapshot.file-limit", "snapshot.file-size", "snapshot.byte-limit", "snapshot.encoding", "snapshot.unsafe-file",
    "snapshot.unsupported", "snapshot.handle-limit", "snapshot.unreadable", "snapshot.config-output-limit",
    "snapshot.path-limit", "snapshot.link-excluded", "snapshot.depth-limit", "snapshot.container-limit",
    "snapshot.output-limit",
})
CONFIG_OWNER_TEST = "edit_owner::hosted_tests::hosted_config_edit_owner_original_resources"
CONFIG_DRIVER_LOSS_TEST = "edit_owner::hosted_tests::hosted_config_driver_loss_original_resources"
CONFIG_WATCHDOG_LOSS_TEST = "edit_owner::hosted_tests::hosted_config_watchdog_loss_original_resources"
CONFIG_STOP_TEST = "edit_owner::hosted_tests::hosted_config_stop_original_resources"
CONFIG_TERMINAL_DEADLINE_TEST = "edit_owner::hosted_tests::hosted_config_terminal_deadline_original_resources"
CONFIG_STARTUP_STOP_TEST = "edit_owner::hosted_tests::hosted_config_startup_stop_original_resources"
CONFIG_TRANSACTION_EOF_TEST = "edit_owner::hosted_tests::hosted_config_transaction_eof_original_resources"
TARGETS = {
    "linux": "x86_64-unknown-linux-gnu",
    "macos": "aarch64-apple-darwin",
    "windows": "x86_64-pc-windows-msvc",
}
NATIVE_CASES = (
    "core-capabilities", "core-catalog", "core-zip-catalog", "core-valid-draft",
    "core-invalid-draft", "core-service-error", "core-snapshot", "malformed",
    "truncated", "extra_frames", "wrong_id", "nonzero_exit", "pipe_pressure",
    "stdout_limit", "stderr_limit", "delay_exit", "busy-abandon", "operation-timeout",
    "shutdown-active", "controlled-startup", "controlled-io-join",
    "controlled-management-returns", "controlled-management-late",
)
CONFIG_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
CONFIG_CASES = {
    "ordinary": (
        "create", "save", "no-op", "ignore-append", "ignore-conflict", "invalid-existing",
        "single-link-admission", "stale-config-bytes", "stale-config-inode", "stale-ignore-after-prepare",
        "stale-release", "absent-release-appeared", "stale-root", "init-0", "init-1", "init-2",
        "build-pending", "build-terminal", "build-stage", "init-alias", "malformed-private-mode",
        "contention-init", "contention-build", "idle-review-unlocked", "precommit-publication-injection",
        "legacy-public-commit", "legacy-public-rollback",
    ),
    "committed-fsync": ("committed-fsync-injection",),
    "committed-close": ("committed-close-return-injection",),
}
CONFIG_INJECTIONS = {
    "ordinary": "precommit-publication",
    "committed-fsync": "postdecision-pre-fsync",
    "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss",
}
CONFIG_OWNER_SOURCES = {
    "fixture": "desktop/src-tauri/src/edit_hosted_tests.rs",
    "owner": "desktop/src-tauri/src/edit_owner.rs",
    "editProtocol": "desktop/src-tauri/src/edit_protocol.rs",
    "runtime": "desktop/src-tauri/src/runtime.rs",
    "protocol": "desktop/src-tauri/src/protocol.rs",
    "errors": "desktop/src-tauri/src/error.rs",
    "library": "desktop/src-tauri/src/lib.rs",
    "build": "desktop/src-tauri/build.rs",
    "cargoManifest": "desktop/src-tauri/Cargo.toml",
    "cargoLock": "desktop/src-tauri/Cargo.lock",
    "bootstrap": "desktop/config_edit_bootstrap.py",
    "passiveBootstrap": "desktop/engine_bootstrap.py",
    "corePackage": "src/mobile_release/__init__.py",
    "engine": "src/mobile_release/_desktop_edit_engine.py",
    "control": "src/mobile_release/_desktop_edit_control.py",
    "coreProtocol": "src/mobile_release/_desktop_edit_protocol.py",
    "configEdit": "src/mobile_release/config_edit.py",
    "configPayloads": "src/mobile_release/config_payloads.py",
    "config": "src/mobile_release/config.py",
    "transaction": "src/mobile_release/init_transaction.py",
    "rootCustody": "src/mobile_release/init_workspace_custody.py",
    "cancellation": "src/mobile_release/cancellation.py",
    "buildInputs": "src/mobile_release/build_inputs.py",
    "coreErrors": "src/mobile_release/errors.py",
    "preview": "src/mobile_release/api/_preview.py",
    "nativeFixture": "tests/native_desktop_config.py",
}
CONFIG_OWNER_NOT_VERIFIED = (
    "production-runtime-custody", "production-save-enablement", "native-gui", "window-reload-crash",
    "parent-death", "native-stuck-wait-close", "windows-filesystem", "stores", "mobile-builds", "installers",
)
CONFIG_TRANSACTION_EOF_SOURCES = {
    **CONFIG_OWNER_SOURCES,
    "transactionEofShim": "tests/native_desktop_config_eof.py",
}
CONFIG_OWNER_FINALITY = (
    "originalWait", "stdoutEof", "stderrEof", "stdinClosed", "stdoutClosed", "stderrClosed",
    "startupJoined", "ioJoined", "driverJoined", "watchdogJoined", "managerJoined",
)
# Closed synthetic workflow bindings; DATA only, never a generator import.
# Canonical payload companion: 245da8ed86544b7826ec70cec3c5e34205e8e4d1a0f6e1b701dcf79d9034c536.
WORKFLOW_CORE_SOURCES = {
    'fixture': 'tests/native_desktop_config.py',
    'workflowEdit': 'src/mobile_release/github_workflow_edit.py',
    'configEdit': 'src/mobile_release/config_edit.py',
    'transaction': 'src/mobile_release/init_transaction.py',
    'rootCustody': 'src/mobile_release/init_workspace_custody.py',
    'cancellation': 'src/mobile_release/cancellation.py',
    'buildInputs': 'src/mobile_release/build_inputs.py',
    'workflowPayloads': 'src/mobile_release/workflow_payloads.py',
    'proposal': 'src/mobile_release/api/_github_setup.py',
    'resource': 'src/mobile_release/api/data/github-setup-v1.json',
    'canonicalPreflight': 'templates/workflows/mobile-preflight.yml',
    'canonicalCandidate': 'templates/workflows/mobile-candidate.yml',
    'canonicalExternalTesting': 'templates/workflows/mobile-external-testing.yml',
    'canonicalProductionSubmit': 'templates/workflows/mobile-production-submit.yml',
}
WORKFLOW_PAYLOAD_BINDINGS = {
    'draftSha256': 'e7530b44993489441ab3b0530899b4376d49f1188d5def28979fcb5300d3cd34',
    'toolingRepository': 'Example/mobile-release-kit',
    'toolingSha': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'templateSet': {
        'coreVersion': '0.3.0',
        'resourceVersion': 1,
        'resourceSha256': '4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c',
    },
    'payloadHashes': {
        'preflight': '50845641f06763aab532900d1b3b186a5d684d465a4d63fab05f53c99f9685de',
        'candidate': '8fb540be24c263c97f7dbf95df524a8b11633e5fa7b1dc92e77cd648ad16e32f',
        'external-testing': '97fa27d95cc7b2d75be0c3a0860af1d350edb6a52741ed87c0a5b13eca8386f1',
        'production-submit': '85865a4df661ef7c7b708b55598a70d56fd84957ce07c9c60f15bcf10a5554b8',
    },
}
# Every row is an exact observed-fact contract, not a success summary.
# Rows: name, effect, journal, resources, reason, fatal, observed.
WORKFLOW_CORE_ROWS = {
    'ordinary': (
        ('capture-prepare-discard', 'not_started', 'not_created', 'settled', 'none', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'scopesClosed': 2, 'discardRetired': True, 'diskConfigUnchanged': True}),
        ('existing-differs', 'not_started', 'not_created', 'settled', 'none', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'conflictIds': ['preflight'], 'tokenAbsent': True, 'rechecks': 1}),
        ('oversized', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('unreadable', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('symlink-leaf', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('symlink-ancestor', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('hardlink', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('aliased-leaf', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('nonregular-fifo', 'not_started', 'not_created', 'settled', 'filesystem_error', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'observationRefused': True}),
        ('registered-root-replaced', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'targetObservations': 0, 'registeredIdentityChanged': True, 'replacementUnchanged': True, 'originalUnchanged': True, 'journalAbsent': True}),
        ('stale-leaf-bytes-before-prepare', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 1, 'retired': True}),
        ('stale-leaf-inode-before-apply', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 2, 'retired': True}),
        ('stale-ancestor-mode-before-prepare', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 1, 'retired': True}),
        ('absent-ancestor-before-prepare', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 1, 'retired': True}),
        ('absent-leaf-before-apply', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 2, 'retired': True}),
        ('stale-root-before-apply', 'not_started', 'not_created', 'settled', 'stale_revision', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'rechecks': 1, 'retired': True}),
        ('pending-init', 'not_started', 'not_created', 'settled', 'pending_state', False,
         {'snapshotUnchanged': True, 'noTargetsCreated': True}),
        ('pending-build', 'not_started', 'not_created', 'settled', 'pending_state', False,
         {'snapshotUnchanged': True, 'noTargetsCreated': True}),
        ('contention-init', 'not_started', 'not_created', 'settled', 'busy', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'holderClosed': True}),
        ('contention-build', 'not_started', 'not_created', 'settled', 'busy', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'holderClosed': True}),
        ('review-unlocked', 'not_started', 'not_created', 'settled', 'none', False,
         {'snapshotUnchanged': True, 'journalAbsent': True, 'holdersClosed': 2, 'scopesClosed': 2, 'discardRetired': True}),
        ('partial-install-rollback', 'rolled_back', 'clean', 'settled', 'filesystem_error', False,
         {'firstLeafInstalled': True, 'rollbackReturned': True, 'snapshotRestored': True, 'journalAbsent': True, 'injections': 1, 'recoveryAttempts': 1}),
        ('incomplete-preparing', 'not_started', 'recovery_required', 'settled', 'filesystem_error', False,
         {'preparingRetained': True, 'completeProof': False, 'numberedSlotRetained': True, 'recoverCalls': 0, 'cleanupUnlinks': 0, 'injections': 1}),
        ('wrong-roster-controls', 'not_started', 'recovery_required', 'settled', 'filesystem_error', False,
         {'completeProof': True, 'selfConsistentJournal': True, 'wrongRosterRetained': True, 'rollbackCalls': 0, 'cleanupUnlinks': 0, 'injections': 1}),
        ('unowned-staging-slot', 'not_started', 'recovery_required', 'settled', 'filesystem_error', False,
         {'completeProof': True, 'unownedSlotRetained': True, 'rollbackCalls': 0, 'cleanupUnlinks': 0, 'injections': 1}),
        ('rollback-pending-replaced', 'not_started', 'recovery_required', 'settled', 'filesystem_error', False,
         {'completeProof': True, 'sameBytesNewInode': True, 'terminalMoveCalls': 0, 'rollbackCalls': 1, 'cleanupUnlinks': 0, 'remainingProofRetained': True, 'injections': 1}),
        ('cleanup-committed-unused-missing', 'committed', 'recovery_required', 'settled', 'filesystem_error', False,
         {'terminal': 'COMMITTED', 'durable': True, 'unusedPendingAbsent': True, 'cleanupUnlinks': 0, 'remainingProofRetained': True, 'injections': 1}),
        ('cleanup-rolled-back-unused-missing', 'not_started', 'recovery_required', 'settled', 'filesystem_error', False,
         {'terminal': 'ROLLED_BACK', 'durable': True, 'unusedPendingAbsent': True, 'cleanupUnlinks': 0, 'remainingProofRetained': True, 'injections': 1}),
        ('commit-pending-replaced', 'unknown', 'recovery_required', 'settled', 'filesystem_error', False,
         {'completeProof': True, 'sameBytesNewInode': True, 'allFourInstalledBeforeRefusal': True, 'terminalMoveCalls': 0, 'rollbackCalls': 0, 'cleanupUnlinks': 0, 'remainingProofNotConsumed': True, 'injections': 1}),
    ),
    'committed-fsync': (
        ('committed-fsync-injection', 'committed', 'recovery_required', 'settled', 'filesystem_error', False,
         {'committedObserved': True, 'durabilityConfirmed': False, 'rollbackCalls': 0, 'allFourInstalled': True, 'journalRetained': True, 'injections': 1}),
    ),
    'committed-close': (
        ('committed-close-return-injection', 'committed', 'clean', 'unknown', 'cancelled', True,
         {'actualScopeCloseReturned': True, 'cancelledAfterCommit': 1, 'committedCarrier': True, 'injections': 1, 'afterUnknownProbes': 0}),
    ),
}
WORKFLOW_CORE_INJECTIONS = {
    'ordinary': 'fixed-original-workflow-boundaries',
    'committed-fsync': 'postdecision-pre-fsync',
    'committed-close': 'postcommit-cancellation-and-positive-scope-close-return-loss',
}

WORKFLOW_OWNER_SOURCES = {
    **CONFIG_OWNER_SOURCES,
    "workflowProtocol": "desktop/src-tauri/src/github_workflow_edit_protocol.rs",
    "bridge": "desktop/src-tauri/src/bridge.rs",
    "documentBinding": "desktop/src-tauri/src/asset_session.rs",
    "documentLifetime": "desktop/src-tauri/src/document_lifetime.rs",
    "assetSource": "desktop/src-tauri/src/asset_source.rs",
    "assetCommands": "desktop/src-tauri/src/asset_commands.rs",
    "supervisor": "desktop/src-tauri/src/supervisor.rs",
    "editCommands": "desktop/src-tauri/src/edit_commands.rs",
    "githubCommands": "desktop/src-tauri/src/github_commands.rs",
    "workflowEdit": "src/mobile_release/github_workflow_edit.py",
    "workflowPayloads": "src/mobile_release/workflow_payloads.py",
    "githubSetup": "src/mobile_release/api/_github_setup.py",
    "githubResource": "src/mobile_release/api/data/github-setup-v1.json",
    "canonicalPreflight": "templates/workflows/mobile-preflight.yml",
    "canonicalCandidate": "templates/workflows/mobile-candidate.yml",
    "canonicalExternalTesting": "templates/workflows/mobile-external-testing.yml",
    "canonicalProductionSubmit": "templates/workflows/mobile-production-submit.yml",
}
WORKFLOW_TRANSACTION_EOF_SOURCES = {**WORKFLOW_OWNER_SOURCES, "transactionEofShim": "tests/native_desktop_config_eof.py"}
WORKFLOW_NOT_VERIFIED = (
    "production-runtime-custody", "production-workflow-enablement", "native-gui", "webview-callbacks-or-crash-hook",
    "parent-death", "native-stuck-wait-close", "persisted-recovery", "macos-windows-workflow-writes",
    "credentials", "remote-github", "stores", "mobile-builds", "installers",
)
WORKFLOW_OWNER_PAYLOAD_HASHES = {
    "draft": "7c19854e3652c3f3ed698c02fa6078e3e8f62f73682517617bac86cb0038acc7",
    "workflows": WORKFLOW_PAYLOAD_BINDINGS["payloadHashes"],
    "protectedConfig": hashlib.sha256(b"fixed synthetic configuration; intentionally not parsed\r\n").hexdigest(),
    "protectedIgnore": hashlib.sha256(b"# fixed synthetic workflow ignore\r\n").hexdigest(),
    "unrelated": hashlib.sha256(b"fixed synthetic unrelated content\n").hexdigest(),
    "umaskProbe": hashlib.sha256(b"fixed workflow fixture umask\n").hexdigest(),
}
WORKFLOW_OWNER_CASES = (
    "create-fresh", "create-under-github", "mixed-create-preserve", "preserve-all", "different-refusal",
    "root-replaced-before-open", "registration-before-prepare", "registration-before-apply", "config-blocks-workflow", "document-loss",
)
WORKFLOW_EOF_CASES = ("precommit-eof", "postcommit-eof", "precommit-conflict-eof")
# The whole headless library is compiled, but only the two named workflow tests
# may execute. No shell/GTK or Node/Vite outputs are prerequisites for this lane.
WORKFLOW_NATIVE_SOURCES = tuple(sorted({
    *WORKFLOW_TRANSACTION_EOF_SOURCES.values(), *WORKFLOW_CORE_SOURCES.values(),
    "desktop/src-tauri/src/credential_assessment.rs", "desktop/src-tauri/src/credential_format.rs",
    "desktop/src-tauri/src/installed_runtime.rs", "desktop/src-tauri/src/hosted_tests.rs",
    "desktop/src-tauri/src/passive_management_tests.rs",
    "desktop/src-tauri/tests/fixtures/passive_core/__init__.py",
    "desktop/src-tauri/tests/fixtures/passive_core/_desktop_engine.py",
    "desktop/native/linux-mount-observation/Cargo.toml", "desktop/native/linux-mount-observation/src/lib.rs",
    "desktop/tools/ci_foundation.py", "tests/desktop/test_ci_foundation_contract.py", "pyproject.toml",
    WORKFLOW_NATIVE_WORKFLOW,
}))
GITHUB_READONLY_SCOPE = "github-readonly-native-v1"
GITHUB_READONLY_EVIDENCE_SCOPE = "desktop-github-readonly-native-only-v1"
GITHUB_READONLY_WORKFLOW = ".github/workflows/desktop-github-connection-native.yml"
GITHUB_READONLY_REF = "refs/heads/verify/desktop-github-connection-native"
GITHUB_READONLY_TEST = "supervisor::hosted_tests::github_readonly_hosted_contract"
GITHUB_READONLY_PHASES = ("prepare", "acquire", "compile", "github-owner", "clean")
GITHUB_READONLY_CHECKS = {
    "acquire": ("rust-toolchain-install", "rust-version-target", "github-locked-headless-metadata"),
    "compile": ("rust-version-target", "github-headless-test-compile-only", "github-compiled-artifact"),
    "github-owner": ("github-original-artifact", "github-owner-native-contract", "github-owner-receipt"),
}
GITHUB_READONLY_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target", "github-owner")
# The workflow/configuration fixture modules are compile-time inputs to this
# libtest, NOT permission to execute their tests. Reuse that reviewed closure.
GITHUB_READONLY_SOURCES = tuple(sorted({
    *WORKFLOW_NATIVE_SOURCES, GITHUB_READONLY_WORKFLOW,
    "desktop/github_connection_bootstrap.py",
    "desktop/src-tauri/src/github_connection_protocol.rs",
    "desktop/src-tauri/src/github_connection_session.rs",
    "desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py",
    "tests/desktop/test_github_connection_native_contract.py",
}))
GITHUB_TLS_SCOPE = "github-readonly-tls-native-v1"
GITHUB_TLS_EVIDENCE_SCOPE = "desktop-github-readonly-tls-native-only-v1"
GITHUB_TLS_RECEIPT_SCOPE = "github-readonly-tls-hosted-v1"
GITHUB_TLS_WORKFLOW = ".github/workflows/desktop-github-connection-tls.yml"
GITHUB_TLS_REF = "refs/heads/verify/desktop-github-connection-tls"
GITHUB_TLS_TEST = "supervisor::hosted_tests::github_tls_hosted_contract"
GITHUB_TLS_PHASES = ("prepare", "acquire", "compile", "github-tls", "clean")
GITHUB_TLS_CHECKS = {
    "acquire": ("rust-toolchain-install", "rust-version-target", "github-tls-locked-headless-metadata"),
    "compile": ("rust-version-target", "github-tls-headless-test-compile-only", "github-tls-compiled-artifact"),
    "github-tls": ("github-tls-original-artifact", "github-tls-original-outer-wait", "github-tls-receipt"),
}
GITHUB_TLS_CASES = ("T1-source", "T1-zip", "T2-root", "T2-name", "T2-expired",
                    "T3-clean", "T3-ragged", "T3-length", "T3-chunk")
GITHUB_TLS_CERTIFICATES = ("root-ca.pem", "other-root-ca.pem", "api-valid.pem",
                           "wrong-san.pem", "api-expired.pem", "server-key.pem")
GITHUB_TLS_FIXTURES = "desktop/src-tauri/tests/fixtures"
GITHUB_TLS_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target", "github-tls", "github-tls-namespace")
GITHUB_TLS_CONFIG = {
    "hosts": b"127.0.0.1 api.github.com localhost\n::1 localhost\n",
    "resolv.conf": b"# Synthetic namespace: DNS is disabled by hosts: files.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
    "nsswitch.conf": b"passwd: files\ngroup: files\nhosts: files\n",
}
GITHUB_TLS_SOURCES = tuple(sorted({
    *GITHUB_READONLY_SOURCES, GITHUB_TLS_WORKFLOW,
    f"{GITHUB_TLS_FIXTURES}/github_tls_peer.py", f"{GITHUB_TLS_FIXTURES}/github_tls_namespace.sh",
    *(f"{GITHUB_TLS_FIXTURES}/github_tls/{name}" for name in GITHUB_TLS_CERTIFICATES),
}))
GITHUB_TLS_NOT_VERIFIED = (
    "T4-destination-ambient-environment", "T5-real-network-deadlines", "T6-streaming-controls",
    "CA-file-native-faults", "real-github-authentication", "production-runtime-custody",
    "native-gui", "native-document-lifecycle", "packaged-runtime", "production-enablement",
)
# Absolute tool spellings are part of the fixed namespace entry, not PATH selection.
GITHUB_TLS_TOOLS = {
    "sudo": "/usr/bin/sudo", "unshare": "/usr/bin/unshare", "env": "/usr/bin/env",
    "bash": "/usr/bin/bash", "mount": "/usr/bin/mount", "ip": "/usr/bin/ip",
    "sysctl": "/usr/sbin/sysctl", "setpriv": "/usr/bin/setpriv", "stat": "/usr/bin/stat",
    "sha256sum": "/usr/bin/sha256sum", "readlink": "/usr/bin/readlink", "findmnt": "/usr/bin/findmnt",
}
TOOL_CHECKS = frozenset({
    "source-head", "source-tree", "source-clean", "rust-toolchain-install",
    "cargo-selection", "rustc-selection", "rust-version-target", "locked-platform-metadata",
    "node-version", "npm-locked-no-scripts", "headless-test-compile-only",
    "typescript-no-emit", "vite-assets", "tauri-debug-compile-only", "passive-native-contract",
    "config-core-ordinary", "config-core-committed-fsync", "config-core-committed-close",
    "config-owner-native-contract",
    "config-driver-loss-native-contract", "config-watchdog-loss-native-contract",
    "config-stop-native-contract", "config-terminal-deadline-native-contract", "config-startup-stop-native-contract",
    "config-transaction-eof-native-contract",
    "gtk-python-syntax-only", "gtk-js-syntax-only", "gtk-c-pkg-config",
    "gtk-c-compile-only", "gtk-integration-compile-only",
    "workflow-locked-headless-metadata", "workflow-owner-source-native-contract", "workflow-owner-zip-native-contract",
    "workflow-transaction-eof-native-contract", "workflow-core-ordinary", "workflow-core-committed-fsync",
    "workflow-core-committed-close", "workflow-source-status",
    "windows-snapshot-native-contract",
    "github-locked-headless-metadata", "github-headless-test-compile-only", "github-owner-native-contract",
    "github-tls-locked-headless-metadata", "github-tls-headless-test-compile-only",
})


class CheckFailure(ValueError):
    """Fixed, non-secret diagnostic for an explicit check condition."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def admit_phase(scope: str, phase: str) -> None:
    """Closed scope selection, before context, tools, or native dispatch."""
    require(scope in {BOUNDARY_SCOPE, WORKFLOW_NATIVE_SCOPE, GITHUB_READONLY_SCOPE, GITHUB_TLS_SCOPE, WINDOWS_SNAPSHOT_SCOPE, *COMPILE_PROFILES}, "Unknown desktop verification scope")
    if scope in COMPILE_PROFILES:
        require(phase in COMPILE_PHASES, "Compiler-only scope cannot execute a native phase")
    elif scope == WORKFLOW_NATIVE_SCOPE:
        require(phase in WORKFLOW_NATIVE_PHASES, "Workflow-only scope cannot execute an unrelated native phase")
    elif scope == WINDOWS_SNAPSHOT_SCOPE:
        require(phase in WINDOWS_SNAPSHOT_PHASES, "Windows snapshot scope cannot execute an unrelated phase")
    elif scope == GITHUB_READONLY_SCOPE:
        require(phase in GITHUB_READONLY_PHASES, "G1 scope cannot execute an unrelated phase")
    elif scope == GITHUB_TLS_SCOPE:
        require(phase in GITHUB_TLS_PHASES, "TLS scope cannot execute an unrelated phase")
    else:
        require(phase in BOUNDARY_PHASES, "Foundation scope cannot execute a workflow-only phase")


def admit_platform(scope: str, platform: str) -> None:
    require(platform in TARGETS, "Unknown desktop verification platform")
    require(scope != GTK_COMPILE_SCOPE or platform == "linux", "SG1 compilation requires Linux")
    require(scope != WORKFLOW_NATIVE_SCOPE or platform == "linux", "Workflow native verification requires Linux")
    require(scope != WINDOWS_SNAPSHOT_SCOPE or platform == "windows", "Windows snapshot verification requires Windows")
    require(scope != GITHUB_READONLY_SCOPE or platform == "linux", "G1 native verification requires Linux")
    require(scope != GITHUB_TLS_SCOPE or platform == "linux", "TLS verification requires Linux")


def compile_profile(scope: str) -> dict:
    require(type(scope) is str and scope in COMPILE_PROFILES, "Unknown compiler-only profile")
    return COMPILE_PROFILES[scope]


def compile_workflow_binding(environment: dict[str, str], scope: str = COMPILE_SCOPE) -> dict[str, str]:
    """Pure binding to the actual fixed verification workflow, not a caller path."""
    profile = compile_profile(scope)
    sha, repository = environment.get("GITHUB_SHA", ""), environment.get("GITHUB_REPOSITORY", "")
    run_id, attempt = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "Compiler workflow source identity differs")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (run_id, attempt)),
            "Compiler workflow run identity differs")
    require(environment.get("GITHUB_REF") == profile["ref"]
            and environment.get("GITHUB_WORKFLOW_SHA") == sha
            and environment.get("GITHUB_WORKFLOW_REF") == f"{repository}/{profile['workflow']}@{profile['ref']}",
            "Compiler workflow/ref binding differs")
    event = environment.get("GITHUB_EVENT_NAME")
    require(event == "push" or event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == sha,
            "Compiler workflow event or exact dispatch source differs")
    return {"workflowPath": profile["workflow"], "workflowSha": sha,
            "workflowRef": environment["GITHUB_WORKFLOW_REF"], "sourceSha": sha,
            "runId": run_id, "attempt": attempt}


def workflow_native_binding(environment: dict[str, str]) -> dict[str, str]:
    """Separate native lane; never a compiler-profile or renderer capability."""
    sha, repository = environment.get("GITHUB_SHA", ""), environment.get("GITHUB_REPOSITORY", "")
    run_id, attempt = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "Workflow native source identity differs")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (run_id, attempt)),
            "Workflow native run identity differs")
    require(environment.get("GITHUB_REF") == WORKFLOW_NATIVE_REF
            and environment.get("GITHUB_WORKFLOW_SHA") == sha
            and environment.get("GITHUB_WORKFLOW_REF") == f"{repository}/{WORKFLOW_NATIVE_WORKFLOW}@{WORKFLOW_NATIVE_REF}",
            "Workflow native workflow/ref binding differs")
    event = environment.get("GITHUB_EVENT_NAME")
    require(event == "push" or event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == sha,
            "Workflow native event or exact dispatch source differs")
    return {"workflowPath": WORKFLOW_NATIVE_WORKFLOW, "workflowSha": sha,
            "workflowRef": environment["GITHUB_WORKFLOW_REF"], "sourceSha": sha,
            "runId": run_id, "attempt": attempt}


def same_compile_json(value: object, expected: object) -> bool:
    """JSON equality with exact types; booleans/floats cannot stand in for ints."""
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return value.keys() == expected.keys() and all(same_compile_json(value[key], item) for key, item in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(same_compile_json(a, b) for a, b in zip(value, expected))
    return value == expected


def validate_compile_receipt(value: object, context: dict, phase: str) -> dict:
    """A compile receipt licenses only compiler-output cleanup, not native finality."""
    profile = compile_profile(context.get("executionScope", ""))
    admit_platform(context["executionScope"], context.get("platform", ""))
    require(phase in profile["checks"] and context.get("workflowPath") == profile["workflow"],
            "Compiler receipt scope or workflow differs")
    require(type(value) is dict, "Missing compiler phase receipt")
    binding_names = ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")
    expected = {
        "schemaVersion": 1, "scope": profile["evidence"], "phase": phase, "status": "passed",
        **{name: context[name] for name in binding_names},
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": NODE,
        "checks": [{"check": name, "exitCode": 0} for name in profile["checks"][phase]],
    }
    if context["executionScope"] == GTK_COMPILE_SCOPE:
        expected.update(sourceTree=context["sourceTree"], sg1=context["sg1"])
    require(same_compile_json(value, expected),
            "Compiler phase receipt is incomplete or its original source/checks differ")
    return value


def parse_compile_receipt(raw: bytes) -> object:
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "Compiler phase receipt exceeds its bound")
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate compiler receipt field")
            result[key] = value
        return result
    def nonfinite(_: str) -> None:
        raise CheckFailure("Nonfinite compiler receipt value")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("Malformed compiler phase receipt") from None


def validate_compile_inventory(names: set[str], nonempty_native: set[str]) -> None:
    expected = set(COMPILER_DIRECTORIES + EMPTY_NATIVE_DIRECTORIES + COMPILER_PRIVATE_FILES + COMPILE_PUBLIC_FILES)
    require(names == expected and not nonempty_native,
            "Compiler-only task contains missing, unexpected, or native outputs; retain it")


def ordinary(path: Path) -> None:
    details = path.lstat()
    require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1
            and not getattr(details, "st_file_attributes", 0) & 0x400,
            "Expected an ordinary, single-link file")


def hash_file(path: Path) -> str:
    ordinary(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def gtk_compile_binding(source: Path) -> dict:
    """Named SG1 compiler inputs, not an installed/native qualification freeze."""
    sources = []
    for relative in GTK_COMPILE_SOURCES:
        path = source / relative
        ordinary(path)
        size = path.stat().st_size
        require(0 < size <= 1024 * 1024, "SG1 compiler input exceeds its bound")
        sources.append({"path": relative, "size": size, "sha256": hash_file(path)})
    return {"features": list(GTK_COMPILE_FEATURES), "testTarget": "session-gtk-qualification",
            "execution": "no-run", "sources": sources}


def validate_gtk_core_inventory(value: object) -> None:
    """Pure exact-name/shape check; byte identities still come from prepare()."""
    require(type(value) is list and len(value) == len(GTK_CORE_PATHS),
            "SG1 requires its complete reviewed core inventory")
    names = []
    total = 0
    for row in value:
        require(type(row) is dict and set(row) == {"path", "sha256", "size"},
                "SG1 core inventory entry differs")
        require(type(row["path"]) is str and type(row["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
                and type(row["size"]) is int and 0 <= row["size"] <= 8 * 1024 * 1024,
                "SG1 core inventory entry is malformed")
        names.append(row["path"])
        total += row["size"]
    require(len(set(names)) == len(names) and tuple(names) == GTK_CORE_PATHS,
            "SG1 core inventory has missing, duplicate, extra, or reordered paths")
    require(total <= 32 * 1024 * 1024, "SG1 core aggregate bound exceeded")


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def run(argv: list[str], *, check: str, cwd: Path, env: dict[str, str], timeout: int,
        capture: bool = False, output: TextIO | None = None, diagnostics: TextIO | None = None) -> str:
    # Only fixed commands below reach this internal helper. No shell, inherited
    # credentials, renderer input, project hook or arbitrary command selection.
    require(check in TOOL_CHECKS, "Unknown fixed compiler check")
    require(not (capture and output is not None), "Conflicting compiler output destinations")
    require(diagnostics is None or (output is not None and check in {
        "github-locked-headless-metadata", "github-headless-test-compile-only", "github-owner-native-contract",
        "github-tls-locked-headless-metadata", "github-tls-headless-test-compile-only"}),
        "Unexpected private diagnostic destination")
    print(f"Fixed check: {check}", flush=True)
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout,
                                text=True, stdout=subprocess.PIPE if capture else output, stderr=diagnostics)
    except subprocess.CalledProcessError as error:
        # Do not interpolate exception text: it includes argv and may contain
        # local paths or captured output. These labels come only from fixed code.
        raise CheckFailure(f"Fixed check {check} exited {error.returncode}") from None
    except subprocess.TimeoutExpired:
        raise CheckFailure(f"Fixed check {check} exceeded its deadline") from None
    except OSError:
        raise CheckFailure(f"Fixed check {check} could not start") from None
    if capture:
        require(len(result.stdout.encode("utf-8")) <= 1024 * 1024, "Tool metadata exceeded its bound")
        return result.stdout.strip()
    return ""


def admitted_host() -> str:
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") in {BOUNDARY_SCOPE, WORKFLOW_NATIVE_SCOPE, GITHUB_READONLY_SCOPE, GITHUB_TLS_SCOPE, WINDOWS_SNAPSHOT_SCOPE, *COMPILE_PROFILES},
            "This fixed check requires an explicitly admitted disposable hosted job")
    platform = os.environ.get("MRK_DESKTOP_PLATFORM", "")
    require(platform in TARGETS and platform == {
        "linux": "linux", "darwin": "macos", "win32": "windows",
    }.get(sys.platform), "Unexpected host platform")
    admit_platform(os.environ["MRK_DESKTOP_HOSTED_CHECKS"], platform)
    if os.environ["MRK_DESKTOP_HOSTED_CHECKS"] == WINDOWS_SNAPSHOT_SCOPE:
        admitted_scope(platform)
    if os.environ["MRK_DESKTOP_HOSTED_CHECKS"] in {WORKFLOW_NATIVE_SCOPE, GITHUB_READONLY_SCOPE, GITHUB_TLS_SCOPE}:
        require(os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64"
                and os.environ.get("ImageOS") == "ubuntu24" and os.uname().machine == "x86_64"
                and os.geteuid() != 0, "Workflow native checks require the non-root Ubuntu 24 x86_64 runner")
    require(sys.version.split()[0] == PYTHON, "Unexpected selected Python version")
    selected = Path(os.environ["MRK_PYTHON"]).resolve(strict=True)
    require(selected == Path(sys.executable).resolve(strict=True), "Python setup output differs")
    return platform


def admitted_scope(platform: str) -> str:
    """Recheck the fixed workflow route, not a user-selectable execution grant."""
    scope = os.environ.get("MRK_DESKTOP_HOSTED_CHECKS", "")
    require(scope in {FOUNDATION_SCOPE, WINDOWS_SNAPSHOT_SCOPE}, "Unexpected fixed verification scope")
    windows = scope == WINDOWS_SNAPSHOT_SCOPE
    if windows:
        require(platform == "windows" and os.environ.get("RUNNER_OS") == "Windows"
                and os.environ.get("RUNNER_ARCH") == "X64", "Windows snapshot requires the native X64 job")
    sha = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid exact event source")
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event == "push":
        expected_ref = ("refs/heads/verify/desktop-windows-snapshot" if windows
                        else "refs/heads/feature/desktop-application")
        require(os.environ.get("GITHUB_REF") == expected_ref, "Push ref and fixed verification scope differ")
    else:
        require(event == "workflow_dispatch", "Unexpected verification event")
        require(os.environ.get("MRK_DESKTOP_DISPATCH_SCOPE") == ("windows-snapshot" if windows else "foundation")
                and os.environ.get("MRK_DESKTOP_EXPECTED_SHA") == sha,
                "Dispatch scope or reviewed source differs")
    return scope


def clean_environment(root: Path) -> dict[str, str]:
    # The ordinary compiler PATH is supplied by the trusted hosted image/setup
    # Actions. It is not a production-runtime admission or application PATH.
    environment = {"PATH": os.environ["PATH"], "HOME": str(root / "home"),
                   "CARGO_HOME": str(root / "cargo"), "RUSTUP_HOME": str(root / "rustup"),
                   "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
                   "LC_ALL": "C", "LANG": "C", "CARGO_INCREMENTAL": "0",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(root / "gitconfig-empty"),
                   "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                   "NODE_DISABLE_COMPILE_CACHE": "1", "ESBUILD_WORKER_THREADS": "0", "GOMAXPROCS": "2"}
    if sys.platform == "win32":
        for name in ("SystemRoot", "SystemDrive", "COMSPEC", "PATHEXT", "ProgramFiles",
                     "ProgramFiles(x86)", "ProgramW6432", "WINDIR", "INCLUDE", "LIB", "LIBPATH",
                     "VCToolsInstallDir", "VCINSTALLDIR", "VSINSTALLDIR", "WindowsSdkDir",
                     "WindowsSDKVersion", "UniversalCRTSdkDir", "UCRTVersion"):
            if name in os.environ:
                environment[name] = os.environ[name]
        environment.update(USERPROFILE=str(root / "home"), APPDATA=str(root / "appdata"),
                           LOCALAPPDATA=str(root / "localappdata"))
    return environment


def source_unchanged(context: dict) -> None:
    source, root = Path(context["source"]), Path(context["root"])
    git = context["git"]
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment, timeout=15, capture=True)
            == context["sourceSha"], "Checkout commit changed")
    run([git, "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "--quiet", "HEAD", "--"],
        check="source-clean", cwd=source, env=environment, timeout=15)


def no_cargo_configuration(directories: tuple[Path, ...]) -> None:
    for directory in directories:
        for name in ("config", "config.toml"):
            path = directory / ".cargo" / name
            require(not path.exists() and not path.is_symlink(), "Ambient Cargo configuration is not admitted")


def parse_workflow_receipt(raw: bytes) -> object:
    """Bounded native DATA only; duplicate fields cannot overwrite a failure."""
    require(type(raw) is bytes and 0 < len(raw) <= 128 * 1024, "Workflow receipt exceeds its bound")
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate workflow receipt field")
            result[key] = value
        return result
    def nonfinite(_: str) -> None:
        raise CheckFailure("Nonfinite workflow receipt value")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("Malformed workflow receipt") from None


def workflow_json(path: Path, *, maximum: int = 128 * 1024) -> object:
    require(maximum in (64 * 1024, 128 * 1024), "Unknown workflow DATA size bound")
    ordinary(path)
    size = path.stat().st_size
    require(0 < size <= maximum, "Workflow receipt exceeds its bound")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == size, "Workflow receipt changed")
    return parse_workflow_receipt(raw)


def validate_workflow_host(value: object) -> None:
    require(type(value) is dict and set(value) == {"kernelRelease", "machine", "nonRoot", "filesystem"},
            "Workflow observed host fields differ")
    require(type(value["kernelRelease"]) is str and 0 < len(value["kernelRelease"]) <= 256
            and all(0x21 <= ord(char) <= 0x7e for char in value["kernelRelease"])
            and value["machine"] == "x86_64" and value["nonRoot"] is True,
            "Workflow observed host differs")
    filesystem = value["filesystem"]
    require(type(filesystem) is dict and set(filesystem) == {"device", "blockSize", "fragmentSize", "nameMax", "flags"},
            "Workflow observed filesystem fields differ")
    require(type(filesystem["device"]) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", filesystem["device"]) is not None
            and int(filesystem["device"]) < 2**64
            and all(type(filesystem[key]) is int and 0 < filesystem[key] < 2**64
                    for key in ("blockSize", "fragmentSize", "nameMax"))
            and type(filesystem["flags"]) is int and 0 <= filesystem["flags"] < 2**64,
            "Workflow observed filesystem values differ")


def workflow_host(root: Path) -> dict:
    details, filesystem, kernel = root.lstat(), os.statvfs(root), os.uname()
    value = {"kernelRelease": kernel.release, "machine": kernel.machine, "nonRoot": os.geteuid() != 0,
             "filesystem": {"device": str(details.st_dev), "blockSize": filesystem.f_bsize,
                            "fragmentSize": filesystem.f_frsize, "nameMax": filesystem.f_namemax,
                            "flags": filesystem.f_flag}}
    validate_workflow_host(value)
    return value


def workflow_directory_identity(path: Path) -> dict:
    details = path.lstat()
    require(stat.S_ISDIR(details.st_mode) and not path.is_symlink()
            and details.st_uid == os.geteuid(), "Workflow original task directory differs")
    return {"device": str(details.st_dev), "inode": str(details.st_ino), "mode": details.st_mode,
            "uid": details.st_uid, "gid": details.st_gid}


def workflow_source_files(source: Path) -> list[dict]:
    files = []
    for relative in WORKFLOW_NATIVE_SOURCES:
        path = source / relative
        ordinary(path)
        size = path.stat().st_size
        require(0 < size <= 2 * 1024 * 1024, "Workflow native source exceeds its bound")
        files.append({"path": relative, "size": size, "sha256": hash_file(path)})
    return files


def workflow_core_inventory(source: Path) -> list[dict]:
    """Reobserve the original bounded ZIP input roster; never import the core."""
    workflow_directory_identity(source / "src")
    workflow_directory_identity(source / "src/mobile_release")
    inventory, total = [], 0
    for path in sorted((source / "src/mobile_release").rglob("*"), key=lambda item: item.as_posix()):
        require(not path.is_symlink(), "Workflow core input contains a symbolic link")
        if path.is_dir():
            continue
        ordinary(path)
        size = path.stat().st_size
        require(path.suffix in {".py", ".json", ".pem"} and len(inventory) < 2048
                and 0 <= size <= 8 * 1024 * 1024, "Workflow core input bound differs")
        total += size
        require(total <= 32 * 1024 * 1024, "Workflow core aggregate bound differs")
        inventory.append({"path": path.relative_to(source / "src").as_posix(), "size": size, "sha256": hash_file(path)})
    require(bool(inventory), "Workflow core inventory is empty")
    return inventory


def workflow_inputs_unchanged(context: dict) -> None:
    """Source/receipt DATA reads only, also safe after the lane-last control.

    Never inspect a synthetic project, recover a journal, select a tool, or
    interpret the intentional resources-Unknown as a deletion capability.
    """
    require(context.get("executionScope") == WORKFLOW_NATIVE_SCOPE and context.get("platform") == "linux",
            "Unexpected workflow input scope")
    root, source = Path(context["root"]), Path(context["source"])
    identities = {"root": workflow_directory_identity(root), "source": workflow_directory_identity(source),
                  **{name: workflow_directory_identity(root / name) for name in WORKFLOW_NATIVE_DIRECTORIES}}
    require(same_compile_json(identities, context["originalDirectories"]), "Workflow original directory identity changed")
    inputs = context["workflowInputs"]
    observed = {"sourceFiles": workflow_source_files(source), "coreFiles": workflow_core_inventory(source),
                "coreZipSha256": hash_file(root / "core.zip"), "pythonSha256": hash_file(Path(context["python"]))}
    require(same_compile_json(inputs, observed), "Workflow original source/runtime inputs changed")
    require(same_compile_json(workflow_json(root / "metadata.json"), workflow_core_metadata(context)), "Workflow source/ZIP metadata changed")


def workflow_core_metadata(context: dict) -> dict:
    return {**{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
            "ref": WORKFLOW_NATIVE_REF, "coreFiles": context["workflowInputs"]["coreFiles"],
            "coreZipSha256": context["workflowInputs"]["coreZipSha256"]}


def workflow_source_unchanged(context: dict) -> None:
    source_unchanged(context)
    require(run([context["git"], "status", "--porcelain=v1", "--untracked-files=all"], check="workflow-source-status",
                cwd=Path(context["source"]), env=clean_environment(Path(context["root"])), timeout=15, capture=True) == "",
            "Workflow source contains unreviewed or generated inputs")
    workflow_inputs_unchanged(context)


def validate_workflow_core_receipt(receipt: object, partition: str, *, source_sha: str,
                                   source_hashes: dict[str, str], python_hash: str, host: dict) -> dict:
    require(partition in WORKFLOW_PARTITIONS and set(source_hashes) == set(WORKFLOW_CORE_SOURCES),
            "Unknown workflow core partition or source inventory")
    validate_workflow_host(host)
    rows = WORKFLOW_CORE_ROWS[partition]
    expected = {
        "schemaVersion": 1, "suite": "desktop-workflow-native", "domain": "github_workflows",
        "partition": partition, "status": "passed", "reason": "none", "failedAt": None,
        "retained": True, "uncertaintyLatched": partition != "committed-fsync",
        "injection": WORKFLOW_CORE_INJECTIONS[partition], "host": host,
        "bindings": {"sourceSha": source_sha, "sourceKind": "source", "sourceHashes": source_hashes,
                     "pythonSha256": python_hash, **WORKFLOW_PAYLOAD_BINDINGS},
        "completed": [row[0] for row in rows],
        "cases": [{"case": name, "outcome": {"effect": effect, "journal": journal, "resources": resources, "reason": reason},
                   "owner": {"closed": True, "handlerRestored": True, "fatal": fatal}, "observed": observed}
                  for name, effect, journal, resources, reason, fatal, observed in rows],
    }
    require(same_compile_json(receipt, expected),
            "Workflow core original facts, source, retention or ordered case inventory differ")
    return receipt


def workflow_owner_bindings(context: dict, mode: str, source_hashes: dict[str, str], *, eof: bool = False) -> dict:
    require(context.get("executionScope") == WORKFLOW_NATIVE_SCOPE and context.get("platform") == "linux"
            and mode in ("source", "zip") and (not eof or mode == "source")
            and set(source_hashes) == set(WORKFLOW_TRANSACTION_EOF_SOURCES if eof else WORKFLOW_OWNER_SOURCES),
            "Workflow owner runtime choice or source inventory differs")
    inputs = context["workflowInputs"]
    inventory = json.dumps(inputs["coreFiles"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return {**{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
            "ref": WORKFLOW_NATIVE_REF, "domain": "github_workflows", "host": "linux", "target": TARGETS["linux"],
            "runtimeMode": "trusted-development-only", "runtimeInput": mode, "pythonSha256": inputs["pythonSha256"],
            "coreZipSha256": inputs["coreZipSha256"], "coreInventorySha256": hashlib.sha256(inventory).hexdigest(),
            "sourceHashes": source_hashes, "payloadHashes": WORKFLOW_OWNER_PAYLOAD_HASHES,
            "templateResourceSha256": WORKFLOW_PAYLOAD_BINDINGS["templateSet"]["resourceSha256"],
            "toolingRepository": WORKFLOW_PAYLOAD_BINDINGS["toolingRepository"], "toolingSha": WORKFLOW_PAYLOAD_BINDINGS["toolingSha"],
            "inheritedFileMaskObserved": True, "requestedCreateMode": 0o644, "observedCreateMode": 0o600, "newDirectoryMode": 0o755,
            "documentEvidence": "controlled-original-lifetime-not-gui-callbacks"}


def validate_workflow_owner_header(receipt: object, context: dict, mode: str, source_hashes: dict[str, str], *, eof: bool = False) -> list:
    require(type(receipt) is dict and type(receipt.get("cases")) is list, "Unexpected workflow owner receipt")
    expected = {"schemaVersion": 1, "scope": "github-workflow-transaction-eof-hosted-v1" if eof else "github-workflow-owner-hosted-v1",
                "domain": "github_workflows", "status": "passed", "allOwnersSettled": not eof, "originalResourcesSettled": True,
                "ownerDisabled": eof, "retainedEffectUnknown": eof, "failureCode": None, "cases": receipt["cases"],
                "bindings": workflow_owner_bindings(context, mode, source_hashes, eof=eof), "notVerified": list(WORKFLOW_NOT_VERIFIED)}
    require(same_compile_json(receipt, expected), "Workflow owner source/runtime/retention or original resource header differs")
    return receipt["cases"]


def workflow_case_value(case: object, *, name: str, effect: str, journal: str, reason: tuple[str, ...], native_reason: str,
                        applying: bool, requests: int, responses: int, sequence: int, observations: dict,
                        domain: str = "github_workflows", unknown: bool = False, stderr: int = 0) -> dict:
    require(type(case) is dict and type(case.get("stdoutBytes")) is int and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024,
            "Workflow original stdout accounting differs")
    outcome = case.get("outcome")
    require(type(outcome) is dict and type(outcome.get("reason")) is str and outcome["reason"] in reason,
            "Workflow original core reason differs")
    return {"name": name, "domain": domain, "nativePhase": "unknown" if unknown else "final",
            "nativeFinality": "unknown" if unknown else "settled", "nativeReason": native_reason,
            "applySubmitted": applying, "lateSettled": unknown,
            "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": outcome["reason"]},
            "terminalSeq": sequence, "registeredByOriginalProbe": True, "sourceProbesSettled": True,
            "observations": observations, "requestFrames": requests, "responseFrames": responses,
            "stdoutBytes": case["stdoutBytes"], "stderrBytes": stderr, "forceAttempted": False,
            **dict.fromkeys(CONFIG_OWNER_FINALITY, True)}


def validate_workflow_owner_receipt(receipt: object, mode: str, *, context: dict, source_hashes: dict[str, str]) -> dict:
    cases = validate_workflow_owner_header(receipt, context, mode, source_hashes)
    names = WORKFLOW_OWNER_CASES if mode == "source" else WORKFLOW_OWNER_CASES[:1]
    require(len(cases) == len(names), "Workflow source/ZIP case inventory differs")
    for index, (name, case) in enumerate(zip(names, cases, strict=True)):
        values = {"name": name, "effect": "not_started", "journal": "not_created", "reason": ("none",),
                  "native_reason": "none", "applying": False, "requests": 1, "responses": 2, "sequence": 0}
        if index < 4:
            preserved = (0, 0, 2, 4)[index]
            values.update(effect="unchanged" if preserved == 4 else "committed", journal="not_created" if preserved == 4 else "clean",
                          applying=True, requests=3, responses=3, sequence=2)
            observations = {"created": 4 - preserved, "preserved": preserved,
                "directoriesCreated": ([".github", ".github/workflows"], [".github/workflows"], [], [])[index],
                "canonicalPayloads": True, "templateIdentity": True, "completePreparedBytes": True, "capturePrepareUnchanged": True,
                "protectedPreserved": True, "existingIdentityPreserved": True, "createModesMasked": True, "directoryModesExact": True,
                "duplicateApplyObservation": index == 0, "oppositeDomainRefused": index == 0, "sharedStatusRevision": True}
        elif name == "different-refusal":
            values.update(requests=2, responses=2, sequence=1)
            observations = {"noPlanToken": True, "oneDifferingNewline": True, "noPreparedFrame": True,
                            "wholeBundleRefused": True, "treeUnchanged": True}
        elif name == "root-replaced-before-open":
            values.update(reason=("stale_revision",), responses=1)
            observations = {"registeredIdentityRetained": True, "replacementRejectedBeforeCheckout": True, "replacementTreeUnchanged": True}
        elif name in ("registration-before-prepare", "registration-before-apply"):
            after_prepare = name == "registration-before-apply"
            values.update(reason=("none", "cancelled"), native_reason="caller_lost", requests=2 if after_prepare else 1,
                          responses=3 if after_prepare else 2, sequence=1 if after_prepare else 0)
            observations = {"newRegistrationPublishedUnderDocumentLock": True, "originalRegistrationRetained": True,
                            "staleCommandNotSent": True, "treeUnchanged": True}
        elif name == "config-blocks-workflow":
            values.update(domain="configuration", reason=("none", "cancelled"), native_reason="discarded")
            observations = {"oppositeDomainRefused": True, "sharedStatusRevision": True, "sharedLastTerminalReplaced": True,
                            "configurationFilesUnchanged": True, "workflowPermitStillSeparate": True}
        else:
            require(name == "document-loss", "Unknown workflow owner case")
            values.update(reason=("none", "cancelled"), native_reason="window_lost", requests=2, responses=3, sequence=1)
            observations = {"controlledOriginalDocumentLoss": True, "originalStopRequested": True, "replacementDocumentRefused": True,
                            "preparedCorrelationRetained": True, "treeUnchanged": True, "guiCallbacksNotClaimed": True}
        expected = workflow_case_value(case, **values, observations=observations)
        require(same_compile_json(case, expected), "Workflow original bridge/owner/registration facts differ")
    return receipt


def validate_workflow_transaction_eof_receipt(receipt: object, *, context: dict, source_hashes: dict[str, str]) -> dict:
    cases = validate_workflow_owner_header(receipt, context, "source", source_hashes, eof=True)
    require(len(cases) == 3, "Workflow EOF case inventory differs")
    for index, (name, case) in enumerate(zip(WORKFLOW_EOF_CASES, cases, strict=True)):
        committed, unknown = index == 1, index == 2
        boundary, checkpoint = ("after-durable-COMMITTED", "descriptor-close") if committed else ("before-COMMITTED", "publisher-entry")
        terminal = "UNKNOWN" if unknown else "COMMITTED" if committed else "ROLLED_BACK"
        records = (f"MRK_WORKFLOW_EOF_V1 {name} boundary={boundary}\n"
            f"MRK_WORKFLOW_EOF_V1 {name} eof=1 nonempty=0 readErrors=0 checkpoint={checkpoint} "
            f"applied=1 committed={int(committed)} rolledBack={int(not committed and not unknown)} terminal={terminal} "
            f"durable={int(not unknown)} recovery=1 clean={int(not unknown)} settled=1 cancelled=1\n")
        observations = {"evidenceKind": "real-stdin-eof-at-controlled-transaction-boundary", "bootstrapMode": "instrumented-genuine-engine",
            "boundary": boundary, "originalCheckpoint": checkpoint, "closeBeforeActiveDeadline": True, "controlRecords": 2,
            "actualStdinEof": True, "eofReadCount": 1, "nonemptyReadCount": 0, "readErrorCount": 0, "preparedCorrelation": True,
            "committedPublication": committed, "rolledBackPublication": not committed and not unknown, "terminalDurable": not unknown,
            "fixedRecovery": True, "journalClean": not unknown, "journalAbsent": not unknown, "originalTreeRestored": not committed and not unknown,
            "canonicalPayloadsRemain": committed or unknown, "protectedPreserved": True, "unrelatedIntroducedBeforeEof": unknown,
            "introducedOriginalPreserved": unknown, "recoveryEvidenceRetained": unknown, "sharedBlockedProject": unknown,
            "bothDomainsDisabled": unknown, "noFurtherAdmission": unknown, "fixtureFilesSettled": True}
        expected = workflow_case_value(case, name=name, effect="unknown" if unknown else "committed" if committed else "rolled_back",
            journal="recovery_required" if unknown else "clean", reason=("cancelled",), native_reason="cancelled", applying=True,
            requests=3, responses=3, sequence=2, observations=observations, unknown=unknown, stderr=len(records.encode("ascii")))
        require(same_compile_json(case, expected), "Workflow real EOF or invocation-last retained Unknown facts differ")
    return receipt


def workflow_owner_receipt(context: dict, mode: str) -> dict:
    require(mode in ("source", "zip"), "Unknown workflow owner runtime form")
    source = Path(context["source"])
    return validate_workflow_owner_receipt(workflow_json(Path(context["root"]) / f"workflow-owner-{mode}/receipt.json", maximum=64 * 1024), mode,
        context=context, source_hashes={name: hash_file(source / relative) for name, relative in WORKFLOW_OWNER_SOURCES.items()})


def workflow_transaction_eof_receipt(context: dict) -> dict:
    source = Path(context["source"])
    return validate_workflow_transaction_eof_receipt(workflow_json(Path(context["root"]) / "workflow-transaction-eof/receipt.json", maximum=64 * 1024),
        context=context, source_hashes={name: hash_file(source / relative) for name, relative in WORKFLOW_TRANSACTION_EOF_SOURCES.items()})


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise CheckFailure("Invalid canonical fixed JSON data") from None


def closed_object(value: object, keys: set[str], diagnostic: str) -> dict:
    require(type(value) is dict and set(value) == keys, diagnostic)
    return value


def integer_between(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def sha256_value(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def bounded_json(data: bytes, limit: int) -> object:
    require(len(data) <= limit, "Fixed JSON input exceeds its bound")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate fixed JSON field")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise CheckFailure("Nonfinite fixed JSON number")

    try:
        result = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise CheckFailure("Invalid fixed JSON encoding") from None
    pending, nodes = [(result, 0)], 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        require(depth <= 16 and nodes <= 50000, "Fixed JSON structure exceeds its bound")
        if type(value) is dict:
            pending.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            pending.extend((child, depth + 1) for child in value)
        else:
            require(type(value) in {str, bool, int, type(None)}, "Unexpected fixed JSON scalar")
    return result


def read_bounded_json(path: Path, limit: int) -> object:
    ordinary(path)
    before = path.stat()
    require(before.st_size <= limit, "Fixed JSON file exceeds its bound")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(data) == before.st_size, "Fixed JSON file changed")
    return bounded_json(data, limit)


def fixed_file_inventory(root: Path, names: tuple[str, ...]) -> list[dict]:
    inventory = []
    require(len(names) <= 2048 and all(type(name) is str and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None
            and not name.startswith("/") and not any(part in {"", ".", ".."} for part in name.split("/")) for name in names),
            "Fixed input roster contains an unsafe path")
    require(names == tuple(sorted(set(names))), "Fixed input roster is not unique and ordered")
    for name in names:
        path = root / name
        ordinary(path)
        before = path.stat()
        require(before.st_size <= 8 * 1024 * 1024, "Fixed input file exceeds its bound")
        digest = hash_file(path)
        after = path.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "Fixed input file changed")
        inventory.append({"path": name, "sha256": digest, "size": before.st_size})
    return inventory


def windows_sdk_root() -> Path:
    # Explicit installed SDK, not latest/version discovery or an SDK download.
    program_files = Path(os.environ["ProgramFiles(x86)"])
    require(program_files.is_absolute(), "Windows Program Files root is unavailable")
    root = program_files / "Windows Kits" / "10" / "Include" / WINDOWS_SDK_VERSION
    for path in (program_files, *[program_files.joinpath(*root.relative_to(program_files).parts[:length])
                                for length in range(1, len(root.relative_to(program_files).parts) + 1)]):
        details = path.lstat()
        require(stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
                "The fixed installed Windows SDK is unavailable or redirected")
    return root


def windows_prepare_bindings(context: dict, public: dict) -> None:
    source = Path(context["source"])
    sdk = windows_sdk_root()
    context["sdkRoot"] = str(sdk)
    public["windowsSnapshot"] = {
        "sources": fixed_file_inventory(source, WINDOWS_SNAPSHOT_SOURCES),
        "sdk": {"version": WINDOWS_SDK_VERSION, "headers": fixed_file_inventory(sdk, WINDOWS_SDK_HEADERS)},
        "pythonSha256": hash_file(Path(context["python"])),
        "coreInventorySha256": hashlib.sha256(canonical_json(public["coreFiles"])).hexdigest(),
        "job": os.environ["GITHUB_JOB"],
    }
    require(public["windowsSnapshot"]["job"] == "windows-snapshot", "Windows job identity differs")
    public["notQualified"] = list(WINDOWS_SNAPSHOT_NOT_VERIFIED)


def windows_executable_path(value: object, *, target_root: Path) -> Path:
    """Admit the compiler's exact spelling without resolving a different file."""
    require(type(value) is str and 0 < len(value) <= 32768 and "\0" not in value
            and not any(part in {".", ".."} for part in re.split(r"[\\/]", value)),
            "Original executable artifact has an unsafe path")
    executable = Path(value)
    require(target_root.is_absolute() and executable.is_absolute() and executable != target_root
            and executable.is_relative_to(target_root) and executable.suffix == ".exe",
            "Original executable artifact left its target root")
    require(all(part not in {"", ".", ".."} and ":" not in part and "\\" not in part
                for part in executable.relative_to(target_root).parts),
            "Original executable artifact has an alternate path or stream")
    return executable


def ordinary_windows_executable(value: object, *, target_root: Path) -> Path:
    executable = windows_executable_path(value, target_root=target_root)
    relative = executable.relative_to(target_root)
    for length in range(len(relative.parts)):
        directory = target_root.joinpath(*relative.parts[:length])
        details = directory.lstat()
        require(stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
                "Original compiler target ancestry is redirected or unavailable")
    ordinary(executable)
    return executable


def compiled_windows_test(messages: bytes, *, target_root: Path) -> Path:
    """Read only the original successful Cargo no-run output; never scan/run bins."""
    require(len(messages) <= 16 * 1024 * 1024, "Original compiler message stream exceeds its bound")
    executables = []
    finished = 0
    for line in messages.splitlines():
        message = bounded_json(line, 1024 * 1024)
        require(type(message) is dict and type(message.get("reason")) is str, "Unexpected original compiler message")
        if message["reason"] == "compiler-artifact" and message.get("executable") is not None:
            target, profile = message.get("target"), message.get("profile")
            require(type(target) is dict and target.get("name") == "mobile_release_desktop" and target.get("kind") == ["lib"]
                    and type(profile) is dict and profile.get("test") is True
                    and message.get("features") == ["development-runtime"]
                    and type(message["executable"]) is str, "Unexpected original executable artifact")
            executable = windows_executable_path(message["executable"], target_root=target_root)
            executables.append(executable)
        elif message["reason"] == "build-finished":
            require(message.get("success") is True, "Original compiler did not finish successfully")
            finished += 1
    require(finished == 1 and len(executables) == 1, "Original no-run compilation did not identify exactly one test executable")
    return executables[0]


def windows_compile_record(context: dict, argv: list[str], messages: Path) -> dict:
    root = Path(context["root"])
    ordinary(messages)
    require(messages.stat().st_size <= 16 * 1024 * 1024, "Original compiler output exceeds its bound")
    with messages.open("rb") as stream:
        original = stream.read(16 * 1024 * 1024 + 1)
    executable = compiled_windows_test(original, target_root=root / "target")
    ordinary_windows_executable(str(executable), target_root=root / "target")
    compiled = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "path": str(executable),
                "size": executable.stat().st_size, "sha256": hash_file(executable),
                "invocationSha256": hashlib.sha256(canonical_json(argv)).hexdigest()}
    write_json(root / "windows-compiled-test.json", compiled)
    return compiled


def windows_inputs(context: dict, *, create: bool) -> dict:
    root, source = Path(context["root"]), Path(context["source"])
    public = read_bounded_json(root / "public-bindings.json", 1024 * 1024)
    require(type(public) is dict and public.get("scope") == WINDOWS_SNAPSHOT_PUBLIC_SCOPE
            and public.get("sourceSha") == context["sourceSha"] and public.get("sourceTree") == context["sourceTree"]
            and public.get("runId") == context["runId"] and public.get("attempt") == context["attempt"],
            "Original Windows preparation bindings differ")
    prepared = closed_object(public.get("windowsSnapshot"), {"sources", "sdk", "pythonSha256", "coreInventorySha256", "job"},
                             "Original Windows preparation fields differ")
    sdk_root = windows_sdk_root()
    require(str(sdk_root) == context["sdkRoot"], "Original Windows SDK selection changed")
    require(fixed_file_inventory(source, WINDOWS_SNAPSHOT_SOURCES) == prepared["sources"]
            and {"version": WINDOWS_SDK_VERSION, "headers": fixed_file_inventory(sdk_root, WINDOWS_SDK_HEADERS)} == prepared["sdk"]
            and hash_file(Path(context["python"])) == prepared["pythonSha256"], "Prepared source/Python/SDK inputs changed")
    inventory = public["coreFiles"]
    require(type(inventory) is list and 0 < len(inventory) <= 2048
            and hashlib.sha256(canonical_json(inventory)).hexdigest() == prepared["coreInventorySha256"]
            and hash_file(root / "core.zip") == public["coreZipSha256"], "Prepared whole-core inventory/ZIP changed")
    names = tuple(entry["path"] for entry in inventory)
    require(fixed_file_inventory(source / "src", names) == inventory, "Prepared whole-core source members changed")
    actual_names = tuple(sorted(path.relative_to(source / "src").as_posix()
                               for path in (source / "src/mobile_release").rglob("*") if not path.is_dir()))
    require(actual_names == names, "Packaged core gained or lost members")
    compiled = closed_object(read_bounded_json(root / "windows-compiled-test.json", 8192),
                             {"schemaVersion", "sourceSha", "path", "size", "sha256", "invocationSha256"},
                             "Original compiled test record differs")
    executable = ordinary_windows_executable(compiled["path"], target_root=root / "target")
    require(type(compiled["schemaVersion"]) is int and compiled["schemaVersion"] == 1
            and compiled["sourceSha"] == context["sourceSha"] and sha256_value(compiled["invocationSha256"])
            and type(compiled["size"]) is int and compiled["size"] > 0 and sha256_value(compiled["sha256"])
            and executable.stat().st_size == compiled["size"] and hash_file(executable) == compiled["sha256"],
            "Original compiled test identity changed")
    bindings = {
        "sourceSha": context["sourceSha"], "sourceTree": context["sourceTree"], "target": TARGETS["windows"],
        "pythonVersion": PYTHON, "rustVersion": RUST, "runId": context["runId"], "attempt": context["attempt"],
        "job": prepared["job"], "image": public["image"], "architecture": "X64", "coreZipSha256": public["coreZipSha256"],
        "coreInventorySha256": prepared["coreInventorySha256"], "sources": prepared["sources"],
        "pythonSha256": prepared["pythonSha256"], "compiledTestSha256": compiled["sha256"],
        "compileInvocationSha256": compiled["invocationSha256"], "sdk": prepared["sdk"],
    }
    inputs = {"schemaVersion": 1, "scope": WINDOWS_SNAPSHOT_RECEIPT_SCOPE, "bindings": bindings,
              "coreFiles": inventory, "sdkRoot": str(sdk_root)}
    require(len(canonical_json(inputs)) <= 1024 * 1024, "Windows native inputs exceed their bound")
    path = root / "windows-snapshot-inputs.json"
    if create:
        write_json(path, inputs)
    else:
        require(canonical_json(read_bounded_json(path, 1024 * 1024)) == canonical_json(inputs),
                "Original Windows native input binding changed")
    return inputs


def windows_snapshot_receipt(context: dict) -> dict:
    inputs = windows_inputs(context, create=False)
    report = read_bounded_json(Path(context["root"]) / "windows-snapshot/receipt.json", 256 * 1024)
    return validate_windows_snapshot_receipt(report, bindings=inputs["bindings"])


def _windows_cleanup_kind(metadata: object) -> str:
    """Classify only ordinary entries and the two exact link-like Windows tags."""
    mode = getattr(metadata, "st_mode", None)
    attributes = getattr(metadata, "st_file_attributes", None)
    require(type(mode) is int and mode >= 0 and type(attributes) is int and 0 <= attributes <= 0xFFFFFFFF,
            "Windows task cleanup encountered incoherent type metadata")
    directory = bool(attributes & 0x10)
    if not attributes & 0x400:
        # The tag is not meaningful when FILE_ATTRIBUTE_REPARSE_POINT is clear.
        if stat.S_ISDIR(mode) and directory:
            return "directory"
        if stat.S_ISREG(mode) and not directory:
            return "regular"
        require(not (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)),
                "Windows task cleanup encountered incoherent type metadata")
        raise CheckFailure("Windows task cleanup encountered an unsupported file type")
    tag = getattr(metadata, "st_reparse_tag", None)
    require(type(tag) is int and tag in {0xA000000C, 0xA0000003},
            "Windows task cleanup encountered an unsupported reparse tag")
    if tag == 0xA000000C:
        require(stat.S_ISLNK(mode), "Windows task cleanup encountered incoherent reparse metadata")
        return "directory-symlink" if directory else "file-symlink"
    require(directory and stat.S_ISDIR(mode), "Windows task cleanup encountered incoherent reparse metadata")
    return "junction"


def clean_windows_outputs(context: dict) -> None:
    # This is ordinary finite post-verification cleanup, NOT a cleanup remedy for
    # native failure/uncertainty. The original root/ancestry remain ordinary and
    # no additional writer is admitted; known reparse entries are leaves only.
    windows_snapshot_receipt(context)
    root = Path(context["root"])
    leaves, directories, pending = [], [], [(root, 0)]
    seen, groups, members = {str(root)}, {}, {}
    count = 0
    while pending:
        directory, depth = pending.pop()
        try:
            info = directory.lstat()
        except OSError:
            raise CheckFailure("Windows cleanup inventory directory metadata failed") from None
        require(_windows_cleanup_kind(info) == "directory" and depth <= 64,
                "Windows cleanup directory is redirected or too deep")
        directories.append((directory, info.st_dev, info.st_ino))
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    require(count <= 500000, "Windows task cleanup inventory exceeded its bound")
                    require(entry.path not in seen, "Windows task cleanup inventory repeated a path")
                    seen.add(entry.path)
                    path = Path(entry.path)
                    # CPython 3.14.7 caches raw Windows enumeration attributes/tag.
                    # Screen them before lstat, which may process non-name-surrogate
                    # tags. Cached zero dev/inode/nlink NEVER supplies group authority.
                    # This screen is not atomic custody against an additional writer.
                    try:
                        cached_kind = _windows_cleanup_kind(entry.stat(follow_symlinks=False))
                        metadata = path.lstat()
                    except OSError:
                        raise CheckFailure("Windows cleanup inventory entry metadata failed") from None
                    kind = _windows_cleanup_kind(metadata)
                    require(kind == cached_kind, "Windows task cleanup inventory entry classification changed")
                    if kind == "directory":
                        pending.append((path, depth + 1))
                    else:
                        links = getattr(metadata, "st_nlink", None)
                        require(type(links) is int and 1 <= links <= 500000,
                                "Windows task cleanup inventory has an invalid link count")
                        device, inode = getattr(metadata, "st_dev", None), getattr(metadata, "st_ino", None)
                        require(type(device) is int and device >= 0 and type(inode) is int and inode > 0,
                                "Windows task cleanup inventory has an unusable file identity")
                        identity = (device, inode)
                        reparse = ((metadata.st_file_attributes, metadata.st_reparse_tag) if kind != "regular" else None)
                        binding = (links, metadata.st_size, metadata.st_mtime_ns, kind, reparse)
                        if identity in groups:
                            require(groups[identity] == binding, "Windows task cleanup hardlink metadata disagrees")
                        else:
                            groups[identity] = binding
                        members[identity] = members.get(identity, 0) + 1
                        leaves.append((path, identity))
        except OSError:
            raise CheckFailure("Windows cleanup inventory enumeration failed") from None
    # The complete manifest never descends into known reparse leaves. All original
    # owners are already joined; every leaf group closes before the first deletion.
    for identity, binding in groups.items():
        require(members[identity] == binding[0],
                "Windows task cleanup hardlink group is not closed inside the original root")
    remaining = {identity: binding[0] for identity, binding in groups.items()}
    for path, identity in leaves:
        try:
            info = path.lstat()
        except OSError:
            raise CheckFailure("Windows cleanup before-unlink metadata failed") from None
        _, size, modified, kind, reparse = groups[identity]
        observed_kind = _windows_cleanup_kind(info)
        device, inode = getattr(info, "st_dev", None), getattr(info, "st_ino", None)
        require(observed_kind == kind and type(device) is int and type(inode) is int
                and (device, inode, info.st_size, info.st_mtime_ns) == (*identity, size, modified)
                and (reparse is None or (info.st_file_attributes, info.st_reparse_tag) == reparse),
                "Windows task cleanup file identity changed" if kind == "regular"
                else "Windows task cleanup reparse leaf binding changed")
        links = getattr(info, "st_nlink", None)
        require(type(links) is int and links == remaining[identity], "Windows task cleanup remaining link count changed")
        # An earlier successful unlink may change this inode's ctime, not its
        # retained size/mtime. Never replace this counter with later metadata.
        # Pinned CPython's unlink dispatch removes directory symlinks/junctions
        # with RemoveDirectoryW, not their targets. No fallback is permitted.
        try:
            path.unlink()
        except OSError:
            raise CheckFailure("Windows task cleanup original unlink failed; remaining outputs retained") from None
        remaining[identity] -= 1
    require(all(value == 0 for value in remaining.values()), "Windows task cleanup hardlink accounting did not settle")
    for path, device, inode in sorted(directories, key=lambda item: len(item[0].parts), reverse=True):
        try:
            info = path.lstat()
        except OSError:
            raise CheckFailure("Windows cleanup final directory metadata failed") from None
        require(_windows_cleanup_kind(info) == "directory"
                and (info.st_dev, info.st_ino) == (device, inode), "Windows task cleanup directory identity changed")
        try:
            path.rmdir()
        except OSError:
            raise CheckFailure("Windows task cleanup original directory removal failed; remaining outputs retained") from None
    print("Removed only the fully settled Windows job's inventoried compiler/dependency and synthetic fixture outputs.")


def validate_windows_checks(name: str, value: object) -> None:
    """Closed case predicates, not a generic passed flag or a fixture log parser."""
    def truths(names: str) -> dict:
        return dict.fromkeys(names.split(), True)

    race = {**truths("parentIdSame mutationSucceeded originalRelativeEntry entryBeforeDeadline unsafeControlMatched "
                    "sharingWriteDenied sharingDeleteDenied reparseRestored"),
            "mutationAccess": 256, "mutationTag": 0xA0000003, "outsideAcquired": 0, "outsideReadBytes": 0}
    expected = {
        "ordinary-source": {**truths("genuineCore configExact androidExact iosExact versionNotDisclosed"),
                            "unicodeOpens": (1, 1000000), "spelling": "ordinary"},
        "ordinary-zip": {**truths("genuineCore configExact androidExact iosExact versionNotDisclosed"),
                         "unicodeOpens": (1, 1000000), "spelling": "verbatim"},
        "closed-gate": {},
        "link-children": {"fileSymlinkTag": 0xA000000C, "directorySymlinkTag": 0xA000000C,
                          "junctionTag": 0xA0000003, "hardlinkCount": (2, 1024), "hardlinkIdMatch": True,
                          "excludedReparses": (3, 10000), "hardlinkReadBytes": 0, "restoredLinks": 4},
        "reparse-root": {"junctionTag": 0xA0000003, "unsafeControlMatched": True, "rootRefused": True, "reparseRestored": 1},
        "reparse-ancestor": {"junctionTag": 0xA0000003, "unsafeControlMatched": True, "rootRefused": True, "reparseRestored": 1},
        "short-alias": {**truths("aliasObserved spellingDiffers sameObject"), "aliasAcquired": (0, 1), "aliasReadBytes": 0},
        "case-alias": {**truths("aliasObserved spellingDiffers sameObject"), "aliasAcquired": (0, 1), "aliasReadBytes": 0},
        "case-collision": {"enabledFlags": 1, "distinctIds": True, "collisionFiles": 2,
                           "collisionDirectoryBatches": 0, "caseRestored": True},
        "subst-drive": {**truths("aliasInitiallyAbsent localNonSystemToken subtreeMappingObserved mappingRemoved"), "rootOpens": 0},
        "unc": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "device": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "ads": {"readerFfiEntries": 0, "readerInstances": 0, "unsafePathRefused": True},
        "root-reparse-race": {**race, "preparatoryDeletes": 0},
        "config-reparse-race": {**race, "preparatoryDeletes": 0},
        "walk-reparse-race": {**race, "preparatoryDeletes": 1},
        "case-mode-race": {**truths("parentIdSame originalRelativeEntry entryBeforeDeadline missingNotTrusted caseRestored"),
                           "mutationAccess": 256, "enabledFlags": 1},
        "acl-type": {**truths("fileAccessDenied directoryAccessDenied accessibleSiblingRead configDirectoryRefused initialAbsenceRestored"),
                     "denialPoliciesConfirmed": 2, "createdObjectsRemoved": 2},
        "read-eof-size": {**truths("emptyEof invalidUtf8Refused shortFinalRead multichunkEof exactLimitEof"),
                          "oversizeReadBytes": 0, "largestRequest": (1, 65536), "largestReturn": (1, 65536)},
        "entry-limit": {"returnedRecords": (10000, 1000000), "chargedEntries": 10000, "overBudgetChildOpens": 0, "entryLimitIssue": True},
        "candidate-limit": {"chargedCandidates": 128, "refusedExtraCandidate": True, "sourceFileLimitIssue": True},
        "aggregate-limit": {"chargedBytes": (0, 8388608), "extraByteRead": 0, "capNotEof": True, "byteLimitIssue": True},
        "depth-path-limit": {"deepestAdmitted": (0, 12), "depth13Opens": 0, "oversizedPathOpens": 0,
                             **truths("depthIssue pathIssue siblingRead")},
        "replace": {**truths("entryObserved originalIdDiffers changedIssue"), "replacementReadBytes": 0},
        "disappear": truths("entryObserved actualMissingReturn changedIssue missingNotTrusted"),
        "config-disappear": truths("entryObserved actualMissingReturn changedIssue missingNotTrusted"),
        "ending-metadata-case": truths("genuineFileEof writeMetadataChanged fileChangeVeto genuineDirectoryEof "
                                       "caseFlagsChanged directoryCaseVeto attributesRestored"),
        "drive-map-change": {**truths("aliasInitiallyAbsent localNonSystemToken initialVolumeMapping endingSubtreeMapping "
                                     "changedIssue mappingRemoved"), "laterProjectOpens": 0},
        "oplock-release": truths("grantPending originalReaderEntered breakSignalled completionKnown blockedBeforeRelease "
                                 "holderCloseReturned observerJoined eventCloseReturned originalReaderReturned"),
        "oplock-withhold": {**truths("grantPending originalReaderEntered breakSignalled completionKnown originalProcessStopped"),
                            "readerReturnedBeforeStop": False, "holderReleasedBeforeStop": False},
        "pending-failstop": {"originalParentHeld": True, "realFsctlEntry": True, "afterCallMarker": False, "originalExitCode": 70},
    }[name]
    checks = closed_object(value, set(expected), "Windows case-check fields differ")
    for field, rule in expected.items():
        actual = checks[field]
        require(integer_between(actual, *rule) if type(rule) is tuple else type(actual) is type(rule) and actual == rule,
                "A required Windows native predicate is not established")


def validate_windows_result(name: str, value: object) -> str | None:
    result = closed_object(value, {"return", "code", "configState", "partial", "scan", "issueCodes", "dtoSha256"},
                           "Windows result fields differ")
    errors = {
        "closed-gate": {"platform_unavailable"}, "reparse-root": {"unsafe_path", "snapshot_unavailable"},
        "reparse-ancestor": {"unsafe_path", "snapshot_unavailable"},
        "root-reparse-race": {"unsafe_path", "snapshot_unavailable"},
        "short-alias": {"unsafe_path", "snapshot_unavailable"}, "case-alias": {"unsafe_path", "snapshot_unavailable"},
        "subst-drive": {"snapshot_unavailable"}, "unc": {"unsafe_path"}, "device": {"unsafe_path"}, "ads": {"unsafe_path"},
        "oplock-withhold": {"query_timeout"}, "pending-failstop": {"engine_failed"},
    }
    if name in errors:
        require(result["return"] == "error" and type(result["code"]) is str and result["code"] in errors[name]
                and all(result[field] is None for field in ("configState", "partial", "scan", "dtoSha256"))
                and result["issueCodes"] == [], "Windows required refusal/owner failure differs")
        return result["code"]
    require(result["return"] == "ok" and result["code"] is None and type(result["configState"]) is str
            and result["configState"] in {"missing", "format-valid", "invalid", "unavailable"}
            and type(result["partial"]) is bool and sha256_value(result["dtoSha256"]), "Windows snapshot result differs")
    scan = closed_object(result["scan"], {"entries", "sourceFiles", "sourceBytes", "excludedEntries"}, "Windows scan fields differ")
    for field, limit in (("entries", 10000), ("sourceFiles", 128), ("sourceBytes", 8388608), ("excludedEntries", 10000)):
        require(integer_between(scan[field], 0, limit), "Windows snapshot scan bound differs")
    codes = result["issueCodes"]
    require(type(codes) is list and len(codes) <= 64
            and all(type(code) is str and code in WINDOWS_SNAPSHOT_ISSUES for code in codes), "Windows issue-code vocabulary differs")
    if name in {"ordinary-source", "ordinary-zip"}:
        require(result["configState"] == "format-valid" and result["partial"] is False and not codes,
                "Ordinary Windows snapshot was not complete")
    elif name != "oplock-release":
        require(result["partial"] is True and bool(codes), "A changed/excluded Windows input was reported as complete")
    if name in {"config-reparse-race", "case-mode-race", "acl-type", "config-disappear", "drive-map-change"}:
        require(result["configState"] == "unavailable", "Unavailable configuration was treated as trustworthy")
    required_codes = {
        "entry-limit": {"snapshot.entry-limit"}, "candidate-limit": {"snapshot.file-limit"},
        "aggregate-limit": {"snapshot.byte-limit"}, "depth-path-limit": {"snapshot.depth-limit", "snapshot.path-limit"},
        "replace": {"snapshot.changed"}, "disappear": {"snapshot.changed"}, "config-disappear": {"snapshot.changed"},
        "ending-metadata-case": {"snapshot.changed"}, "drive-map-change": {"snapshot.changed"},
        "read-eof-size": {"snapshot.encoding", "snapshot.file-size"},
    }.get(name, set())
    require(required_codes <= set(codes), "Windows result does not contain the control's actual required issue")
    return None


def validate_windows_original(name: str, value: object, error: str | None) -> None:
    original = closed_object(value, {"id", *WINDOWS_ORIGINAL_FLAGS, "waitExitCode", "exitSuccess", "stdoutBytes",
                                    "stderrBytes", "unknownLatched", "disabled", "errorCode"},
                             "Windows original-owner fields differ")
    require(original["id"] == "query-1" and all(original[field] is True for field in WINDOWS_ORIGINAL_FLAGS)
            and original["unknownLatched"] is False and original["disabled"] is False
            and original["errorCode"] == error, "Windows original ownership or sticky outcome is incomplete")
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(type(original["exitSuccess"]) is bool and original["exitSuccess"] is not abnormal
            and integer_between(original["waitExitCode"], -(2**31), 2**32 - 1)
            and (original["waitExitCode"] != 0 if abnormal else original["waitExitCode"] == 0),
            "Windows original process status differs")
    if name == "pending-failstop":
        require(original["waitExitCode"] == 70, "Windows pending classifier did not return its fixed process status")
    require(integer_between(original["stdoutBytes"], 0 if abnormal else 1, 4 * 1024 * 1024)
            and integer_between(original["stderrBytes"], 0, 64 * 1024), "Windows original stream observations exceed bounds")


def validate_windows_reader(name: str, value: object) -> None:
    reader = closed_object(value, {"state", "calls", *WINDOWS_READER_COUNTERS, "eventSha256", "closeDisposition"},
                           "Windows reader fields differ")
    if name == "closed-gate":
        require(reader["state"] == reader["closeDisposition"] == "uninstrumented" and reader["calls"] == []
                and all(reader[field] is None for field in (*WINDOWS_READER_COUNTERS, "eventSha256")),
                "Uninstrumented Windows refusal invented native observations")
        return
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(reader["state"] == ("prefix" if abnormal else "complete")
            and reader["closeDisposition"] == ("not-observed-after-abnormal-exit" if abnormal else "returned-once")
            and sha256_value(reader["eventSha256"]), "Windows reader observation scope differs")
    for field in WINDOWS_READER_COUNTERS:
        maximum = {"maxLive": 144, "live": 144, "maxBufferBytes": 65536, "readBytes": 8388608}.get(field, 1000000)
        require(integer_between(reader[field], 0, maximum), "Windows reader counter exceeds its bound")
    calls = reader["calls"]
    require(type(calls) is list and len(calls) == len(WINDOWS_READER_APIS), "Windows reader API roster differs")
    for call, api in zip(calls, WINDOWS_READER_APIS, strict=True):
        call = closed_object(call, {"api", "entered", "returned", "completed", "errors"}, "Windows reader API fields differ")
        require(call["api"] == api and all(integer_between(call[field], 0, 1000000)
                for field in ("entered", "returned", "completed", "errors")), "Windows reader API counter differs")
        require(call["errors"] <= call["completed"] <= call["returned"] <= call["entered"], "Windows call classification order differs")
        if not abnormal:
            require(call["entered"] == call["returned"] == call["completed"], "Windows entered call is not classified")
    require(reader["outsideReads"] == reader["outsideDescent"] == reader["violations"] == 0,
            "Windows reader crossed an excluded input boundary")
    require(reader["outsideAcquired"] == reader["aliasMetadataAcquired"]
            and (name == "link-children" or reader["outsideAcquired"] == 0), "Windows outside referent was acquired")
    by_api = {call["api"]: call for call in calls}
    opens, closes = by_api["NtCreateFile"], by_api["CloseHandle"]
    reads, information = by_api["ReadFile"], by_api["GetFileInformationByHandleEx"]
    require(reader["rootOpens"] + reader["relativeOpens"] == opens["entered"]
            and reader["acquired"] == opens["completed"] - opens["errors"]
            and reader["closeAttempts"] == closes["entered"]
            and reader["closeSucceeded"] == closes["completed"] - closes["errors"]
            and reader["closeFailed"] == closes["errors"] == 0
            and reader["closeSucceeded"] == reader["closeAttempts"] <= reader["acquired"]
            and reader["live"] == reader["acquired"] - reader["closeAttempts"]
            and reader["live"] <= reader["maxLive"] <= reader["acquired"],
            "Windows reader original-open/close accounting is inconsistent")
    require(reader["identitiesMatched"] == reader["metadataChecks"] <= by_api["GetFileType"]["completed"]
            and 4 * reader["metadataChecks"] + reader["directoryEof"] <= information["completed"]
            and reader["readEof"] <= reads["completed"] - reads["errors"] <= reads["entered"] <= reader["readCalls"]
            and reader["readBytes"] <= 65536 * (reads["completed"] - reads["errors"] - reader["readEof"])
            and reader["directoryEof"] <= reader["directoryCalls"]
            and reader["directoryEof"] <= information["errors"]
            and reader["eventCount"] >= sum(call["completed"] for call in calls),
            "Windows reader identity/read/EOF observations contradict original calls")
    if reader["acquired"]:
        require(reader["maxLive"] > 0 and reader["eventCount"] > 0, "Windows reader acquisition has no resource observations")
    if reader["readCalls"] or reader["directoryCalls"] or reader["metadataChecks"]:
        require(reader["acquired"] > 0 and reader["maxBufferBytes"] > 0,
                "Windows reader IO has no acquired original or output arena")
    if not abnormal:
        require(reader["acquired"] == reader["closeAttempts"] == reader["closeSucceeded"]
                and reader["closeFailed"] == reader["live"] == 0, "Windows reader original closes are incomplete")
    if name in {"ordinary-source", "ordinary-zip", "oplock-release"}:
        require(reader["rootOpens"] == 1 and reader["relativeOpens"] > 0 and reader["metadataChecks"] > 0
                and reader["identitiesMatched"] > 0 and reader["readEof"] > 0 and reader["directoryEof"] > 0,
                "Ordinary Windows handles, identity or EOF were not observed")
    if name in {"unc", "device", "ads"}:
        require(all(call["entered"] == 0 for call in calls) and reader["acquired"] == 0,
                "Unsafe Windows namespace reached the reader API")
    else:
        require(by_api["GetCurrentProcess"]["completed"] == by_api["IsWow64Process2"]["completed"] == 1
                and by_api["QueryDosDeviceW"]["completed"] > 0, "Windows reader native admission was not observed")
    if abnormal:
        pending_api = "NtCreateFile" if name == "oplock-withhold" else "DeviceIoControl"
        require(reader["rootOpens"] == 1 and reader["relativeOpens"] > 0 and reader["live"] > 0
                and reader["identitiesMatched"] > 0
                and all(call["entered"] - call["returned"] == (1 if call["api"] == pending_api else 0)
                        and call["returned"] == call["completed"] for call in calls),
                "Windows abnormal prefix lacks its retained parent or exact unmatched native entry")


def validate_windows_fixture(name: str, value: object, bindings: dict) -> None:
    fixture = closed_object(value, {"state", *WINDOWS_FIXTURE_COUNTERS, "pending", "thread", "event", "restored",
                                   "resourcesSettledBy", "data", "profile", "checks"}, "Windows fixture fields differ")
    validate_windows_checks(name, fixture["checks"])
    if name == "closed-gate":
        require(fixture["state"] == fixture["resourcesSettledBy"] == "uninstrumented"
                and all(fixture[field] is None for field in (*WINDOWS_FIXTURE_COUNTERS, "restored", "data", "profile"))
                and all(fixture[field] == "none" for field in ("pending", "thread", "event")),
                "Uninstrumented Windows refusal invented fixture observations")
        return
    abnormal = name in {"oplock-withhold", "pending-failstop"}
    require(fixture["state"] == ("prefix" if abnormal else "complete")
            and fixture["resourcesSettledBy"] == ("original-process" if abnormal else "returned-closes"),
            "Windows fixture settlement class differs")
    for field in WINDOWS_FIXTURE_COUNTERS:
        require(integer_between(fixture[field], 0, {"live": 32, "maxLive": 32, "maxArenaBytes": 131072}.get(field, 1000000)),
                "Windows fixture counter exceeds its bound")
    require(fixture["closeSucceeded"] == fixture["closeAttempts"] <= fixture["acquired"]
            and fixture["closeFailed"] == 0 and fixture["live"] == fixture["acquired"] - fixture["closeAttempts"]
            and fixture["live"] <= fixture["maxLive"] <= fixture["acquired"]
            and fixture["maxLive"] > 0 and fixture["maxArenaBytes"] > 0, "Windows fixture accounting is inconsistent")
    if abnormal:
        require(fixture["restored"] is None and fixture["event"] == "retained"
                and fixture["pending"] == ("completed" if name == "oplock-withhold" else "retained")
                and fixture["thread"] == ("not-observed" if name == "oplock-withhold" else "none"),
                "Abnormal Windows exit invented in-process cleanup")
        require(fixture["live"] >= 2 and fixture["maxLive"] >= 2 and fixture["maxArenaBytes"] >= 36,
                "Windows pending prefix lacks its retained holder/event/OVERLAPPED resources")
    else:
        require(fixture["restored"] is True and fixture["acquired"] == fixture["closeAttempts"] == fixture["closeSucceeded"]
                and fixture["live"] == fixture["closeFailed"] == 0, "Windows fixture restoration/closes are incomplete")
        require((fixture["pending"], fixture["thread"], fixture["event"])
                == (("completed", "joined", "closed") if name == "oplock-release" else ("none", "none", "none")),
                "Windows pending IO or thread/event settlement differs")
        if name == "oplock-release":
            require(fixture["acquired"] >= 2 and fixture["maxLive"] >= 2 and fixture["maxArenaBytes"] >= 36,
                    "Windows released oplock lacks its original resource observations")
    data = closed_object(fixture["data"], {"entries", "bytes", "maxDepth", "manifestSha256", "after"}, "Windows fixture data fields differ")
    require(integer_between(data["entries"], 3, 12000) and integer_between(data["bytes"], 0, 32 * 1024 * 1024)
            and integer_between(data["maxDepth"], 0, 14) and sha256_value(data["manifestSha256"]), "Windows fixture data exceeds its bound")
    after = closed_object(data["after"], {"entries", "bytes", "maxDepth", "inventorySha256"}, "Windows final payload inventory is missing")
    require(integer_between(after["entries"], 3, 12000) and integer_between(after["bytes"], 0, 32 * 1024 * 1024)
            and integer_between(after["maxDepth"], 0, 14) and sha256_value(after["inventorySha256"]),
            "Windows actual post-settlement payload exceeds its bound")
    profile = closed_object(fixture["profile"], {"pointerBytes", "processMachine", "nativeMachine", "filesystem",
                                              "pythonSha256", "ctypesSha256", "dlls", "layoutSha256", "sdkSha256"},
                            "Windows native profile fields differ")
    require(type(profile["pointerBytes"]) is int and profile["pointerBytes"] == 8
            and type(profile["processMachine"]) is int and profile["processMachine"] == 0
            and type(profile["nativeMachine"]) is int and profile["nativeMachine"] == 34404
            and profile["filesystem"] == "NTFS" and profile["pythonSha256"] == bindings["pythonSha256"]
            and all(sha256_value(profile[field]) for field in ("ctypesSha256", "layoutSha256", "sdkSha256"))
            and profile["sdkSha256"] == hashlib.sha256(canonical_json(bindings["sdk"])).hexdigest(),
            "Windows native architecture/SDK profile differs")
    dlls = profile["dlls"]
    require(type(dlls) is list and len(dlls) == 3, "Windows selected DLL roster differs")
    for dll, expected in zip(dlls, ("kernel32.dll", "ntdll.dll", "advapi32.dll"), strict=True):
        dll = closed_object(dll, {"name", "sha256", "size"}, "Windows selected DLL fields differ")
        require(dll["name"] == expected and sha256_value(dll["sha256"]) and integer_between(dll["size"], 1, 64 * 1024 * 1024),
                "Windows selected DLL identity differs")


def validate_windows_snapshot_receipt(receipt: object, *, bindings: dict) -> dict:
    report = closed_object(receipt, {"schemaVersion", "scope", "status", "failureCode", "bindings", "groups",
                                    "allOwnersSettled", "allFixtureResourcesSettled", "allFixturesRestored",
                                    "cleanupDisposition", "notVerified"}, "Windows receipt fields differ")
    require(type(report["schemaVersion"]) is int and report["schemaVersion"] == 1
            and report["scope"] == WINDOWS_SNAPSHOT_RECEIPT_SCOPE and report["status"] == "passed"
            and report["failureCode"] is None and report["cleanupDisposition"] == "proven-settled"
            and all(report[field] is True for field in ("allOwnersSettled", "allFixtureResourcesSettled", "allFixturesRestored"))
            and report["notVerified"] == list(WINDOWS_SNAPSHOT_NOT_VERIFIED), "Windows receipt is not a complete bounded pass")
    # Byte equality of closed canonical data also distinguishes bool from int.
    require(canonical_json(report["bindings"]) == canonical_json(bindings), "Windows receipt source/run/profile bindings differ")
    groups = report["groups"]
    require(type(groups) is list and len(groups) == len(WINDOWS_SNAPSHOT_GROUPS), "Windows native group roster is incomplete")
    for group, (expected_group, names) in zip(groups, WINDOWS_SNAPSHOT_GROUPS, strict=True):
        group = closed_object(group, {"id", "controls"}, "Windows native group fields differ")
        require(group["id"] == expected_group and type(group["controls"]) is list and len(group["controls"]) == len(names),
                "Windows native controls are missing, reordered or duplicated")
        for control, name in zip(group["controls"], names, strict=True):
            control = closed_object(control, {"id", "coreMode", "bootstrapMode", "evidenceKind", "result", "reader", "fixture",
                                              "original", "elapsedMs", "failureCode"}, "Windows native control fields differ")
            evidence = {"closed-gate": "uninstrumented-public-refusal", "oplock-withhold": "original-process-oplock-stop",
                        "pending-failstop": "instrumented-pending-classifier-exit"}.get(name, "native-static-reader")
            require(control["id"] == name and control["coreMode"] == ("zip" if name == "ordinary-zip" else "source")
                    and control["bootstrapMode"] == ("ordinary" if name == "closed-gate" else "windows-snapshot")
                    and control["evidenceKind"] == evidence and control["failureCode"] is None
                    and integer_between(control["elapsedMs"], 0, 45000), "Windows native control scope differs")
            error = validate_windows_result(name, control["result"])
            validate_windows_original(name, control["original"], error)
            validate_windows_reader(name, control["reader"])
            validate_windows_fixture(name, control["fixture"], bindings)
            charged = {"entry-limit": ("entries", "chargedEntries"), "candidate-limit": ("sourceFiles", "chargedCandidates"),
                       "aggregate-limit": ("sourceBytes", "chargedBytes")}.get(name)
            if charged:
                require(control["result"]["scan"][charged[0]] == control["fixture"]["checks"][charged[1]],
                        "Windows native charged count and genuine snapshot scan differ")
    return report


def validate_native_receipt(receipt: object, *, source_sha: str, platform: str, core_zip_hash: str) -> dict:
    require(platform in TARGETS and isinstance(receipt, dict), "Unexpected native receipt")
    require(type(receipt.get("schemaVersion")) is int and receipt.get("schemaVersion") == 1
            and receipt.get("scope") == "passive-hosted-v2"
            and receipt.get("status") == "passed" and receipt.get("allOwnersSettled") is True,
            "Native ownership is not confirmed settled; preserve outputs")
    bindings = receipt.get("bindings", {})
    require(isinstance(bindings, dict) and bindings.get("sourceSha") == source_sha
            and bindings.get("target") == TARGETS[platform] and bindings.get("coreZipSha256") == core_zip_hash,
            "Native receipt source/target differs")
    cases = receipt.get("cases", [])
    require(isinstance(cases, list) and all(isinstance(case, dict) for case in cases)
            and tuple(case.get("case") for case in cases) == NATIVE_CASES
            and all(case.get("passed") is True for case in cases), "Fixed native batch was not fully verified")
    # Keep the original 21 cases' acceptance predicates. Only the two new v2
    # records add this closed management-return contract; notes alone cannot
    # replace the original native/IO/management observations and retirement.
    case_fields = {"case", "passed", "failureCode", "elapsedMs", "evidenceKind", "results", "notes", "owners",
                   "registeredOwners", "disabled"}
    native_flags = ("inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
                    "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined",
                    "driver_joined", "watchdog_joined")
    checkpoint_notes = (
        {"nativeSettledBeforeManagementReturns", "driverReturnHeldBeforeReply", "watchdogReturnHeldBeforeReply"},
        {"nativeSettledBeforeWatchdogReturn", "originalCleanupEndpointUnchanged", "retainedWhileUnknown",
         "newQueryRefused", "lateJoinPreservedFailure"},
    )
    for case, late, notes in zip(cases[-2:], (False, True), checkpoint_notes, strict=True):
        require(set(case) == case_fields and case["failureCode"] is None
                and case["evidenceKind"] == "scheduling-control-not-os-fault"
                and case["disabled"] is late and type(case["registeredOwners"]) is int and case["registeredOwners"] == 0,
                "Native management case or retirement differs")
        require(type(case["elapsedMs"]) is int and case["elapsedMs"] >= (2000 if late else 0),
                "Native management cleanup allowance differs")
        expected_result = {"return": "error", "code": "cleanup_unknown"} if late else {"return": "ok"}
        require(case["results"] == [expected_result], "Native management result differs")
        require(isinstance(case["notes"], dict) and set(case["notes"]) == notes
                and all(case["notes"][field] is True for field in notes), "Native management checkpoint facts differ")
        owners = case["owners"]
        require(isinstance(owners, list) and len(owners) == 1 and isinstance(owners[0], dict),
                "Native management original owner inventory differs")
        owner = owners[0]
        require(set(owner) == {"id", "terminal", "unknownLatched", "permitRetained", "native"}
                and owner["id"] == "query-1" and owner["terminal"] is True
                and owner["permitRetained"] is False and owner["unknownLatched"] is late,
                "Native management original owner finality differs")
        native = owner["native"]
        require(isinstance(native, dict) and set(native) == {*native_flags, "stdout_bytes", "stderr_bytes"}
                and all(native[field] is True for field in native_flags), "Native management original returns are incomplete")
        require(type(native["stdout_bytes"]) is int and 0 < native["stdout_bytes"] <= 4 * 1024 * 1024
                and type(native["stderr_bytes"]) is int and 0 <= native["stderr_bytes"] <= 64 * 1024,
                "Native management output accounting differs")
    return receipt


def native_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "native/receipt.json"
    ordinary(path)
    size = path.stat().st_size
    require(0 < size <= 64 * 1024, "Native receipt size differs")
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    require(len(data) == size, "Native receipt changed")
    return validate_native_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        core_zip_hash=hash_file(Path(context["root"]) / "core.zip"))


def validate_config_receipt(receipt: object, partition: str) -> dict:
    require(partition in CONFIG_PARTITIONS and isinstance(receipt, dict), "Unexpected configuration receipt")
    require(set(receipt) == {"suite", "partition", "status", "reason", "completed", "failedAt", "retained",
                             "uncertaintyLatched", "injection"}, "Configuration receipt fields differ")
    require(receipt["suite"] == "desktop-config-native" and receipt["partition"] == partition
            and receipt["status"] == "passed" and receipt["reason"] == "none" and receipt["failedAt"] is None,
            "Configuration fixture did not pass; preserve outputs")
    require(isinstance(receipt["completed"], list) and tuple(receipt["completed"]) == CONFIG_CASES[partition]
            and receipt["injection"] == CONFIG_INJECTIONS[partition], "Configuration case inventory differs")
    require(receipt["retained"] is (partition != "ordinary")
            and receipt["uncertaintyLatched"] is (partition == "committed-close"),
            "Configuration fixture retention/uncertainty differs")
    return receipt


def config_receipt(context: dict, partition: str) -> dict:
    require(partition in CONFIG_PARTITIONS, "Unknown configuration partition")
    path = Path(context["root"]) / f"config-{partition}.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 16 * 1024, "Configuration receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 + 1)
    require(len(data) <= 16 * 1024, "Configuration receipt changed")
    return validate_config_receipt(json.loads(data), partition)


def validate_config_owner_bindings(bindings: object, *, source_sha: str, platform: str,
                                    source_hashes: dict[str, str], python_hash: str) -> None:
    require(platform in {"linux", "macos"} and isinstance(bindings, dict)
            and set(bindings) == {"sourceSha", "host", "target", "runtimeMode", "pythonSha256", "sourceHashes", "payloadHashes"}
            and bindings["sourceSha"] == source_sha and bindings["host"] == platform
            and bindings["target"] == TARGETS[platform] and bindings["runtimeMode"] == "trusted-development-only"
            and bindings["pythonSha256"] == python_hash and bindings["sourceHashes"] == source_hashes,
            "Configuration owner source/runtime bindings differ")
    payloads = bindings["payloadHashes"]
    require(isinstance(payloads, dict) and set(payloads) == {"draft", "createConfig", "createIgnore", "noOpConfig", "noOpIgnore", "unrelated"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in payloads.values()),
            "Configuration owner payload bindings differ")


def validate_config_owner_receipt(receipt: object, *, source_sha: str, platform: str,
                                  source_hashes: dict[str, str], python_hash: str) -> dict:
    require(platform in {"linux", "macos"} and isinstance(receipt, dict), "Unexpected configuration owner receipt")
    require(set(receipt) == {"schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "bindings", "cases", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-owner-hosted-v1" and receipt["status"] == "passed"
            and receipt["allOwnersSettled"] is True and receipt["failureCode"] is None,
            "Configuration original ownership is unconfirmed; preserve outputs")
    require(receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED), "Configuration owner scope differs")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    cases = receipt["cases"]
    require(isinstance(cases, list) and len(cases) == 3, "Configuration owner case inventory differs")
    fields = {"name", "outcome", "nativeReason", "nativeFinality", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "forceAttempted", *CONFIG_OWNER_FINALITY}
    for case, name, effect, journal, native_reason, requests, responses in zip(
        cases, ("create", "no-op", "discard-editing"), ("committed", "unchanged", "not_started"),
        ("clean", "not_created", "not_created"), ("none", "none", "discarded"), (3, 3, 1), (3, 3, 2), strict=True,
    ):
        require(isinstance(case, dict) and set(case) == fields and case["name"] == name
                and case["nativeReason"] == native_reason and case["nativeFinality"] == "settled"
                and all(case[field] is True for field in CONFIG_OWNER_FINALITY)
                and case["forceAttempted"] is False, "Configuration original resource receipt differs")
        require(all(type(case[field]) is int for field in ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
                and case["requestFrames"] == requests and case["responseFrames"] == responses
                and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0,
                "Configuration frame/output accounting differs")
        outcome = case["outcome"]
        require(isinstance(outcome, dict) and set(outcome) == {"effect", "journal", "resources", "reason"}
                and outcome["effect"] == effect and outcome["journal"] == journal and outcome["resources"] == "settled"
                and outcome["reason"] in (("none", "cancelled") if name == "discard-editing" else ("none",)),
                "Configuration owner effect/finality differs")
    return receipt


def validate_config_loss_receipt(receipt: object, kind: str, *, source_sha: str, platform: str,
                                 source_hashes: dict[str, str], python_hash: str) -> dict:
    require(kind in ("driver-loss", "watchdog-loss") and isinstance(receipt, dict), "Unexpected management-loss receipt")
    require(set(receipt) == {"schemaVersion", "scope", "status", "failureCode", "bindings", "case", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-owner-management-loss-hosted-v1"
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED), "Management-loss fixture did not pass; preserve outputs")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    case = receipt["case"]
    fields = {"name", "nativePhase", "nativeFinality", "registryDisabled", "editPermitClosed", "nativeCanExit",
              "originalResourcesSettled", "failedTask", "failedJoinKind", "failedTaskHandleRetained",
              "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "forceAttempted", *CONFIG_OWNER_FINALITY}
    require(isinstance(case, dict) and set(case) == fields and case["name"] == kind
            and case["nativePhase"] == "unknown" and case["nativeFinality"] == "unknown"
            and case["registryDisabled"] is True and case["editPermitClosed"] is True and case["nativeCanExit"] is False
            and case["originalResourcesSettled"] is True and case["failedTask"] == kind.removesuffix("-loss")
            and case["failedJoinKind"] == "panic" and case["failedTaskHandleRetained"] is True
            and case["forceAttempted"] is False, "Management uncertainty or original native settlement differs")
    # Only the injected management task lacks a normal return. Its actual panic
    # JoinError remains retained; every independent resource-bearing task joined.
    require(case["driverJoined"] is (kind != "driver-loss") and case["watchdogJoined"] is (kind != "watchdog-loss")
            and all(case[field] is True for field in CONFIG_OWNER_FINALITY if field not in {"driverJoined", "watchdogJoined"}),
            "Management-loss original task receipts differ")
    require(all(type(case[field]) is int for field in ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
            and case["requestFrames"] == 1 and case["responseFrames"] == 2
            and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0,
            "Management-loss original frame accounting differs")
    return receipt


def validate_config_delta_receipt(receipt: object, kind: str, *, source_sha: str, platform: str,
                                  source_hashes: dict[str, str], python_hash: str) -> dict:
    require(kind in {"stop", "terminal-deadline", "startup-stop"} and isinstance(receipt, dict),
            "Unexpected configuration lifecycle receipt")
    stopping = kind == "stop"
    fields = {"schemaVersion", "scope", "status", "failureCode", "bindings", "notVerified"}
    fields.update({"allOwnersSettled", "cases"} if stopping else {"case"})
    require(set(receipt) == fields and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == ("configuration-owner-stop-hosted-v1" if stopping else
                                     "configuration-owner-clock-retention-hosted-v1")
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED),
            "Configuration lifecycle fixture did not pass its exact scope")
    validate_config_owner_bindings(receipt["bindings"], source_sha=source_sha, platform=platform,
                                    source_hashes=source_hashes, python_hash=python_hash)
    common = {"name", "evidenceKind", "nativePhase", "nativeFinality", "nativeReason", "applySubmitted",
              "outcome", "terminalSeq", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes",
              "forceAttempted", *CONFIG_OWNER_FINALITY}
    if stopping:
        require(receipt["allOwnersSettled"] is True and isinstance(receipt["cases"], list)
                and len(receipt["cases"]) == 2, "Configuration stop case inventory differs")
        for case, name, evidence, reason, applying, prefix in zip(
            receipt["cases"], ("discard-reviewing", "partial-apply-eof"),
            ("actual-config-child", "fixed-prefix-scheduling-control"), ("discarded", "cancelled"),
            (False, True), (0, 1), strict=True,
        ):
            require(isinstance(case, dict) and set(case) == common | {"preparedCorrelation", "prefixBytes", "applySuffixStarted"}
                    and case["name"] == name and case["evidenceKind"] == evidence
                    and case["nativePhase"] == "final" and case["nativeFinality"] == "settled"
                    and case["nativeReason"] == reason and case["applySubmitted"] is applying
                    and all(case[field] is True for field in CONFIG_OWNER_FINALITY)
                    and case["preparedCorrelation"] is True and case["applySuffixStarted"] is False
                    and case["forceAttempted"] is False, "Configuration stop original custody differs")
            require(all(type(case[field]) is int for field in
                        ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "prefixBytes", "terminalSeq"))
                    and case["requestFrames"] == 2 and case["responseFrames"] == 3
                    and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024 and case["stderrBytes"] == 0
                    and case["terminalSeq"] == 1 and case["prefixBytes"] == prefix
                    and case["outcome"] == {"effect": "not_started", "journal": "not_created", "resources": "settled", "reason": "cancelled"},
                    "Configuration partial-input or prepared-EOF outcome differs")
    else:
        terminal = kind == "terminal-deadline"
        case = receipt["case"]
        additional = {"registryDisabled", "editPermitClosed", "editAvailability", "nativeCanExit",
                      "originalResourcesSettled", "lateSettled", "retainedBeforeRelease", "cleanupStartUnchanged",
                      "cleanupElapsedMs", "scheduledActiveDeadline", "inspectionJoined", "acquisitionNotAdmitted",
                      "pipeAcquisition", "controlEntered", "controlReleased", "shutdownObserved"}
        require(isinstance(case, dict) and set(case) == common | additional and case["name"] == kind
                and case["evidenceKind"] == "scheduling-control-not-os-fault"
                and case["nativePhase"] == "unknown" and case["nativeFinality"] == "unknown"
                and case["nativeReason"] == ("active_timeout" if terminal else "discarded")
                and case["applySubmitted"] is terminal and case["forceAttempted"] is False
                and case["editAvailability"] == ("shutdown" if terminal else "cleanup_unknown"),
                "Configuration clock control cannot claim normal owner success")
        require(all(case[field] is True for field in (
                    "registryDisabled", "editPermitClosed", "nativeCanExit", "originalResourcesSettled", "lateSettled",
                    "retainedBeforeRelease", "cleanupStartUnchanged", "inspectionJoined", "controlEntered", "controlReleased"))
                and case["scheduledActiveDeadline"] is terminal and case["shutdownObserved"] is terminal
                and case["acquisitionNotAdmitted"] is (not terminal)
                and case["pipeAcquisition"] == ("available" if terminal else "absent"),
                "Configuration retained-to-late-settlement facts differ")
        # The childless case proves positive inspection/STOP refusal/Absent and
        # original IO/management joins. No wait, close, EOF or acquisition join
        # is invented for endpoints that were never acquired.
        for field in CONFIG_OWNER_FINALITY:
            require(case[field] is (terminal or field in {"ioJoined", "driverJoined", "watchdogJoined", "managerJoined"}),
                    "Configuration original wait/EOF/close or no-acquisition facts differ")
        require(all(type(case[field]) is int for field in
                    ("requestFrames", "responseFrames", "stdoutBytes", "stderrBytes", "cleanupElapsedMs"))
                and 10_000 <= case["cleanupElapsedMs"] <= 60_000
                and case["requestFrames"] == (3 if terminal else 0)
                and case["responseFrames"] == (3 if terminal else 0) and case["stderrBytes"] == 0,
                "Configuration clock or frame accounting differs")
        if terminal:
            require(0 < case["stdoutBytes"] <= 12 * 1024 * 1024
                    and type(case["terminalSeq"]) is int and case["terminalSeq"] == 2
                    and case["outcome"] == {"effect": "committed", "journal": "clean", "resources": "settled", "reason": "none"},
                    "Configuration late committed result was lost or replaced")
        else:
            require(case["stdoutBytes"] == 0 and case["terminalSeq"] is None and case["outcome"] is None,
                    "Never-started configuration owner fabricated a core result")
    return receipt


def validate_config_transaction_eof_receipt(receipt: object, *, source_sha: str, platform: str,
                                           source_hashes: dict[str, str], python_hash: str) -> dict:
    require(isinstance(receipt, dict) and set(receipt) == {
                "schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "bindings", "cases", "notVerified"}
            and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
            and receipt["scope"] == "configuration-transaction-eof-hosted-v1"
            and receipt["status"] == "passed" and receipt["failureCode"] is None
            and receipt["allOwnersSettled"] is True
            and receipt["notVerified"] == list(CONFIG_OWNER_NOT_VERIFIED),
            "Configuration transaction EOF fixture did not pass its exact scope")
    bindings = receipt["bindings"]
    require(isinstance(bindings, dict), "Configuration EOF bindings differ")
    payloads = bindings.get("payloadHashes")
    base_payloads = {"draft", "createConfig", "createIgnore", "noOpConfig", "noOpIgnore", "unrelated"}
    require(isinstance(payloads, dict) and set(payloads) == base_payloads | {"eofDraft", "eofConfig", "eofInitialIgnore", "eofIgnore"}
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in payloads.values()),
            "Configuration EOF payload inventory differs")
    # Older healthy/lifecycle receipts retain their exact six-payload contract.
    # Only this new scope carries the extra shim and changed transaction inputs.
    validate_config_owner_bindings({**bindings, "payloadHashes": {key: payloads[key] for key in base_payloads}},
        source_sha=source_sha, platform=platform, source_hashes=source_hashes, python_hash=python_hash)
    cases = receipt["cases"]
    require(isinstance(cases, list) and len(cases) == 2, "Configuration transaction EOF case inventory differs")
    fields = {"name", "evidenceKind", "bootstrapMode", "nativePhase", "nativeFinality", "nativeReason", "applySubmitted",
              "lateSettled", "ownerDisabled", "outcome", "terminalSeq", "preparedCorrelation", "closeBeforeActiveDeadline",
              "controlRecords", "boundary", "actualStdinEof", "eofReadCount", "nonemptyReadCount", "readErrorCount",
              "originalCheckpoint", "committedPublication", "rolledBackPublication", "terminalDurable", "fixedRecovery",
              "journalClean", "originalsPreserved", "payloadsInstalled", "modesPreserved", "unrelatedPreserved",
              "journalAbsent", "fixtureFilesSettled", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes",
              "forceAttempted", *CONFIG_OWNER_FINALITY}
    for case, name, boundary, checkpoint, committed in zip(cases,
            ("precommit-eof", "postcommit-eof"), ("before-COMMITTED", "after-durable-COMMITTED"),
            ("publisher-entry", "descriptor-close"), (False, True), strict=True):
        require(isinstance(case, dict) and set(case) == fields and case["name"] == name
                and case["evidenceKind"] == "real-stdin-eof-at-controlled-transaction-boundary"
                and case["bootstrapMode"] == "instrumented-genuine-engine"
                and case["nativePhase"] == "final" and case["nativeFinality"] == "settled" and case["nativeReason"] == "cancelled"
                and case["lateSettled"] is False and case["ownerDisabled"] is False and case["forceAttempted"] is False
                and case["boundary"] == boundary and case["originalCheckpoint"] == checkpoint,
                "Configuration transaction EOF original owner facts differ")
        require(all(case[field] is True for field in (*CONFIG_OWNER_FINALITY, "applySubmitted", "preparedCorrelation",
                    "closeBeforeActiveDeadline", "actualStdinEof", "terminalDurable", "fixedRecovery", "journalClean",
                    "modesPreserved", "unrelatedPreserved", "journalAbsent", "fixtureFilesSettled"))
                and case["committedPublication"] is committed and case["rolledBackPublication"] is (not committed)
                and case["originalsPreserved"] is (not committed) and case["payloadsInstalled"] is committed,
                "Configuration transaction EOF recovery or original settlement differs")
        terminal = "COMMITTED" if committed else "ROLLED_BACK"
        control_records = (f"MRK_CONFIG_EOF_V1 {name} boundary={boundary}\n"
            f"MRK_CONFIG_EOF_V1 {name} eof=1 nonempty=0 readErrors=0 checkpoint={checkpoint} "
            f"applied=1 committed={int(committed)} rolledBack={int(not committed)} terminal={terminal} "
            "durable=1 recovery=1 clean=1 settled=1 cancelled=1\n")
        require(all(type(case[field]) is int for field in ("terminalSeq", "controlRecords", "eofReadCount",
                    "nonemptyReadCount", "readErrorCount", "requestFrames", "responseFrames", "stdoutBytes", "stderrBytes"))
                and case["terminalSeq"] == 2 and case["controlRecords"] == 2 and case["eofReadCount"] == 1
                and case["nonemptyReadCount"] == 0 and case["readErrorCount"] == 0
                and case["requestFrames"] == 3 and case["responseFrames"] == 3
                and 0 < case["stdoutBytes"] <= 12 * 1024 * 1024
                and case["stderrBytes"] == len(control_records.encode("ascii")),
                "Configuration transaction EOF control/frame accounting differs")
        require(case["outcome"] == {"effect": "committed" if committed else "rolled_back", "journal": "clean",
                                   "resources": "settled", "reason": "cancelled"},
                "Configuration transaction EOF result cannot be normal Saved")
    return receipt


def config_transaction_eof_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "config-transaction-eof/receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration transaction EOF receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration transaction EOF receipt changed")
    source = Path(context["source"])
    return validate_config_transaction_eof_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_TRANSACTION_EOF_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_owner_receipt(context: dict) -> dict:
    path = Path(context["root"]) / "config-owner/receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration owner receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration owner receipt changed")
    source = Path(context["source"])
    return validate_config_owner_receipt(json.loads(data), source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_loss_receipt(context: dict, kind: str) -> dict:
    require(kind in ("driver-loss", "watchdog-loss"), "Unknown management-loss partition")
    path = Path(context["root"]) / ("config-" + kind) / "receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Management-loss receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Management-loss receipt changed")
    source = Path(context["source"])
    return validate_config_loss_receipt(json.loads(data), kind, source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


def config_delta_receipt(context: dict, kind: str) -> dict:
    require(kind in {"stop", "terminal-deadline", "startup-stop"}, "Unknown configuration lifecycle partition")
    path = Path(context["root"]) / ("config-" + kind) / "receipt.json"
    ordinary(path)
    require(0 < path.stat().st_size <= 64 * 1024, "Configuration lifecycle receipt exceeded its bound")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(len(data) <= 64 * 1024, "Configuration lifecycle receipt changed")
    source = Path(context["source"])
    return validate_config_delta_receipt(json.loads(data), kind, source_sha=context["sourceSha"], platform=context["platform"],
        source_hashes={name: hash_file(source / relative) for name, relative in CONFIG_OWNER_SOURCES.items()},
        python_hash=hash_file(Path(context["python"])))


GITHUB_READONLY_RECEIPT_LIMIT = 128 * 1024
GITHUB_READONLY_CASES = (
    "g1-correct", "g1-passive-envelope", "g1-wrong-id", "g1-wrong-protocol",
    "g1-truncated", "g1-extra-frames", "g1-nonzero-exit", "g1-delay-exit",
    "g1-stdout-limit", "g1-stderr-limit", "g1-stalled-input", "g1-mixed-abandon",
    "g1-controlled-inspection", "g1-controlled-acquisition", "g1-controlled-io-join",
    "g1-controlled-management", "g1-controlled-management-late",
    "g1-document-connect-refresh", "g1-document-disconnect-held",
    "g1-document-registry-change", "g1-document-loss", "g1-document-unknown-late",
    "g1-document-terminal-unknown",
)
GITHUB_READONLY_NOT_VERIFIED = (
    "live-transport", "authenticated-remote-facts", "native-gui",
    "webview-callbacks-or-crash-hook", "production-runtime-custody",
    "production-github-enablement", "native-stuck-wait-close", "macos-windows-github",
    "credentials", "stores", "mobile-builds", "installers",
)
GITHUB_READONLY_HASH_BINDINGS = (
    "coreZipSha256", "engineSha256", "bootstrapSha256", "cargoLockSha256",
    "fixtureSha256", "githubBootstrapSha256", "githubFixtureSha256", "packageSha256",
    "pythonSha256",
)
GITHUB_READONLY_BINDINGS = {
    "sourceSha", "host", "target", "runtimeMode", "pythonBytes",
    *GITHUB_READONLY_HASH_BINDINGS,
}
_GITHUB_READONLY_OWNER_LATE = frozenset({
    "g1-controlled-inspection", "g1-controlled-acquisition", "g1-controlled-io-join",
    "g1-controlled-management-late",
})
_GITHUB_READONLY_STICKY = _GITHUB_READONLY_OWNER_LATE | {
    "g1-document-unknown-late", "g1-document-terminal-unknown",
}
_GITHUB_READONLY_FIRST_ERRORS = {
    **dict.fromkeys(("g1-passive-envelope", "g1-wrong-id", "g1-wrong-protocol",
                    "g1-truncated", "g1-extra-frames"), "protocol_error"),
    "g1-nonzero-exit": "engine_failed",
    "g1-stdout-limit": "output_limit", "g1-stderr-limit": "output_limit",
    "g1-stalled-input": "query_timeout",
    **dict.fromkeys(_GITHUB_READONLY_OWNER_LATE, "shutting_down"),
    "g1-document-disconnect-held": "cancelled", "g1-document-loss": "cancelled",
    "g1-document-unknown-late": "cancelled",
    "g1-document-terminal-unknown": "shutting_down",
}
_GITHUB_READONLY_LATE_NOTES = (
    "retainedWhileUnknown", "newPassiveAndGitHubAdmissionRefused",
    "originalCleanupEndpointUnchanged", "lateJoinPreservedFailure",
    "terminalReceiptAndSettledAtImmutable",
)
_GITHUB_READONLY_NOTES = {
    "g1-correct": ("typedGitHubMailbox", "terminalReceiptAndSettledAtImmutable"),
    "g1-nonzero-exit": ("validOutputDidNotSalvageFailedExit",),
    "g1-delay-exit": ("mailboxPendingAfterBothEofs",),
    "g1-stalled-input": ("originalOperationDeadlineObserved", "originalCleanupEndpointUnchanged",
                         "unreadInputIsNotBlockedWriterEvidence"),
    "g1-mixed-abandon": ("sharedTwoSlotLimit", "originalRetainedAfterTicketDrop",
                         "droppedTicketOriginalReturnedTypedSuccess"),
    "g1-controlled-inspection": (*_GITHUB_READONLY_LATE_NOTES,
        "noChildBeforeHeldStartupReturn", "noLateChildAfterCleanupExpiry"),
    "g1-controlled-acquisition": (*_GITHUB_READONLY_LATE_NOTES,
        "noChildBeforeHeldStartupReturn", "noLateChildAfterCleanupExpiry"),
    "g1-controlled-io-join": (*_GITHUB_READONLY_LATE_NOTES,
        "nativeExitAndEofBeforeStdoutJoin", "lateOriginalStdoutJoined"),
    "g1-controlled-management": ("nativeSettledBeforeManagementReturns", "driverReturnHeldBeforeMailbox",
                                 "watchdogReturnHeldBeforeMailbox", "terminalReceiptAndSettledAtImmutable"),
    "g1-controlled-management-late": (*_GITHUB_READONLY_LATE_NOTES, "nativeSettledBeforeWatchdogReturn"),
    "g1-document-connect-refresh": ("ordinaryAndUnrelatedRefusedBeforeDecode", "statusStartsNoRead",
                                    "refreshPinsAndOriginalExpiryPreserved"),
    "g1-document-disconnect-held": ("wrongSessionUnchanged", "pendingMaterialRetained",
                                    "originalCleanupEndpointUnchanged", "lateReceiptCannotRestoreSession"),
    "g1-document-registry-change": ("registryRecheckedBeforePositiveReceipt",),
    "g1-document-loss": ("actualLossPathRetiredSynchronously", "newAdmissionRefusedAfterLoss",
                         "lateReceiptCannotRestoreSession"),
    "g1-document-unknown-late": ("pendingMaterialRetained", "originalCleanupEndpointUnchanged",
                                 "lateSettlementPreservedUnknown", "originalSettledAtImmutable"),
    "g1-document-terminal-unknown": ("terminalOperationUsesReservedUnknownIdentity",
                                     "settledDocumentDoesNotReplaceOwnerFinality"),
}


def _github_readonly_terminal(first_error: str | None, unknown: bool) -> dict:
    if unknown:
        return {"return": "error", "code": "cleanup_unknown", "wasUnknown": True}
    if first_error is not None:
        return {"return": "error", "code": first_error, "wasUnknown": False}
    return {"return": "github-facts", "wasUnknown": False}


def _validate_github_readonly_native(value: object, name: str, profile: str) -> None:
    diagnostic = f"GitHub readonly {name} original native observations differ"
    native = closed_object(value, {
        "inspection_joined", "acquisition_joined", "spawned", "waited", "exit_success",
        "writer_joined", "writer_complete", "stdout_eof", "stderr_eof", "stdout_joined",
        "stderr_joined", "stdout_bytes", "stderr_bytes", "driver_joined", "watchdog_joined",
    }, diagnostic)
    startup = name in {"g1-controlled-inspection", "g1-controlled-acquisition"}
    for field in ("inspection_joined", "driver_joined", "watchdog_joined"):
        require(native[field] is True, diagnostic)
    require(native["acquisition_joined"] is (name != "g1-controlled-inspection"), diagnostic)
    for field in ("spawned", "waited", "writer_joined", "stdout_eof", "stderr_eof", "stdout_joined", "stderr_joined"):
        require(native[field] is (not startup), diagnostic)
    if name == "g1-stalled-input":
        # Unread <=8KiB can fit into a pipe. This row proves the real operation
        # deadline and original writer JOIN, not a blocked/incomplete write.
        require(type(native["writer_complete"]) is bool, diagnostic)
    else:
        require(native["writer_complete"] is (not startup), diagnostic)
    if startup:
        require(native["exit_success"] is None, diagnostic)
    elif name in {"g1-stdout-limit", "g1-stderr-limit"}:
        # The real child may finish or be stopped after the output limit latches.
        # Neither exit status can turn the required typed failure into success.
        require(type(native["exit_success"]) is bool, diagnostic)
    else:
        require(native["exit_success"] is (name not in {
            "g1-nonzero-exit", "g1-stalled-input", "g1-document-loss",
        }), diagnostic)
    zero_stdout = startup or name in {"g1-stalled-input", "g1-stderr-limit", "g1-document-loss"}
    stdout_limit = 4 * 1024 * 1024 if profile == "passive" else 64 * 1024
    require(integer_between(native["stdout_bytes"], 0 if zero_stdout else 1,
                            0 if zero_stdout else stdout_limit), diagnostic)
    require(integer_between(native["stderr_bytes"], 1 if name == "g1-stderr-limit" else 0,
                            64 * 1024 if name == "g1-stderr-limit" else 0), diagnostic)


def validate_github_readonly_receipt(value: object, *, bindings: dict) -> dict:
    """Closed redacted G1 DATA contract; expected bindings come from outside it.

    Never derive ``bindings`` from the received receipt. The caller must bind
    them to the admitted original source, runtime and compiled fixture bytes,
    and separately retain the workflow/run/attempt and full source inventory.
    Passing this consumer is not native or production-enablement evidence.
    """
    expected = closed_object(bindings, GITHUB_READONLY_BINDINGS, "GitHub readonly expected bindings differ")
    require(type(expected["sourceSha"]) is str and re.fullmatch(r"[0-9a-f]{40}", expected["sourceSha"]) is not None
            and expected["sourceSha"] != "0" * 40, "GitHub readonly expected source identity differs")
    require(same_compile_json({key: expected[key] for key in ("host", "target", "runtimeMode")}, {
        "host": "linux", "target": "x86_64-unknown-linux-gnu", "runtimeMode": "trusted-development-only",
    }), "GitHub readonly expected platform or runtime differs")
    require(all(sha256_value(expected[key]) for key in GITHUB_READONLY_HASH_BINDINGS)
            and integer_between(expected["pythonBytes"], 1, 512 * 1024 * 1024),
            "GitHub readonly expected input hashes or Python size differ")
    receipt = closed_object(value, {
        "schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "bindings", "cases", "notVerified",
    }, "GitHub readonly receipt fields differ")
    require(same_compile_json({key: receipt[key] for key in (
        "schemaVersion", "scope", "status", "allOwnersSettled", "failureCode", "notVerified",
    )}, {
        "schemaVersion": 1, "scope": "github-readonly-hosted-v1", "status": "passed",
        "allOwnersSettled": True, "failureCode": None, "notVerified": list(GITHUB_READONLY_NOT_VERIFIED),
    }), "GitHub readonly receipt header or limitations differ")
    require(same_compile_json(receipt["bindings"], expected), "GitHub readonly independently bound inputs differ")
    require(type(receipt["cases"]) is list and len(receipt["cases"]) == len(GITHUB_READONLY_CASES),
            "GitHub readonly receipt case roster differs")
    for name, supplied in zip(GITHUB_READONLY_CASES, receipt["cases"], strict=True):
        diagnostic = f"GitHub readonly {name} case contract differs"
        case = closed_object(supplied, {
            "case", "passed", "failureCode", "elapsedMs", "evidenceKind", "results", "notes",
            "owners", "registeredOwners", "disabled",
        }, diagnostic)
        document = name.startswith("g1-document-")
        sticky = name in _GITHUB_READONLY_STICKY
        kind = ("controlled-document-original-owner" if document else
                "scheduling-control-not-os-fault" if name.startswith("g1-controlled-") else "actual-private-frame-child")
        require(same_compile_json({key: case[key] for key in (
            "case", "passed", "failureCode", "evidenceKind", "registeredOwners", "disabled",
        )}, {"case": name, "passed": True, "failureCode": None, "evidenceKind": kind,
             "registeredOwners": 0, "disabled": sticky}), diagnostic)
        # No small machine-speed upper bound; the original native finality and
        # byte/structure bounds still apply. A shortened original clock cannot pass.
        minimum_ms = 10000 if name == "g1-stalled-input" else 2000 if sticky else 0
        require(type(case["elapsedMs"]) is int and case["elapsedMs"] >= minimum_ms, diagnostic)
        notes = {"originalRetentionSettled": True, **dict.fromkeys(_GITHUB_READONLY_NOTES.get(name, ()), True)}
        if document:
            notes.update(documentEvidence="controlled-original-lifetime-not-gui-callbacks",
                         sourceBooksSettled=2 if name == "g1-document-registry-change" else 1,
                         documentMaterialSettled=True)
        require(same_compile_json(case["notes"], notes), f"GitHub readonly {name} lifecycle evidence differs")
        owner_specs = [("github-read-1", "github-readonly")]
        if name == "g1-mixed-abandon":
            owner_specs.append(("query-2", "passive"))
        elif name in {"g1-document-connect-refresh", "g1-document-terminal-unknown"}:
            owner_specs.append(("github-read-2", "github-readonly"))
        require(type(case["owners"]) is list and len(case["owners"]) == len(owner_specs),
                f"GitHub readonly {name} original owner roster differs")
        for index, ((identity, profile), supplied_owner) in enumerate(zip(owner_specs, case["owners"], strict=True)):
            owner = closed_object(supplied_owner, {
                "id", "terminal", "unknownLatched", "permitRetained", "native", "profile",
                "observerJoined", "firstError", "receipt",
            }, f"GitHub readonly {name} original owner fields differ")
            earlier_healthy = name == "g1-document-terminal-unknown" and index == 0
            unknown = sticky and not earlier_healthy
            first_error = None if earlier_healthy else _GITHUB_READONLY_FIRST_ERRORS.get(name)
            terminal = None if profile == "passive" else _github_readonly_terminal(first_error, unknown)
            require(same_compile_json({key: owner[key] for key in owner if key != "native"}, {
                "id": identity, "terminal": True, "unknownLatched": unknown, "permitRetained": False,
                "profile": profile, "observerJoined": True, "firstError": first_error, "receipt": terminal,
            }), f"GitHub readonly {name} original finality or typed receipt differs")
            _validate_github_readonly_native(owner["native"], name, profile)
        if document:
            results = []  # Document receipts live on the same original owners.
        elif name == "g1-mixed-abandon":
            results = [{"return": "error", "code": "busy"},
                       {"return": "ticket-dropped", "ownerRetained": True}, {"return": "ok"}]
        else:
            results = [_github_readonly_terminal(_GITHUB_READONLY_FIRST_ERRORS.get(name), sticky)]
            if name in _GITHUB_READONLY_OWNER_LATE:
                results.insert(0, {"return": "retained-unknown"})
        require(same_compile_json(case["results"], results), f"GitHub readonly {name} ordered results differ")
    require(len(canonical_json(receipt)) <= GITHUB_READONLY_RECEIPT_LIMIT, "GitHub readonly receipt exceeds its bound")
    return receipt


def parse_github_readonly_receipt(raw: bytes, *, bindings: dict) -> dict:
    """No IO: bound the actual bytes before decoding the closed DATA contract."""
    require(type(raw) is bytes and 0 < len(raw) <= GITHUB_READONLY_RECEIPT_LIMIT,
            "GitHub readonly receipt bytes exceed their bound or differ in type")
    return validate_github_readonly_receipt(bounded_json(raw, GITHUB_READONLY_RECEIPT_LIMIT), bindings=bindings)


def github_readonly_binding(environment: dict[str, str]) -> dict[str, str]:
    """Exact private fixture lane, never a token/product or release capability."""
    sha, repository = environment.get("GITHUB_SHA", ""), environment.get("GITHUB_REPOSITORY", "")
    run_id, attempt = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "G1 source identity differs")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (run_id, attempt)),
            "G1 run identity differs")
    require(environment.get("GITHUB_REF") == GITHUB_READONLY_REF
            and environment.get("GITHUB_WORKFLOW_SHA") == sha
            and environment.get("GITHUB_WORKFLOW_REF") == f"{repository}/{GITHUB_READONLY_WORKFLOW}@{GITHUB_READONLY_REF}",
            "G1 workflow/ref binding differs")
    event = environment.get("GITHUB_EVENT_NAME")
    require(event == "push" or event == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == sha,
            "G1 event or exact dispatch source differs")
    return {"workflowPath": GITHUB_READONLY_WORKFLOW, "workflowSha": sha,
            "workflowRef": environment["GITHUB_WORKFLOW_REF"], "sourceSha": sha,
            "runId": run_id, "attempt": attempt}


def github_original_directories(context: dict) -> dict:
    root = Path(context["root"])
    return {"root": workflow_directory_identity(root), "source": workflow_directory_identity(Path(context["source"])),
            **{name: workflow_directory_identity(root / name) for name in GITHUB_READONLY_DIRECTORIES}}


def github_input_bindings(context: dict) -> dict:
    source, root, python = Path(context["source"]), Path(context["root"]), Path(context["python"])
    core = workflow_core_inventory(source)
    validate_gtk_core_inventory(core)  # The same literal 72-file core inventory; no GTK execution.
    ordinary(python)
    size = python.stat().st_size
    require(0 < size <= 512 * 1024 * 1024, "G1 Python executable size differs")
    return {"sourceFiles": fixed_file_inventory(source, GITHUB_READONLY_SOURCES), "coreFiles": core,
            "coreZipSha256": hash_file(root / "core.zip"), "pythonSha256": hash_file(python), "pythonBytes": size}


def github_inputs_unchanged(context: dict) -> None:
    """DATA-only observation: never invoke a tool after uncertain native work."""
    require(context.get("executionScope") == GITHUB_READONLY_SCOPE and context.get("platform") == "linux",
            "Wrong G1 input scope")
    require(same_compile_json(github_original_directories(context), context["originalDirectories"]),
            "G1 original directory identity changed")
    require(same_compile_json(github_input_bindings(context), context["githubInputs"]),
            "G1 original source/runtime inputs changed")


def github_source_unchanged(context: dict) -> None:
    source_unchanged(context)
    environment = clean_environment(Path(context["root"]))
    require(run([context["git"], "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=Path(context["source"]),
                env=environment, timeout=15, capture=True) == context["sourceTree"], "G1 source tree changed")
    require(run([context["git"], "status", "--porcelain=v1", "--untracked-files=all"], check="workflow-source-status",
                cwd=Path(context["source"]), env=environment, timeout=15, capture=True) == "",
            "G1 source contains unreviewed or generated inputs")
    github_inputs_unchanged(context)


def prepare_github_readonly_context(context: dict, inventory: list[dict]) -> None:
    context["originalDirectories"] = github_original_directories(context)
    context["observedHost"] = workflow_host(Path(context["root"]))
    context["githubInputs"] = github_input_bindings(context)
    require(same_compile_json(inventory, context["githubInputs"]["coreFiles"]), "G1 original ZIP/source inventory differs")
    github_source_unchanged(context)


def github_public_bindings(context: dict) -> dict:
    return {"schemaVersion": 1, "scope": GITHUB_READONLY_EVIDENCE_SCOPE,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "githubInputs")},
            "python": PYTHON, "rust": {"release": RUST, "target": TARGETS["linux"]},
            "features": ["development-runtime"], "testTarget": "lib", "host": context["observedHost"],
            "notVerified": list(GITHUB_READONLY_NOT_VERIFIED)}


def github_owner_bindings(context: dict) -> dict:
    inputs = context["githubInputs"]
    files = {row["path"]: row["sha256"] for row in inputs["sourceFiles"]}
    core = {row["path"]: row["sha256"] for row in inputs["coreFiles"]}
    return {"sourceSha": context["sourceSha"], "host": "linux", "target": TARGETS["linux"],
            "runtimeMode": "trusted-development-only", "coreZipSha256": inputs["coreZipSha256"],
            "engineSha256": core["mobile_release/_desktop_engine.py"],
            "bootstrapSha256": files["desktop/engine_bootstrap.py"],
            "cargoLockSha256": files["desktop/src-tauri/Cargo.lock"],
            "fixtureSha256": files["desktop/src-tauri/tests/fixtures/passive_core/_desktop_engine.py"],
            "githubBootstrapSha256": files["desktop/github_connection_bootstrap.py"],
            "githubFixtureSha256": files["desktop/src-tauri/tests/fixtures/github_core/_desktop_github_engine.py"],
            "packageSha256": files["desktop/src-tauri/tests/fixtures/passive_core/__init__.py"],
            "pythonSha256": inputs["pythonSha256"], "pythonBytes": inputs["pythonBytes"]}


def github_owner_receipt(context: dict) -> dict:
    return validate_github_readonly_receipt(
        read_bounded_json(Path(context["root"]) / "github-owner/receipt.json", 128 * 1024),
        bindings=github_owner_bindings(context))


def github_executable_path(value: object, *, target_root: Path) -> Path:
    require(type(value) is str and 0 < len(value) <= 16384 and "\0" not in value
            and not any(part in {"", ".", ".."} for part in value.split("/")[1:]),
            "G1 compiler executable path differs")
    path = Path(value)
    require(path.is_absolute() and target_root.is_absolute()
            and path.parent == target_root / TARGETS["linux"] / "debug/deps"
            and re.fullmatch(r"mobile_release_desktop-[0-9a-f]{16}", path.name) is not None,
            "G1 compiler executable left the exact original target")
    return path


def github_compiled_test(messages: bytes, *, source: Path, target_root: Path) -> Path:
    """One original Cargo result, not a glob, newest output or second build."""
    require(type(messages) is bytes and 0 < len(messages) <= 16 * 1024 * 1024,
            "G1 original compiler messages exceed their bound")
    executable, finished = None, False
    for line in messages.splitlines():
        require(not finished, "G1 compiler data followed the final result")
        row = bounded_json(line, 1024 * 1024)
        require(type(row) is dict and type(row.get("reason")) is str, "Malformed G1 compiler message")
        if row["reason"] == "compiler-artifact" and row.get("executable") is not None:
            target, profile = row.get("target"), row.get("profile")
            require(executable is None and type(target) is dict and target.get("kind") == ["lib"]
                    and target.get("name") == "mobile_release_desktop"
                    and target.get("src_path") == str(source / "desktop/src-tauri/src/lib.rs")
                    and row.get("manifest_path") == str(source / "desktop/src-tauri/Cargo.toml")
                    and type(profile) is dict and profile.get("test") is True and profile.get("debug_assertions") is True
                    and row.get("features") == ["development-runtime"] and row.get("fresh") is False,
                    "G1 original executable is not the requested fresh libtest")
            executable = github_executable_path(row["executable"], target_root=target_root)
        elif row["reason"] == "build-finished":
            require(row.get("success") is True, "G1 original compilation failed")
            finished = True
    require(finished and executable is not None, "G1 original compilation did not yield exactly one libtest")
    return executable


def github_file_identity(path: Path) -> dict:
    ordinary(path)
    info = path.lstat()
    return {"device": str(info.st_dev), "inode": str(info.st_ino), "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "size": info.st_size, "mtimeNs": info.st_mtime_ns}


def github_artifact_identity(path: Path, root: Path) -> dict:
    require(github_executable_path(str(path), target_root=root / "target") == path, "G1 artifact path differs")
    for directory in (root, root / "target", root / "target" / TARGETS["linux"],
                      root / "target" / TARGETS["linux"] / "debug", path.parent):
        workflow_directory_identity(directory)
    before = github_file_identity(path)
    require(0 < before["size"] <= 512 * 1024 * 1024 and before["mode"] & 0o111
            and before["uid"] == os.geteuid(), "G1 artifact kind, owner or size differs")
    digest = hash_file(path)
    require(same_compile_json(before, github_file_identity(path)), "G1 artifact changed while binding")
    return {"identity": before, "size": before["size"], "sha256": digest}


def github_compile_record(context: dict, argv: list[str], messages: Path) -> dict:
    ordinary(messages)
    require(messages.stat().st_size <= 16 * 1024 * 1024, "G1 compiler output exceeds its bound")
    with messages.open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    root = Path(context["root"])
    path = github_compiled_test(raw, source=Path(context["source"]), target_root=root / "target")
    value = {"schemaVersion": 1, "sourceSha": context["sourceSha"], "sourceTree": context["sourceTree"],
             "path": str(path), **github_artifact_identity(path, root),
             "invocationSha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
             "messagesSha256": hashlib.sha256(raw).hexdigest()}
    write_json(root / "github-compiled-test.json", value)
    return value


def github_original_artifact(context: dict) -> dict:
    root = Path(context["root"])
    value = closed_object(read_bounded_json(root / "github-compiled-test.json", 16384),
        {"schemaVersion", "sourceSha", "sourceTree", "path", "identity", "size", "sha256", "invocationSha256", "messagesSha256"},
        "G1 compiled artifact record differs")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["sourceSha"] == context["sourceSha"] and value["sourceTree"] == context["sourceTree"]
            and sha256_value(value["invocationSha256"]) and sha256_value(value["messagesSha256"]),
            "G1 compiled artifact source differs")
    path = github_executable_path(value["path"], target_root=root / "target")
    require(same_compile_json({key: value[key] for key in ("identity", "size", "sha256")}, github_artifact_identity(path, root)),
            "G1 original compiled artifact changed")
    return value


def github_phase_value(context: dict, name: str, checks: list[str]) -> dict:
    require(name in GITHUB_READONLY_CHECKS, "Unknown G1 phase receipt")
    value = {"schemaVersion": 1, "scope": GITHUB_READONLY_EVIDENCE_SCOPE, "phase": name, "status": "passed",
             **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                            "workflowRef", "workflowSha256", "runId", "attempt")},
             "inputSha256": hashlib.sha256(canonical_json(context["githubInputs"])).hexdigest(),
             "rust": {"release": RUST, "target": TARGETS["linux"]},
             "checks": [{"check": check, "exitCode": 0} for check in checks]}
    if name in {"compile", "github-owner"}:
        compiled = github_original_artifact(context)
        value["compiledTest"] = {key: compiled[key] for key in ("size", "sha256", "invocationSha256", "messagesSha256")}
    return value


def validate_github_phase_receipt(value: object, context: dict, name: str) -> dict:
    require(name in GITHUB_READONLY_CHECKS and context.get("executionScope") == GITHUB_READONLY_SCOPE,
            "Unexpected G1 receipt scope or phase")
    require(same_compile_json(value, github_phase_value(context, name, list(GITHUB_READONLY_CHECKS[name]))),
            "G1 original phase receipt is incomplete or changed")
    return value


def github_phase_claim(context: dict, name: str) -> dict:
    return {"scope": GITHUB_READONLY_SCOPE, "phase": name,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")}}


def github_predecessors(context: dict, name: str) -> None:
    require(name in (*GITHUB_READONLY_CHECKS, "clean"), "Unknown G1 successor")
    phases, root = list(GITHUB_READONLY_CHECKS), Path(context["root"])
    previous = phases if name == "clean" else phases[:phases.index(name)]
    for prior in previous:
        require(same_compile_json(read_bounded_json(root / f"{prior}-started.json", 4096), github_phase_claim(context, prior)),
                "G1 original phase claim differs")
        validate_github_phase_receipt(read_bounded_json(root / f"{prior}-checks.json", 16384), context, prior)
        if prior == "github-owner":
            github_owner_receipt(context)  # Original joins/material finality, not the outer exit.
    for later in (*phases[len(previous):], "clean"):
        for suffix in ("started", "checks"):
            path = root / f"{later}-{suffix}.json"
            require(not path.exists() and not path.is_symlink(), "G1 phase was already claimed; retain outputs")


def phase_github_readonly(name: str, context: dict) -> None:
    require(context.get("executionScope") == GITHUB_READONLY_SCOPE and context.get("platform") == "linux",
            "Wrong G1 native scope")
    admit_phase(GITHUB_READONLY_SCOPE, name)
    require(name != "prepare", "G1 preparation has a separate fixed entry")
    if name == "clean":
        clean_github_readonly(context)
        return
    github_predecessors(context, name)
    root, source = Path(context["root"]), Path(context["source"])
    write_json(root / f"{name}-started.json", github_phase_claim(context, name))
    github_source_unchanged(context)
    no_cargo_configuration((root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents))
    environment = clean_environment(root)
    environment["GITHUB_SHA"] = context["sourceSha"]
    manifest = source / "desktop/src-tauri/Cargo.toml"
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        with (root / "cargo-metadata.json").open("x", encoding="utf-8") as output, \
                (root / "acquire.stderr").open("x", encoding="utf-8") as diagnostics:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", "development-runtime", "--filter-platform", TARGETS["linux"], "--manifest-path", str(manifest)],
                check="github-locked-headless-metadata", cwd=root, env=environment, timeout=600,
                output=output, diagnostics=diagnostics)
    elif name == "compile":
        cargo, _ = tools(context, environment)
        argv = [cargo, "test", "--locked", "--offline", "--jobs", "1", "--no-default-features",
                "--features", "development-runtime", "--target", TARGETS["linux"], "--manifest-path", str(manifest),
                "--target-dir", str(root / "target"), "--lib", "--no-run", "--message-format=json"]
        messages = root / "github-compile-messages.jsonl"
        with messages.open("x", encoding="utf-8", newline="\n") as output, \
                (root / "compile.stderr").open("x", encoding="utf-8") as diagnostics:
            run(argv, check="github-headless-test-compile-only", cwd=root, env=environment, timeout=600,
                output=output, diagnostics=diagnostics)
        github_compile_record(context, argv, messages)
    else:
        require(name == "github-owner", "Unknown G1 native phase")
        compiled = github_original_artifact(context)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"), MRK_DESKTOP_TEST_ROOT=str(root / "github-owner"),
                           MRK_DESKTOP_HOSTED_CHECKS="github-readonly-v1", GITHUB_ACTIONS="true",
                           RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", RUNNER_ARCH="X64")
        with (root / "github-owner.stdout").open("x", encoding="utf-8") as output, \
                (root / "github-owner.stderr").open("x", encoding="utf-8") as diagnostics:
            run([compiled["path"], GITHUB_READONLY_TEST, "--exact", "--ignored", "--test-threads=1"],
                check="github-owner-native-contract", cwd=root, env=environment, timeout=180,
                output=output, diagnostics=diagnostics)
        github_owner_receipt(context)
    # A missing or failed native receipt raises above. No later git/tool call or
    # deletion is authorized by process exit alone or by a positive frame.
    github_source_unchanged(context)
    phase_receipt(context, name, list(GITHUB_READONLY_CHECKS[name]))


def github_cleanup_identity(info: object, *, directory: bool = False) -> tuple:
    base = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    # Removing our own entries changes parent timestamps/link counts. File
    # ctime also changes when another inventoried hard link is unlinked.
    return base if directory else (*base, info.st_size, info.st_mtime_ns)


def clean_github_readonly(context: dict) -> None:
    """Positive original finality only; finite no-follow deletion, no process scan.

    On failure retain all remaining names for disposable-host teardown. This is
    a cooperative, private job namespace, not an atomic unlink against a hostile
    same-user renamer. Unknown/new entries are never added to the deletion plan.
    """
    github_predecessors(context, "clean")
    github_inputs_unchanged(context)
    root = Path(context["root"])
    write_json(root / "clean-started.json", github_phase_claim(context, "clean"))
    private_files = ("core.zip", "gitconfig-empty", "cargo-metadata.json", "acquire.stderr",
                     "github-compile-messages.jsonl", "compile.stderr", "github-compiled-test.json",
                     "github-owner.stdout", "github-owner.stderr")
    evidence = ("context.json", "public-bindings.json", "clean-started.json",
                *(f"{phase}-{suffix}.json" for phase in GITHUB_READONLY_CHECKS for suffix in ("started", "checks")))
    require({path.name for path in root.iterdir()} == set((*GITHUB_READONLY_DIRECTORIES, *private_files, *evidence)),
            "G1 task cleanup has missing or unexpected top-level entries; retain outputs")
    native = root / "github-owner"
    require({path.name for path in native.iterdir()} == {"receipt.json", *GITHUB_READONLY_CASES},
            "G1 settled fixture inventory differs; retain outputs")
    original_root = root.lstat()
    directories = {root: original_root, native: native.lstat()}
    leaves, removals, total = [], [], 0
    pending = [(root / name, 0) for name in GITHUB_READONLY_DIRECTORIES if name != "github-owner"]
    pending.extend((native / name, 0) for name in GITHUB_READONLY_CASES)
    pending.extend((root / name, 0) for name in private_files)
    while pending:
        path, depth = pending.pop()
        info = path.lstat()
        require(depth <= 32 and len(leaves) + len(removals) < 100000
                and info.st_dev == original_root.st_dev and info.st_uid == os.geteuid(),
                "G1 cleanup crossed its original filesystem, owner or inventory bound")
        if stat.S_ISDIR(info.st_mode):
            directories[path] = info
            removals.append(path)
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(pending) + len(leaves) + len(removals) < 100000, "G1 cleanup inventory exceeds its bound")
                    pending.append((path / entry.name, depth + 1))
            require(github_cleanup_identity(path.lstat(), directory=True) == github_cleanup_identity(info, directory=True),
                    "G1 cleanup directory changed during inventory")
        else:
            require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode),
                    "G1 cleanup found an unexpected file kind; retain outputs")
            total += info.st_size
            require(total <= 8 * 1024 * 1024 * 1024, "G1 cleanup output size exceeds its bound")
            leaves.append((path, info))
    # The whole finite plan is admitted before the first unlink. Keep the
    # original parent identities, never follow a link or sweep a changed tree.
    removed_links: dict[tuple[int, int], int] = {}
    def parent_unchanged(path: Path) -> None:
        for parent in (path.parent, *path.parent.parents):
            if parent not in directories:
                break
            require(github_cleanup_identity(parent.lstat(), directory=True)
                    == github_cleanup_identity(directories[parent], directory=True), "G1 cleanup original parent changed")
            if parent == root:
                break
    for path, original in leaves:
        parent_unchanged(path)
        current, key = path.lstat(), (original.st_dev, original.st_ino)
        require(github_cleanup_identity(current) == github_cleanup_identity(original)
                and current.st_nlink == original.st_nlink - removed_links.get(key, 0), "G1 cleanup original leaf changed")
        path.unlink()  # A link is removed as a leaf; its target is never opened.
        removed_links[key] = removed_links.get(key, 0) + 1
    for path in sorted(removals, key=lambda item: len(item.parts), reverse=True):
        parent_unchanged(path)
        require(github_cleanup_identity(path.lstat(), directory=True)
                == github_cleanup_identity(directories[path], directory=True), "G1 cleanup original directory changed")
        path.rmdir()  # Unknown/new content fails closed rather than being swept.
    require({path.name for path in root.iterdir()} == {"github-owner", *evidence}
            and {path.name for path in native.iterdir()} == {"receipt.json"}, "G1 cleanup postcondition differs")
    write_json(root / "clean-checks.json", {
        "schemaVersion": 1, "scope": GITHUB_READONLY_EVIDENCE_SCOPE, "phase": "clean", "status": "passed",
        **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef",
                                       "workflowSha256", "runId", "attempt")},
        "allOriginalOwnersSettled": True, "documentMaterialSettled": True, "observerJoinsComplete": True,
        "removedFiles": len(leaves), "removedDirectories": len(removals), "inventoriedBytes": total,
        "retained": ["redacted-evidence", "private-original-context"], "productionQualified": False,
    })
    print("Removed only positively settled G1 compiler and fixture outputs; original evidence retained.")


def github_tls_binding(environment: dict[str, str]) -> dict[str, str]:
    """The TLS lane is not an alias or successor of the owner23 lane."""
    sha, repository = environment.get("GITHUB_SHA", ""), environment.get("GITHUB_REPOSITORY", "")
    run_id, attempt = environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "TLS source identity differs")
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", item) is not None for item in (run_id, attempt)),
            "TLS run identity differs")
    require(environment.get("GITHUB_REF") == GITHUB_TLS_REF and environment.get("GITHUB_WORKFLOW_SHA") == sha
            and environment.get("GITHUB_WORKFLOW_REF") == f"{repository}/{GITHUB_TLS_WORKFLOW}@{GITHUB_TLS_REF}",
            "TLS workflow/ref binding differs")
    require(environment.get("GITHUB_EVENT_NAME") == "push"
            or environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and environment.get("MRK_EXPECTED_SHA") == sha,
            "TLS event or exact dispatch source differs")
    return {"workflowPath": GITHUB_TLS_WORKFLOW, "workflowSha": sha,
            "workflowRef": environment["GITHUB_WORKFLOW_REF"], "sourceSha": sha, "runId": run_id, "attempt": attempt}


def github_tls_namespaces() -> dict:
    values = {name: os.readlink(f"/proc/self/ns/{name}") for name in ("net", "mnt")}
    require(all(re.fullmatch(name + r":\[[1-9][0-9]{0,19}\]", value) is not None
                for name, value in values.items()), "TLS original namespace identity differs")
    return {"parentNetns": values["net"], "parentMntns": values["mnt"]}


def github_tls_file(path: Path) -> dict:
    """Reuse the original ordinary-file hash discipline for a canonical input."""
    require(path.is_absolute() and path.resolve(strict=True) == path, "TLS input is not canonical")
    before = github_file_identity(path)
    require(0 <= before["size"] <= 64 * 1024 * 1024, "TLS input exceeds its file bound")
    result = {"path": str(path), "size": before["size"], "sha256": hash_file(path)}
    require(same_compile_json(before, github_file_identity(path)), "TLS input changed while binding")
    return result


def github_tls_stdlib_files(library: Path) -> set[Path]:
    """Finite DATA-only import-roster observation, also usable before cleanup."""
    require(library.is_absolute() and library.resolve(strict=True) == library and library.is_dir(),
            "TLS selected stdlib directory differs")
    archive = library.parent / "python314.zip"
    require(not os.path.lexists(archive), "TLS unexpected stdlib archive is not bound")
    paths, seen = set(), 0
    excluded = {"site-packages", "test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip", "venv"}
    for parent, directories, names in os.walk(library, followlinks=False):
        here = Path(parent)
        seen += len(directories) + len(names)
        require(seen <= 8192 and len(here.relative_to(library).parts) <= 16,
                "TLS selected stdlib enumeration exceeds its bound")
        directories[:] = sorted(name for name in directories if name not in excluded)
        for name in directories:
            require(not (here / name).is_symlink(), "TLS stdlib directory link differs")
        for name in sorted(names):
            # Fixed -I -S -B without -O cannot select optimization1/2 caches.
            if name.endswith((".py", ".pyc", ".so")) and not re.search(r"\.opt-[12]\.pyc$", name):
                path = here / name
                require(not path.is_symlink(), "TLS stdlib input link differs")
                paths.add(path)
                require(len(paths) <= 1800, "TLS selected stdlib file count exceeds its bound")
    require(bool(paths), "TLS selected stdlib is empty")
    return paths


def github_tls_runtime() -> tuple[dict, dict, set[Path]]:
    """Admitted prepare only: selected development runtime, not a host audit.

    No product import, CA generation, peer/socket or production selection occurs.
    The SSL option roundtrip and actual ELF mapping are real runtime observations,
    not deductions from a version string. Lazy imports keep inert loaders inert.
    """
    import resource
    import socket
    import ssl
    import sysconfig

    require(sys.version.split()[0] == PYTHON and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and sys.flags.optimize == 0 and sys.platform == "linux",
            "TLS development interpreter flags/version differ")
    prefix = Path(sys.base_prefix).resolve(strict=True)
    library = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    require(library == prefix / "lib/python3.14"
            and Path(sys.executable).resolve(strict=True).parent.parent == prefix, "TLS selected stdlib layout differs")
    paths = github_tls_stdlib_files(library)
    allowed_search = {str(library), str(library / "lib-dynload"), str(prefix / "lib/python314.zip")}
    require(all(item in allowed_search for item in sys.path), "TLS import search escaped the selected stdlib")
    roles = {name: str(Path(module.__file__).resolve(strict=True)) for name, module in (
        ("ssl", ssl), ("socket", socket), ("_ssl", sys.modules["_ssl"]), ("_socket", sys.modules["_socket"]))}
    require(all(Path(value) in paths for value in roles.values()), "TLS SSL/socket extension is outside its bound runtime")
    mask = int(getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0))
    require(0 < mask < 2**64 and type(ssl.OPENSSL_VERSION) is str and 0 < len(ssl.OPENSSL_VERSION) <= 128,
            "TLS public EOF option is unavailable")
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.options |= mask
    require(int(probe.options) & mask == mask, "TLS public EOF option cannot be set")
    probe.options &= ~mask
    require(int(probe.options) & mask == 0, "TLS public EOF option cannot be cleared")
    # Capture after the actual SSL option probe, including any object loaded by
    # SSLContext construction as well as the previously imported resource limit.
    with Path("/proc/self/maps").open("rb") as stream:
        maps = stream.read(1024 * 1024 + 1)
    require(len(maps) <= 1024 * 1024, "TLS loader mapping exceeds its bound")
    libraries = set()
    for line in maps.decode("utf-8", errors="strict").splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or "x" not in fields[1] or not fields[5].startswith("/"):
            continue
        require(not fields[5].endswith(" (deleted)"), "TLS mapped runtime was deleted")
        path = Path(fields[5]).resolve(strict=True)
        libraries.add(path)
        require(len(libraries) <= 128, "TLS mapped loader closure exceeds its bound")
    for role, pattern in (("libssl", r"libssl\.so\.[0-9.]+"), ("libcrypto", r"libcrypto\.so\.[0-9.]+"),
                          ("loader", r"ld-linux-x86-64\.so\.2")):
        found = [path for path in libraries if re.fullmatch(pattern, path.name)]
        require(len(found) == 1, "TLS required original SSL/loader object differs")
        roles[role] = str(found[0])
    paths.update(libraries)
    # resource is loaded before the mapping snapshot so the fixed outer limiter
    # does not silently add an unbound extension after the runtime freeze.
    require(Path(resource.__file__).resolve(strict=True) in paths, "TLS outer limiter extension is not bound")
    return {"opensslVersion": ssl.OPENSSL_VERSION, "ignoreUnexpectedEof": mask}, roles, paths


def github_tls_manifest(context: dict) -> dict:
    source, root = Path(context["source"]), Path(context["root"])
    ssl, runtime_roles, paths = github_tls_runtime()
    roles = {"python": context["python"], "bootstrap": str(source / "desktop/github_connection_bootstrap.py"),
             "coreZip": str(root / "core.zip"), "peer": str(source / GITHUB_TLS_FIXTURES / "github_tls_peer.py"),
             "namespace": str(source / GITHUB_TLS_FIXTURES / "github_tls_namespace.sh"), **runtime_roles,
             **{name: str(source / GITHUB_TLS_FIXTURES / "github_tls" / name) for name in GITHUB_TLS_CERTIFICATES},
             **{name: str(root / "github-tls-namespace" / name) for name in GITHUB_TLS_CONFIG},
             **{"tool:" + name: value for name, value in GITHUB_TLS_TOOLS.items()}}
    paths.update(Path(value) for value in roles.values())
    paths.update(source / name for name in GITHUB_TLS_SOURCES)
    paths.update(source / "src" / name for name in GTK_CORE_PATHS)
    require(len(paths) <= 2048, "TLS input closure has too many files")
    files = [github_tls_file(path) for path in sorted(paths, key=str)]
    require(sum(row["size"] for row in files) <= 256 * 1024 * 1024, "TLS input closure exceeds its byte bound")
    for name, expected in GITHUB_TLS_CONFIG.items():
        require((root / "github-tls-namespace" / name).read_bytes() == expected, "TLS fixed resolver configuration differs")
    uid, gid = os.geteuid(), os.getegid()
    require(0 < uid < 2**32 and 0 < gid < 2**32 and os.getuid() == uid and os.getgid() == gid,
            "TLS original non-root identity differs")
    value = {"schemaVersion": 1, "scope": GITHUB_TLS_SCOPE,
             **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
             "sourceRoot": str(source), "jobRoot": str(root), "python": context["python"],
             "coreSource": str(source / "src"), "coreZip": str(root / "core.zip"), "uid": uid, "gid": gid,
             **github_tls_namespaces(), "ssl": ssl, "roles": roles, "files": files}
    require(len(canonical_json(value)) + 1 <= 1024 * 1024, "TLS precompile manifest exceeds its bound")
    validate_github_tls_manifest(value, context=context)
    return value


def validate_github_tls_manifest(value: object, *, context: dict) -> dict:
    """Pure closed input DATA shape; acquisition and hashes remain independent."""
    manifest = closed_object(value, {"schemaVersion", "scope", "sourceSha", "sourceTree", "workflowSha256", "runId", "attempt",
        "sourceRoot", "jobRoot", "python", "coreSource", "coreZip", "uid", "gid", "parentNetns", "parentMntns", "ssl", "roles", "files"},
        "TLS input manifest fields differ")
    source, root = Path(context["source"]), Path(context["root"])
    fixed = {"schemaVersion": 1, "scope": GITHUB_TLS_SCOPE,
             **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt")},
             "sourceRoot": str(source), "jobRoot": str(root), "python": context["python"],
             "coreSource": str(source / "src"), "coreZip": str(root / "core.zip")}
    require(same_compile_json({key: manifest[key] for key in fixed}, fixed)
            and all(integer_between(manifest[key], 1, 2**32 - 1) for key in ("uid", "gid")), "TLS manifest source/user differs")
    for key, kind in (("parentNetns", "net"), ("parentMntns", "mnt")):
        require(type(manifest[key]) is str and re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", manifest[key]) is not None,
                "TLS manifest original namespace differs")
    ssl = closed_object(manifest["ssl"], {"opensslVersion", "ignoreUnexpectedEof"}, "TLS SSL option fields differ")
    require(type(ssl["opensslVersion"]) is str and ssl["opensslVersion"].startswith("OpenSSL ")
            and 0 < len(ssl["opensslVersion"]) <= 128 and all(0x20 <= ord(c) <= 0x7e for c in ssl["opensslVersion"])
            and integer_between(ssl["ignoreUnexpectedEof"], 1, 2**64 - 1), "TLS genuine SSL option support differs")
    fixed_roles = {"python": context["python"], "bootstrap": str(source / "desktop/github_connection_bootstrap.py"),
        "coreZip": str(root / "core.zip"), "peer": str(source / GITHUB_TLS_FIXTURES / "github_tls_peer.py"),
        "namespace": str(source / GITHUB_TLS_FIXTURES / "github_tls_namespace.sh"),
        **{name: str(source / GITHUB_TLS_FIXTURES / "github_tls" / name) for name in GITHUB_TLS_CERTIFICATES},
        **{name: str(root / "github-tls-namespace" / name) for name in GITHUB_TLS_CONFIG},
        **{"tool:" + name: path for name, path in GITHUB_TLS_TOOLS.items()}}
    runtime_roles = {"ssl", "socket", "_ssl", "_socket", "libssl", "libcrypto", "loader"}
    roles = closed_object(manifest["roles"], set(fixed_roles) | runtime_roles, "TLS closed runtime/fixture/tool roles differ")
    require(all(roles[key] == path for key, path in fixed_roles.items()), "TLS fixed source/CA/config/tool path differs")
    require(type(manifest["files"]) is list and 0 < len(manifest["files"]) <= 2048, "TLS input file roster differs")
    names, total = [], 0
    for row in manifest["files"]:
        closed_object(row, {"path", "size", "sha256"}, "TLS input file fields differ")
        path = row["path"]
        require(type(path) is str and 0 < len(path) <= 16384 and path.startswith("/") and "\0" not in path
                and "\\" not in path and not any(part in {"", ".", ".."} for part in path.split("/")[1:])
                and integer_between(row["size"], 0, 64 * 1024 * 1024) and sha256_value(row["sha256"]),
                "TLS input file binding is malformed")
        names.append(path)
        total += row["size"]
    require(names == sorted(set(names)) and total <= 256 * 1024 * 1024
            and all(type(path) is str and path in names for path in roles.values()), "TLS input closure is missing, duplicate or oversized")
    library = Path(context["python"]).parent.parent / "lib/python3.14"
    require(all(roles[name] == str(library / f"{name}.py") for name in ("ssl", "socket"))
            and all(Path(roles[name]).parent == library / "lib-dynload"
                    and re.fullmatch(re.escape(name) + r"\.(cpython-314-x86_64-linux-gnu|abi3)\.so", Path(roles[name]).name)
                    for name in ("_ssl", "_socket")), "TLS selected SSL/socket import paths differ")
    for name, pattern in (("libssl", r"libssl\.so\.[0-9.]+"), ("libcrypto", r"libcrypto\.so\.[0-9.]+"),
                          ("loader", r"ld-linux-x86-64\.so\.2")):
        require(re.fullmatch(pattern, Path(roles[name]).name) is not None, "TLS selected SSL/loader object differs")
    require(all(str(source / name) in names for name in GITHUB_TLS_SOURCES)
            and all(str(source / "src" / name) in names for name in GTK_CORE_PATHS), "TLS actual source/core closure is incomplete")
    records = {row["path"]: row for row in manifest["files"]}
    require(all(records[path]["size"] > 0 for path in roles.values())
            and records[str(source / GITHUB_TLS_WORKFLOW)]["sha256"] == context["workflowSha256"],
            "TLS required input is empty or workflow bytes differ")
    require(len(canonical_json(manifest)) <= 1024 * 1024, "TLS manifest byte bound differs")
    return manifest


def github_tls_directories(context: dict) -> dict:
    root = Path(context["root"])
    return {"root": workflow_directory_identity(root), "source": workflow_directory_identity(Path(context["source"])),
            **{name: workflow_directory_identity(root / name) for name in GITHUB_TLS_DIRECTORIES}}


def github_tls_input_summary(context: dict, manifest: dict) -> dict:
    source = Path(context["source"])
    by_path = {row["path"]: row for row in manifest["files"]}
    def row(path: str, relative: str) -> dict:
        return {"path": relative, **{key: by_path[path][key] for key in ("size", "sha256")}}
    core = [row(str(source / "src" / name), name) for name in GTK_CORE_PATHS]
    validate_gtk_core_inventory(core)
    python = by_path[manifest["python"]]
    return {"sourceFiles": [row(str(source / name), name) for name in GITHUB_TLS_SOURCES], "coreFiles": core,
            "coreZipSha256": by_path[manifest["coreZip"]]["sha256"],
            "pythonSha256": python["sha256"], "pythonBytes": python["size"],
            "closureFiles": len(by_path), "closureBytes": sum(item["size"] for item in by_path.values()),
            "closureSha256": hashlib.sha256(canonical_json(manifest["files"])).hexdigest(),
            "ssl": manifest["ssl"],
            "roles": {name: {key: by_path[path][key] for key in ("size", "sha256")}
                      for name, path in manifest["roles"].items()}}


def prepare_github_tls_context(context: dict, inventory: list[dict]) -> None:
    root = Path(context["root"])
    for name, data in GITHUB_TLS_CONFIG.items():
        with (root / "github-tls-namespace" / name).open("xb") as stream:
            stream.write(data)
    context["originalDirectories"] = github_tls_directories(context)
    context["observedHost"] = workflow_host(root)
    manifest = github_tls_manifest(context)
    write_json(root / "github-tls-inputs.json", manifest)
    context["tlsInputsSha256"] = hash_file(root / "github-tls-inputs.json")
    context["tlsInputs"] = github_tls_input_summary(context, manifest)
    require(same_compile_json(inventory, context["tlsInputs"]["coreFiles"]), "TLS source/ZIP inventory differs")
    github_tls_source_unchanged(context)


def github_tls_inputs_unchanged(context: dict) -> None:
    # Revalidate the frozen bytes as DATA, not a new SSL probe, product import or
    # tool invocation. In particular this remains safe at the cleanup boundary.
    require(context.get("executionScope") == GITHUB_TLS_SCOPE and context.get("platform") == "linux",
            "Wrong TLS input scope")
    require(same_compile_json(github_tls_directories(context), context["originalDirectories"]),
            "TLS original directory identity changed")
    path = Path(context["root"]) / "github-tls-inputs.json"
    require(hash_file(path) == context["tlsInputsSha256"], "TLS compiled input anchor changed")
    manifest = read_bounded_json(path, 1024 * 1024)
    validate_github_tls_manifest(manifest, context=context)
    require(type(manifest) is dict and manifest.get("scope") == GITHUB_TLS_SCOPE
            and manifest.get("schemaVersion") == 1
            and all(manifest.get(key) == context[key]
                    for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt"))
            and manifest.get("sourceRoot") == context["source"] and manifest.get("jobRoot") == context["root"]
            and manifest.get("python") == context["python"] and manifest.get("uid") == os.geteuid()
            and manifest.get("gid") == os.getegid()
            and all(manifest.get(key) == value for key, value in github_tls_namespaces().items()),
            "TLS original context/namespace binding changed")
    require(type(manifest.get("files")) is list and 0 < len(manifest["files"]) <= 2048,
            "TLS original input roster differs")
    library = Path(manifest["roles"]["ssl"]).parent
    expected_stdlib = {Path(row["path"]) for row in manifest["files"] if library in Path(row["path"]).parents}
    require(github_tls_stdlib_files(library) == expected_stdlib, "TLS original import roster changed")
    observed = [github_tls_file(Path(row["path"])) for row in manifest["files"]]
    require(same_compile_json(manifest["files"], observed)
            and same_compile_json(context["tlsInputs"], github_tls_input_summary(context, manifest)),
            "TLS original runtime/source/CA/namespace inputs changed")


def github_tls_source_unchanged(context: dict) -> None:
    source_unchanged(context)
    environment = clean_environment(Path(context["root"]))
    require(run([context["git"], "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=Path(context["source"]),
                env=environment, timeout=15, capture=True) == context["sourceTree"], "TLS source tree changed")
    require(run([context["git"], "status", "--porcelain=v1", "--untracked-files=all"], check="workflow-source-status",
                cwd=Path(context["source"]), env=environment, timeout=15, capture=True) == "",
            "TLS source contains unreviewed or generated inputs")
    github_tls_inputs_unchanged(context)


def github_tls_public_bindings(context: dict) -> dict:
    return {"schemaVersion": 1, "scope": GITHUB_TLS_EVIDENCE_SCOPE,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "tlsInputsSha256", "tlsInputs")},
            "python": PYTHON, "rust": {"release": RUST, "target": TARGETS["linux"]},
            "features": ["development-runtime"], "testTarget": "lib", "host": context["observedHost"],
            "notVerified": list(GITHUB_TLS_NOT_VERIFIED)}


def validate_github_tls_peer(value: object, name: str) -> None:
    """Pure redacted peer DATA; socket exit alone is not either parent's finality."""
    peer = closed_object(value, {"schemaVersion", "scope", "case", "state", "status", "code", "connections",
        "handshakes", "requests", "decryptedBytes", "authBytes", "closeNotify", "tlsRefused",
        "wireReadBytes", "wireWriteBytes", "replyBytes", "allSocketsClosed"}, "TLS peer terminal fields differ")
    connections = 5 if name == "T1-zip" else 4 if name in {"T1-source", "T3-clean"} else 1
    refused = name.startswith("T2-")
    exact = {"schemaVersion": 1, "scope": "github-tls-peer-v1", "case": name, "state": "finished",
             "status": "passed", "code": None, "connections": connections,
             "handshakes": 0 if refused else connections, "requests": 0 if refused else connections,
             "authBytes": 0 if refused else connections * len(b"Bearer INERT_NOT_A_CREDENTIAL"),
             "closeNotify": 0 if refused or name == "T3-ragged" else connections,
             "tlsRefused": refused, "allSocketsClosed": True}
    require(same_compile_json({key: peer[key] for key in exact}, exact), "TLS peer protocol/case/finality differs")
    require(integer_between(peer["decryptedBytes"], 0 if refused else peer["authBytes"],
                            0 if refused else connections * 8192), "TLS peer decrypted-byte bound differs")
    for key, maximum in (("wireReadBytes", 128 * 1024), ("wireWriteBytes", 128 * 1024), ("replyBytes", 64 * 1024)):
        require(type(peer[key]) is list and len(peer[key]) == connections, "TLS peer connection byte roster differs")
        require(all(integer_between(item, 0 if refused and key == "replyBytes" else 1,
                                    0 if refused and key == "replyBytes" else maximum) for item in peer[key]),
                "TLS peer connection byte bounds differ")


def validate_github_tls_receipt(value: object, *, bindings: dict) -> dict:
    """Closed nine-case inner facts, independently bound; never an outer wait."""
    binding_keys = {"sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256",
                    "artifactSha256", "artifactBytes", "coreZipSha256", "pythonSha256", "namespace"}
    expected = closed_object(bindings, binding_keys, "TLS expected binding fields differ")
    require(all(type(expected[key]) is str and re.fullmatch(r"[0-9a-f]{40}", expected[key]) is not None
                and expected[key] != "0" * 40 for key in ("sourceSha", "sourceTree"))
            and all(sha256_value(expected[key]) for key in ("workflowSha256", "tlsInputsSha256", "artifactSha256",
                                                          "coreZipSha256", "pythonSha256"))
            and all(type(expected[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", expected[key]) is not None
                    for key in ("runId", "attempt"))
            and integer_between(expected["artifactBytes"], 1, 512 * 1024 * 1024), "TLS expected bindings are malformed")
    original = closed_object(expected["namespace"], {"parentNetns", "parentMntns", "uid", "gid"},
                             "TLS expected original namespace differs")
    require(all(integer_between(original[key], 1, 2**32 - 1) for key in ("uid", "gid")), "TLS original user differs")
    receipt = closed_object(value, {"schemaVersion", "scope", "status", "allOwnersSettled", "allPeersSettled",
        "failureCode", "bindings", "cases", "outerWait", "notVerified"}, "TLS receipt fields differ")
    exact = {"schemaVersion": 1, "scope": GITHUB_TLS_RECEIPT_SCOPE, "status": "passed", "allOwnersSettled": True,
             "allPeersSettled": True, "failureCode": None, "outerWait": "external-original-observer-required",
             "notVerified": list(GITHUB_TLS_NOT_VERIFIED)}
    require(same_compile_json({key: receipt[key] for key in exact}, exact), "TLS receipt header/finality/limitations differ")
    supplied = closed_object(receipt["bindings"], binding_keys, "TLS receipt binding fields differ")
    require(same_compile_json({key: supplied[key] for key in binding_keys - {"namespace"}},
                             {key: expected[key] for key in binding_keys - {"namespace"}}), "TLS independently bound inputs differ")
    namespace = closed_object(supplied["namespace"], set(original) | {"netns", "mntns"}, "TLS namespace fields differ")
    require(same_compile_json({key: namespace[key] for key in original}, original), "TLS original namespace/user changed")
    for key, parent, kind in (("netns", "parentNetns", "net"), ("mntns", "parentMntns", "mnt")):
        require(all(type(namespace[item]) is str and re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", namespace[item]) is not None
                    for item in (key, parent)) and namespace[key] != namespace[parent], "TLS namespace was not distinct")
    require(type(receipt["cases"]) is list and len(receipt["cases"]) == len(GITHUB_TLS_CASES), "TLS nine-case roster differs")
    for name, supplied_case in zip(GITHUB_TLS_CASES, receipt["cases"], strict=True):
        case = closed_object(supplied_case, {"case", "passed", "failureCode", "elapsedMs", "coreMode", "trustFixture", "product", "peer"},
                             "TLS case fields differ")
        require(same_compile_json({key: case[key] for key in ("case", "passed", "failureCode", "coreMode", "trustFixture")},
                    {"case": name, "passed": True, "failureCode": None, "coreMode": "zip" if name == "T1-zip" else "source",
                     "trustFixture": "other-root-ca.pem" if name == "T2-root" else "root-ca.pem"})
                and integer_between(case["elapsedMs"], 0, 300000), "TLS case order, trust or original endpoint differs")
        product = closed_object(case["product"], {"settled", "projectionChecked", "reason", "registeredOwners", "disabled", "owners"},
                                "TLS product observation fields differ")
        reason = "none" if name in {"T1-source", "T1-zip", "T3-clean"} else "response-invalid" if name in {"T3-length", "T3-chunk"} else "tls-failed"
        require(same_compile_json({key: product[key] for key in product if key != "owners"},
                {"settled": True, "projectionChecked": True, "reason": reason, "registeredOwners": 0, "disabled": False})
                and type(product["owners"]) is list and len(product["owners"]) == 1, "TLS typed projection or owner finality differs")
        owner = closed_object(product["owners"][0], {"id", "profile", "terminal", "unknownLatched", "permitRetained",
                                                     "observerJoined", "firstError", "native"}, "TLS original owner fields differ")
        require(same_compile_json({key: owner[key] for key in owner if key != "native"},
                {"id": "github-read-1", "profile": "github-readonly", "terminal": True, "unknownLatched": False,
                 "permitRetained": False, "observerJoined": True, "firstError": None}), "TLS original owner was not completely settled")
        _validate_github_readonly_native(owner["native"], name, "github-readonly")
        peer = closed_object(case["peer"], {"acquisitionJoined", "spawned", "waited", "exitCode", "exitSuccess", "stopAttempted",
            "stdoutJoined", "stderrJoined", "stdoutEof", "stderrEof", "stdoutBytes", "stderrBytes", "stdoutOverflow",
            "stderrOverflow", "ready", "settled", "withinEndpoint", "protocolChecked", "terminal"}, "TLS original peer fields differ")
        required = {key: True for key in ("acquisitionJoined", "spawned", "waited", "exitSuccess", "stdoutJoined", "stderrJoined",
                                         "stdoutEof", "stderrEof", "ready", "settled", "withinEndpoint", "protocolChecked")}
        required.update(exitCode=0, stopAttempted=False, stdoutOverflow=False, stderrOverflow=False, stderrBytes=0)
        require(same_compile_json({key: peer[key] for key in required}, required)
                and integer_between(peer["stdoutBytes"], 1, 8192), "TLS original peer wait/reader/finality differs")
        validate_github_tls_peer(peer["terminal"], name)
    require(len(canonical_json(receipt)) <= 128 * 1024, "TLS receipt exceeds its byte bound")
    return receipt


def parse_github_tls_receipt(raw: bytes, *, bindings: dict) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= 128 * 1024, "TLS receipt bytes differ or exceed their bound")
    return validate_github_tls_receipt(bounded_json(raw, 128 * 1024), bindings=bindings)


def github_tls_compile_record(context: dict, argv: list[str], messages: Path) -> dict:
    ordinary(messages)
    require(0 < messages.stat().st_size <= 16 * 1024 * 1024, "TLS compiler output exceeds its bound")
    with messages.open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    root = Path(context["root"])
    path = github_compiled_test(raw, source=Path(context["source"]), target_root=root / "target")
    value = {"schemaVersion": 1, "scope": GITHUB_TLS_SCOPE,
             **{key: context[key] for key in ("sourceSha", "sourceTree", "tlsInputsSha256")},
             "path": str(path), **github_artifact_identity(path, root),
             "invocationSha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
             "messagesSha256": hashlib.sha256(raw).hexdigest()}
    write_json(root / "github-tls-compiled-test.json", value)
    return value


def github_tls_original_artifact(context: dict) -> dict:
    root = Path(context["root"])
    value = closed_object(read_bounded_json(root / "github-tls-compiled-test.json", 16384),
        {"schemaVersion", "scope", "sourceSha", "sourceTree", "tlsInputsSha256", "path", "identity", "size",
         "sha256", "invocationSha256", "messagesSha256"}, "TLS original compile record differs")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == GITHUB_TLS_SCOPE
            and all(value[key] == context[key] for key in ("sourceSha", "sourceTree", "tlsInputsSha256"))
            and sha256_value(value["invocationSha256"]) and sha256_value(value["messagesSha256"]),
            "TLS original compiler source/input anchor differs")
    path = github_executable_path(value["path"], target_root=root / "target")
    require(same_compile_json({key: value[key] for key in ("identity", "size", "sha256")}, github_artifact_identity(path, root)),
            "TLS original compiled artifact changed")
    return value


def github_tls_compiled_public(compiled: dict) -> dict:
    return {**{key: compiled[key] for key in ("size", "sha256", "invocationSha256", "messagesSha256")},
            "identitySha256": hashlib.sha256(canonical_json(compiled["identity"])).hexdigest()}


def github_tls_expected_bindings(context: dict, compiled: dict, manifest: dict) -> dict:
    return {**{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256")},
            "artifactSha256": compiled["sha256"], "artifactBytes": compiled["size"],
            "coreZipSha256": context["tlsInputs"]["coreZipSha256"], "pythonSha256": context["tlsInputs"]["pythonSha256"],
            "namespace": {key: manifest[key] for key in ("parentNetns", "parentMntns", "uid", "gid")}}


def github_tls_launch_argv(context: dict, compiled: dict, manifest: dict) -> list[str]:
    """Exactly the original artifact through the fixed namespace entry; no shell command string."""
    require(context.get("executionScope") == GITHUB_TLS_SCOPE and context.get("platform") == "linux",
            "Wrong TLS namespace launch scope")
    return ["/usr/bin/sudo", "-n", "--", "/usr/bin/unshare", "--mount", "--net", "--",
            "/usr/bin/env", "-i", "LANG=C", "LC_ALL=C", "/usr/bin/bash", "--noprofile", "--norc",
            str(Path(context["source"]) / GITHUB_TLS_FIXTURES / "github_tls_namespace.sh"),
            context["source"], context["root"], compiled["path"], context["python"],
            str(manifest["uid"]), str(manifest["gid"]), manifest["parentNetns"], manifest["parentMntns"],
            context["tlsInputsSha256"], compiled["sha256"], str(compiled["size"]), context["sourceSha"]]


def github_tls_outer_limits() -> None:
    # Fixed child-only POSIX envelope, not a hostile-code sandbox or VM disposal.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))


def github_tls_outer_base(context: dict, compiled: dict) -> dict:
    return {"schemaVersion": 1, "scope": "github-readonly-tls-original-outer-v1",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256")},
            "artifactSha256": compiled["sha256"], "artifactBytes": compiled["size"],
            "artifactIdentitySha256": hashlib.sha256(canonical_json(compiled["identity"])).hexdigest()}


def github_tls_run_outer(context: dict, compiled: dict) -> dict:
    """Only this original CompletedProcess supplies an outer-wait observation.

    Timeout/OSError/nonzero return spends the claim and never permits clean.
    subprocess.run owns its original launcher handle; no PID lookup/adoption or
    assertion from the inner fixture substitutes for the actual returned wait.
    """
    root = Path(context["root"])
    manifest = read_bounded_json(root / "github-tls-inputs.json", 1024 * 1024)
    destination = root / "github-tls-outer.json"
    require(not os.path.lexists(destination), "TLS outer attempt was already recorded")
    value = {**github_tls_outer_base(context, compiled), "status": "unknown", "waitObserved": False,
             "exitCode": None, "timedOut": False, "elapsedMs": 0, "stdoutBytes": None, "stderrBytes": None}
    start = time.monotonic()
    with (root / "github-tls.stdout").open("x", encoding="utf-8") as output, \
            (root / "github-tls.stderr").open("x", encoding="utf-8") as diagnostics:
        try:
            original = subprocess.run(github_tls_launch_argv(context, compiled, manifest), cwd=root,
                env=clean_environment(root), stdin=subprocess.DEVNULL, stdout=output, stderr=diagnostics,
                check=False, timeout=300, preexec_fn=github_tls_outer_limits)
        except subprocess.TimeoutExpired:
            value["timedOut"] = True
        except (OSError, subprocess.SubprocessError):
            pass
        else:
            require(type(original.returncode) is int, "TLS original outer return differs")
            value.update(status="passed" if original.returncode == 0 else "failed",
                         waitObserved=True, exitCode=original.returncode)
    value["elapsedMs"] = max(0, int((time.monotonic() - start) * 1000))
    if value["waitObserved"]:
        value.update(stdoutBytes=(root / "github-tls.stdout").stat().st_size,
                     stderrBytes=(root / "github-tls.stderr").stat().st_size)
    write_json(destination, value)  # Exclusive original record, never overwritten by a receipt projection.
    validate_github_tls_outer(value, context=context, compiled=compiled)
    return value


def validate_github_tls_outer(value: object, *, context: dict, compiled: dict) -> dict:
    base = github_tls_outer_base(context, compiled)
    closed_object(value, set(base) | {"status", "waitObserved", "exitCode", "timedOut", "elapsedMs", "stdoutBytes", "stderrBytes"},
                  "TLS original outer receipt fields differ")
    require(same_compile_json({key: value[key] for key in base}, base)
            and value["status"] == "passed" and value["waitObserved"] is True
            and type(value["exitCode"]) is int and value["exitCode"] == 0 and value["timedOut"] is False
            and integer_between(value["elapsedMs"], 0, 300000)
            and all(integer_between(value[key], 0, 1024 * 1024) for key in ("stdoutBytes", "stderrBytes")),
            "TLS original outer wait failed, was unknown, or changed")
    return value


def github_tls_result(context: dict) -> dict:
    root = Path(context["root"])
    compiled = github_tls_original_artifact(context)
    manifest = read_bounded_json(root / "github-tls-inputs.json", 1024 * 1024)
    raw = read_bounded_json(root / "github-tls/receipt.json", 128 * 1024)
    validate_github_tls_receipt(raw, bindings=github_tls_expected_bindings(context, compiled, manifest))
    outer = validate_github_tls_outer(read_bounded_json(root / "github-tls-outer.json", 16384), context=context, compiled=compiled)
    return {"nativeReceiptSha256": hash_file(root / "github-tls/receipt.json"), "outer": outer}


def github_tls_phase_claim(context: dict, name: str) -> dict:
    return {"scope": GITHUB_TLS_SCOPE, "phase": name,
            **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowSha256", "runId", "attempt", "tlsInputsSha256")}}


def github_tls_phase_value(context: dict, name: str, checks: list[str]) -> dict:
    require(name in GITHUB_TLS_CHECKS and context.get("executionScope") == GITHUB_TLS_SCOPE, "Unknown TLS phase receipt")
    value = {"schemaVersion": 1, "scope": GITHUB_TLS_EVIDENCE_SCOPE, "phase": name, "status": "passed",
             **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                            "workflowRef", "workflowSha256", "runId", "attempt", "tlsInputsSha256")},
             "inputSha256": hashlib.sha256(canonical_json(context["tlsInputs"])).hexdigest(),
             "rust": {"release": RUST, "target": TARGETS["linux"]},
             "checks": [{"check": check, "exitCode": 0} for check in checks]}
    if name in {"compile", "github-tls"}:
        value["compiledTest"] = github_tls_compiled_public(github_tls_original_artifact(context))
    if name == "github-tls":
        value.update(github_tls_result(context))
    return value


def validate_github_tls_phase_receipt(value: object, context: dict, name: str) -> dict:
    require(name in GITHUB_TLS_CHECKS and context.get("executionScope") == GITHUB_TLS_SCOPE,
            "Unexpected TLS receipt scope or phase")
    require(same_compile_json(value, github_tls_phase_value(context, name, list(GITHUB_TLS_CHECKS[name]))),
            "TLS original phase receipt is incomplete or changed")
    return value


def github_tls_predecessors(context: dict, name: str) -> None:
    require(context.get("executionScope") == GITHUB_TLS_SCOPE and name in (*GITHUB_TLS_CHECKS, "clean"),
            "Unknown TLS successor or scope")
    phases, root = list(GITHUB_TLS_CHECKS), Path(context["root"])
    previous = phases if name == "clean" else phases[:phases.index(name)]
    for prior in previous:
        require(same_compile_json(read_bounded_json(root / f"{prior}-started.json", 4096), github_tls_phase_claim(context, prior)),
                "TLS original phase claim differs")
        validate_github_tls_phase_receipt(read_bounded_json(root / f"{prior}-checks.json", 32768), context, prior)
    for later in (*phases[len(previous):], "clean"):
        for suffix in ("started", "checks"):
            require(not os.path.lexists(root / f"{later}-{suffix}.json"), "TLS phase already claimed; retain outputs")
    if name == "github-tls":
        require(not os.path.lexists(root / "github-tls-outer.json")
                and not os.path.lexists(root / "github-tls/receipt.json"), "TLS original native attempt already has output")


def phase_github_tls(name: str, context: dict) -> None:
    require(context.get("executionScope") == GITHUB_TLS_SCOPE and context.get("platform") == "linux", "Wrong TLS phase scope")
    admit_phase(GITHUB_TLS_SCOPE, name)
    require(name != "prepare", "TLS preparation has a separate fixed entry")
    if name == "clean":
        clean_github_tls(context)
        return
    github_tls_predecessors(context, name)
    root, source = Path(context["root"]), Path(context["source"])
    write_json(root / f"{name}-started.json", github_tls_phase_claim(context, name))
    github_tls_source_unchanged(context)
    no_cargo_configuration((root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents))
    environment = clean_environment(root)
    environment.update(GITHUB_SHA=context["sourceSha"], MRK_GITHUB_TLS_INPUTS_SHA256=context["tlsInputsSha256"])
    manifest = source / "desktop/src-tauri/Cargo.toml"
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        with (root / "cargo-metadata.json").open("x", encoding="utf-8") as output, \
                (root / "acquire.stderr").open("x", encoding="utf-8") as diagnostics:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", "development-runtime", "--filter-platform", TARGETS["linux"], "--manifest-path", str(manifest)],
                check="github-tls-locked-headless-metadata", cwd=root, env=environment, timeout=600, output=output, diagnostics=diagnostics)
    elif name == "compile":
        cargo, _ = tools(context, environment)
        argv = [cargo, "test", "--locked", "--offline", "--jobs", "1", "--no-default-features", "--features", "development-runtime",
                "--target", TARGETS["linux"], "--manifest-path", str(manifest), "--target-dir", str(root / "target"),
                "--lib", "--no-run", "--message-format=json"]
        messages = root / "github-tls-compile-messages.jsonl"
        with messages.open("x", encoding="utf-8", newline="\n") as output, \
                (root / "compile.stderr").open("x", encoding="utf-8") as diagnostics:
            run(argv, check="github-tls-headless-test-compile-only", cwd=root, env=environment, timeout=600,
                output=output, diagnostics=diagnostics)
        github_tls_compile_record(context, argv, messages)
    else:
        require(name == "github-tls", "Unknown TLS native phase")
        compiled = github_tls_original_artifact(context)
        github_tls_run_outer(context, compiled)
        github_tls_result(context)  # Both independent inner original owners AND the actual original outer wait.
    # No source/tool call or deletion follows a missing/unknown original result.
    github_tls_source_unchanged(context)
    phase_receipt(context, name, list(GITHUB_TLS_CHECKS[name]))


def clean_github_tls(context: dict) -> None:
    """Positive original finality only; finite no-follow deletion, no process scan.

    On failure retain all remaining names for disposable-host teardown. This is
    a cooperative, private job namespace, not an atomic unlink against a hostile
    same-user renamer. Unknown/new entries are never added to the deletion plan.
    """
    github_tls_predecessors(context, "clean")
    github_tls_inputs_unchanged(context)
    root = Path(context["root"])
    compiled = github_tls_compiled_public(github_tls_original_artifact(context))
    original_result = github_tls_result(context)
    write_json(root / "clean-started.json", github_tls_phase_claim(context, "clean"))
    private_files = ("core.zip", "gitconfig-empty", "cargo-metadata.json", "acquire.stderr",
                     "github-tls-compile-messages.jsonl", "compile.stderr", "github-tls-compiled-test.json",
                     "github-tls.stdout", "github-tls.stderr")
    evidence = ("context.json", "public-bindings.json", "clean-started.json",
                "github-tls-inputs.json", "github-tls-outer.json",
                *(f"{phase}-{suffix}.json" for phase in GITHUB_TLS_CHECKS for suffix in ("started", "checks")))
    require({path.name for path in root.iterdir()} == set((*GITHUB_TLS_DIRECTORIES, *private_files, *evidence)),
            "TLS task cleanup has missing or unexpected top-level entries; retain outputs")
    native = root / "github-tls"
    require({path.name for path in native.iterdir()} == {"receipt.json", *GITHUB_TLS_CASES},
            "TLS settled fixture inventory differs; retain outputs")
    original_root = root.lstat()
    directories = {root: original_root, native: native.lstat()}
    leaves, removals, total = [], [], 0
    pending = [(root / name, 0) for name in GITHUB_TLS_DIRECTORIES if name != "github-tls"]
    pending.extend((native / name, 0) for name in GITHUB_TLS_CASES)
    pending.extend((root / name, 0) for name in private_files)
    while pending:
        path, depth = pending.pop()
        info = path.lstat()
        require(depth <= 32 and len(leaves) + len(removals) < 100000
                and info.st_dev == original_root.st_dev and info.st_uid == os.geteuid(),
                "TLS cleanup crossed its original filesystem, owner or inventory bound")
        if stat.S_ISDIR(info.st_mode):
            directories[path] = info
            removals.append(path)
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(pending) + len(leaves) + len(removals) < 100000, "TLS cleanup inventory exceeds its bound")
                    pending.append((path / entry.name, depth + 1))
            require(github_cleanup_identity(path.lstat(), directory=True) == github_cleanup_identity(info, directory=True),
                    "TLS cleanup directory changed during inventory")
        else:
            require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode),
                    "TLS cleanup found an unexpected file kind; retain outputs")
            total += info.st_size
            require(total <= 8 * 1024 * 1024 * 1024, "TLS cleanup output size exceeds its bound")
            leaves.append((path, info))
    # The whole finite plan is admitted before the first unlink. Keep the
    # original parent identities, never follow a link or sweep a changed tree.
    removed_links: dict[tuple[int, int], int] = {}
    def parent_unchanged(path: Path) -> None:
        for parent in (path.parent, *path.parent.parents):
            if parent not in directories:
                break
            require(github_cleanup_identity(parent.lstat(), directory=True)
                    == github_cleanup_identity(directories[parent], directory=True), "TLS cleanup original parent changed")
            if parent == root:
                break
    for path, original_info in leaves:
        parent_unchanged(path)
        current, key = path.lstat(), (original_info.st_dev, original_info.st_ino)
        require(github_cleanup_identity(current) == github_cleanup_identity(original_info)
                and current.st_nlink == original_info.st_nlink - removed_links.get(key, 0), "TLS cleanup original leaf changed")
        path.unlink()  # A link is removed as a leaf; its target is never opened.
        removed_links[key] = removed_links.get(key, 0) + 1
    for path in sorted(removals, key=lambda item: len(item.parts), reverse=True):
        parent_unchanged(path)
        require(github_cleanup_identity(path.lstat(), directory=True)
                == github_cleanup_identity(directories[path], directory=True), "TLS cleanup original directory changed")
        path.rmdir()  # Unknown/new content fails closed rather than being swept.
    require({path.name for path in root.iterdir()} == {"github-tls", *evidence}
            and {path.name for path in native.iterdir()} == {"receipt.json"}, "TLS cleanup postcondition differs")
    write_json(root / "clean-checks.json", {
        "schemaVersion": 1, "scope": GITHUB_TLS_EVIDENCE_SCOPE, "phase": "clean", "status": "passed",
        **{key: context[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef",
                                       "workflowSha256", "runId", "attempt")},
        "allOriginalOwnersSettled": True, "allOriginalPeersSettled": True, "observerJoinsComplete": True,
        "originalOuterWaitObserved": True, "tlsInputsSha256": context["tlsInputsSha256"],
        "compiledTest": compiled, **original_result,
        "removedFiles": len(leaves), "removedDirectories": len(removals), "inventoriedBytes": total,
        "retained": ["redacted-evidence", "private-original-context", "private-tls-input-manifest", "private-original-outer-receipt"], "productionQualified": False,
    })
    print("Removed only positively settled TLS compiler and fixture outputs; original evidence retained.")


def phase_receipt(context: dict, name: str, checks: list[str], *, node: str | None = None,
                  scope: str = "passive-development-foundation-only", compiled: dict | None = None) -> None:
    # Only called after the fixed phase and final source check actually succeed.
    # Missing files on failed/skipped phases cannot become passing evidence.
    value = {
        "schemaVersion": 1, "scope": scope, "phase": name,
        "status": "passed", "sourceSha": context["sourceSha"], "platform": context["platform"],
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": node,
        "checks": [{"check": check, "exitCode": 0} for check in checks],
    }
    if compiled is not None:
        require(context.get("executionScope") == WINDOWS_SNAPSHOT_SCOPE
                and context.get("scope") == WINDOWS_SNAPSHOT_SCOPE and name == "compile"
                and scope == WINDOWS_SNAPSHOT_PUBLIC_SCOPE and node is None,
                "Unexpected compiler artifact receipt")
        value["compiledTest"] = {"sha256": compiled["sha256"], "size": compiled["size"],
                                 "invocationSha256": compiled["invocationSha256"]}
    if context.get("executionScope") in COMPILE_PROFILES:
        profile = compile_profile(context["executionScope"])
        require(name in profile["checks"] and scope == "passive-development-foundation-only",
                "Compiler-only phase cannot produce native evidence")
        value.update(scope=profile["evidence"],
                     **{key: context[key] for key in ("workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")})
        if context["executionScope"] == GTK_COMPILE_SCOPE:
            value.update(sourceTree=context["sourceTree"], sg1=context["sg1"])
        validate_compile_receipt(value, context, name)
    elif context.get("executionScope") == WORKFLOW_NATIVE_SCOPE:
        require(node is None and scope == "passive-development-foundation-only",
                "Workflow-only phase cannot produce compiler or product authority")
        value = workflow_phase_value(context, name, checks)
        validate_workflow_phase_receipt(value, context, name)
    elif context.get("executionScope") == GITHUB_READONLY_SCOPE:
        require(node is None and scope == "passive-development-foundation-only" and compiled is None,
                "G1 phase cannot produce other native or product authority")
        value = github_phase_value(context, name, checks)
        validate_github_phase_receipt(value, context, name)
    elif context.get("executionScope") == GITHUB_TLS_SCOPE:
        require(node is None and scope == "passive-development-foundation-only" and compiled is None,
                "TLS phase cannot produce another lane's authority")
        value = github_tls_phase_value(context, name, checks)
        validate_github_tls_phase_receipt(value, context, name)
    write_json(Path(context["root"]) / f"{name}-checks.json", value)


def prepare_workflow_native_context(context: dict, inventory: list[dict]) -> None:
    root, source = Path(context["root"]), Path(context["source"])
    context["workflowInputs"] = {"sourceFiles": workflow_source_files(source), "coreFiles": inventory,
                                 "coreZipSha256": hash_file(root / "core.zip"), "pythonSha256": hash_file(Path(context["python"]))}
    context["originalDirectories"] = {"root": workflow_directory_identity(root), "source": workflow_directory_identity(source),
                                      **{name: workflow_directory_identity(root / name) for name in WORKFLOW_NATIVE_DIRECTORIES}}
    context["observedHost"] = workflow_host(root)
    require(hash_file(source / WORKFLOW_CORE_SOURCES["resource"]) == WORKFLOW_PAYLOAD_BINDINGS["templateSet"]["resourceSha256"],
            "Workflow canonical template resource differs")
    # This native-only metadata is the original bounded ZIP binding, NOT Cargo
    # metadata. Existing compiler/configuration scopes keep their old filename.
    write_json(root / "metadata.json", workflow_core_metadata(context))
    workflow_source_unchanged(context)


def workflow_public_bindings(context: dict) -> dict:
    return {"schemaVersion": 1, "scope": WORKFLOW_NATIVE_EVIDENCE_SCOPE,
            **{name: context[name] for name in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                               "workflowRef", "workflowSha256", "runId", "attempt", "workflowInputs")},
            "python": PYTHON, "rust": {"release": RUST, "target": TARGETS["linux"]},
            "features": ["development-runtime"], "testTarget": "lib", "host": context["observedHost"],
            "payloadBindings": WORKFLOW_PAYLOAD_BINDINGS, "notVerified": list(WORKFLOW_NOT_VERIFIED)}


def prepare(platform: str, scope: str = BOUNDARY_SCOPE) -> None:
    admit_phase(scope, "prepare")
    admit_platform(scope, platform)
    windows = scope == WINDOWS_SNAPSHOT_SCOPE
    if windows:
        require(admitted_scope(platform) == scope, "Windows preparation scope differs")
    profile = compile_profile(scope) if scope in COMPILE_PROFILES else None
    native_workflow = scope == WORKFLOW_NATIVE_SCOPE
    native_github = scope == GITHUB_READONLY_SCOPE
    native_tls = scope == GITHUB_TLS_SCOPE
    binding = (compile_workflow_binding(os.environ, scope) if profile else workflow_native_binding(os.environ)
               if native_workflow else github_readonly_binding(os.environ) if native_github
               else github_tls_binding(os.environ) if native_tls else {})
    source = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    sha = os.environ["GITHUB_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "Invalid source SHA")
    for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/target", "desktop/src-tauri/gen"):
        require(not (source / relative).exists() and not (source / relative).is_symlink(),
                "Fresh checkout contains an existing generated output")
    no_cargo_configuration((source / "desktop/src-tauri", source / "desktop", source, *source.parents,
                            temp, *temp.parents))
    for ancestor in (source / "desktop", source, *source.parents):
        require(not (ancestor / ".npmrc").exists(), "Ambient npm project configuration is not admitted")
    if native_workflow or native_github or native_tls:
        # One original root per actual job attempt. A second prepare must not
        # mint a fresh path to evade a failed/Unknown phase's retained claims.
        label = "github-tls" if native_tls else "github" if native_github else "workflow"
        root = temp / f"mrk-desktop-foundation-{label}-{binding['runId']}-{binding['attempt']}"
        root.mkdir(mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix="mrk-desktop-foundation-", dir=temp))
    no_cargo_configuration((root,))
    directories = GITHUB_TLS_DIRECTORIES if native_tls else GITHUB_READONLY_DIRECTORIES if native_github else WORKFLOW_NATIVE_DIRECTORIES if native_workflow else (
        "home", "cargo", "rustup", "tmp", "target", "windows-snapshot", "appdata", "localappdata") if windows else (
        "home", "cargo", "rustup", "tmp", "target", "native", "config-owner", "config-driver-loss", "config-watchdog-loss",
        "config-stop", "config-terminal-deadline", "config-startup-stop", "config-transaction-eof", "appdata", "localappdata", "npm-cache")
    for name in directories:
        (root / name).mkdir(mode=0o700)
    empty_files = ("gitconfig-empty",) if native_workflow or native_github or native_tls or windows else ("npmrc-user", "npmrc-global", "gitconfig-empty")
    for name in empty_files:
        (root / name).touch(mode=0o600, exist_ok=False)
    git = shutil.which("git")
    rustup = shutil.which("rustup")
    require(git is not None and rustup is not None, "Hosted compiler tools unavailable")
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment, timeout=15, capture=True) == sha,
            "Event and checkout source differ")
    tree = run([git, "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=source, env=environment, timeout=15, capture=True)
    if native_workflow or native_github or native_tls:
        require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None and tree != "0" * 40,
                "Workflow native source tree differs")
    inventory = []
    total = 0
    package = source / "src/mobile_release"
    input_paths = sorted(package.rglob("*"), key=(lambda path: path.as_posix()) if native_workflow or native_github or native_tls else None)
    with zipfile.ZipFile(root / "core.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in input_paths:
            require(not path.is_symlink(), "Core input contains a symbolic link")
            if path.is_dir():
                continue
            ordinary(path)
            require(path.suffix in {".py", ".json", ".pem"}, "Unexpected/generated core input")
            require(len(inventory) < 2048 and path.stat().st_size <= 8 * 1024 * 1024, "Core input bound exceeded")
            data = path.read_bytes()
            total += len(data)
            require(total <= 32 * 1024 * 1024, "Core aggregate bound exceeded")
            name = path.relative_to(source / "src").as_posix()
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED)
            inventory.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    context = {"root": str(root), "source": str(source), "sourceSha": sha, "sourceTree": tree, "platform": platform,
               "executionScope": scope,
               "runId": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "git": git, "rustup": rustup, "python": str(Path(sys.executable).resolve(strict=True))}
    context.update(binding)
    if windows:
        context.update(scope=scope, event=os.environ["GITHUB_EVENT_NAME"], ref=os.environ["GITHUB_REF"])
    workflow = (profile["workflow"] if profile else WORKFLOW_NATIVE_WORKFLOW if native_workflow
                else GITHUB_READONLY_WORKFLOW if native_github else GITHUB_TLS_WORKFLOW if native_tls
                else ".github/workflows/desktop-foundation.yml")
    if profile or native_workflow or native_github or native_tls:
        context["workflowSha256"] = hash_file(source / workflow)
    if scope == GTK_COMPILE_SCOPE:
        validate_gtk_core_inventory(inventory)
        context["sg1"] = gtk_compile_binding(source)
    if native_workflow:
        prepare_workflow_native_context(context, inventory)
    elif native_github:
        prepare_github_readonly_context(context, inventory)
    elif native_tls:
        prepare_github_tls_context(context, inventory)
    source_unchanged(context)
    if not windows:
        write_json(root / "context.json", context)
    if native_workflow:
        public = workflow_public_bindings(context)
    elif native_github:
        public = github_public_bindings(context)
    elif native_tls:
        public = github_tls_public_bindings(context)
    else:
        public = {
            "scope": profile["evidence"] if profile else WINDOWS_SNAPSHOT_PUBLIC_SCOPE if windows else "passive-development-foundation-only", "sourceSha": sha, "sourceTree": tree,
            "workflowSha256": hash_file(source / workflow),
            "runId": context["runId"], "attempt": context["attempt"], "platform": platform,
            "image": os.environ.get("ImageOS", "") + "/" + os.environ.get("ImageVersion", ""),
            # Version only (never hostname): future kernel-bound runtime admission
            # must use actual native observations, not infer a kernel from ImageOS.
            "kernelRelease": os.uname().release if platform in {"linux", "macos"} else None,
            "architecture": os.environ["RUNNER_ARCH"], "python": PYTHON, "expectedRust": RUST,
            "coreZipSha256": hash_file(root / "core.zip"), "coreFiles": inventory,
            "bootstrapSha256": hash_file(source / "desktop/engine_bootstrap.py"),
            "cargoLockSha256": hash_file(source / "desktop/src-tauri/Cargo.lock"),
            "npmLockSha256": hash_file(source / "desktop/package-lock.json"),
            "configBootstrapSha256": hash_file(source / "desktop/config_edit_bootstrap.py"),
            "configFixtureSha256": hash_file(source / "tests/native_desktop_config.py"),
            "configOwnerFixtureSha256": hash_file(source / "desktop/src-tauri/src/edit_hosted_tests.rs"),
            "notQualified": ["production-runtime", "native-GUI", "native-document-lifecycle", "configuration-saving",
                             "Windows-filesystem", "installers", "release-operations"],
        }
    if profile:
        public.update(binding)
        public["notQualified"].append("test-execution")
    if scope == GTK_COMPILE_SCOPE:
        public["sg1"] = context["sg1"]
        public["notQualified"].extend(("SG1-native-qualification", "installed-API-loader-writer-admission"))
    if windows:
        windows_prepare_bindings(context, public)
        write_json(root / "context.json", context)
    write_json(root / "public-bindings.json", public)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"root={root}\n")
    print("Prepared bounded source ZIP and source-bound synthetic check inputs.")


def load_context(platform: str, scope: str = BOUNDARY_SCOPE) -> dict:
    admit_platform(scope, platform)
    if scope == WINDOWS_SNAPSHOT_SCOPE:
        require(admitted_scope(platform) == scope, "Windows context scope differs")
    root = Path(os.environ["MRK_DESKTOP_CI_ROOT"])
    require(root.is_absolute() and root.name.startswith("mrk-desktop-foundation-")
            and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and not root.is_symlink(), "Unrecognized task root")
    ordinary(root / "context.json")
    context = (read_bounded_json(root / "context.json", 256 * 1024) if scope in {GITHUB_READONLY_SCOPE, GITHUB_TLS_SCOPE}
               else workflow_json(root / "context.json") if scope == WORKFLOW_NATIVE_SCOPE
               else json.loads((root / "context.json").read_text(encoding="utf-8")))
    require(context["root"] == str(root) and context["platform"] == platform and context.get("executionScope") == scope
            and context["sourceSha"] == os.environ["GITHUB_SHA"]
            and context["runId"] == os.environ["GITHUB_RUN_ID"]
            and context["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Task context differs")
    if scope == WINDOWS_SNAPSHOT_SCOPE:
        require(context.get("scope") == scope and context.get("event") == os.environ["GITHUB_EVENT_NAME"]
                and context.get("ref") == os.environ["GITHUB_REF"], "Windows task event binding differs")
    if scope in COMPILE_PROFILES:
        profile = compile_profile(scope)
        binding = compile_workflow_binding(os.environ, scope)
        require(all(context.get(key) == value for key, value in binding.items())
                and context.get("workflowSha256") == hash_file(Path(context["source"]) / profile["workflow"]),
                "Compiler task workflow binding changed")
        if scope == GTK_COMPILE_SCOPE:
            require(type(context.get("sourceTree")) is str
                    and re.fullmatch(r"[0-9a-f]{40}", context["sourceTree"]) is not None
                    and context.get("sg1") == gtk_compile_binding(Path(context["source"])),
                    "SG1 compiler source binding changed")
    elif scope == WORKFLOW_NATIVE_SCOPE:
        binding = workflow_native_binding(os.environ)
        require(type(context) is dict and all(context.get(key) == value for key, value in binding.items())
                and root.name == f"mrk-desktop-foundation-workflow-{binding['runId']}-{binding['attempt']}"
                and context.get("source") == str(Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True))
                and context.get("python") == str(Path(sys.executable).resolve(strict=True))
                and type(context.get("sourceTree")) is str and re.fullmatch(r"[0-9a-f]{40}", context["sourceTree"]) is not None
                and context["sourceTree"] != "0" * 40
                and context.get("workflowSha256") == hash_file(Path(context["source"]) / WORKFLOW_NATIVE_WORKFLOW),
                "Workflow native context/source binding changed")
        validate_workflow_host(context.get("observedHost"))
        workflow_inputs_unchanged(context)
        require(same_compile_json(workflow_json(root / "public-bindings.json"), workflow_public_bindings(context)),
                "Workflow native public source binding changed")
    elif scope == GITHUB_READONLY_SCOPE:
        binding = github_readonly_binding(os.environ)
        require(type(context) is dict and all(context.get(key) == value for key, value in binding.items())
                and root.name == f"mrk-desktop-foundation-github-{binding['runId']}-{binding['attempt']}"
                and context.get("source") == str(Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True))
                and context.get("python") == str(Path(sys.executable).resolve(strict=True))
                and type(context.get("sourceTree")) is str and re.fullmatch(r"[0-9a-f]{40}", context["sourceTree"]) is not None
                and context["sourceTree"] != "0" * 40
                and context.get("workflowSha256") == hash_file(Path(context["source"]) / GITHUB_READONLY_WORKFLOW),
                "G1 context/source binding changed")
        validate_workflow_host(context.get("observedHost"))
        github_inputs_unchanged(context)
        require(same_compile_json(read_bounded_json(root / "public-bindings.json", 256 * 1024), github_public_bindings(context)),
                "G1 public source binding changed")
    elif scope == GITHUB_TLS_SCOPE:
        binding = github_tls_binding(os.environ)
        require(type(context) is dict and all(context.get(key) == value for key, value in binding.items())
                and root.name == f"mrk-desktop-foundation-github-tls-{binding['runId']}-{binding['attempt']}"
                and context.get("source") == str(Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True))
                and context.get("python") == str(Path(sys.executable).resolve(strict=True))
                and type(context.get("sourceTree")) is str and re.fullmatch(r"[0-9a-f]{40}", context["sourceTree"]) is not None
                and context["sourceTree"] != "0" * 40
                and context.get("workflowSha256") == hash_file(Path(context["source"]) / GITHUB_TLS_WORKFLOW),
                "TLS context/source binding changed")
        validate_workflow_host(context.get("observedHost"))
        github_tls_inputs_unchanged(context)
        require(same_compile_json(read_bounded_json(root / "public-bindings.json", 256 * 1024), github_tls_public_bindings(context)),
                "TLS public source binding changed")
    return context


def tools(context: dict, environment: dict[str, str]) -> tuple[str, str]:
    root = Path(context["root"])
    cargo = run([context["rustup"], "which", "--toolchain", RUST, "cargo"], cwd=root,
                check="cargo-selection", env=environment, timeout=15, capture=True)
    rustc = run([context["rustup"], "which", "--toolchain", RUST, "rustc"], cwd=root,
                check="rustc-selection", env=environment, timeout=15, capture=True)
    require(all(Path(value).is_absolute() and Path(value).is_file() for value in (cargo, rustc)),
            "Selected compiler paths unavailable")
    version = run([rustc, "-vV"], check="rust-version-target", cwd=root, env=environment, timeout=15, capture=True)
    require(f"release: {RUST}\n" in version + "\n"
            and f"host: {TARGETS[context['platform']]}\n" in version + "\n", "Compiler host/version differs")
    environment["RUSTC"] = rustc
    environment["PATH"] = str(Path(cargo).parent) + os.pathsep + environment["PATH"]
    return cargo, rustc


def workflow_phase_value(context: dict, name: str, checks: list[str]) -> dict:
    require(context.get("executionScope") == WORKFLOW_NATIVE_SCOPE and context.get("platform") == "linux"
            and name in WORKFLOW_NATIVE_CHECKS, "Unexpected workflow-only phase receipt")
    return {"schemaVersion": 1, "scope": WORKFLOW_NATIVE_EVIDENCE_SCOPE, "phase": name, "status": "passed",
            **{key: context[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                            "workflowRef", "workflowSha256", "runId", "attempt", "workflowInputs")},
            "rust": {"release": RUST, "target": TARGETS["linux"]}, "python": PYTHON,
            "features": ["development-runtime"], "testTarget": "lib",
            "checks": [{"check": check, "exitCode": 0} for check in checks],
            "notVerified": list(WORKFLOW_NOT_VERIFIED)}


def validate_workflow_phase_receipt(value: object, context: dict, name: str) -> dict:
    require(name in WORKFLOW_NATIVE_CHECKS and context.get("workflowPath") == WORKFLOW_NATIVE_WORKFLOW,
            "Workflow phase or source workflow differs")
    expected = workflow_phase_value(context, name, list(WORKFLOW_NATIVE_CHECKS[name]))
    require(same_compile_json(value, expected), "Workflow phase receipt or original source/check inventory differs")
    return value


def workflow_core_receipt(context: dict, partition: str) -> dict:
    require(partition in WORKFLOW_PARTITIONS, "Unknown workflow core partition")
    source = Path(context["source"])
    return validate_workflow_core_receipt(workflow_json(Path(context["root"]) / f"workflow-{partition}.json"), partition,
        source_sha=context["sourceSha"], source_hashes={name: hash_file(source / relative) for name, relative in WORKFLOW_CORE_SOURCES.items()},
        python_hash=context["workflowInputs"]["pythonSha256"], host=context["observedHost"])


def workflow_predecessors(context: dict, name: str) -> None:
    """No new original process until every earlier exact proof was consumed.

    Expected effect-Unknown is accepted only in its fixed invocation-last row,
    with distinct positive original-resource facts; never as ordinary success.
    """
    require(name in (*WORKFLOW_NATIVE_CHECKS, "clean"), "Unknown workflow successor")
    phases = list(WORKFLOW_NATIVE_CHECKS)
    previous = phases if name == "clean" else phases[:phases.index(name)]
    root = Path(context["root"])
    for prior in previous:
        expected_claim = {"scope": WORKFLOW_NATIVE_SCOPE, "phase": prior,
                          **{key: context[key] for key in ("sourceSha", "runId", "attempt")}}
        require(same_compile_json(workflow_json(root / f"{prior}-started.json"), expected_claim), "Workflow original phase claim differs")
        validate_workflow_phase_receipt(workflow_json(root / f"{prior}-checks.json"), context, prior)
        if prior == "workflow-owner":
            workflow_owner_receipt(context, "source")
            workflow_owner_receipt(context, "zip")
        elif prior == "workflow-transaction-eof":
            workflow_transaction_eof_receipt(context)
        elif prior == "workflow-core":
            for partition in WORKFLOW_PARTITIONS:
                workflow_core_receipt(context, partition)
    # A failed or completed phase is one-use. Neither a missing success receipt
    # nor a new helper interpreter authorizes a replay after uncertain work.
    for later in phases[len(previous):]:
        for suffix in ("started", "checks"):
            path = root / f"{later}-{suffix}.json"
            require(not path.exists() and not path.is_symlink(), "Workflow phase was already claimed; retain outputs")


def workflow_phase_start(context: dict, name: str) -> None:
    workflow_predecessors(context, name)
    write_json(Path(context["root"]) / f"{name}-started.json", {"scope": WORKFLOW_NATIVE_SCOPE, "phase": name,
               **{key: context[key] for key in ("sourceSha", "runId", "attempt")}})


def clean_workflow_native(context: dict) -> None:
    """Lane-last resource uncertainty licenses retention only, not deletion."""
    workflow_predecessors(context, "clean")
    workflow_inputs_unchanged(context)
    write_json(Path(context["root"]) / "retention-checks.json", {
        "schemaVersion": 1, "scope": WORKFLOW_NATIVE_EVIDENCE_SCOPE, "status": "retained",
        **{key: context[key] for key in ("sourceSha", "sourceTree", "runId", "attempt")},
        "reason": "lane-last-committed-close-resources-unknown", "deleted": False,
        "laterNativeWork": False, "projectProbes": False, "vmDisposalRequired": True,
    })
    print("Retained workflow roots and compiler/runtime outputs for hosted VM disposal; no native or product qualification.")


def phase_workflow_native(name: str, context: dict) -> None:
    """One fixed headless lane using the existing runner and original fixtures."""
    require(context.get("executionScope") == WORKFLOW_NATIVE_SCOPE and context.get("platform") == "linux",
            "Wrong workflow native scope")
    admit_phase(WORKFLOW_NATIVE_SCOPE, name)
    require(name != "prepare", "Workflow preparation has a separate fixed entry")
    if name == "clean":
        clean_workflow_native(context)  # DATA only; no tools after final Unknown.
        return
    workflow_phase_start(context, name)
    workflow_source_unchanged(context)
    root, source = Path(context["root"]), Path(context["source"])
    no_cargo_configuration((root, *root.parents, source / "desktop/src-tauri", source / "desktop", source, *source.parents))
    environment = clean_environment(root)
    environment["GITHUB_SHA"] = context["sourceSha"]
    manifest = source / "desktop/src-tauri/Cargo.toml"
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        with (root / "cargo-metadata.json").open("x", encoding="utf-8") as output:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", "development-runtime", "--filter-platform", TARGETS["linux"],
                 "--manifest-path", str(manifest)], check="workflow-locked-headless-metadata", cwd=root,
                env=environment, timeout=600, output=output)
        ordinary(root / "cargo-metadata.json")
        require(0 < (root / "cargo-metadata.json").stat().st_size <= 32 * 1024 * 1024, "Workflow compiler metadata exceeds its bound")
    elif name == "workflow-core":
        # No Cargo/compiler selection here. Every subprocess has its own fixed
        # root/interpreter. The ordinary effect-Unknown row is invocation-last;
        # the known committed-fsync control is positively resource-settled.
        environment.update(MRK_DESKTOP_WORKFLOW_NATIVE="1", MRK_DESKTOP_WORKFLOW_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                           GITHUB_WORKSPACE=str(source), RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        fixture = [context["python"], "-I", "-S", "-B", str(source / "tests/native_desktop_config.py"),
                   "--task-root", str(root), "--domain", "github_workflows", "--case"]
        with (root / "workflow-ordinary.json").open("x", encoding="utf-8") as output:
            run([*fixture, "ordinary"], check="workflow-core-ordinary", cwd=root, env=environment, timeout=90, output=output)
        workflow_core_receipt(context, "ordinary")
        workflow_inputs_unchanged(context)
        with (root / "workflow-committed-fsync.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-fsync"], check="workflow-core-committed-fsync", cwd=root, env=environment, timeout=45, output=output)
        workflow_core_receipt(context, "committed-fsync")
        workflow_source_unchanged(context)
        # Final native work of the entire lane. Even a zero interpreter exit or
        # actual injected close return does not undo the explicit Unknown fact.
        with (root / "workflow-committed-close.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-close"], check="workflow-core-committed-close", cwd=root, env=environment, timeout=45, output=output)
        workflow_core_receipt(context, "committed-close")
        workflow_inputs_unchanged(context)
        phase_receipt(context, name, list(WORKFLOW_NATIVE_CHECKS[name]))
        return
    else:
        cargo, _ = tools(context, environment)
        common = ["--locked", "--offline", "--jobs", "1", "--no-default-features", "--target", TARGETS["linux"],
                  "--manifest-path", str(manifest), "--target-dir", str(root / "target")]
        if name == "compile":
            run([cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"],
                check="headless-test-compile-only", cwd=root, env=environment, timeout=600)
        else:
            environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                               MRK_DESKTOP_WORKFLOW_HOSTED_CHECKS="github-workflows-v1", MRK_DESKTOP_WORKFLOW_INPUT="source",
                               MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"], GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                               RUNNER_OS="Linux", RUNNER_ARCH="X64", GITHUB_RUN_ID=context["runId"], GITHUB_RUN_ATTEMPT=context["attempt"],
                               GITHUB_REF=WORKFLOW_NATIVE_REF, RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
            if name == "workflow-owner":
                environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "workflow-owner-source")
                run([cargo, "test", *common, "--lib", "--features", "development-runtime", WORKFLOW_OWNER_TEST,
                     "--", "--exact", "--ignored", "--test-threads=1"], check="workflow-owner-source-native-contract",
                    cwd=root, env=environment, timeout=180)
                workflow_owner_receipt(context, "source")
                workflow_inputs_unchanged(context)
                # One fresh ZIP parity invocation, not a replay of the matrix.
                environment.update(MRK_DESKTOP_EDIT_TEST_ROOT=str(root / "workflow-owner-zip"),
                                   MRK_DESKTOP_DEV_CORE=str(root / "core.zip"), MRK_DESKTOP_WORKFLOW_INPUT="zip")
                run([cargo, "test", *common, "--lib", "--features", "development-runtime", WORKFLOW_OWNER_TEST,
                     "--", "--exact", "--ignored", "--test-threads=1"], check="workflow-owner-zip-native-contract",
                    cwd=root, env=environment, timeout=60)
                workflow_owner_receipt(context, "zip")
            else:
                require(name == "workflow-transaction-eof", "Unknown fixed workflow native phase")
                environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "workflow-transaction-eof")
                run([cargo, "test", *common, "--lib", "--features", "development-runtime", WORKFLOW_TRANSACTION_EOF_TEST,
                     "--", "--exact", "--ignored", "--test-threads=1"], check="workflow-transaction-eof-native-contract",
                    cwd=root, env=environment, timeout=90)
                workflow_transaction_eof_receipt(context)
    workflow_source_unchanged(context)
    phase_receipt(context, name, list(WORKFLOW_NATIVE_CHECKS[name]))


def clean_compile(context: dict) -> None:
    """Only positively completed compiler work; no fabricated native receipts."""
    profile = compile_profile(context.get("executionScope", ""))
    root, source = Path(context["root"]), Path(context["source"])
    for phase_name in profile["checks"]:
        path = root / f"{phase_name}-checks.json"
        ordinary(path)
        require(0 < path.stat().st_size <= 16384, "Compiler phase receipt exceeds its bound")
        with path.open("rb") as stream:
            raw = stream.read(16385)
        validate_compile_receipt(parse_compile_receipt(raw), context, phase_name)
    nonempty = set()
    for name in EMPTY_NATIVE_DIRECTORIES:
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink()
                and not getattr(directory.lstat(), "st_file_attributes", 0) & 0x400,
                "Compiler native placeholder is no longer an ordinary directory")
        if any(directory.iterdir()):
            nonempty.add(name)
    validate_compile_inventory({path.name for path in root.iterdir()}, nonempty)
    # Validate the complete deletion roster before removing any of it. All were
    # created by prepare/acquire/compile in this fresh hosted job, never user data.
    directories = [source / relative for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen")]
    directories.extend(root / name for name in COMPILER_DIRECTORIES)
    for directory in directories:
        require(directory.is_dir() and not directory.is_symlink()
                and not getattr(directory.lstat(), "st_file_attributes", 0) & 0x400,
                "Task-owned compiler output directory differs")
    for name in COMPILER_PRIVATE_FILES + COMPILE_PUBLIC_FILES:
        ordinary(root / name)
    for directory in directories:
        shutil.rmtree(directory)
    for name in EMPTY_NATIVE_DIRECTORIES:
        (root / name).rmdir()
    for name in COMPILER_PRIVATE_FILES:
        (root / name).unlink()
    require({path.name for path in root.iterdir()} == set(COMPILE_PUBLIC_FILES), "Unexpected output after compiler cleanup")
    print("Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.")


def gtk_compiler_tools() -> tuple[str, str]:
    # Fixed system compiler tools on the admitted Ubuntu runner. No environment
    # supplied compiler, package-config path or actor execution is accepted.
    paths = [Path(name).resolve(strict=True) for name in ("/usr/bin/cc", "/usr/bin/pkg-config")]
    for path in paths:
        ordinary(path)
    return str(paths[0]), str(paths[1])


GTK_PYTHON_SYNTAX = (
    "import sys\n"
    "with open(sys.argv[1], 'rb') as f: data = f.read(1048577)\n"
    "if not 0 < len(data) <= 1048576: raise ValueError('syntax input bound')\n"
    "compile(data, '<SG1 outer syntax only>', 'exec', dont_inherit=True)\n"
)


def compile_gtk(context: dict, cargo: str, common: list[str], environment: dict[str, str]) -> str:
    """Fixed Linux integration/C compilation. NEVER executes a produced binary."""
    require(context.get("executionScope") == GTK_COMPILE_SCOPE and context.get("platform") == "linux",
            "Wrong SG1 compiler profile")
    root, source = Path(context["root"]), Path(context["source"])
    desktop = source / "desktop"
    node = shutil.which("node")
    require(node is not None, "Node unavailable after setup")
    observed_node = run([node, "--version"], check="node-version", cwd=root, env=environment, timeout=15, capture=True)
    require(observed_node == NODE, "Selected Node version changed")
    # Fail fast on inert syntax/C compilation before the expensive Rust graph.
    # compile() constructs a code object only; it does not import/execute O and
    # creates no pycache. Node --check similarly never evaluates the recipe.
    run([context["python"], "-I", "-S", "-B", "-c", GTK_PYTHON_SYNTAX,
         str(desktop / "tools/qualify_session_gtk.py")],
        check="gtk-python-syntax-only", cwd=root, env=environment, timeout=15)
    run([node, "--check", str(desktop / "src-tauri/tests/session_gtk_recipe.js")],
        check="gtk-js-syntax-only", cwd=root, env=environment, timeout=15)
    cc, pkg_config = gtk_compiler_tools()
    flags = run([pkg_config, "--cflags", "--libs", "dbus-1", "glib-2.0", "atspi-2"],
                check="gtk-c-pkg-config", cwd=root, env=environment, timeout=15, capture=True)
    require(0 < len(flags.encode("utf-8")) <= 16384, "GTK compiler flags exceed their bound")
    compiler_flags = shlex.split(flags)
    require(len(compiler_flags) <= 128 and all(
        flag == "-pthread" or flag.startswith(("-I/", "-L/", "-l", "-D"))
        for flag in compiler_flags), "Unexpected GTK compiler flag")
    run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror=implicit-function-declaration",
         "-Werror=incompatible-pointer-types", str(desktop / "native/session_gtk_input_linux.c"),
         "-o", str(root / "target/session-gtk-input"), *compiler_flags],
        check="gtk-c-compile-only", cwd=root, env=environment, timeout=60)
    run([node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build", "--config",
         str(desktop / "vite.config.mjs"), "--configLoader", "native", "--outDir", str(desktop / "dist")],
        check="vite-assets", cwd=desktop, env=environment, timeout=90)
    run([cargo, "test", *common, "--test", "session-gtk-qualification", "--no-run", "--features",
         ",".join(GTK_COMPILE_FEATURES)], check="gtk-integration-compile-only", cwd=root,
        env=environment, timeout=1500)
    return observed_node


def phase(name: str, platform: str, scope: str = BOUNDARY_SCOPE) -> None:
    admit_phase(scope, name)
    admit_platform(scope, platform)
    context = load_context(platform, scope)
    if scope == WORKFLOW_NATIVE_SCOPE:
        phase_workflow_native(name, context)
        return
    if scope == GITHUB_READONLY_SCOPE:
        phase_github_readonly(name, context)
        return
    if scope == GITHUB_TLS_SCOPE:
        phase_github_tls(name, context)
        return
    windows = scope == WINDOWS_SNAPSHOT_SCOPE
    root, source = Path(context["root"]), Path(context["source"])
    environment = clean_environment(root)
    # The owner fixture binds its compiled source to this exact event commit.
    # Compile and test must use the same value; no None/ambient/latest fallback.
    environment["GITHUB_SHA"] = context["sourceSha"]
    manifest = source / "desktop/src-tauri/Cargo.toml"
    source_unchanged(context)
    no_cargo_configuration((root, *root.parents))
    if name == "clean" and scope in COMPILE_PROFILES:
        clean_compile(context)
        return
    if name == "acquire":
        run([context["rustup"], "toolchain", "install", RUST, "--profile", "minimal", "--no-self-update"],
            check="rust-toolchain-install", cwd=root, env=environment, timeout=600)
        cargo, _ = tools(context, environment)
        features = "development-runtime" if windows else "desktop-shell,development-runtime"
        # Metadata filters acquisition to this platform and active feature graph.
        with (root / "metadata.json").open("x", encoding="utf-8") as output:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", features, "--filter-platform", TARGETS[platform],
                 "--manifest-path", str(manifest)], check="locked-platform-metadata", cwd=root,
                 env=environment, timeout=600, output=output)
        if windows:
            source_unchanged(context)
            phase_receipt(context, name, ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"],
                          scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE)
            return
        node = shutil.which("node")
        require(node is not None, "Selected Node unavailable")
        observed_node = run([node, "--version"], check="node-version", cwd=root, env=environment, timeout=15, capture=True)
        require(observed_node == NODE, "Selected Node version differs")
        npm = (Path(node).parent / "node_modules/npm/bin/npm-cli.js" if platform == "windows" else
               Path(node).parent.parent / "lib/node_modules/npm/bin/npm-cli.js")
        ordinary(npm)
        run([node, "--max-old-space-size=768", str(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
             "--userconfig", str(root / "npmrc-user"), "--globalconfig", str(root / "npmrc-global"),
             "--cache", str(root / "npm-cache"), "--registry", "https://registry.npmjs.org/"],
            check="npm-locked-no-scripts", cwd=source / "desktop", env=environment, timeout=300)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-toolchain-install", "rust-version-target", "locked-platform-metadata"]
                      + ["node-version", "npm-locked-no-scripts"], node=observed_node)
        return
    cargo, _ = tools(context, environment)
    common = ["--locked", "--offline", "--jobs", "1", "--no-default-features",
              "--target", TARGETS[platform], "--manifest-path", str(manifest), "--target-dir", str(root / "target")]
    if name == "compile" and scope == GTK_COMPILE_SCOPE:
        observed_node = compile_gtk(context, cargo, common, environment)
        source_unchanged(context)
        require(context["sg1"] == gtk_compile_binding(source), "SG1 compiler inputs changed during compilation")
        phase_receipt(context, name, list(GTK_COMPILE_CHECKS["compile"]), node=observed_node)
        return
    if name == "compile":
        if windows:
            argv = [cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"]
            argv.append("--message-format=json")
            messages = root / "windows-compile-messages.jsonl"
            with messages.open("x", encoding="utf-8", newline="\n") as output:
                run(argv, check="headless-test-compile-only", cwd=root, env=environment, timeout=600, output=output)
            compiled = windows_compile_record(context, argv, messages)
            source_unchanged(context)
            phase_receipt(context, name, ["rust-version-target", "headless-test-compile-only"],
                          scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE, compiled=compiled)
            return
        run([cargo, "test", *common, "--lib", "--no-run", "--features", "development-runtime"],
            check="headless-test-compile-only", cwd=root, env=environment, timeout=600)
        node = shutil.which("node")
        require(node is not None, "Node unavailable after setup")
        observed_node = run([node, "--version"], check="node-version", cwd=root, env=environment, timeout=15, capture=True)
        require(observed_node == NODE, "Selected Node version changed")
        desktop = source / "desktop"
        run([node, "--max-old-space-size=768", "node_modules/typescript/bin/tsc", "--noEmit", "-p", "tsconfig.json"],
            check="typescript-no-emit", cwd=desktop, env=environment, timeout=60)
        run([node, "--max-old-space-size=768", "node_modules/vite/bin/vite.js", "build", "--config",
             str(desktop / "vite.config.mjs"), "--configLoader", "native", "--outDir", str(desktop / "dist")],
            check="vite-assets", cwd=desktop, env=environment, timeout=90)
        run([cargo, "build", *common, "--features", "desktop-shell,development-runtime",
             "--bin", "mobile-release-kit-desktop"], check="tauri-debug-compile-only", cwd=root, env=environment, timeout=1500)
        source_unchanged(context)
        phase_receipt(context, name, ["rust-version-target", "headless-test-compile-only"]
                      + ["node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"], node=observed_node)
    elif name == "windows-snapshot":
        require(windows and platform == "windows", "Windows snapshot phase requires its dedicated scope")
        windows_inputs(context, create=True)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_ROOT=str(root / "windows-snapshot"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                           MRK_DESKTOP_HOSTED_CHECKS=WINDOWS_SNAPSHOT_SCOPE, GITHUB_ACTIONS="true",
                           RUNNER_ENVIRONMENT="github-hosted", GITHUB_SHA=context["sourceSha"])
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", WINDOWS_SNAPSHOT_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="windows-snapshot-native-contract",
            cwd=root, env=environment, timeout=300)
        source_unchanged(context)
        windows_snapshot_receipt(context)
        phase_receipt(context, name, ["rust-version-target", WINDOWS_SNAPSHOT_TEST, "windows-snapshot-original-resource-receipt-acceptance"],
                      scope=WINDOWS_SNAPSHOT_PUBLIC_SCOPE)
    elif name == "native":
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_TEST_ROOT=str(root / "native"), MRK_DESKTOP_TEST_CORE_ZIP=str(root / "core.zip"),
                           MRK_DESKTOP_HOSTED_CHECKS="passive-v1", GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           GITHUB_SHA=context["sourceSha"])
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", NATIVE_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="passive-native-contract", cwd=root, env=environment, timeout=300)
        source_unchanged(context)
        native_receipt(context)
        phase_receipt(context, name, ["rust-version-target", NATIVE_TEST, "native-receipt-acceptance"])
    elif name == "config-owner":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_TEST_ROOT=str(root / "config-owner"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_OWNER_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-owner-native-contract", cwd=root, env=environment, timeout=180)
        source_unchanged(context)
        config_owner_receipt(context)
        phase_receipt(context, name, [CONFIG_OWNER_TEST, "configuration-original-resource-receipt-acceptance"],
                      scope="configuration-owner-native-only-not-desktop-enablement")
    elif name == "config-task-loss":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-driver-loss")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_DRIVER_LOSS_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-driver-loss-native-contract", cwd=root, env=environment, timeout=90)
        config_loss_receipt(context, "driver-loss")
        # The original prior subprocess has exited/waited and its underlying
        # native resources are proved settled. Its management Unknown/root is
        # retained; the next process receives a different exclusive fixture root.
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-watchdog-loss")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_WATCHDOG_LOSS_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-watchdog-loss-native-contract", cwd=root, env=environment, timeout=90)
        config_loss_receipt(context, "watchdog-loss")
        source_unchanged(context)
        phase_receipt(context, name, [CONFIG_DRIVER_LOSS_TEST, CONFIG_WATCHDOG_LOSS_TEST, "native-resources-settled-management-unknown"],
                      scope="controlled-management-loss-only-not-normal-owner-settlement")
    elif name == "config-owner-delta":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-stop")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_STOP_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-stop-native-contract", cwd=root, env=environment, timeout=60)
        config_delta_receipt(context, "stop")
        # Each original subprocess must return and its actual resource facts
        # must pass before the next fixed process/root is admitted. The clock
        # cases retain sticky Unknown, not ordinary successful-save finality.
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-terminal-deadline")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_TERMINAL_DEADLINE_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-terminal-deadline-native-contract", cwd=root, env=environment, timeout=90)
        config_delta_receipt(context, "terminal-deadline")
        environment["MRK_DESKTOP_EDIT_TEST_ROOT"] = str(root / "config-startup-stop")
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_STARTUP_STOP_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-startup-stop-native-contract", cwd=root, env=environment, timeout=60)
        config_delta_receipt(context, "startup-stop")
        source_unchanged(context)
        phase_receipt(context, name, [CONFIG_STOP_TEST, CONFIG_TERMINAL_DEADLINE_TEST, CONFIG_STARTUP_STOP_TEST,
                                     "original-resource-clock-and-stop-receipt-acceptance"],
                      scope="configuration-clock-and-stop-controls-only-not-desktop-enablement")
    elif name == "config-transaction-eof":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        for kind in ("stop", "terminal-deadline", "startup-stop"):
            config_delta_receipt(context, kind)
        environment.update(MRK_DESKTOP_DEV_PYTHON=context["python"], MRK_DESKTOP_DEV_CORE=str(source / "src"),
                           MRK_DESKTOP_EDIT_TEST_ROOT=str(root / "config-transaction-eof"),
                           MRK_DESKTOP_EDIT_HOSTED_CHECKS="configuration-v1", MRK_DESKTOP_EDIT_SOURCE_SHA=context["sourceSha"],
                           GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        run([cargo, "test", *common, "--lib", "--features", "development-runtime", CONFIG_TRANSACTION_EOF_TEST,
             "--", "--exact", "--ignored", "--test-threads=1"], check="config-transaction-eof-native-contract", cwd=root, env=environment, timeout=90)
        source_unchanged(context)
        config_transaction_eof_receipt(context)
        phase_receipt(context, name, [CONFIG_TRANSACTION_EOF_TEST, "transaction-eof-original-resource-receipt-acceptance"],
                      scope="controlled-transaction-eof-only-not-desktop-enablement")
    elif name == "config-core":
        require(platform in {"linux", "macos"}, "POSIX configuration fixtures are not Windows support")
        native_receipt(context)
        config_owner_receipt(context)
        config_loss_receipt(context, "driver-loss")
        config_loss_receipt(context, "watchdog-loss")
        for kind in ("stop", "terminal-deadline", "startup-stop"):
            config_delta_receipt(context, kind)
        config_transaction_eof_receipt(context)
        environment.update(MRK_DESKTOP_CONFIG_NATIVE="1", GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                           RUNNER_OS="Linux" if platform == "linux" else "macOS",
                           RUNNER_TEMP=str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        fixture = [context["python"], "-I", "-S", "-B", str(source / "tests/native_desktop_config.py"),
                   "--task-root", str(root), "--case"]
        # Each return includes the original interpreter's wait. Validate its
        # complete positive settlement contract before admitting the next one.
        with (root / "config-ordinary.json").open("x", encoding="utf-8") as output:
            run([*fixture, "ordinary"], check="config-core-ordinary", cwd=root, env=environment, timeout=90, output=output)
        config_receipt(context, "ordinary")
        with (root / "config-committed-fsync.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-fsync"], check="config-core-committed-fsync", cwd=root, env=environment, timeout=45, output=output)
        config_receipt(context, "committed-fsync")
        with (root / "config-committed-close.json").open("x", encoding="utf-8") as output:
            run([*fixture, "committed-close"], check="config-core-committed-close", cwd=root, env=environment, timeout=45, output=output)
        config_receipt(context, "committed-close")
        # This last control deliberately retains uncertainty. No further native
        # fixture/owner is started, and no retaining root is adopted for cleanup.
        source_unchanged(context)
        phase_receipt(context, name, ["config-core-ordinary", "config-core-committed-fsync", "config-core-committed-close"],
                      scope="configuration-core-native-only-not-desktop-enablement")
    else:
        require(name == "clean", "Unknown fixed phase")
        if windows:
            clean_windows_outputs(context)
            return
        native_receipt(context)
        retained = False
        if platform in {"linux", "macos"}:
            config_owner_receipt(context)
            config_loss_receipt(context, "driver-loss")
            config_loss_receipt(context, "watchdog-loss")
            for kind in ("stop", "terminal-deadline", "startup-stop"):
                config_delta_receipt(context, kind)
            config_transaction_eof_receipt(context)
            for partition in CONFIG_PARTITIONS:
                config_receipt(context, partition)
            retained = True  # Management-loss roots stay retained even after proved native settlement.
        # Only fresh outputs whose absence prepare() required. No dependency or
        # file outside this exact job root/fresh checkout is selected for removal.
        for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen"):
            output = source / relative
            require(not output.is_symlink(), "Generated output became a link")
            if output.exists():
                shutil.rmtree(output)
        if retained:
            for name in ("cargo", "rustup", "target", "npm-cache", "tmp", "home", "appdata", "localappdata"):
                output = root / name
                require(output.is_dir() and not output.is_symlink(), "Task-owned compiler directory differs")
                shutil.rmtree(output)
            print("Removed settled compiler/dependency outputs; retained fixture journals/uncertainty for hosted VM disposal.")
        else:
            shutil.rmtree(root)
            print("Removed settled task-owned compiler, dependency and fixture outputs.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=(*BOUNDARY_PHASES, "workflow-owner", "workflow-transaction-eof", "workflow-core", "windows-snapshot", "github-owner", "github-tls"))
    args = parser.parse_args()
    os.umask(0o077)
    print(f"Starting fixed desktop phase: {args.phase}", flush=True)
    try:
        scope = os.environ.get("MRK_DESKTOP_HOSTED_CHECKS", "")
        admit_phase(scope, args.phase)
        platform = admitted_host()
        prepare(platform, scope) if args.phase == "prepare" else phase(args.phase, platform, scope)
    except Exception as error:
        reason = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        print(f"Desktop {args.phase} failed: {reason}. Preserve evidence; no native or product success is implied.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
