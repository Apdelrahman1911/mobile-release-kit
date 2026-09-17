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
    "desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
    "desktop/src-tauri/src/asset_session.rs", "desktop/src-tauri/src/asset_source.rs",
    "desktop/src-tauri/src/edit_owner.rs", "desktop/src-tauri/src/hosted_tests.rs",
    "desktop/src-tauri/src/shell.rs", "desktop/src-tauri/src/supervisor.rs",
    "desktop/src-tauri/src/session_gtk_qualification.rs",
    "desktop/src-tauri/src/session_gtk_qualification/native_contract.rs",
    "desktop/src-tauri/tests/session_gtk_qualification.rs",
    "desktop/src-tauri/tests/session_gtk_recipe.js",
    "desktop/native/session_gtk_input_linux.c", "desktop/tools/qualify_session_gtk.py",
    "desktop/tools/ci_foundation.py", GTK_COMPILE_WORKFLOW,
)
EMPTY_NATIVE_DIRECTORIES = (
    "native", "config-owner", "config-driver-loss", "config-watchdog-loss", "config-stop",
    "config-terminal-deadline", "config-startup-stop", "config-transaction-eof",
)
COMPILER_DIRECTORIES = ("home", "cargo", "rustup", "tmp", "target", "appdata", "localappdata", "npm-cache")
COMPILER_PRIVATE_FILES = ("context.json", "core.zip", "metadata.json", "npmrc-user", "npmrc-global", "gitconfig-empty")
COMPILE_PUBLIC_FILES = ("public-bindings.json", "acquire-checks.json", "compile-checks.json")
NATIVE_TEST = "supervisor::hosted_tests::passive_hosted_contract"
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
})


class CheckFailure(ValueError):
    """Fixed, non-secret diagnostic for an explicit check condition."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def admit_phase(scope: str, phase: str) -> None:
    """Closed scope selection, before context, tools, or native dispatch."""
    require(scope in {BOUNDARY_SCOPE, WORKFLOW_NATIVE_SCOPE, *COMPILE_PROFILES}, "Unknown desktop verification scope")
    if scope in COMPILE_PROFILES:
        require(phase in COMPILE_PHASES, "Compiler-only scope cannot execute a native phase")
    elif scope == WORKFLOW_NATIVE_SCOPE:
        require(phase in WORKFLOW_NATIVE_PHASES, "Workflow-only scope cannot execute an unrelated native phase")
    else:
        require(phase in BOUNDARY_PHASES, "Foundation scope cannot execute a workflow-only phase")


def admit_platform(scope: str, platform: str) -> None:
    require(platform in TARGETS, "Unknown desktop verification platform")
    require(scope != GTK_COMPILE_SCOPE or platform == "linux", "SG1 compilation requires Linux")
    require(scope != WORKFLOW_NATIVE_SCOPE or platform == "linux", "Workflow native verification requires Linux")


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


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def run(argv: list[str], *, check: str, cwd: Path, env: dict[str, str], timeout: int,
        capture: bool = False, output: TextIO | None = None) -> str:
    # Only fixed commands below reach this internal helper. No shell, inherited
    # credentials, renderer input, project hook or arbitrary command selection.
    require(check in TOOL_CHECKS, "Unknown fixed compiler check")
    require(not (capture and output is not None), "Conflicting compiler output destinations")
    print(f"Fixed check: {check}", flush=True)
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, check=True, timeout=timeout,
                                text=True, stdout=subprocess.PIPE if capture else output)
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
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") in {BOUNDARY_SCOPE, WORKFLOW_NATIVE_SCOPE, *COMPILE_PROFILES},
            "This fixed check requires an explicitly admitted disposable hosted job")
    platform = os.environ.get("MRK_DESKTOP_PLATFORM", "")
    require(platform in TARGETS and platform == {
        "linux": "linux", "darwin": "macos", "win32": "windows",
    }.get(sys.platform), "Unexpected host platform")
    admit_platform(os.environ["MRK_DESKTOP_HOSTED_CHECKS"], platform)
    if os.environ["MRK_DESKTOP_HOSTED_CHECKS"] == WORKFLOW_NATIVE_SCOPE:
        require(os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64"
                and os.environ.get("ImageOS") == "ubuntu24" and os.uname().machine == "x86_64"
                and os.geteuid() != 0, "Workflow native checks require the non-root Ubuntu 24 x86_64 runner")
    require(sys.version.split()[0] == PYTHON, "Unexpected selected Python version")
    selected = Path(os.environ["MRK_PYTHON"]).resolve(strict=True)
    require(selected == Path(sys.executable).resolve(strict=True), "Python setup output differs")
    return platform


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


def phase_receipt(context: dict, name: str, checks: list[str], *, node: str | None = None,
                  scope: str = "passive-development-foundation-only") -> None:
    # Only called after the fixed phase and final source check actually succeed.
    # Missing files on failed/skipped phases cannot become passing evidence.
    value = {
        "schemaVersion": 1, "scope": scope, "phase": name,
        "status": "passed", "sourceSha": context["sourceSha"], "platform": context["platform"],
        "rust": {"release": RUST, "target": TARGETS[context["platform"]]}, "node": node,
        "checks": [{"check": check, "exitCode": 0} for check in checks],
    }
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
    profile = compile_profile(scope) if scope in COMPILE_PROFILES else None
    native_workflow = scope == WORKFLOW_NATIVE_SCOPE
    binding = compile_workflow_binding(os.environ, scope) if profile else workflow_native_binding(os.environ) if native_workflow else {}
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
    if native_workflow:
        # One original root per actual job attempt. A second prepare must not
        # mint a fresh path to evade a failed/Unknown phase's retained claims.
        root = temp / f"mrk-desktop-foundation-workflow-{binding['runId']}-{binding['attempt']}"
        root.mkdir(mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix="mrk-desktop-foundation-", dir=temp))
    no_cargo_configuration((root,))
    directories = WORKFLOW_NATIVE_DIRECTORIES if native_workflow else (
        "home", "cargo", "rustup", "tmp", "target", "native", "config-owner", "config-driver-loss", "config-watchdog-loss",
        "config-stop", "config-terminal-deadline", "config-startup-stop", "config-transaction-eof", "appdata", "localappdata", "npm-cache")
    for name in directories:
        (root / name).mkdir(mode=0o700)
    empty_files = ("gitconfig-empty",) if native_workflow else ("npmrc-user", "npmrc-global", "gitconfig-empty")
    for name in empty_files:
        (root / name).touch(mode=0o600, exist_ok=False)
    git = shutil.which("git")
    rustup = shutil.which("rustup")
    require(git is not None and rustup is not None, "Hosted compiler tools unavailable")
    environment = clean_environment(root)
    require(run([git, "rev-parse", "HEAD"], check="source-head", cwd=source, env=environment, timeout=15, capture=True) == sha,
            "Event and checkout source differ")
    tree = run([git, "rev-parse", "HEAD^{tree}"], check="source-tree", cwd=source, env=environment, timeout=15, capture=True)
    if native_workflow:
        require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None and tree != "0" * 40,
                "Workflow native source tree differs")
    inventory = []
    total = 0
    package = source / "src/mobile_release"
    input_paths = sorted(package.rglob("*"), key=(lambda path: path.as_posix()) if native_workflow else None)
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
    workflow = profile["workflow"] if profile else WORKFLOW_NATIVE_WORKFLOW if native_workflow else ".github/workflows/desktop-foundation.yml"
    if profile or native_workflow:
        context["workflowSha256"] = hash_file(source / workflow)
    if scope == GTK_COMPILE_SCOPE:
        require(len(inventory) == 67, "SG1 requires its complete reviewed 67-file core")
        context["sg1"] = gtk_compile_binding(source)
    if native_workflow:
        prepare_workflow_native_context(context, inventory)
    source_unchanged(context)
    write_json(root / "context.json", context)
    if native_workflow:
        public = workflow_public_bindings(context)
    else:
        public = {
            "scope": profile["evidence"] if profile else "passive-development-foundation-only", "sourceSha": sha, "sourceTree": tree,
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
    write_json(root / "public-bindings.json", public)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"root={root}\n")
    print("Prepared bounded source ZIP and source-bound synthetic check inputs.")


def load_context(platform: str, scope: str = BOUNDARY_SCOPE) -> dict:
    admit_platform(scope, platform)
    root = Path(os.environ["MRK_DESKTOP_CI_ROOT"])
    require(root.is_absolute() and root.name.startswith("mrk-desktop-foundation-")
            and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and not root.is_symlink(), "Unrecognized task root")
    ordinary(root / "context.json")
    context = workflow_json(root / "context.json") if scope == WORKFLOW_NATIVE_SCOPE else json.loads((root / "context.json").read_text(encoding="utf-8"))
    require(context["root"] == str(root) and context["platform"] == platform and context.get("executionScope") == scope
            and context["sourceSha"] == os.environ["GITHUB_SHA"]
            and context["runId"] == os.environ["GITHUB_RUN_ID"]
            and context["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Task context differs")
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
        features = "desktop-shell,development-runtime"
        # Metadata filters acquisition to this platform and active feature graph.
        with (root / "metadata.json").open("x", encoding="utf-8") as output:
            run([cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
                 "--features", features, "--filter-platform", TARGETS[platform],
                 "--manifest-path", str(manifest)], check="locked-platform-metadata", cwd=root,
                env=environment, timeout=600, output=output)
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
    parser.add_argument("phase", choices=(*BOUNDARY_PHASES, "workflow-owner", "workflow-transaction-eof", "workflow-core"))
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
