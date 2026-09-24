"""Closed hosted-only configuration fixtures; never unittest discovery.

Source authoring is not execution approval. Each approved invocation uses
``python3 -I -S -B ... --task-root <original-private-root> --case <fixed-case>``.
There is no subprocess controller, credential input, recovery command or
alternative transaction engine. Uncertainty ends native admission in this
interpreter; the workflow disposes the retained synthetic case directory/VM.

The separate github_workflows, metadata_text and release_version domains are
source-only core qualification, not production permits. Their closed argv/env/receipt inventories
never accept a caller path roster, replacement policy or ZIP selector. Rust owns
the ZIP parity cases and real bridge/owner/EOF fixtures; this file spawns no process.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
_GUARD_MESSAGE = "configuration fixture original ownership did not settle"
_RUN_CLAIMED = False
_RETAINED_BATCH: Any = None

_WORKFLOW_REPOSITORY = "Example/mobile-release-kit"
_WORKFLOW_SHA = "a" * 40
_WORKFLOW_FILES = (
    ("preflight", ".github/workflows/mobile-preflight.yml"),
    ("candidate", ".github/workflows/mobile-candidate.yml"),
    ("external-testing", ".github/workflows/mobile-external-testing.yml"),
    ("production-submit", ".github/workflows/mobile-production-submit.yml"),
)
_WORKFLOW_CASES = {
    "ordinary": (
        "capture-prepare-discard", "existing-differs", "oversized", "unreadable",
        "symlink-leaf", "symlink-ancestor", "hardlink", "aliased-leaf", "nonregular-fifo",
        "registered-root-replaced", "stale-leaf-bytes-before-prepare",
        "stale-leaf-inode-before-apply", "stale-ancestor-mode-before-prepare",
        "absent-ancestor-before-prepare", "absent-leaf-before-apply", "stale-root-before-apply",
        "pending-init", "pending-build", "contention-init", "contention-build", "review-unlocked",
        "partial-install-rollback", "incomplete-preparing", "wrong-roster-controls",
        "unowned-staging-slot", "rollback-pending-replaced", "cleanup-committed-unused-missing",
        "cleanup-rolled-back-unused-missing", "commit-pending-replaced",
    ),
    "committed-fsync": ("committed-fsync-injection",),
    "committed-close": ("committed-close-return-injection",),
}
_WORKFLOW_SOURCES = {
    "fixture": "tests/native_desktop_config.py",
    "workflowEdit": "src/mobile_release/github_workflow_edit.py",
    "configEdit": "src/mobile_release/config_edit.py",
    "transaction": "src/mobile_release/init_transaction.py",
    "rootCustody": "src/mobile_release/init_workspace_custody.py",
    "cancellation": "src/mobile_release/cancellation.py",
    "buildInputs": "src/mobile_release/build_inputs.py",
    "workflowPayloads": "src/mobile_release/workflow_payloads.py",
    "proposal": "src/mobile_release/api/_github_setup.py",
    "resource": "src/mobile_release/api/data/github-setup-v1.json",
    "canonicalPreflight": "templates/workflows/mobile-preflight.yml",
    "canonicalCandidate": "templates/workflows/mobile-candidate.yml",
    "canonicalExternalTesting": "templates/workflows/mobile-external-testing.yml",
    "canonicalProductionSubmit": "templates/workflows/mobile-production-submit.yml",
}
_WORKFLOW_DISK_CONFIG = b"fixed deliberately invalid on-disk configuration; never saved\n"
_WORKFLOW_IGNORE = b"# fixed workflow fixture ignore sentinel; never edited\n"
_WORKFLOW_DRAFT_SHA256 = "e7530b44993489441ab3b0530899b4376d49f1188d5def28979fcb5300d3cd34"
_WORKFLOW_TEMPLATE_SET = {
    "coreVersion": "0.3.0", "resourceVersion": 1,
    "resourceSha256": "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c",
}
_WORKFLOW_PAYLOAD_SHA256 = (
    "50845641f06763aab532900d1b3b186a5d684d465a4d63fab05f53c99f9685de",
    "8fb540be24c263c97f7dbf95df524a8b11633e5fa7b1dc92e77cd648ad16e32f",
    "97fa27d95cc7b2d75be0c3a0860af1d350edb6a52741ed87c0a5b13eca8386f1",
    "85865a4df661ef7c7b708b55598a70d56fd84957ce07c9c60f15bcf10a5554b8",
)


# Literal metadata fixture DATA, shared with the SOURCE coordination contract.
# Expected bytes/rows are independent constants, never product-generated truth.
_METADATA_CASES = {'committed-close': ('metadata-committed-close-return-injection',),
 'committed-fsync': ('metadata-committed-fsync-injection',),
 'ordinary': ('configured-platform-disabled',
              'configured-locale-absent',
              'legacy-four-ignore-rules-refused',
              'ambiguous-ignore-negation-refused',
              'config-retarget-before-prepare',
              'ignore-bytes-before-apply',
              'dependency-only-parent-mode-before-apply',
              'target-parent-inode-before-prepare',
              'target-parent-mode-before-apply',
              'missing-target-parent-appears-before-apply',
              'noop-last-leaf-ctime-after-recheck',
              'noop-target-parent-mode-after-recheck',
              'unreadable-leaf-before-prepare',
              'first-replacement-installed-rollback',
              'incomplete-metadata-preparing-retained',
              'committed-old-backup-replaced-at-cleanup-entry',
              'legacy-domains-refuse-empty-metadata-prepare',
              'legacy-domains-refuse-header-tmp-metadata-prepare',
              'metadata-refuses-legacy-ready',
              'dependency-drift-after-first-replacement')}

_METADATA_SOURCES = {'apiContracts': 'src/mobile_release/api/contracts.py',
 'buildInputs': 'src/mobile_release/build_inputs.py',
 'cancellation': 'src/mobile_release/cancellation.py',
 'catalogue': 'src/mobile_release/api/_catalog.py',
 'configEdit': 'src/mobile_release/config_edit.py',
 'configPayloads': 'src/mobile_release/config_payloads.py',
 'configuration': 'src/mobile_release/config.py',
 'editControl': 'src/mobile_release/_desktop_edit_control.py',
 'editEngine': 'src/mobile_release/_desktop_edit_engine.py',
 'editProtocol': 'src/mobile_release/_desktop_edit_protocol.py',
 'fixture': 'tests/native_desktop_config.py',
 'metadataApi': 'src/mobile_release/api/_metadata_text.py',
 'metadataEdit': 'src/mobile_release/metadata_text_edit.py',
 'metadataPolicy': 'src/mobile_release/metadata.py',
 'metadataText': 'src/mobile_release/metadata_text.py',
 'passiveEngine': 'src/mobile_release/_desktop_engine.py',
 'resource': 'src/mobile_release/api/data/metadata-text-help-v1.json',
 'rootCustody': 'src/mobile_release/init_workspace_custody.py',
 'snapshot': 'src/mobile_release/api/_snapshot.py',
 'transaction': 'src/mobile_release/init_transaction.py',
 'versionEdit': 'src/mobile_release/release_version_edit.py',
 'versionResource': 'src/mobile_release/api/data/release-version-help-v1.json',
 'versionText': 'src/mobile_release/version_text.py'}

_METADATA_FILES = {'android': ('title.txt', 'short_description.txt', 'full_description.txt'),
 'ios': ('description.txt', 'keywords.txt', 'privacy_url.txt', 'support_url.txt', 'release_notes.txt')}

_METADATA_CONFIG_TEXT = {'publicStore': '{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}\n',
 'releaseStore': '{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"release/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}\n'}

_METADATA_CONFIG_HASHES = {'publicStore': '1b0b02e48d03cca36aaf36e5d8a8daf15f59924803bd4a5c0ec2e655828d3f94',
 'releaseStore': 'caabad94b27c616e9deaf8570ded7edca9a41de86ca3e1982ab6e4a3f57073f1'}

_METADATA_IGNORE = (b'.mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n.mobi'
 b'le-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n')

_METADATA_IGNORE_SHA256 = 'e60087ecefac81e23666444e6aea9490b3fc42b2510f566cfd4aa5a36a35b7d4'

_METADATA_TEXT = {'android': {'full_description.txt': 'Public release details: café.\nSecond line.\n',
             'short_description.txt': 'A fixed public description.\r\n',
             'title.txt': 'Fixture public title\n'},
 'ios': {'description.txt': 'Public iOS description: café.\r\nSecond line.\r\n',
         'keywords.txt': 'public,fixture,release',
         'privacy_url.txt': 'https://public.invalid/privacy',
         'release_notes.txt': '  Public release notes.\nNo private content.\n',
         'support_url.txt': 'https://public.invalid/support'}}

_METADATA_FIELD_HASHES = {'android': {'full_description.txt': '52002e38814d0b0a78bc21cad572d5fa265ad3f9f72a672829982e889a4422fa',
             'short_description.txt': '233524e36ed836f2fc5b2754e73ff6f125f443d1bb57770942368c2fb90a0c63',
             'title.txt': '17c61ad21566db1d3e8bc33087e2ea25eced56a923addd81a3a80305dea3ee94'},
 'ios': {'description.txt': '417b4365404b44f1c83e478dbebb43864924c858fcca7346aac4db1b9f2c6ee5',
         'keywords.txt': 'd563110a53a8d4b4e320f549a957fcbc6d0f8ca14a02f77dfce9bdfaa2e0f866',
         'privacy_url.txt': '5cb73fc576bb124e3930e583584ad86d8052264a12c273cf207874b3c82aa5ee',
         'release_notes.txt': '4ec8e8f6389b0ece64c0f2ada003d134934dccba9c942ebbdfbadeb18c2ae5c9',
         'support_url.txt': '0cf21b6bc2716d68e9e9b41edda65445ab46e022fa94eeaa150c3c4045da1104'}}

_METADATA_PREVIOUS_TEXT = {'android': {'short_description.txt': 'Previous public description.\n', 'title.txt': 'Previous public title\n'},
 'ios': {'description.txt': 'Previous public iOS description.\n', 'keywords.txt': 'previous,public'}}

_METADATA_EXPECTED = {'configured-platform-disabled': {'case': 'configured-platform-disabled',
                                  'observed': {'journalAbsent': True,
                                               'revisionAbsent': True,
                                               'scopesClosed': 1,
                                               'snapshotUnchanged': True,
                                               'targetDescriptorAbsent': True},
                                  'outcome': {'effect': 'not_started',
                                              'journal': 'not_created',
                                              'reason': 'invalid_config',
                                              'resources': 'settled'},
                                  'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'configured-locale-absent': {'case': 'configured-locale-absent',
                              'observed': {'journalAbsent': True,
                                           'revisionAbsent': True,
                                           'scopesClosed': 1,
                                           'snapshotUnchanged': True,
                                           'targetDescriptorAbsent': True},
                              'outcome': {'effect': 'not_started',
                                          'journal': 'not_created',
                                          'reason': 'invalid_config',
                                          'resources': 'settled'},
                              'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'legacy-four-ignore-rules-refused': {'case': 'legacy-four-ignore-rules-refused',
                                      'observed': {'journalAbsent': True,
                                                   'revisionAbsent': True,
                                                   'scopesClosed': 1,
                                                   'snapshotUnchanged': True,
                                                   'targetDescriptorAbsent': True},
                                      'outcome': {'effect': 'not_started',
                                                  'journal': 'not_created',
                                                  'reason': 'ignore_conflict',
                                                  'resources': 'settled'},
                                      'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'ambiguous-ignore-negation-refused': {'case': 'ambiguous-ignore-negation-refused',
                                       'observed': {'journalAbsent': True,
                                                    'revisionAbsent': True,
                                                    'scopesClosed': 1,
                                                    'snapshotUnchanged': True,
                                                    'targetDescriptorAbsent': True},
                                       'outcome': {'effect': 'not_started',
                                                   'journal': 'not_created',
                                                   'reason': 'ignore_conflict',
                                                   'resources': 'settled'},
                                       'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'config-retarget-before-prepare': {'case': 'config-retarget-before-prepare',
                                    'observed': {'authorityRetired': True,
                                                 'changeObserved': True,
                                                 'journalAbsent': True,
                                                 'scopesClosed': 2,
                                                 'selectionNotRetargeted': True,
                                                 'snapshotUnchanged': True},
                                    'outcome': {'effect': 'not_started',
                                                'journal': 'not_created',
                                                'reason': 'stale_revision',
                                                'resources': 'settled'},
                                    'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'ignore-bytes-before-apply': {'case': 'ignore-bytes-before-apply',
                               'observed': {'authorityRetired': True,
                                            'changeObserved': True,
                                            'journalAbsent': True,
                                            'scopesClosed': 3,
                                            'selectionNotRetargeted': True,
                                            'snapshotUnchanged': True},
                               'outcome': {'effect': 'not_started',
                                           'journal': 'not_created',
                                           'reason': 'stale_revision',
                                           'resources': 'settled'},
                               'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'dependency-only-parent-mode-before-apply': {'case': 'dependency-only-parent-mode-before-apply',
                                              'observed': {'authorityRetired': True,
                                                           'changeObserved': True,
                                                           'journalAbsent': True,
                                                           'scopesClosed': 3,
                                                           'selectionNotRetargeted': True,
                                                           'snapshotUnchanged': True},
                                              'outcome': {'effect': 'not_started',
                                                          'journal': 'not_created',
                                                          'reason': 'stale_revision',
                                                          'resources': 'settled'},
                                              'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'target-parent-inode-before-prepare': {'case': 'target-parent-inode-before-prepare',
                                        'observed': {'authorityRetired': True,
                                                     'changeObserved': True,
                                                     'journalAbsent': True,
                                                     'scopesClosed': 2,
                                                     'selectionNotRetargeted': True,
                                                     'snapshotUnchanged': True},
                                        'outcome': {'effect': 'not_started',
                                                    'journal': 'not_created',
                                                    'reason': 'stale_revision',
                                                    'resources': 'settled'},
                                        'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'target-parent-mode-before-apply': {'case': 'target-parent-mode-before-apply',
                                     'observed': {'authorityRetired': True,
                                                  'changeObserved': True,
                                                  'journalAbsent': True,
                                                  'scopesClosed': 3,
                                                  'selectionNotRetargeted': True,
                                                  'snapshotUnchanged': True},
                                     'outcome': {'effect': 'not_started',
                                                 'journal': 'not_created',
                                                 'reason': 'stale_revision',
                                                 'resources': 'settled'},
                                     'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'missing-target-parent-appears-before-apply': {'case': 'missing-target-parent-appears-before-apply',
                                                'observed': {'authorityRetired': True,
                                                             'changeObserved': True,
                                                             'journalAbsent': True,
                                                             'scopesClosed': 3,
                                                             'selectionNotRetargeted': True,
                                                             'snapshotUnchanged': True},
                                                'outcome': {'effect': 'not_started',
                                                            'journal': 'not_created',
                                                            'reason': 'stale_revision',
                                                            'resources': 'settled'},
                                                'owner': {'closed': True,
                                                          'fatal': False,
                                                          'handlerRestored': True}},
 'noop-last-leaf-ctime-after-recheck': {'case': 'noop-last-leaf-ctime-after-recheck',
                                        'observed': {'changedOnlyDeclaredFacts': True,
                                                     'consumingTargetChecks': 1,
                                                     'injections': 1,
                                                     'journalAbsent': True,
                                                     'recheckReturns': 1,
                                                     'renameProbes': 0,
                                                     'scopesClosed': 3,
                                                     'snapshotUnchangedAfterInjection': True,
                                                     'unchangedMarked': False},
                                        'outcome': {'effect': 'not_started',
                                                    'journal': 'not_created',
                                                    'reason': 'stale_revision',
                                                    'resources': 'settled'},
                                        'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'noop-target-parent-mode-after-recheck': {'case': 'noop-target-parent-mode-after-recheck',
                                           'observed': {'changedOnlyDeclaredFacts': True,
                                                        'consumingTargetChecks': 1,
                                                        'injections': 1,
                                                        'journalAbsent': True,
                                                        'recheckReturns': 1,
                                                        'renameProbes': 0,
                                                        'scopesClosed': 3,
                                                        'snapshotUnchangedAfterInjection': True,
                                                        'unchangedMarked': False},
                                           'outcome': {'effect': 'not_started',
                                                       'journal': 'not_created',
                                                       'reason': 'stale_revision',
                                                       'resources': 'settled'},
                                           'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'unreadable-leaf-before-prepare': {'case': 'unreadable-leaf-before-prepare',
                                    'observed': {'deniedOriginalReads': 1,
                                                 'journalAbsent': True,
                                                 'permissionErrorObserved': True,
                                                 'scopesClosed': 2,
                                                 'snapshotUnchanged': True},
                                    'outcome': {'effect': 'not_started',
                                                'journal': 'not_created',
                                                'reason': 'filesystem_error',
                                                'resources': 'settled'},
                                    'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'first-replacement-installed-rollback': {'case': 'first-replacement-installed-rollback',
                                          'observed': {'firstLeafInstalled': True,
                                                       'injections': 1,
                                                       'journalAbsent': True,
                                                       'originalBackupBound': True,
                                                       'recoveryAttempts': 1,
                                                       'rollbackReturned': True,
                                                       'scopesClosed': 3,
                                                       'secondApplyNoScope': True,
                                                       'secondApplyRefused': True,
                                                       'snapshotRestored': True},
                                          'outcome': {'effect': 'rolled_back',
                                                      'journal': 'clean',
                                                      'reason': 'filesystem_error',
                                                      'resources': 'settled'},
                                          'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'incomplete-metadata-preparing-retained': {'case': 'incomplete-metadata-preparing-retained',
                                            'observed': {'cleanupUnlinks': 0,
                                                         'completeProof': False,
                                                         'dependenciesPreserved': True,
                                                         'injections': 1,
                                                         'numberedSlotRetained': True,
                                                         'preparingRetained': True,
                                                         'recoverCalls': 0,
                                                         'scopesClosed': 3,
                                                         'targetsPreserved': True},
                                            'outcome': {'effect': 'not_started',
                                                        'journal': 'recovery_required',
                                                        'reason': 'filesystem_error',
                                                        'resources': 'settled'},
                                            'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'committed-old-backup-replaced-at-cleanup-entry': {'case': 'committed-old-backup-replaced-at-cleanup-entry',
                                                    'observed': {'allSelectedPayloadsInstalled': True,
                                                                 'cleanupUnlinks': 0,
                                                                 'committedObserved': True,
                                                                 'dependenciesPreserved': True,
                                                                 'durabilityConfirmed': True,
                                                                 'injections': 1,
                                                                 'originalBackupRetained': True,
                                                                 'proofRetained': True,
                                                                 'sameBytesForeignInode': True,
                                                                 'scopesClosed': 3},
                                                    'outcome': {'effect': 'committed',
                                                                'journal': 'recovery_required',
                                                                'reason': 'filesystem_error',
                                                                'resources': 'settled'},
                                                    'owner': {'closed': True,
                                                              'fatal': False,
                                                              'handlerRestored': True}},
 'legacy-domains-refuse-empty-metadata-prepare': {'case': 'legacy-domains-refuse-empty-metadata-prepare',
                                                  'observed': {'bothOwnersSettled': True,
                                                               'bothRefused': True,
                                                               'legacyDomains': ['configuration',
                                                                                 'github_workflows'],
                                                               'originalOwners': 2,
                                                               'scopesClosed': 2,
                                                               'snapshotUnchanged': True,
                                                               'stateRetained': True,
                                                               'targetDescriptorsAbsent': True},
                                                  'outcome': {'effect': 'not_started',
                                                              'journal': 'not_created',
                                                              'reason': 'pending_state',
                                                              'resources': 'settled'},
                                                  'owner': {'closed': True,
                                                            'fatal': False,
                                                            'handlerRestored': True}},
 'legacy-domains-refuse-header-tmp-metadata-prepare': {'case': 'legacy-domains-refuse-header-tmp-metadata-prepare',
                                                       'observed': {'bothOwnersSettled': True,
                                                                    'bothRefused': True,
                                                                    'legacyDomains': ['configuration',
                                                                                      'github_workflows'],
                                                                    'originalOwners': 2,
                                                                    'scopesClosed': 2,
                                                                    'snapshotUnchanged': True,
                                                                    'stateRetained': True,
                                                                    'targetDescriptorsAbsent': True},
                                                       'outcome': {'effect': 'not_started',
                                                                   'journal': 'not_created',
                                                                   'reason': 'pending_state',
                                                                   'resources': 'settled'},
                                                       'owner': {'closed': True,
                                                                 'fatal': False,
                                                                 'handlerRestored': True}},
 'metadata-refuses-legacy-ready': {'case': 'metadata-refuses-legacy-ready',
                                   'observed': {'legacyStateRetained': True,
                                                'metadataStateAbsent': True,
                                                'scopesClosed': 1,
                                                'snapshotUnchanged': True,
                                                'targetDescriptorAbsent': True},
                                   'outcome': {'effect': 'not_started',
                                               'journal': 'not_created',
                                               'reason': 'pending_state',
                                               'resources': 'settled'},
                                   'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'dependency-drift-after-first-replacement': {'case': 'dependency-drift-after-first-replacement',
                                              'observed': {'afterUnknownProbes': 0,
                                                           'cleanupUnlinks': 0,
                                                           'dependencyChanged': True,
                                                           'firstLeafInstalled': True,
                                                           'injections': 1,
                                                           'laterInstallMoves': 0,
                                                           'originalBackupBound': True,
                                                           'partialTreeRetainedInsideOriginal': True,
                                                           'recoverCalls': 0,
                                                           'scopesClosed': 3},
                                              'outcome': {'effect': 'unknown',
                                                          'journal': 'recovery_required',
                                                          'reason': 'stale_revision',
                                                          'resources': 'settled'},
                                              'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'metadata-committed-fsync-injection': {'case': 'metadata-committed-fsync-injection',
                                        'observed': {'allSelectedPayloadsInstalled': True,
                                                     'committedObserved': True,
                                                     'dependenciesPreserved': True,
                                                     'durabilityConfirmed': False,
                                                     'injections': 1,
                                                     'journalRetained': True,
                                                     'rollbackCalls': 0,
                                                     'scopesClosed': 3},
                                        'outcome': {'effect': 'committed',
                                                    'journal': 'recovery_required',
                                                    'reason': 'filesystem_error',
                                                    'resources': 'settled'},
                                        'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'metadata-committed-close-return-injection': {'case': 'metadata-committed-close-return-injection',
                                               'observed': {'actualScopeCloseReturned': True,
                                                            'afterUnknownProbes': 0,
                                                            'cancelledAfterCommit': 1,
                                                            'committedCarrier': True,
                                                            'injections': 1,
                                                            'scopesClosed': 3},
                                               'outcome': {'effect': 'committed',
                                                           'journal': 'clean',
                                                           'reason': 'cancelled',
                                                           'resources': 'unknown'},
                                               'owner': {'closed': True, 'fatal': True, 'handlerRestored': True}}}

# Literal saved-version DATA from the frozen SOURCE coordination contract.
# Expected rows assert actual observations; they never supply an outcome.
_VERSION_CASES = {'committed-close': ('version-committed-close-return-injection',),
 'committed-fsync': ('version-committed-fsync-injection',),
 'ordinary': ('present-malformed-source-refused',
              'present-nonregular-source-refused',
              'legacy-seven-ignore-rules-refused',
              'config-retarget-before-prepare',
              'ignore-bytes-before-apply',
              'target-parent-inode-before-prepare',
              'target-parent-mode-before-apply',
              'missing-target-parent-appears-before-apply',
              'noop-leaf-ctime-after-recheck',
              'noop-target-parent-mode-after-recheck',
              'unreadable-source-before-prepare',
              'version-replacement-installed-rollback',
              'incomplete-version-preparing-retained',
              'committed-version-backup-replaced-at-cleanup-entry',
              'foreign-domains-refuse-version-prepare',
              'foreign-domains-refuse-version-ready',
              'foreign-domains-refuse-version-cleanup',
              'version-refuses-foreign-ready',
              'dependency-drift-after-version-install')}

_VERSION_SOURCES = {'apiContracts': 'src/mobile_release/api/contracts.py',
 'buildInputs': 'src/mobile_release/build_inputs.py',
 'cancellation': 'src/mobile_release/cancellation.py',
 'catalogue': 'src/mobile_release/api/_catalog.py',
 'configEdit': 'src/mobile_release/config_edit.py',
 'configPayloads': 'src/mobile_release/config_payloads.py',
 'configuration': 'src/mobile_release/config.py',
 'editControl': 'src/mobile_release/_desktop_edit_control.py',
 'editEngine': 'src/mobile_release/_desktop_edit_engine.py',
 'editProtocol': 'src/mobile_release/_desktop_edit_protocol.py',
 'errors': 'src/mobile_release/errors.py',
 'fixture': 'tests/native_desktop_config.py',
 'metadataEdit': 'src/mobile_release/metadata_text_edit.py',
 'metadataPolicy': 'src/mobile_release/metadata.py',
 'metadataText': 'src/mobile_release/metadata_text.py',
 'passiveEngine': 'src/mobile_release/_desktop_engine.py',
 'resource': 'src/mobile_release/api/data/release-version-help-v1.json',
 'rootCustody': 'src/mobile_release/init_workspace_custody.py',
 'snapshot': 'src/mobile_release/api/_snapshot.py',
 'transaction': 'src/mobile_release/init_transaction.py',
 'versionApi': 'src/mobile_release/api/_release_version.py',
 'versionEdit': 'src/mobile_release/release_version_edit.py',
 'versionText': 'src/mobile_release/version_text.py',
 'workflowEdit': 'src/mobile_release/github_workflow_edit.py',
 'workflowPayloads': 'src/mobile_release/workflow_payloads.py'}

_VERSION_CONFIG_TEXT = {'nestedVersion': '{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"public/version-tree/version.properties"}}\n',
 'publicVersion': '{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"public/version.properties"}}\n',
 'releaseVersion': '{"android":{"applicationId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"ios":{"bundleId":"org.fixture.app","enabled":true,"identityStatus":"unverified"},"metadata":{"androidLocales":["en-US","fr-FR"],"iosLocales":["en-US"],"root":"public/store"},"projectChecks":{"androidArtifact":[],"iosArtifact":[],"preflight":[]},"schemaVersion":1,"services":{"androidFirebase":"disabled","iosFirebase":"disabled"},"source":{"candidateBranch":"main","productionBranch":"production"},"version":{"buildKey":"BUILD_NUMBER","nameKey":"VERSION_NAME","source":"release/version.properties"}}\n'}

_VERSION_CONFIG_HASHES = {'nestedVersion': '8db69de9d4a3c83d312ee37e8952531f71b633f0f7f36b042b5d143cc2357de9',
 'publicVersion': '1dcd101a440da3c950903bca1b54f926aa63ce36ae5ed1eead5fb24f7813dfbd',
 'releaseVersion': '1b0b02e48d03cca36aaf36e5d8a8daf15f59924803bd4a5c0ec2e655828d3f94'}

_VERSION_PATHS = {'nestedVersion': 'public/version-tree/version.properties',
 'publicVersion': 'public/version.properties',
 'releaseVersion': 'release/version.properties'}

_VERSION_IGNORE = (b'.mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n.mobi'
 b'le-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n'
 b'.mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n')

_VERSION_IGNORE_SHA256 = 'cdf75f09188ea0e3712fcd26c9dbb42819dd467e9744676c6448b2a29a789c5b'

_VERSION_TEXT = {'created': 'VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n',
 'edited': '# Café\r\n VERSION_NAME = \'2.3.4\' \nBUILD_NUMBER = "8"\r\nOTHER = keep',
 'original': '# Café\r\n VERSION_NAME = \'1.2.3\' \nBUILD_NUMBER = "7"\r\nOTHER = keep'}

_VERSION_HASHES = {'created': '3b8dbd6b58e9f42a0ed893e73020cf2f8ddde787e2b1a153da49d382b1e7a9d4',
 'edited': 'bc7f934bcf5f4fcf0b1b9c814613bd773ec4a9f579376f1dca01929d4e9e3732',
 'original': 'd8453785b2637e76d1b7456dd0e5ea0d343cfd5f7d409a06dc38ab791aa6334a'}

_VERSION_VALUES = {'build': '8', 'name': '2.3.4'}

_VERSION_EXPECTED = {'committed-version-backup-replaced-at-cleanup-entry': {'case': 'committed-version-backup-replaced-at-cleanup-entry',
                                                        'observed': {'cleanupUnlinks': 0,
                                                                     'committedObserved': True,
                                                                     'dependenciesPreserved': True,
                                                                     'durabilityConfirmed': True,
                                                                     'injections': 1,
                                                                     'originalBackupRetained': True,
                                                                     'proofRetained': True,
                                                                     'sameBytesForeignInode': True,
                                                                     'scopesClosed': 3,
                                                                     'selectedPayloadInstalled': True},
                                                        'outcome': {'effect': 'committed',
                                                                    'journal': 'recovery_required',
                                                                    'reason': 'filesystem_error',
                                                                    'resources': 'settled'},
                                                        'owner': {'closed': True,
                                                                  'fatal': False,
                                                                  'handlerRestored': True}},
 'config-retarget-before-prepare': {'case': 'config-retarget-before-prepare',
                                    'observed': {'authorityRetired': True,
                                                 'changeObserved': True,
                                                 'journalAbsent': True,
                                                 'scopesClosed': 2,
                                                 'selectionNotRetargeted': True,
                                                 'snapshotUnchanged': True},
                                    'outcome': {'effect': 'not_started',
                                                'journal': 'not_created',
                                                'reason': 'stale_revision',
                                                'resources': 'settled'},
                                    'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'dependency-drift-after-version-install': {'case': 'dependency-drift-after-version-install',
                                            'observed': {'afterUnknownProbes': 0,
                                                         'cleanupUnlinks': 0,
                                                         'conflictObservedInsideOriginal': True,
                                                         'dependencyChanged': True,
                                                         'injections': 1,
                                                         'laterInstallMoves': 0,
                                                         'originalBackupBound': True,
                                                         'recoverCalls': 0,
                                                         'retainedTreeInsideOriginal': True,
                                                         'scopesClosed': 3,
                                                         'versionLeafInstalled': True},
                                            'outcome': {'effect': 'unknown',
                                                        'journal': 'recovery_required',
                                                        'reason': 'stale_revision',
                                                        'resources': 'settled'},
                                            'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'foreign-domains-refuse-version-cleanup': {'case': 'foreign-domains-refuse-version-cleanup',
                                            'observed': {'allOwnersSettled': True,
                                                         'entrypoints': ['legacy',
                                                                         'configuration',
                                                                         'github_workflows',
                                                                         'metadata_text'],
                                                         'legacyApplyRefused': True,
                                                         'legacyRecoverRefused': True,
                                                         'legacyWorkspaceClosed': True,
                                                         'originalOwners': 4,
                                                         'scopesClosed': 3,
                                                         'snapshotUnchanged': True,
                                                         'stateRetained': True,
                                                         'targetDescriptorsAbsent': True,
                                                         'typedRefusals': 3},
                                            'outcome': {'effect': 'not_started',
                                                        'journal': 'not_created',
                                                        'reason': 'pending_state',
                                                        'resources': 'settled'},
                                            'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'foreign-domains-refuse-version-prepare': {'case': 'foreign-domains-refuse-version-prepare',
                                            'observed': {'allOwnersSettled': True,
                                                         'entrypoints': ['legacy',
                                                                         'configuration',
                                                                         'github_workflows',
                                                                         'metadata_text'],
                                                         'legacyApplyRefused': True,
                                                         'legacyRecoverRefused': True,
                                                         'legacyWorkspaceClosed': True,
                                                         'originalOwners': 4,
                                                         'scopesClosed': 3,
                                                         'snapshotUnchanged': True,
                                                         'stateRetained': True,
                                                         'targetDescriptorsAbsent': True,
                                                         'typedRefusals': 3},
                                            'outcome': {'effect': 'not_started',
                                                        'journal': 'not_created',
                                                        'reason': 'pending_state',
                                                        'resources': 'settled'},
                                            'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'foreign-domains-refuse-version-ready': {'case': 'foreign-domains-refuse-version-ready',
                                          'observed': {'allOwnersSettled': True,
                                                       'entrypoints': ['legacy',
                                                                       'configuration',
                                                                       'github_workflows',
                                                                       'metadata_text'],
                                                       'legacyApplyRefused': True,
                                                       'legacyRecoverRefused': True,
                                                       'legacyWorkspaceClosed': True,
                                                       'originalOwners': 4,
                                                       'scopesClosed': 3,
                                                       'snapshotUnchanged': True,
                                                       'stateRetained': True,
                                                       'targetDescriptorsAbsent': True,
                                                       'typedRefusals': 3},
                                          'outcome': {'effect': 'not_started',
                                                      'journal': 'not_created',
                                                      'reason': 'pending_state',
                                                      'resources': 'settled'},
                                          'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'ignore-bytes-before-apply': {'case': 'ignore-bytes-before-apply',
                               'observed': {'authorityRetired': True,
                                            'changeObserved': True,
                                            'journalAbsent': True,
                                            'scopesClosed': 3,
                                            'selectionNotRetargeted': True,
                                            'snapshotUnchanged': True},
                               'outcome': {'effect': 'not_started',
                                           'journal': 'not_created',
                                           'reason': 'stale_revision',
                                           'resources': 'settled'},
                               'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'incomplete-version-preparing-retained': {'case': 'incomplete-version-preparing-retained',
                                           'observed': {'cleanupUnlinks': 0,
                                                        'completeProof': False,
                                                        'dependenciesPreserved': True,
                                                        'injections': 1,
                                                        'numberedSlotRetained': True,
                                                        'preparingRetained': True,
                                                        'recoverCalls': 0,
                                                        'scopesClosed': 3,
                                                        'targetPreserved': True},
                                           'outcome': {'effect': 'not_started',
                                                       'journal': 'recovery_required',
                                                       'reason': 'filesystem_error',
                                                       'resources': 'settled'},
                                           'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'legacy-seven-ignore-rules-refused': {'case': 'legacy-seven-ignore-rules-refused',
                                       'observed': {'journalAbsent': True,
                                                    'revisionAbsent': True,
                                                    'scopesClosed': 1,
                                                    'snapshotUnchanged': True,
                                                    'targetDescriptorAbsent': True},
                                       'outcome': {'effect': 'not_started',
                                                   'journal': 'not_created',
                                                   'reason': 'ignore_conflict',
                                                   'resources': 'settled'},
                                       'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'missing-target-parent-appears-before-apply': {'case': 'missing-target-parent-appears-before-apply',
                                                'observed': {'authorityRetired': True,
                                                             'changeObserved': True,
                                                             'journalAbsent': True,
                                                             'scopesClosed': 3,
                                                             'selectionNotRetargeted': True,
                                                             'snapshotUnchanged': True},
                                                'outcome': {'effect': 'not_started',
                                                            'journal': 'not_created',
                                                            'reason': 'stale_revision',
                                                            'resources': 'settled'},
                                                'owner': {'closed': True,
                                                          'fatal': False,
                                                          'handlerRestored': True}},
 'noop-leaf-ctime-after-recheck': {'case': 'noop-leaf-ctime-after-recheck',
                                   'observed': {'changedOnlyDeclaredFacts': True,
                                                'consumingTargetChecks': 1,
                                                'injections': 1,
                                                'journalAbsent': True,
                                                'recheckReturns': 1,
                                                'renameProbes': 0,
                                                'scopesClosed': 3,
                                                'snapshotUnchangedAfterInjection': True,
                                                'unchangedMarked': False},
                                   'outcome': {'effect': 'not_started',
                                               'journal': 'not_created',
                                               'reason': 'stale_revision',
                                               'resources': 'settled'},
                                   'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'noop-target-parent-mode-after-recheck': {'case': 'noop-target-parent-mode-after-recheck',
                                           'observed': {'changedOnlyDeclaredFacts': True,
                                                        'consumingTargetChecks': 1,
                                                        'injections': 1,
                                                        'journalAbsent': True,
                                                        'recheckReturns': 1,
                                                        'renameProbes': 0,
                                                        'scopesClosed': 3,
                                                        'snapshotUnchangedAfterInjection': True,
                                                        'unchangedMarked': False},
                                           'outcome': {'effect': 'not_started',
                                                       'journal': 'not_created',
                                                       'reason': 'stale_revision',
                                                       'resources': 'settled'},
                                           'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'present-malformed-source-refused': {'case': 'present-malformed-source-refused',
                                      'observed': {'journalAbsent': True,
                                                   'presentSourcePreserved': True,
                                                   'revisionBound': True,
                                                   'scopesClosed': 1,
                                                   'snapshotUnchanged': True,
                                                   'targetDescriptorBound': True},
                                      'outcome': {'effect': 'not_started',
                                                  'journal': 'not_created',
                                                  'reason': 'invalid_params',
                                                  'resources': 'settled'},
                                      'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'present-nonregular-source-refused': {'case': 'present-nonregular-source-refused',
                                       'observed': {'journalAbsent': True,
                                                    'presentSourcePreserved': True,
                                                    'revisionBound': False,
                                                    'scopesClosed': 1,
                                                    'snapshotUnchanged': True,
                                                    'targetDescriptorBound': True},
                                       'outcome': {'effect': 'not_started',
                                                   'journal': 'not_created',
                                                   'reason': 'filesystem_error',
                                                   'resources': 'settled'},
                                       'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'target-parent-inode-before-prepare': {'case': 'target-parent-inode-before-prepare',
                                        'observed': {'authorityRetired': True,
                                                     'changeObserved': True,
                                                     'journalAbsent': True,
                                                     'scopesClosed': 2,
                                                     'selectionNotRetargeted': True,
                                                     'snapshotUnchanged': True},
                                        'outcome': {'effect': 'not_started',
                                                    'journal': 'not_created',
                                                    'reason': 'stale_revision',
                                                    'resources': 'settled'},
                                        'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'target-parent-mode-before-apply': {'case': 'target-parent-mode-before-apply',
                                     'observed': {'authorityRetired': True,
                                                  'changeObserved': True,
                                                  'journalAbsent': True,
                                                  'scopesClosed': 3,
                                                  'selectionNotRetargeted': True,
                                                  'snapshotUnchanged': True},
                                     'outcome': {'effect': 'not_started',
                                                 'journal': 'not_created',
                                                 'reason': 'stale_revision',
                                                 'resources': 'settled'},
                                     'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'unreadable-source-before-prepare': {'case': 'unreadable-source-before-prepare',
                                      'observed': {'deniedOriginalReads': 1,
                                                   'journalAbsent': True,
                                                   'permissionErrorObserved': True,
                                                   'scopesClosed': 2,
                                                   'snapshotUnchanged': True},
                                      'outcome': {'effect': 'not_started',
                                                  'journal': 'not_created',
                                                  'reason': 'filesystem_error',
                                                  'resources': 'settled'},
                                      'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'version-committed-close-return-injection': {'case': 'version-committed-close-return-injection',
                                              'observed': {'actualScopeCloseReturned': True,
                                                           'afterUnknownProbes': 0,
                                                           'cancelledAfterCommit': 1,
                                                           'committedCarrier': True,
                                                           'injections': 1,
                                                           'scopesClosed': 3},
                                              'outcome': {'effect': 'committed',
                                                          'journal': 'clean',
                                                          'reason': 'cancelled',
                                                          'resources': 'unknown'},
                                              'owner': {'closed': True,
                                                        'fatal': True,
                                                        'handlerRestored': True}},
 'version-committed-fsync-injection': {'case': 'version-committed-fsync-injection',
                                       'observed': {'committedObserved': True,
                                                    'dependenciesPreserved': True,
                                                    'durabilityConfirmed': False,
                                                    'injections': 1,
                                                    'journalRetained': True,
                                                    'rollbackCalls': 0,
                                                    'scopesClosed': 3,
                                                    'selectedPayloadInstalled': True},
                                       'outcome': {'effect': 'committed',
                                                   'journal': 'recovery_required',
                                                   'reason': 'filesystem_error',
                                                   'resources': 'settled'},
                                       'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'version-refuses-foreign-ready': {'case': 'version-refuses-foreign-ready',
                                   'observed': {'allOwnersSettled': True,
                                                'bothRefused': True,
                                                'foreignDomains': ['legacy', 'metadata_text'],
                                                'foreignStateRetained': True,
                                                'originalOwners': 2,
                                                'scopesClosed': 2,
                                                'snapshotUnchanged': True,
                                                'targetDescriptorsAbsent': True,
                                                'versionStateAbsent': True},
                                   'outcome': {'effect': 'not_started',
                                               'journal': 'not_created',
                                               'reason': 'pending_state',
                                               'resources': 'settled'},
                                   'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}},
 'version-replacement-installed-rollback': {'case': 'version-replacement-installed-rollback',
                                            'observed': {'injections': 1,
                                                         'journalAbsent': True,
                                                         'originalBackupBound': True,
                                                         'recoveryAttempts': 1,
                                                         'rollbackReturned': True,
                                                         'scopesClosed': 3,
                                                         'secondApplyNoScope': True,
                                                         'secondApplyRefused': True,
                                                         'snapshotRestored': True,
                                                         'versionLeafInstalled': True},
                                            'outcome': {'effect': 'rolled_back',
                                                        'journal': 'clean',
                                                        'reason': 'filesystem_error',
                                                        'resources': 'settled'},
                                            'owner': {'closed': True, 'fatal': False, 'handlerRestored': True}}}


class FixtureRefused(Exception):
    pass


class FixtureUnknown(Exception):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise AssertionError("fixed configuration fixture assertion failed")


def document() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


@dataclass
class Runtime:
    edit: Any
    transaction: Any
    custody: Any
    build: Any
    cancellation: Any
    errors: Any
    payloads: Any
    domain: str = "configuration"
    workflow: Any = None
    workflow_payloads: Any = None
    workflow_setup: Any = None
    workflow_bytes: tuple[bytes, ...] = ()
    metadata: Any = None
    metadata_text: Any = None
    version: Any = None
    version_text: Any = None

    @property
    def ignore_bytes(self) -> bytes:
        return ("\n".join(self.transaction.IGNORE_LINES) + "\n").encode()


@dataclass
class Owner:
    guard: Any
    lease: Any
    domain: str = "configuration"
    outcome: Any = None
    closed: bool = False
    restored: bool = False
    fatal: bool = False


@dataclass
class Batch:
    runtime: Runtime
    root: Path
    partition: str
    blocked: bool = False
    retain: bool = False
    current: str = "startup"
    completed: list[str] = field(default_factory=list)
    owners: list[Owner] = field(default_factory=list)
    workflow_rows: list[dict[str, Any]] = field(default_factory=list)
    workflow_fixture_failed: bool = False
    workflow_after_unknown_probes: int = 0

    def case_root(self, name: str) -> Path:
        if self.blocked:
            raise FixtureUnknown()
        self.current = name
        root = self.root / name
        root.mkdir(mode=0o700)  # Exclusive fixed child, never an existing project.
        return root

    def record(self, owner: Owner, outcome: Any, *, expected_unknown: bool = False) -> Any:
        owner.outcome = outcome
        uncertain = (outcome.effect == "unknown" or outcome.journal == "unknown"
                     or outcome.resources == "unknown")
        if uncertain:
            self.blocked = self.retain = True
            if not expected_unknown:
                raise FixtureUnknown()
        if outcome.journal == "recovery_required":
            self.retain = True
        return outcome


@contextmanager
def owned_lease(batch: Batch, root: Path, *, expected_unknown: bool = False,
                registered_identity: dict[str, int] | None = None, domain: str | None = None):
    """Prearmed real guard/lease, with unconditional original cleanup dispatch."""
    if batch.blocked:
        raise FixtureUnknown()
    runtime = batch.runtime
    selected_domain = runtime.domain if domain is None else domain
    require(selected_domain in {"configuration", "github_workflows", "metadata_text", "release_version"})
    guard = runtime.cancellation.DefaultCancellation(runtime.errors.ValidationError, _GUARD_MESSAGE)
    if selected_domain == "configuration":
        require(registered_identity is None)
        lease = runtime.custody.InitRootLease(root, cancellation=guard)
    else:
        # Only this fixed fixture observes registration facts. No renderer,
        # argv, environment or supplied digest can provide root authority.
        identity = workflow_root_identity(root) if registered_identity is None else registered_identity
        profiles = {"github_workflows": runtime.transaction.TypedEditProfile.GITHUB_WORKFLOWS,
                    "metadata_text": runtime.transaction.TypedEditProfile.METADATA_TEXT,
                    "release_version": runtime.transaction.TypedEditProfile.RELEASE_VERSION}
        lease = runtime.custody.InitRootLease(root, cancellation=guard,
            profile=profiles[selected_domain], registered_identity=identity)
    owner = Owner(guard, lease, domain=selected_domain)
    batch.owners.append(owner)  # Retain even an incomplete/uncertain original.
    cleanup = runtime.cancellation.CleanupScope(
        guard, lease.close, owns_cancellation=True, first_primary=True)
    body_error = caught = None
    try:
        try:
            with cleanup:
                guard.install()
                guard.activate()
                lease.acquire()
                try:
                    yield owner
                except BaseException as error:
                    body_error = error
                    raise
        finally:
            cleanup.__exit__(*sys.exc_info())
    except BaseException as error:
        caught = error
    try:
        owner.closed = lease.closed is True
        owner.restored = guard.handler_state == "RESTORED"
        owner.fatal = guard.lifetime_ledger.fatal is True
    except BaseException:
        owner.fatal = True
    healthy = owner.closed and owner.restored and not owner.fatal
    if not healthy:
        batch.blocked = batch.retain = True
    if body_error is not None:
        raise body_error
    allowed = (expected_unknown and owner.outcome is not None
               and owner.outcome.effect == "committed" and owner.outcome.resources == "unknown")
    if allowed:
        # This does not clear sticky uncertainty or allow another owner. Even
        # late actual close returns do not manufacture a successful edit.
        batch.blocked = batch.retain = True
        return
    if not healthy:
        raise FixtureUnknown() from None
    if caught is not None:
        raise caught


@contextmanager
def actual_lock_holder(batch: Batch, root: Path, guard: Any, kind: str):
    """Use the actual existing init/build-input owners, never a bare flock."""
    require(kind in {"init", "build"})
    runtime = batch.runtime
    owner = (runtime.transaction.InitWorkspace(root) if kind == "init"
             else runtime.build._Project(root, guard, recovery=False))
    closed = False

    def close() -> None:
        nonlocal closed
        if kind == "init":
            owner.__exit__(None, None, None)
        else:
            owner.cleanup()
        closed = True  # Positive original call return, not just claimed state.

    cleanup = runtime.cancellation.CleanupScope(guard, close, owns_cancellation=False, first_primary=True)
    try:
        try:
            with cleanup:
                if kind == "init":
                    owner.__enter__()
                else:
                    owner.acquire()
                yield owner
        finally:
            cleanup.__exit__(*sys.exc_info())
    finally:
        if not closed or guard.lifetime_ledger.fatal:
            batch.blocked = batch.retain = True
            raise FixtureUnknown() from None
    if kind == "init":
        require(owner.fd == -1)
    else:
        require(owner.meta.close_state == "CLOSED")
        require(all(slot.close_state == "CLOSED" for slot in owner.directory.slots))


def seed(batch: Batch, root: Path, *, raw: bytes | None = None, ignore: bytes | None = None) -> None:
    (root / "release").mkdir(mode=0o700)
    config = root / "release/mobile-release.json"
    config.write_bytes(batch.runtime.payloads.serialize_config_data(document()) if raw is None else raw)
    config.chmod(0o640)
    ignored = root / ".gitignore"
    ignored.write_bytes(batch.runtime.ignore_bytes if ignore is None else ignore)
    ignored.chmod(0o600)
    (root / "unrelated.txt").write_bytes(b"fixed synthetic unrelated content\n")


def snapshot(root: Path) -> tuple[tuple[bytes, int, int, int], ...]:
    result = []
    for name in ("release/mobile-release.json", ".gitignore", "unrelated.txt"):
        path = root / name
        value = path.stat(follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode))
        result.append((path.read_bytes(), value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode)))
    return tuple(result)


def no_journal(batch: Batch, root: Path) -> None:
    require(all(not (root / name).exists() for name in batch.runtime.transaction.STATE_NAMES))


def prepared(batch: Batch, owner: Owner, draft: dict[str, Any] | None = None):
    edit = batch.runtime.edit
    checkout = edit.capture_config_edit(owner.lease)
    plan = edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base,
                                   document() if draft is None else draft)
    return checkout, plan


def refusal(batch: Batch, owner: Owner, reason: str, action) -> Any:
    try:
        action()
    except batch.runtime.edit.ConfigEditFailure as error:
        outcome = batch.record(owner, error.outcome)
        require((outcome.effect, outcome.journal, outcome.resources, outcome.reason)
                == ("not_started", "not_created", "settled", reason))
        return outcome
    raise AssertionError("fixed configuration refusal was not observed")


def create_case(batch: Batch) -> None:
    root = batch.case_root("create")
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout, plan = prepared(batch, owner)
        require(checkout.base is None and plan.view["createReleaseDirectory"] is True)
        require([item["action"] for item in plan.view["files"]] == ["create", "create"])
        require(not (root / "release").exists() and not (root / ".gitignore").exists())
        no_journal(batch, root)  # Real capture/prepare did not create staging.
        result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("committed", "clean", "settled", "none"))
        require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
    require((root / "release/mobile-release.json").read_bytes() == runtime.payloads.serialize_config_data(document()))
    require((root / ".gitignore").read_bytes() == runtime.ignore_bytes)
    require(sorted(path.name for path in root.iterdir()) == [".gitignore", "release"])
    require(sorted(path.name for path in (root / "release").iterdir()) == ["mobile-release.json"])
    no_journal(batch, root)
    batch.completed.append(batch.current)


def save_noop_ignore_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("save", "no-op", "ignore-append"):
        root = batch.case_root(kind)
        raw = b" \r\n" + json.dumps(document(), separators=(",", ":")).encode() + b"\r\n"
        ignore = (b"# retained synthetic comment\r\n/.mobile-release/\r\n" if kind == "ignore-append"
                  else ("\r\n".join("/" + line for line in runtime.transaction.IGNORE_LINES)).encode())
        seed(batch, root, raw=raw, ignore=ignore)
        before = snapshot(root)
        proposed = document()
        if kind == "save":
            proposed["source"]["projectReadTokenRequired"] = True
        with owned_lease(batch, root) as owner:
            _, plan = prepared(batch, owner, proposed)
            require(plan.view["rewritesConfigFormatting"] is (kind == "save"))
            require(plan.view["files"][0]["action"] == ("replace" if kind == "save" else "preserve"))
            require(plan.view["files"][1]["action"] == ("append" if kind == "ignore-append" else "preserve"))
            require(snapshot(root) == before)
            no_journal(batch, root)
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
            expected = ("unchanged", "not_created") if kind == "no-op" else ("committed", "clean")
            require((result.effect, result.journal) == expected and result.reason == "none")
        after = snapshot(root)
        require(after[2] == before[2])
        if kind != "save":
            require(after[0] == before[0])  # Actual bytes, device, inode, mode.
        else:
            require(after[0][0] == runtime.payloads.serialize_config_data(proposed))
            require(after[0][3] == before[0][3])
        if kind != "ignore-append":
            require(after[1] == before[1])
        else:
            require(after[1][0] == ignore + ("\n".join(runtime.transaction.IGNORE_LINES[1:]) + "\n").encode())
            require(after[1][3] == before[1][3])
        no_journal(batch, root)
        batch.completed.append(batch.current)


def refusal_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("ignore-conflict", "invalid-existing", "single-link-admission"):
        root = batch.case_root(kind)
        seed(batch, root, ignore=b"!unrelated.txt\n" if kind == "ignore-conflict" else None)
        if kind == "invalid-existing":
            invalid = document()
            invalid["schemaVersion"] = 2
            (root / "release/mobile-release.json").write_bytes(runtime.payloads.serialize_config_data(invalid))
        if kind == "single-link-admission":
            os.link(root / "release/mobile-release.json", root / "second-link.json")
        before = snapshot(root)
        with owned_lease(batch, root) as owner:
            if kind == "ignore-conflict":
                checkout = runtime.edit.capture_config_edit(owner.lease)
                refusal(batch, owner, "ignore_conflict", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
            else:
                reason = "invalid_config" if kind == "invalid-existing" else "filesystem_error"
                refusal(batch, owner, reason, lambda: runtime.edit.capture_config_edit(owner.lease))
        require(snapshot(root) == before)
        no_journal(batch, root)
        batch.completed.append(batch.current)


def stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("stale-config-bytes", "stale-config-inode", "stale-ignore-after-prepare",
                 "stale-release", "absent-release-appeared", "stale-root"):
        root = batch.case_root(kind)
        if kind != "absent-release-appeared":
            seed(batch, root)
        with owned_lease(batch, root) as owner:
            checkout = runtime.edit.capture_config_edit(owner.lease)
            if kind == "stale-ignore-after-prepare":
                plan = runtime.edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base, document())
                (root / ".gitignore").write_bytes(runtime.ignore_bytes + b"# changed after review\n")
                result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
                require((result.effect, result.journal, result.reason) == ("not_started", "not_created", "stale_revision"))
                require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
            else:
                config = root / "release/mobile-release.json"
                if kind == "stale-config-bytes":
                    config.write_bytes(config.read_bytes() + b" \n")
                elif kind == "stale-config-inode":
                    original_inode = config.stat().st_ino
                    replacement = root / "replacement.json"
                    replacement.write_bytes(config.read_bytes())
                    replacement.chmod(0o640)
                    replacement.replace(config)
                    require(config.stat().st_ino != original_inode)
                elif kind == "stale-release":
                    (root / "release").rename(root / "original-release")
                    (root / "release").mkdir(mode=0o700)
                    config.write_bytes(runtime.payloads.serialize_config_data(document()))
                elif kind == "absent-release-appeared":
                    (root / "release").mkdir(mode=0o700)
                elif kind == "stale-root":
                    root.rename(batch.root / "original-stale-root")
                    root.mkdir(mode=0o700)
                refusal(batch, owner, "stale_revision", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
                refusal(batch, owner, "invalid_params", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
        no_journal(batch, root)
        batch.completed.append(batch.current)


def pending_cases(batch: Batch) -> None:
    runtime = batch.runtime
    entries = [("init-" + str(index), name, True) for index, name in enumerate(runtime.transaction.STATE_NAMES)]
    entries += [("build-pending", ".mobile-release/build-inputs", True),
                ("build-terminal", ".mobile-release/build-inputs-complete.json", False),
                ("build-stage", ".mobile-release/build-inputs-complete.stage", False),
                ("init-alias", ".MOBILE-RELEASE-INIT", True),
                ("malformed-private-mode", ".mobile-release", True)]
    for label, relative, directory in entries:
        root = batch.case_root(label)
        path = root / relative
        if "/" in relative:
            path.parent.mkdir(mode=0o700)
        if directory:
            path.mkdir(mode=0o700)
        else:
            path.write_bytes(b"fixed synthetic reserved state\n")
            path.chmod(0o600)
        if label == "malformed-private-mode":
            path.chmod(0o755)
        original = path.stat(follow_symlinks=False)
        with owned_lease(batch, root) as owner:
            refusal(batch, owner, "pending_state", lambda: runtime.edit.capture_config_edit(owner.lease))
        after = path.stat(follow_symlinks=False)
        require((after.st_dev, after.st_ino, after.st_mode) == (original.st_dev, original.st_ino, original.st_mode))
        require(not (root / "release").exists() and not (root / ".gitignore").exists())
        batch.completed.append(batch.current)


def contention_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("init", "build"):
        root = batch.case_root("contention-" + kind)
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, kind):
                refusal(batch, owner, "busy", lambda: runtime.edit.capture_config_edit(owner.lease))
        no_journal(batch, root)
        batch.completed.append(batch.current)
    root = batch.case_root("idle-review-unlocked")
    seed(batch, root)
    with owned_lease(batch, root) as owner:
        checkout = runtime.edit.capture_config_edit(owner.lease)
        with actual_lock_holder(batch, root, owner.guard, "build"):
            pass  # A real build-input lock is available after capture.
        plan = runtime.edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base, document())
        with actual_lock_holder(batch, root, owner.guard, "init"):
            pass  # A real init lock is also available during plan review.
        runtime.edit.discard_config_edit(plan)
        require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
    no_journal(batch, root)
    batch.completed.append(batch.current)


def prepublication_rollback_case(batch: Batch) -> None:
    root = batch.case_root("precommit-publication-injection")
    seed(batch, root, ignore=b"# original ignore\n")
    before = snapshot(root)
    runtime = batch.runtime
    original = runtime.transaction.InitWorkspace._publish_terminal
    events = {"injected": 0, "rollback_verified": 0}

    def publish(workspace, fd, plan, state):
        if state == "COMMITTED":
            events["injected"] += 1
            raise OSError("fixed precommit publication injection")
        result = original(workspace, fd, plan, state)
        if state == "ROLLED_BACK" and workspace._terminal_seen == "ROLLED_BACK":
            events["rollback_verified"] += 1
        return result

    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root) as owner:
        _, plan = prepared(batch, owner, proposed)
        with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("rolled_back", "clean", "settled", "filesystem_error"))
        require(events == {"injected": 1, "rollback_verified": 1})
    require(snapshot(root) == before)  # Real original inodes, not regenerated bytes.
    no_journal(batch, root)
    batch.completed.append(batch.current)


def legacy_public_apply_cases(batch: Batch) -> None:
    """Protect the unborrowed public API, not just the new typed edit route."""
    runtime = batch.runtime
    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    payload = runtime.payloads.serialize_config_data(proposed)
    original_publish = runtime.transaction.InitWorkspace._publish_terminal
    for kind in ("legacy-public-commit", "legacy-public-rollback"):
        root = batch.case_root(kind)
        seed(batch, root)
        before = snapshot(root)
        events = {"injected": 0, "rollback_verified": 0}
        injected = OSError("fixed legacy precommit publication injection")

        def publish(workspace, fd, plan, state):
            if state == "COMMITTED" and events["injected"] == 0:
                require(workspace._guard is None and workspace._scope is None)
                # The real public apply has already installed the replacement;
                # only terminal publication fails. Recovery is never replaced.
                require((root / "release/mobile-release.json").read_bytes() == payload)
                events["injected"] += 1
                raise injected
            result = original_publish(workspace, fd, plan, state)
            if state == "ROLLED_BACK" and workspace._terminal_seen == "ROLLED_BACK":
                events["rollback_verified"] += 1
            return result

        # An idle lease owns the guard/root but no short flock. The existing
        # legacy lock holder supplies the original public workspace and its
        # positive __exit__ receipt, including the exceptional cleanup path.
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, "init") as workspace:
                require(workspace._guard is None and workspace._scope is None)
                changes = [(workspace.observe("release/mobile-release.json"), payload),
                           (workspace.observe(".gitignore"), None)]
                if kind == "legacy-public-rollback":
                    with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish):
                        try:
                            workspace.apply(changes)
                        except runtime.errors.ValidationError as error:
                            require(error.__cause__ is injected)
                        else:
                            raise AssertionError("fixed legacy apply failure was not observed")
                    require(events == {"injected": 1, "rollback_verified": 1})
                else:
                    require(workspace.apply(changes) is None)
        after = snapshot(root)
        if kind == "legacy-public-rollback":
            require(after == before)  # Original bytes, device/inode and mode.
        else:
            require(after[0][0] == payload and after[0][3] == before[0][3]
                    and after[0][2] != before[0][2] and after[1:] == before[1:])
        no_journal(batch, root)
        require(sorted(path.name for path in root.iterdir()) == [".gitignore", "release", "unrelated.txt"])
        require(sorted(path.name for path in (root / "release").iterdir()) == ["mobile-release.json"])
        batch.completed.append(batch.current)


def committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("committed-fsync-injection")
    seed(batch, root)
    runtime = batch.runtime
    original_fsync = runtime.transaction.InitWorkspace._fsync
    original_rollback = runtime.transaction.InitWorkspace._rollback
    events = {"injected": 0, "rollback_calls": 0}

    def fsync(workspace, fd):
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injected"] == 0):
            events["injected"] += 1
            raise OSError("fixed postdecision pre-fsync injection")
        return original_fsync(workspace, fd)

    def rollback(workspace, *args):
        events["rollback_calls"] += 1
        return original_rollback(workspace, *args)

    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root) as owner:
        _, plan = prepared(batch, owner, proposed)
        with patch.object(runtime.transaction.InitWorkspace, "_fsync", fsync), \
             patch.object(runtime.transaction.InitWorkspace, "_rollback", rollback):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("committed", "recovery_required", "settled", "filesystem_error"))
        require(events == {"injected": 1, "rollback_calls": 0})
    require((root / "release/mobile-release.json").read_bytes() == runtime.payloads.serialize_config_data(proposed))
    require((root / runtime.transaction.READY / "COMMITTED").is_file())
    batch.retain = True  # No recovery, no deleting a retained real journal.
    batch.completed.append(batch.current)


def committed_close_case(batch: Batch) -> None:
    root = batch.case_root("committed-close-return-injection")
    seed(batch, root)
    runtime = batch.runtime
    original_close = runtime.custody.LockedInitScope.close
    original_publish = runtime.transaction.InitWorkspace._publish_terminal
    original_apply = runtime.transaction.InitWorkspace.apply_typed
    events = {"injected": 0, "actual_scope_close_returned": False,
              "cancelled_after_commit": 0, "committed_carrier": False}
    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = prepared(batch, owner, proposed)

        def publish(workspace, fd, manifest, state):
            result = original_publish(workspace, fd, manifest, state)
            if state == "COMMITTED":
                require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                events["cancelled_after_commit"] += 1
                owner.guard.cancelled = True
                raise KeyboardInterrupt  # Deterministic original-guard cancellation injection.
            return result

        def apply(workspace, changes):
            try:
                return original_apply(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                events["committed_carrier"] = (error.outcome.effect == "committed"
                                                and error.outcome.reason == "cancelled")
                raise  # Preserve the real thrown carrier before scope close fails.

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injected"] == 0:
                original_close(scope)
                events["actual_scope_close_returned"] = True
                events["injected"] += 1
                # Deterministic wrapper return loss AFTER actual close, not a
                # claim that the OS closed ambiguously or failed to close.
                raise OSError("fixed positive scope-close return loss injection")
            return original_close(scope)

        with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish), \
             patch.object(runtime.transaction.InitWorkspace, "apply_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan), expected_unknown=True)
        require(result.effect == "committed" and result.resources == "unknown" and result.reason == "cancelled")
        require(events == {"injected": 1, "actual_scope_close_returned": True,
                           "cancelled_after_commit": 1, "committed_carrier": True})
        # No Apply again, filesystem reobserver, fresh owner or native admission
        # follows this uncertainty. Only original prearmed cleanup still runs.
    require(owner.closed and owner.restored and owner.fatal)
    require(batch.blocked and batch.retain)
    batch.completed.append(batch.current)


def workflow_document() -> dict[str, Any]:
    draft = document()
    draft["source"]["productionBranch"] = "production"
    return draft


def workflow_root_identity(root: Path) -> dict[str, int]:
    if type(_RETAINED_BATCH) is Batch and _RETAINED_BATCH.runtime.domain in {"github_workflows", "metadata_text", "release_version"}:
        workflow_probe(_RETAINED_BATCH)
    value = root.stat(follow_symlinks=False)
    require(stat.S_ISDIR(value.st_mode))
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
                uid=value.st_uid, gid=value.st_gid)


def workflow_read(path: Path, limit: int) -> bytes:
    """Bounded fixture DATA only; no symlink/special-file read or chmod retry."""
    if type(_RETAINED_BATCH) is Batch and _RETAINED_BATCH.runtime.domain in {"github_workflows", "metadata_text", "release_version"}:
        workflow_probe(_RETAINED_BATCH)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit)

    def facts(value):
        # A read may update atime; it must not change bytes, object or permissions.
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def opener(name, flags):
        return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)

    with open(path, "rb", opener=opener) as stream:
        opened = os.fstat(stream.fileno())
        require(facts(opened) == facts(before))
        data = stream.read(limit + 1)
        require(facts(os.fstat(stream.fileno())) == facts(opened))
    require(facts(path.stat(follow_symlinks=False)) == facts(before) and len(data) == before.st_size)
    return data


def workflow_probe(batch: Batch) -> None:
    # Shared fixed native DATA readers deny probes after the outcome latch.
    # The original prearmed native closes are not fixture probes or new owners.
    if batch.blocked:
        batch.workflow_after_unknown_probes += 1
        raise FixtureUnknown()


def workflow_snapshot(batch: Batch, root: Path, *, raw_files: bool = False) -> tuple[Any, ...]:
    """Small private tree, lstat traversal; bytes/paths never enter the receipt.

    Directory timestamps/size are deliberately not equality evidence: a clean
    rollback changes directory metadata without replacing any original inode.
    Unreadable files and FIFOs are observed by lstat only, never opened.
    """
    workflow_probe(batch)
    rows: list[Any] = []
    total = 0

    def visit(path: Path, name: str, depth: int) -> None:
        nonlocal total
        require(depth <= 8 and len(rows) < 128)
        value = path.stat(follow_symlinks=False)
        identity = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink)
        if stat.S_ISDIR(value.st_mode):
            rows.append((name, identity))
            names = sorted(item.name for item in path.iterdir())
            require(len(names) <= 128)
            for child in names:
                visit(path / child, child if name == "." else name + "/" + child, depth + 1)
        elif stat.S_ISREG(value.st_mode):
            require(value.st_size <= 2 * 1024 * 1024)
            data = workflow_read(path, 2 * 1024 * 1024) if value.st_mode & 0o444 else None
            total += len(data) if data is not None else 0
            require(total <= 16 * 1024 * 1024)
            row = (name, identity, value.st_size, data)
            rows.append((*row, value.st_mtime_ns, value.st_ctime_ns) if raw_files else row)
        elif stat.S_ISLNK(value.st_mode):
            target = os.readlink(path)
            require(len(os.fsencode(target)) <= 4096)
            rows.append((name, identity, target))
        else:
            require(stat.S_ISFIFO(value.st_mode))
            rows.append((name, identity))
    visit(root, ".", 0)
    return tuple(rows)


def workflow_absent(batch: Batch, path: Path) -> bool:
    workflow_probe(batch)
    try:
        path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def workflow_journal_absent(batch: Batch, root: Path) -> bool:
    return all(workflow_absent(batch, root / name) for name in batch.runtime.transaction.STATE_NAMES)


def workflow_seed(batch: Batch, root: Path, *, directories: bool = False,
                  first_exact: bool = False) -> None:
    workflow_probe(batch)
    seed(batch, root, raw=_WORKFLOW_DISK_CONFIG, ignore=_WORKFLOW_IGNORE)
    if directories or first_exact:
        (root / ".github").mkdir(mode=0o750)
        (root / ".github/workflows").mkdir(mode=0o750)
        # Make the later mode-change case deterministic under hosted umask 077.
        # This is initial fixture creation, never a chmod-around-read-denial.
        (root / ".github").chmod(0o750)
        (root / ".github/workflows").chmod(0o750)
    if first_exact:
        path = root / _WORKFLOW_FILES[0][1]
        path.write_bytes(batch.runtime.workflow_bytes[0])
        path.chmod(0o640)


def workflow_prepare(batch: Batch, owner: Owner, checkout=None):
    runtime = batch.runtime
    if checkout is None:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
    plan = runtime.workflow.prepare_github_workflow_edit(owner.lease, checkout, checkout.revision,
        workflow_document(), _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
    require(type(plan) is runtime.workflow.PreparedWorkflowEdit)
    view = plan.view
    require(tuple((row["id"], row["path"]) for row in view["files"]) == _WORKFLOW_FILES
            and tuple(row["generated"]["content"].encode("utf-8") for row in view["files"])
            == runtime.workflow_bytes and view["templateSet"] == _WORKFLOW_TEMPLATE_SET)
    return checkout, plan


def workflow_scopes_closed(owner: Owner) -> int:
    return sum(scope.closed is True and scope.claimed is True
               and scope.lock.close_state == "CLOSED" and scope.meta.close_state == "CLOSED"
               and scope.workspace is not None
               and all(slot.close_state == "CLOSED" for slot in scope.workspace._slots)
               for scope in owner.lease._scopes)


def workflow_equal(actual: Any, expected: Any) -> bool:
    """Strict assertion equality (bool is not int), not a receipt authority."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(workflow_equal(actual[k], v) for k, v in expected.items())
    if type(expected) in {tuple, list}:
        return len(actual) == len(expected) and all(workflow_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def workflow_finish(batch: Batch, owner: Owner, outcome: Any, expected: tuple[str, ...],
                    observed: dict[str, Any], expected_facts: dict[str, Any]) -> None:
    """Only actual projections are emitted; expected constants only assert."""
    if batch.workflow_fixture_failed:
        raise FixtureUnknown()
    require(type(outcome) in {batch.runtime.edit.CoreEditOutcome, batch.runtime.transaction.InitApplyOutcome})
    actual = (outcome.effect, outcome.journal, outcome.resources, outcome.reason)
    require(actual == expected and owner.outcome is outcome and workflow_equal(observed, expected_facts))
    owner_view = {"closed": owner.closed, "handlerRestored": owner.restored, "fatal": owner.fatal}
    require(workflow_equal(owner_view, {"closed": True, "handlerRestored": True,
                                      "fatal": expected[2] == "unknown"}))
    uncertain = expected[0] == "unknown" or expected[2] == "unknown"
    require(batch.blocked is uncertain and (not uncertain or batch.retain))
    domains = {"github_workflows": _WORKFLOW_CASES, "metadata_text": _METADATA_CASES, "release_version": _VERSION_CASES}
    require(batch.runtime.domain in domains)
    names = domains[batch.runtime.domain][batch.partition]
    require(len(batch.workflow_rows) < len(names) and batch.current == names[len(batch.workflow_rows)])
    row = {"case": batch.current,
           "outcome": dict(zip(("effect", "journal", "resources", "reason"), actual)),
           "owner": owner_view, "observed": observed}
    require(len(json.dumps(row, allow_nan=False, separators=(",", ":")).encode("utf-8")) <= 2048)
    batch.workflow_rows.append(row)
    batch.completed.append(batch.current)


@contextmanager
def workflow_witness(batch: Batch):
    """A broken injection/observer can never pass as the intended native fault.

    Intentional faults are raised OUTSIDE this scope. The real transaction may
    swallow a recovery exception, so fixture errors latch independently of its
    provisional outcome and end every later admission.
    """
    try:
        workflow_probe(batch)
        yield
    except BaseException:
        batch.workflow_fixture_failed = batch.blocked = batch.retain = True
        raise


def workflow_original(batch: Batch, owner: Owner, workspace: Any) -> None:
    require(type(workspace) is batch.runtime.transaction.InitWorkspace
            and workspace._scope is not None and workspace._scope.lease is owner.lease
            and workspace._guard is owner.guard and workspace._typed_claimed
            and workspace._typed_profile is batch.runtime.transaction.TypedEditProfile.GITHUB_WORKFLOWS)


def workflow_installed(batch: Batch, root: Path, workspace: Any) -> bool:
    workflow_probe(batch)
    require(workspace is not None and workspace._workflow_complete and workspace._workflow_plan is not None)
    manifest = json.loads(workspace._workflow_plan)  # Original frozen proof, not a journal re-parse.
    require(tuple(row["path"] for row in manifest["files"]) == tuple(path for _, path in _WORKFLOW_FILES))
    for (_, path), data, row in zip(_WORKFLOW_FILES, batch.runtime.workflow_bytes, manifest["files"]):
        after = row["after"]
        require(row["before"] is None and type(after) is dict)
        value = (root / path).stat(follow_symlinks=False)
        # New regular files honor the inherited umask (077 in this hosted lane).
        # Compare actual original staged mode/inode, never assume mode 0644.
        if (workflow_read(root / path, 16 * 1024) != data or after["sha256"] != hashlib.sha256(data).hexdigest()
                or (value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_size)
                != (after["device"], after["inode"], after["mode"], len(data))):
            return False
    return True


def workflow_capture_case(batch: Batch) -> None:
    root = batch.case_root("capture-prepare-discard")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    disk_before = snapshot(root)[0]
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout, plan = workflow_prepare(batch, owner)
        require(plan.view["createDirectories"] == [".github", ".github/workflows"]
                and [row["action"] for row in plan.view["files"]] == ["create"] * 4)
        require(workflow_snapshot(batch, root) == before and workflow_journal_absent(batch, root))
        runtime.workflow.discard_github_workflow_edit(plan)
        retired = plan._state == checkout._state == runtime.edit._RETIRED
        require(runtime.workflow.apply_github_workflow_edit(owner.lease, plan).reason == "invalid_params")
        result = batch.record(owner, owner.lease.last_outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "scopesClosed": workflow_scopes_closed(owner), "discardRetired": retired,
                "diskConfigUnchanged": snapshot(root)[0] == disk_before}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "scopesClosed": 2,
         "discardRetired": True, "diskConfigUnchanged": True})


def workflow_conflict_case(batch: Batch) -> None:
    root = batch.case_root("existing-differs")
    workflow_seed(batch, root, directories=True)
    (root / _WORKFLOW_FILES[0][1]).write_bytes(b"fixed differing workflow; never replace\n")
    before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
        conflict = runtime.workflow.prepare_github_workflow_edit(owner.lease, checkout, checkout.revision,
            workflow_document(), _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
        require(type(conflict) is runtime.workflow.WorkflowConflict)
        result = batch.record(owner, conflict.outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "conflictIds": [row["id"] for row in conflict.view["conflicts"]],
                "tokenAbsent": not hasattr(conflict, "token") and checkout._prepared is None,
                "rechecks": owner.lease._rechecks}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "conflictIds": ["preflight"],
         "tokenAbsent": True, "rechecks": 1})


def workflow_observation_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("oversized", "unreadable", "symlink-leaf", "symlink-ancestor", "hardlink",
                 "aliased-leaf", "nonregular-fifo"):
        root = batch.case_root(kind)
        workflow_seed(batch, root, directories=kind != "symlink-ancestor")
        leaf = root / _WORKFLOW_FILES[0][1]
        if kind == "oversized":
            leaf.write_bytes(b"x" * (runtime.workflow_setup.MAX_SNAPSHOT_FILE_BYTES + 1))
        elif kind == "unreadable":
            leaf.write_bytes(b"fixed unreadable workflow\n")
            leaf.chmod(0)
        elif kind == "symlink-leaf":
            leaf.symlink_to("../../unrelated.txt")
        elif kind == "symlink-ancestor":
            (root / "workflow-link-target").mkdir(mode=0o700)
            (root / ".github").symlink_to("workflow-link-target", target_is_directory=True)
        elif kind == "hardlink":
            os.link(root / "unrelated.txt", leaf)
        elif kind == "aliased-leaf":
            leaf.with_name(leaf.name.upper()).write_bytes(b"fixed aliased workflow\n")
        else:
            os.mkfifo(leaf, mode=0o600)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            result = refusal(batch, owner, "filesystem_error",
                             lambda: runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "journalAbsent": workflow_journal_absent(batch, root),
                    "observationRefused": result is owner.outcome and owner.lease._revision is None}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "filesystem_error"),
            observed, {"snapshotUnchanged": True, "journalAbsent": True, "observationRefused": True})


def workflow_registered_root_case(batch: Batch) -> None:
    root = batch.case_root("registered-root-replaced")
    workflow_seed(batch, root, first_exact=True)
    registered = workflow_root_identity(root)
    original_before = workflow_snapshot(batch, root)
    original = batch.root / "registered-root-original"
    root.rename(original)
    root.mkdir(mode=0o700)
    workflow_seed(batch, root)
    replacement_before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    observe_original = runtime.transaction.InitWorkspace.observe
    events = {"targetObservations": 0}

    def observe(workspace, *args, **kwargs):
        events["targetObservations"] += 1
        return observe_original(workspace, *args, **kwargs)

    count = len(batch.owners)
    with patch.object(runtime.transaction.InitWorkspace, "observe", observe):
        try:
            with owned_lease(batch, root, registered_identity=registered) as owner:
                runtime.workflow.capture_github_workflow_edit(owner.lease)
        except runtime.transaction.InitOperationFailure as error:
            require(type(error) is runtime.transaction.InitOperationFailure and len(batch.owners) == count + 1)
            owner = batch.owners[count]
            result = batch.record(owner, error.outcome)
        else:
            raise AssertionError("fixed registration replacement was not refused")
    observed = {"targetObservations": events["targetObservations"],
                "registeredIdentityChanged": workflow_root_identity(root) != registered,
                "replacementUnchanged": workflow_snapshot(batch, root) == replacement_before,
                "originalUnchanged": workflow_snapshot(batch, original) == original_before,
                "journalAbsent": workflow_journal_absent(batch, root) and workflow_journal_absent(batch, original)}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "stale_revision"), observed,
        {"targetObservations": 0, "registeredIdentityChanged": True, "replacementUnchanged": True,
         "originalUnchanged": True, "journalAbsent": True})


def workflow_stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("stale-leaf-bytes-before-prepare", "stale-leaf-inode-before-apply",
                 "stale-ancestor-mode-before-prepare", "absent-ancestor-before-prepare",
                 "absent-leaf-before-apply", "stale-root-before-apply"):
        root = batch.case_root(kind)
        workflow_seed(batch, root, directories=kind != "absent-ancestor-before-prepare",
                      first_exact=kind in {"stale-leaf-bytes-before-prepare", "stale-leaf-inode-before-apply"})
        original = None
        original_before = None
        at_apply = kind.endswith("before-apply")
        with owned_lease(batch, root) as owner:
            checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
            plan = workflow_prepare(batch, owner, checkout)[1] if at_apply else None
            leaf = root / _WORKFLOW_FILES[0][1]
            if kind == "stale-leaf-bytes-before-prepare":
                leaf.write_bytes(runtime.workflow_bytes[0] + b"# fixed later edit\n")
            elif kind == "stale-leaf-inode-before-apply":
                before_inode = leaf.stat(follow_symlinks=False).st_ino
                replacement = root / "replacement-workflow.yml"
                with replacement.open("xb") as stream:
                    stream.write(runtime.workflow_bytes[0])
                replacement.chmod(0o640)
                replacement.replace(leaf)
                require(leaf.stat(follow_symlinks=False).st_ino != before_inode)
            elif kind == "stale-ancestor-mode-before-prepare":
                (root / ".github/workflows").chmod(0o700)
            elif kind == "absent-ancestor-before-prepare":
                (root / ".github").mkdir(mode=0o700)
            elif kind == "absent-leaf-before-apply":
                leaf.write_bytes(runtime.workflow_bytes[0])
                leaf.chmod(0o640)
            else:
                original = batch.root / "stale-root-original"
                root.rename(original)
                original_before = workflow_snapshot(batch, original)
                root.mkdir(mode=0o700)
                workflow_seed(batch, root)
            before = workflow_snapshot(batch, root)  # After the deliberate external edit.
            if at_apply:
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
                retired = plan._state == checkout._state == runtime.edit._RETIRED
                require(runtime.workflow.apply_github_workflow_edit(owner.lease, plan).reason == "invalid_params")
            else:
                result = refusal(batch, owner, "stale_revision", lambda: workflow_prepare(batch, owner, checkout))
                retired = checkout._state == runtime.edit._RETIRED and checkout._prepared is None
        unchanged = workflow_snapshot(batch, root) == before
        absent = workflow_journal_absent(batch, root)
        if original is not None:
            unchanged = unchanged and workflow_snapshot(batch, original) == original_before
            absent = absent and workflow_journal_absent(batch, original)
        observed = {"snapshotUnchanged": unchanged, "journalAbsent": absent,
                    "rechecks": owner.lease._rechecks, "retired": retired}
        # Root check precedes workspace_scope's increment: that case has only
        # its original successful Prepare recheck, not a fictional Apply scope.
        rechecks = 2 if at_apply and kind != "stale-root-before-apply" else 1
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "stale_revision"),
            observed, {"snapshotUnchanged": True, "journalAbsent": True, "rechecks": rechecks, "retired": True})


def workflow_pending_cases(batch: Batch) -> None:
    for kind in ("init", "build"):
        root = batch.case_root("pending-" + kind)
        workflow_seed(batch, root)
        if kind == "init":
            (root / batch.runtime.transaction.READY).mkdir(mode=0o700)
        else:
            (root / ".mobile-release").mkdir(mode=0o700)
            (root / ".mobile-release/build-inputs").mkdir(mode=0o700)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            result = refusal(batch, owner, "pending_state",
                lambda: batch.runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "noTargetsCreated": workflow_absent(batch, root / ".github")}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "pending_state"),
            observed, {"snapshotUnchanged": True, "noTargetsCreated": True})


def workflow_holder_closed(holder: Any, kind: str) -> bool:
    if kind == "init":
        return holder.fd == -1
    return (holder.claimed is True and holder.meta.close_state == "CLOSED"
            and all(slot.close_state == "CLOSED" for slot in holder.directory.slots))


def workflow_contention_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("init", "build"):
        root = batch.case_root("contention-" + kind)
        workflow_seed(batch, root)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, kind) as holder:
                result = refusal(batch, owner, "busy",
                    lambda: runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "journalAbsent": workflow_journal_absent(batch, root),
                    "holderClosed": workflow_holder_closed(holder, kind)}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "busy"), observed,
            {"snapshotUnchanged": True, "journalAbsent": True, "holderClosed": True})
    root = batch.case_root("review-unlocked")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    with owned_lease(batch, root) as owner:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
        with actual_lock_holder(batch, root, owner.guard, "build") as build_holder:
            pass
        _, plan = workflow_prepare(batch, owner, checkout)
        with actual_lock_holder(batch, root, owner.guard, "init") as init_holder:
            pass
        runtime.workflow.discard_github_workflow_edit(plan)
        retired = checkout._state == plan._state == runtime.edit._RETIRED
        result = batch.record(owner, owner.lease.last_outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "holdersClosed": sum((workflow_holder_closed(build_holder, "build"),
                                      workflow_holder_closed(init_holder, "init"))),
                "scopesClosed": workflow_scopes_closed(owner), "discardRetired": retired}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "holdersClosed": 2,
         "scopesClosed": 2, "discardRetired": True})


def workflow_partial_rollback_case(batch: Batch) -> None:
    root = batch.case_root("partial-install-rollback")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    recovery_original = workspace_type._fixed_recovery
    events = {"firstLeafInstalled": False, "rollbackReturned": False, "injections": 0, "recoveryAttempts": 0}

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started
                        and destination == Path(_WORKFLOW_FILES[0][1]).name)
                leaf = root / _WORKFLOW_FILES[0][1]
                installed = leaf.stat(follow_symlinks=False)
                events["firstLeafInstalled"] = (workflow_read(leaf, 16 * 1024) == runtime.workflow_bytes[0]
                    and (installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["injections"] += 1
            raise OSError("fixed first-workflow-installed injection")
        return value

    def rollback(workspace, *args):
        value = rollback_original(workspace, *args)
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            events["rollbackReturned"] = workspace._terminal_seen == "ROLLED_BACK" and workspace._terminal_durable
        return value

    def recovery(workspace):
        events["recoveryAttempts"] += 1
        return recovery_original(workspace)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "_rollback", rollback), \
             patch.object(workspace_type, "_fixed_recovery", recovery):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    observed = {**events, "snapshotRestored": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root)}
    workflow_finish(batch, owner, result, ("rolled_back", "clean", "settled", "filesystem_error"), observed,
        {"firstLeafInstalled": True, "rollbackReturned": True, "injections": 1, "recoveryAttempts": 1,
         "snapshotRestored": True, "journalAbsent": True})


def workflow_incomplete_case(batch: Batch) -> None:
    root = batch.case_root("incomplete-preparing")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    write_original, recover_original, unlink_original = workspace_type._write, workspace_type.recover, workspace_type._unlink
    events = {"recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    original_workspace = None

    def write(workspace, fd, name, data, mode=0o600, **kwargs):
        nonlocal original_workspace
        value = write_original(workspace, fd, name, data, mode, **kwargs)
        if name == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(not workspace._workflow_complete and workspace._workflow_header is None)
                original_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed incomplete workflow preparation injection")
        return value

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_write", write), patch.object(workspace_type, "recover", recover), \
             patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    workflow_probe(batch)
    preparing = root / runtime.transaction.PREPARING
    observed = {"preparingRetained": stat.S_ISDIR(preparing.stat(follow_symlinks=False).st_mode),
                "completeProof": original_workspace is not None and original_workspace._workflow_complete,
                "numberedSlotRetained": workflow_read(preparing / "new-0", 16 * 1024) == runtime.workflow_bytes[0],
                **events}
    workflow_finish(batch, owner, result, ("not_started", "recovery_required", "settled", "filesystem_error"), observed,
        {"preparingRetained": True, "completeProof": False, "numberedSlotRetained": True,
         "recoverCalls": 0, "cleanupUnlinks": 0, "injections": 1})


def workflow_ready_corruption_cases(batch: Batch) -> None:
    """One original completed proof; disk controls cannot mint another roster."""
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    rollback_original, unlink_original = workspace_type._rollback, workspace_type._unlink
    for kind in ("wrong-roster-controls", "unowned-staging-slot"):
        root = batch.case_root(kind)
        workflow_seed(batch, root)
        events = {"completeProof": False, "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 0}
        mutated = None
        wrong_bytes = None
        consistent = False

        def install(workspace, fd, manifest):
            nonlocal mutated, wrong_bytes, consistent
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and not workspace._install_started and events["injections"] == 0)
                events["completeProof"] = workspace._workflow_complete
                journal = root / runtime.transaction.READY
                if kind == "wrong-roster-controls":
                    original = workflow_read(journal / "plan.json", runtime.transaction.MAX_CONTROL_BYTES)
                    require(original == workspace._workflow_plan)
                    changed = json.loads(original)
                    changed["files"][0]["path"] = ".github/workflows/unapproved.yml"
                    wrong_bytes = runtime.transaction._json(changed)
                    (journal / "plan.json").write_bytes(wrong_bytes)
                    for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                        (journal / pending).write_bytes(runtime.transaction.InitWorkspace._marker(changed, state))
                    # This asserts self-consistent tampered DATA, not new native
                    # authority. Original _load must still reject its frozen proof.
                    actual = workflow_read(journal / "plan.json", runtime.transaction.MAX_CONTROL_BYTES)
                    markers = [json.loads(workflow_read(journal / pending, 4096))
                               for pending in ("commit.pending", "rollback.pending")]
                    consistent = (actual == wrong_bytes and all(
                        marker["transactionId"] == changed["transactionId"]
                        and marker["planSha256"] == hashlib.sha256(actual).hexdigest()
                        and marker["state"] == state
                        for marker, state in zip(markers, ("COMMITTED", "ROLLED_BACK"))))
                else:
                    with (journal / "new-17").open("xb") as stream:
                        stream.write(b"fixed unowned numbered slot; preserve\n")
                    (journal / "new-17").chmod(0o600)
                mutated = workflow_snapshot(batch, journal)
                events["injections"] += 1
            # Do not call original install: a retained journal can have a known
            # not-started effect. The real one-shot fixed recovery still runs.
            raise OSError("fixed completed workflow proof corruption injection")

        def rollback(workspace, *args):
            events["rollbackCalls"] += 1
            return rollback_original(workspace, *args)

        def unlink(workspace, *args, **kwargs):
            if events["injections"]:
                events["cleanupUnlinks"] += 1
            return unlink_original(workspace, *args, **kwargs)

        with owned_lease(batch, root) as owner:
            _, plan = workflow_prepare(batch, owner)
            with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_rollback", rollback), \
                 patch.object(workspace_type, "_unlink", unlink):
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
        retained = workflow_snapshot(batch, root / runtime.transaction.READY) == mutated
        if kind == "wrong-roster-controls":
            observed = {**events, "selfConsistentJournal": consistent,
                        "wrongRosterRetained": retained and workflow_read(root / runtime.transaction.READY / "plan.json",
                                                                          runtime.transaction.MAX_CONTROL_BYTES) == wrong_bytes}
            expected = {"completeProof": True, "selfConsistentJournal": True, "wrongRosterRetained": True,
                        "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 1}
        else:
            observed = {**events, "unownedSlotRetained": retained and workflow_read(
                root / runtime.transaction.READY / "new-17", 4096) == b"fixed unowned numbered slot; preserve\n"}
            expected = {"completeProof": True, "unownedSlotRetained": True,
                        "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 1}
        workflow_finish(batch, owner, result, ("not_started", "recovery_required", "settled", "filesystem_error"),
                        observed, expected)


def workflow_pending_replaced_case(batch: Batch, *, committed: bool) -> None:
    root = batch.case_root("commit-pending-replaced" if committed else "rollback-pending-replaced")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    install_original, publish_original, terminal_original = workspace_type._install, workspace_type._publish_terminal, workspace_type._terminal
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    unlink_original, recover_original = workspace_type._unlink, workspace_type.recover
    selected_state = "COMMITTED" if committed else "ROLLED_BACK"
    events = {"completeProof": False, "sameBytesNewInode": False, "terminalMoveCalls": 0,
              "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    active = None
    mutated = None
    retained_inside_original = False
    installed = False
    stopped_before_install = False

    def install(workspace, fd, manifest):
        nonlocal stopped_before_install
        if committed:
            return install_original(workspace, fd, manifest)
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            require(workspace._workflow_complete and not workspace._install_started and not stopped_before_install)
            stopped_before_install = True
        # Fixed prerequisite stop to reach the ORIGINAL rollback publisher.
        # "injections" counts the one pending-control replacement below.
        raise OSError("fixed pre-install stop for rollback marker injection")

    def publish(workspace, fd, manifest, state):
        nonlocal active
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            require(active is None)
            active = (workspace, fd, manifest, state)
        try:
            return publish_original(workspace, fd, manifest, state)
        finally:
            active = None

    def terminal(workspace, fd, manifest):
        nonlocal mutated, installed
        value = terminal_original(workspace, fd, manifest)
        if (active is not None and active[0] is workspace and active[1] == fd
                and active[2] is manifest and active[3] == selected_state and events["injections"] == 0):
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(value is None and workspace._workflow_complete
                        and workspace._install_started is committed)
                events["completeProof"] = workspace._workflow_complete
                if committed:
                    installed = workflow_installed(batch, root, workspace)
                    require(installed)
                else:
                    require(stopped_before_install)
                journal = root / runtime.transaction.READY
                pending = journal / ("commit.pending" if committed else "rollback.pending")
                data = workflow_read(pending, 4096)
                before = pending.stat(follow_symlinks=False)
                replacement = journal / "fixture-marker-replacement"
                with replacement.open("xb") as stream:
                    stream.write(data)
                replacement.chmod(stat.S_IMODE(before.st_mode))
                replacement.replace(pending)
                after = pending.stat(follow_symlinks=False)
                events["sameBytesNewInode"] = (workflow_read(pending, 4096) == data
                    and after.st_dev == before.st_dev and after.st_ino != before.st_ino
                    and after.st_mode == before.st_mode and after.st_nlink == before.st_nlink == 1)
                mutated = workflow_snapshot(batch, journal)
                events["injections"] += 1
            # Return the genuine proof's result. The untouched publisher must
            # re-bind pending and reject the replacement BEFORE its real _move.
        return value

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        if destination in {"COMMITTED", "ROLLED_BACK"}:
            events["terminalMoveCalls"] += 1
        return move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    def recover(workspace):
        nonlocal retained_inside_original
        try:
            return recover_original(workspace)
        finally:
            if events["injections"]:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    retained_inside_original = workflow_snapshot(batch, root / runtime.transaction.READY) == mutated

    with owned_lease(batch, root, expected_unknown=committed) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "_terminal", terminal), patch.object(workspace_type, "_move", move), \
             patch.object(workspace_type, "_rollback", rollback), patch.object(workspace_type, "_unlink", unlink), \
             patch.object(workspace_type, "recover", recover):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan),
                                  expected_unknown=committed)
        # No filesystem probes follow this result in either variant. In the
        # final committed variant the effect is Unknown, although these original
        # scope/lease resources settle. Never convert that into rolled-back.
    if committed:
        observed = {**events, "allFourInstalledBeforeRefusal": installed,
                    "remainingProofNotConsumed": retained_inside_original
                        and events["terminalMoveCalls"] == events["rollbackCalls"] == events["cleanupUnlinks"] == 0}
        expected = {"completeProof": True, "sameBytesNewInode": True, "allFourInstalledBeforeRefusal": True,
                    "terminalMoveCalls": 0, "rollbackCalls": 0, "cleanupUnlinks": 0,
                    "remainingProofNotConsumed": True, "injections": 1}
    else:
        observed = {**events, "remainingProofRetained": retained_inside_original}
        expected = {"completeProof": True, "sameBytesNewInode": True, "terminalMoveCalls": 0,
                    "rollbackCalls": 1, "cleanupUnlinks": 0, "remainingProofRetained": True, "injections": 1}
    workflow_finish(batch, owner, result,
        ("unknown" if committed else "not_started", "recovery_required", "settled", "filesystem_error"), observed, expected)


def workflow_cleanup_missing_cases(batch: Batch) -> None:
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    install_original, cleanup_original = workspace_type._install, workspace_type._cleanup
    terminal_original, unlink_original = workspace_type._terminal, workspace_type._unlink
    for committed in (True, False):
        root = batch.case_root("cleanup-committed-unused-missing" if committed else "cleanup-rolled-back-unused-missing")
        workflow_seed(batch, root)
        selected_state = "COMMITTED" if committed else "ROLLED_BACK"
        unused = "rollback.pending" if committed else "commit.pending"
        events = {"terminal": "UNKNOWN", "durable": False, "cleanupUnlinks": 0, "injections": 0}
        active_cleanup = None
        mutated = None

        def install(workspace, fd, manifest):
            if committed:
                return install_original(workspace, fd, manifest)
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and not workspace._install_started)
            raise OSError("fixed pre-install stop for rolled-back cleanup injection")

        def cleanup(workspace):
            nonlocal active_cleanup
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(active_cleanup is None)
                active_cleanup = workspace
            try:
                return cleanup_original(workspace)
            finally:
                active_cleanup = None

        def terminal(workspace, fd, manifest):
            nonlocal mutated
            value = terminal_original(workspace, fd, manifest)
            if active_cleanup is workspace and events["injections"] == 0:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    require(value == selected_state and workspace._terminal_seen == selected_state
                            and workspace._terminal_durable and workspace._workflow_complete)
                    events["terminal"] = workspace._terminal_seen
                    events["durable"] = workspace._terminal_durable
                    journal = root / runtime.transaction.CLEANUP
                    # The original _cleanup has just validated all controls.
                    # Remove ONLY the unused marker before its entry capture;
                    # presence equivalence must reject, not adopt this suffix.
                    (journal / unused).unlink()
                    mutated = workflow_snapshot(batch, journal)
                    events["injections"] += 1
            return value

        def unlink(workspace, *args, **kwargs):
            if active_cleanup is workspace:
                events["cleanupUnlinks"] += 1
            return unlink_original(workspace, *args, **kwargs)

        with owned_lease(batch, root) as owner:
            _, plan = workflow_prepare(batch, owner)
            with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_cleanup", cleanup), \
                 patch.object(workspace_type, "_terminal", terminal), patch.object(workspace_type, "_unlink", unlink):
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
        journal = root / runtime.transaction.CLEANUP
        observed = {**events, "unusedPendingAbsent": workflow_absent(batch, journal / unused),
                    "remainingProofRetained": workflow_snapshot(batch, journal) == mutated}
        workflow_finish(batch, owner, result,
            ("committed" if committed else "not_started", "recovery_required", "settled", "filesystem_error"), observed,
            {"terminal": selected_state, "durable": True, "unusedPendingAbsent": True,
             "cleanupUnlinks": 0, "remainingProofRetained": True, "injections": 1})


def workflow_committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("committed-fsync-injection")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    fsync_original, rollback_original = workspace_type._fsync, workspace_type._rollback
    events = {"rollbackCalls": 0, "injections": 0}
    original_workspace = None

    def fsync(workspace, fd):
        nonlocal original_workspace
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injections"] == 0):
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started)
                original_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed workflow postdecision pre-fsync injection")
        return fsync_original(workspace, fd)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_fsync", fsync), patch.object(workspace_type, "_rollback", rollback):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    workflow_probe(batch)
    marker = root / runtime.transaction.READY / "COMMITTED"
    observed = {"committedObserved": original_workspace is not None and original_workspace._terminal_seen == "COMMITTED",
                "durabilityConfirmed": original_workspace is not None and original_workspace._terminal_durable,
                "allFourInstalled": workflow_installed(batch, root, original_workspace),
                "journalRetained": stat.S_ISREG(marker.stat(follow_symlinks=False).st_mode), **events}
    require(workflow_read(root / "release/mobile-release.json", 4096) == _WORKFLOW_DISK_CONFIG
            and workflow_read(root / ".gitignore", 4096) == _WORKFLOW_IGNORE)
    workflow_finish(batch, owner, result, ("committed", "recovery_required", "settled", "filesystem_error"), observed,
        {"committedObserved": True, "durabilityConfirmed": False, "rollbackCalls": 0,
         "allFourInstalled": True, "journalRetained": True, "injections": 1})


def workflow_committed_close_case(batch: Batch) -> None:
    root = batch.case_root("committed-close-return-injection")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    close_original = runtime.custody.LockedInitScope.close
    publish_original, apply_original = workspace_type._publish_terminal, workspace_type.apply_workflows_typed
    events = {"actualScopeCloseReturned": False, "cancelledAfterCommit": 0, "committedCarrier": False, "injections": 0}
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = workflow_prepare(batch, owner)

        def publish(workspace, fd, manifest, state):
            value = publish_original(workspace, fd, manifest, state)
            if state == "COMMITTED":
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                    events["cancelledAfterCommit"] += 1
                    owner.guard.cancelled = True
                raise KeyboardInterrupt  # Labelled injection, never EOF evidence.
            return value

        def apply(workspace, changes):
            try:
                return apply_original(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    events["committedCarrier"] = (error.outcome.effect == "committed"
                        and error.outcome.journal == "clean" and error.outcome.reason == "cancelled")
                raise

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injections"] == 0:
                close_original(scope)
                with workflow_witness(batch):
                    events["actualScopeCloseReturned"] = scope.closed is True
                    events["injections"] += 1
                raise OSError("fixed workflow positive scope-close return loss injection")
            return close_original(scope)

        with patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "apply_workflows_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan), expected_unknown=True)
        # Nothing beyond original prearmed cleanup follows this resources-Unknown:
        # no filesystem observer, fresh owner, recovery or cleanup adoption.
    observed = {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes}
    workflow_finish(batch, owner, result, ("committed", "clean", "unknown", "cancelled"), observed,
        {"actualScopeCloseReturned": True, "cancelledAfterCommit": 1, "committedCarrier": True,
         "injections": 1, "afterUnknownProbes": 0})


def metadata_snapshot(batch: Batch, root: Path) -> tuple[Any, ...]:
    # Raw equality spans no writer-owned file rename. Rollback and moved selected
    # leaves use separately documented projections rather than old ctime claims.
    return workflow_snapshot(batch, root, raw_files=True)


def metadata_unselected_snapshot(batch: Batch, root: Path, seed_data: dict[str, Any], *,
                                 retained_backup: bool = False) -> tuple[Any, ...]:
    """Exact unselected inventory, excluding only fixed writer/fixture slots.

    A retained metadata journal changes its parent's link count. Directory
    device/inode/full-mode/uid/gid remain evidence; raw file facts stay exact.
    These fixed cases have existing target parents, so no new target directory
    is omitted. Foreign legacy state or any unselected extra file fails equality.
    """
    selected = set(seed_data["paths"])
    states = batch.runtime.transaction.METADATA_STATE_NAMES
    rows = []
    for row in metadata_snapshot(batch, root):
        name, identity = row[:2]
        if (name in selected or retained_backup and name == "fixture-original-old-0"
                or any(name == state or name.startswith(state + "/") for state in states)):
            continue
        rows.append((name, identity[:5]) if stat.S_ISDIR(identity[2]) else row)
    return tuple(rows)


def metadata_facts(batch: Batch, path: Path) -> tuple[Any, ...] | None:
    workflow_probe(batch)
    try:
        value = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(value.st_mode))
    raw = workflow_read(path, 1024 * 1024) if value.st_mode & 0o444 else None
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, raw)


def metadata_dependencies(batch: Batch, root: Path) -> tuple[Any, ...]:
    leaves = tuple(metadata_facts(batch, root / path) for path in ("release/mobile-release.json", ".gitignore"))
    parent = (root / "release").stat(follow_symlinks=False)
    require(stat.S_ISDIR(parent.st_mode))
    return (*leaves, (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_gid))


def metadata_no_state(batch: Batch, root: Path, *, metadata_only: bool = False) -> bool:
    names = (batch.runtime.transaction.METADATA_STATE_NAMES if metadata_only
             else batch.runtime.transaction.ALL_STATE_NAMES)
    return all(workflow_absent(batch, root / name) for name in names)


def metadata_directory(batch: Batch, root: Path, relative: str) -> Path:
    """Only finite fixture seed ancestry, never a product-supplied target path."""
    workflow_probe(batch)
    current = root
    for part in relative.split("/"):
        require(part not in {"", ".", ".."})
        current = current / part
        if workflow_absent(batch, current):
            current.mkdir(mode=0o750)
            current.chmod(0o750)
        else:
            require(stat.S_ISDIR(current.stat(follow_symlinks=False).st_mode))
    return current


def metadata_seed(batch: Batch, root: Path, *, platform: str = "android", locale: str = "en-US",
                  metadata_root: str = "public/store", variant: str = "replace",
                  ignore_kind: str = "current", disabled: bool = False,
                  writable_config: bool = False, writable_ignore: bool = False) -> dict[str, Any]:
    workflow_probe(batch)
    require(platform in _METADATA_FILES and locale in {"en-US", "fr-FR"}
            and (platform == "android" or locale == "en-US")
            and metadata_root in {"public/store", "release/store"}
            and variant in {"replace", "noop", "mixed", "missing-locale"}
            and ignore_kind in {"current", "legacy", "ambiguous"})
    config = _METADATA_CONFIG_TEXT["publicStore" if metadata_root == "public/store" else "releaseStore"].encode("utf-8")
    if disabled:
        value = json.loads(config)
        value[platform]["enabled"] = False
        config = (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    ignore = (_METADATA_IGNORE if ignore_kind == "current" else
              b"\n".join(_METADATA_IGNORE.splitlines()[:4]) + b"\n" if ignore_kind == "legacy" else
              _METADATA_IGNORE + b"!.mobile-release-metadata-text*/\n")
    metadata_directory(batch, root, "release")
    config_path = root / "release/mobile-release.json"
    config_path.write_bytes(config)
    config_path.chmod(0o640 if writable_config else 0o440)
    (root / ".gitignore").write_bytes(ignore)
    (root / ".gitignore").chmod(0o600 if writable_ignore else 0o400)
    (root / "unrelated.txt").write_bytes(b"fixed metadata fixture public sibling\n")
    (root / "release/unrelated.json").write_bytes(b'{"fixed":"unselected configuration sibling"}\n')
    metadata_directory(batch, root, ".github/workflows")
    (root / ".github/workflows/unrelated.yml").write_bytes(b"# fixed unselected workflow sibling\n")
    ids = _METADATA_FILES[platform]
    fields = [{"id": identity, "text": _METADATA_TEXT[platform][identity]} for identity in ids]
    payloads = tuple(row["text"].encode("utf-8") for row in fields)
    originals: list[bytes | None] = list(payloads)
    if variant in {"replace", "mixed"}:
        originals[0] = _METADATA_PREVIOUS_TEXT[platform][ids[0]].encode("utf-8")
    if variant == "mixed":
        originals[1] = _METADATA_PREVIOUS_TEXT[platform][ids[1]].encode("utf-8")
        if platform == "ios":
            originals[2] = None
    if variant == "missing-locale":
        originals = [None] * len(ids)
    paths = tuple(f"{metadata_root}/{platform}/{locale}/{identity}" for identity in ids)
    if variant != "missing-locale":
        metadata_directory(batch, root, f"{metadata_root}/{platform}/{locale}")
        for index, (relative, raw) in enumerate(zip(paths, originals)):
            if raw is not None:
                leaf = root / relative
                leaf.write_bytes(raw)
                leaf.chmod(0o640 if index == 0 else 0o600)
    # Genuine unselected locale/platform files participate in every preservation
    # snapshot; none is part of the adapter's submitted finite field bundle.
    other_platform, other_locale = ("android", "fr-FR") if platform == "ios" or locale == "en-US" else ("ios", "en-US")
    sibling = metadata_directory(batch, root, f"{metadata_root}/{other_platform}/{other_locale}")
    for identity in _METADATA_FILES[other_platform]:
        (sibling / identity).write_bytes(_METADATA_TEXT[other_platform][identity].encode("utf-8"))
    if variant == "missing-locale":
        metadata_directory(batch, root, f"{metadata_root}/{platform}")
        require(workflow_absent(batch, root / f"{metadata_root}/{platform}/{locale}"))
    return {"platform": platform, "locale": locale, "metadataRoot": metadata_root, "config": config,
            "ignore": ignore, "ids": ids, "paths": paths, "fields": fields,
            "payloads": payloads, "originals": tuple(originals),
            "originalFacts": tuple(metadata_facts(batch, root / path) for path in paths)}


def metadata_baseline(seed_data: dict[str, Any]) -> dict[str, Any]:
    def digest(raw: bytes) -> dict[str, Any]:
        return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return {"config": digest(seed_data["config"]), "fields": [
        {"id": identity, "state": "absent"} if raw is None else
        {"id": identity, "state": "present", **digest(raw)}
        for identity, raw in zip(seed_data["ids"], seed_data["originals"])]}


def metadata_capture(batch: Batch, owner: Owner, seed_data: dict[str, Any]):
    before = metadata_snapshot(batch, owner.lease.root)
    checkout = batch.runtime.metadata.capture_metadata_text_edit(owner.lease, seed_data["platform"], seed_data["locale"])
    require(type(checkout) is batch.runtime.metadata.MetadataCheckout
            and checkout._lease is owner.lease and checkout._revision is owner.lease._revision
            and checkout._selection is owner.lease._metadata_targets.selection
            and checkout._selection.paths == seed_data["paths"]
            and workflow_equal(checkout.baseline, metadata_baseline(seed_data))
            and metadata_snapshot(batch, owner.lease.root) == before)
    return checkout


def metadata_prepare(batch: Batch, owner: Owner, seed_data: dict[str, Any], checkout=None):
    if checkout is None:
        checkout = metadata_capture(batch, owner, seed_data)
    before = metadata_snapshot(batch, owner.lease.root)
    plan = batch.runtime.metadata.prepare_metadata_text_edit(owner.lease, checkout, checkout.revision,
        metadata_baseline(seed_data), seed_data["fields"])
    require(type(plan) is batch.runtime.metadata.PreparedMetadataEdit and plan._checkout is checkout)
    view = plan.view
    expected_files = []
    for identity, path, old, new in zip(seed_data["ids"], seed_data["paths"], seed_data["originals"], seed_data["payloads"]):
        def digest(raw):
            return {"byteLength": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        def styles(raw):
            found = {"crlf"} if b"\r\n" in raw else set()
            rest = raw.replace(b"\r\n", b"")
            return found | ({"cr"} if b"\r" in rest else set()) | ({"lf"} if b"\n" in rest else set())
        expected_files.append({"id": identity, "path": path,
            "action": "create" if old is None else "preserve" if old == new else "replace",
            "before": {"state": "absent"} if old is None else {"state": "present", "text": old.decode("utf-8"), **digest(old)},
            "after": {"text": new.decode("utf-8"), **digest(new)}, "lineEndingsChanged": styles(old or b"") != styles(new)})
    expected_directories = [f'{seed_data["metadataRoot"]}/{seed_data["platform"]}/{seed_data["locale"]}'] if all(
        raw is None for raw in seed_data["originals"]) else []
    require(set(view) == {"schemaVersion", "platform", "locale", "metadataRoot", "files", "createDirectories", "validation"}
            and view["schemaVersion"] == 1 and view["platform"] == seed_data["platform"]
            and view["locale"] == seed_data["locale"] and view["metadataRoot"] == seed_data["metadataRoot"]
            and workflow_equal(view["files"], expected_files) and view["createDirectories"] == expected_directories
            and view["validation"]["valid"] is True
            and tuple(row["id"] for row in view["validation"]["fields"]) == seed_data["ids"]
            and metadata_snapshot(batch, owner.lease.root) == before)
    return checkout, plan


def metadata_original(batch: Batch, owner: Owner, workspace: Any, *, typed: bool = True) -> None:
    runtime = batch.runtime
    scope = workspace._scope
    require(runtime.domain == owner.domain == "metadata_text"
            and type(workspace) is runtime.transaction.InitWorkspace
            and type(scope) is runtime.custody.LockedInitScope and scope is owner.lease._active
            and scope.lease is owner.lease and scope.workspace is workspace and scope.locked
            and not scope.claimed and not scope.closed and workspace._guard is owner.guard
            and type(owner.guard) is runtime.cancellation.DefaultCancellation
            and not owner.guard.lifetime_ledger.fatal
            and workspace._typed_profile is owner.lease.profile is runtime.transaction.TypedEditProfile.METADATA_TEXT
            and workspace._typed_claimed is typed
            and type(workspace._rooted_revision) is runtime.custody.RootedRevision
            and workspace._rooted_revision is owner.lease._revision
            and type(workspace._metadata_targets) is runtime.custody.MetadataTargets
            and workspace._metadata_targets is owner.lease._metadata_targets
            and workspace._rooted_revision._metadata_targets is workspace._metadata_targets)
    workspace._metadata_targets._check_workspace(workspace)  # Actual unchanged identity admission.


def metadata_scopes_closed(owner: Owner) -> int:
    return sum(scope.closed is True and scope.claimed is True
               and scope.lock.close_state == "CLOSED" and scope.meta.close_state == "CLOSED"
               and (scope.workspace is None or all(slot.close_state == "CLOSED" for slot in scope.workspace._slots))
               for scope in owner.lease._scopes)


def metadata_finish(batch: Batch, owner: Owner, outcome: Any, observed: dict[str, Any]) -> None:
    expected = _METADATA_EXPECTED[batch.current]
    workflow_finish(batch, owner, outcome, tuple(expected["outcome"][key] for key in ("effect", "journal", "resources", "reason")),
                    observed, expected["observed"])


def metadata_installed(batch: Batch, root: Path, workspace: Any, seed_data: dict[str, Any]) -> bool:
    workflow_probe(batch)
    require(workspace is not None and workspace._workflow_complete and workspace._workflow_plan is not None
            and workspace._workflow_header is not None)
    header, manifest = json.loads(workspace._workflow_header), json.loads(workspace._workflow_plan)
    require(header["domain"] == manifest["domain"] == "metadata_text"
            and tuple(row["path"] for row in manifest["files"]) == seed_data["paths"])
    for path, raw, prior, captured, row in zip(seed_data["paths"], seed_data["payloads"],
            seed_data["originals"], seed_data["originalFacts"], manifest["files"]):
        before = None if captured is None else {
            "device": captured[0], "inode": captured[1], "mode": stat.S_IMODE(captured[2]),
            "size": len(prior), "sha256": hashlib.sha256(prior).hexdigest()}
        if not workflow_equal(row["before"], before):
            return False
        changed, after = prior != raw, row["after"]
        if changed:
            mode = 0o600 if captured is None else stat.S_IMODE(captured[2])
            if (type(after) is not dict or after["mode"] != mode or after["size"] != len(raw)
                    or after["sha256"] != hashlib.sha256(raw).hexdigest()):
                return False
        elif after is not None or metadata_facts(batch, root / path) != captured:
            return False
        expected = after if changed else before
        value = (root / path).stat(follow_symlinks=False)
        if (workflow_read(root / path, 32 * 1024) != raw
                or (value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_size)
                != (expected["device"], expected["inode"], expected["mode"], len(raw))
                or value.st_uid != os.geteuid() or value.st_gid != os.getegid() or value.st_nlink != 1):
            return False
    return True


def metadata_selection_refusals(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _METADATA_CASES["ordinary"][:4]:
        root = batch.case_root(name)
        seed_data = metadata_seed(batch, root, disabled=name == "configured-platform-disabled",
            ignore_kind="legacy" if name == "legacy-four-ignore-rules-refused" else
                        "ambiguous" if name == "ambiguous-ignore-negation-refused" else "current")
        before = metadata_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            reason = _METADATA_EXPECTED[name]["outcome"]["reason"]
            result = refusal(batch, owner, reason, lambda: runtime.metadata.capture_metadata_text_edit(
                owner.lease, seed_data["platform"], "de-DE" if name == "configured-locale-absent" else seed_data["locale"]))
        metadata_finish(batch, owner, result, {
            "snapshotUnchanged": metadata_snapshot(batch, root) == before,
            "journalAbsent": metadata_no_state(batch, root),
            "targetDescriptorAbsent": owner.lease._metadata_targets is None,
            "revisionAbsent": owner.lease._revision is None, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _METADATA_CASES["ordinary"][4:10]:
        root = batch.case_root(name)
        seed_data = metadata_seed(batch, root,
            platform="ios" if name == "dependency-only-parent-mode-before-apply" else "android",
            variant="missing-locale" if name == "missing-target-parent-appears-before-apply" else "replace",
            writable_config=name == "config-retarget-before-prepare",
            writable_ignore=name == "ignore-bytes-before-apply")
        before = metadata_snapshot(batch, root)
        prepare_failure = name in {"config-retarget-before-prepare", "target-parent-inode-before-prepare"}
        plan = None
        with owned_lease(batch, root) as owner:
            checkout = metadata_capture(batch, owner, seed_data)
            targets = owner.lease._metadata_targets
            if not prepare_failure:
                _, plan = metadata_prepare(batch, owner, seed_data, checkout)
            require(metadata_snapshot(batch, root) == before and metadata_no_state(batch, root))
            if name == "config-retarget-before-prepare":
                require(workflow_absent(batch, root / "release/store"))
                raw = _METADATA_CONFIG_TEXT["releaseStore"].encode("utf-8")
                (root / "release/mobile-release.json").write_bytes(raw)
                change_observed = (workflow_read(root / "release/mobile-release.json", 512 * 1024) == raw
                                   and raw != seed_data["config"] and workflow_absent(batch, root / "release/store"))
            elif name == "ignore-bytes-before-apply":
                raw = seed_data["ignore"] + b"# fixed external metadata ignore drift\n"
                (root / ".gitignore").write_bytes(raw)
                change_observed = workflow_read(root / ".gitignore", 1024 * 1024) == raw != seed_data["ignore"]
            elif name in {"dependency-only-parent-mode-before-apply", "target-parent-mode-before-apply"}:
                parent = root / ("release" if name == "dependency-only-parent-mode-before-apply" else
                                 f'{seed_data["metadataRoot"]}/{seed_data["platform"]}')
                old = parent.stat(follow_symlinks=False)
                require(stat.S_IMODE(old.st_mode) == 0o750)
                parent.chmod(0o700)
                new = parent.stat(follow_symlinks=False)
                change_observed = (new.st_dev == old.st_dev and new.st_ino == old.st_ino
                                   and stat.S_IMODE(new.st_mode) == 0o700 and new.st_uid == old.st_uid and new.st_gid == old.st_gid)
            elif name == "target-parent-inode-before-prepare":
                parent = (root / seed_data["paths"][0]).parent
                old = parent.stat(follow_symlinks=False)
                retained = root / "fixture-original-target-parent"
                parent.rename(retained)
                parent.mkdir(mode=0o750)
                parent.chmod(stat.S_IMODE(old.st_mode))
                for identity in seed_data["ids"]:
                    original = retained / identity
                    replacement = parent / identity
                    replacement.write_bytes(workflow_read(original, 32 * 1024))
                    replacement.chmod(stat.S_IMODE(original.stat(follow_symlinks=False).st_mode))
                new = parent.stat(follow_symlinks=False)
                change_observed = (new.st_dev == old.st_dev and new.st_ino != old.st_ino
                    and new.st_mode == old.st_mode and retained.stat(follow_symlinks=False).st_ino == old.st_ino
                    and all(workflow_read(parent / identity, 32 * 1024) == workflow_read(retained / identity, 32 * 1024)
                            for identity in seed_data["ids"]))
            else:
                parent = (root / seed_data["paths"][0]).parent
                require(workflow_absent(batch, parent))
                parent.mkdir(mode=0o700)
                change_observed = stat.S_ISDIR(parent.stat(follow_symlinks=False).st_mode)
            changed = metadata_snapshot(batch, root)
            if prepare_failure:
                result = refusal(batch, owner, "stale_revision", lambda: metadata_prepare(batch, owner, seed_data, checkout))
            else:
                result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
                count = len(owner.lease._scopes)
                require(runtime.metadata.apply_metadata_text_edit(owner.lease, plan).reason == "invalid_params"
                        and len(owner.lease._scopes) == count)
            selection_retained = (owner.lease._metadata_targets is targets and checkout._selection is targets.selection
                                  and targets.paths == seed_data["paths"])
            retired = checkout._state == runtime.edit._RETIRED and (plan is None or plan._state == runtime.edit._RETIRED)
        metadata_finish(batch, owner, result, {"snapshotUnchanged": metadata_snapshot(batch, root) == changed,
            "journalAbsent": metadata_no_state(batch, root), "selectionNotRetargeted": selection_retained,
            "changeObserved": change_observed, "authorityRetired": retired, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_late_noop_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _METADATA_CASES["ordinary"][10:12]:
        root = batch.case_root(name)
        seed_data = metadata_seed(batch, root, variant="noop")
        lease_type, workspace_type = runtime.custody.InitRootLease, runtime.transaction.InitWorkspace
        recheck_original, current_original = lease_type._recheck, workspace_type._current
        rename_original = runtime.transaction._rename_function
        events = {"recheckReturns": 0, "injections": 0, "changedOnlyDeclaredFacts": False,
                  "consumingTargetChecks": 0, "renameProbes": 0}
        active_workspace = None
        changed = None

        def recheck(lease, workspace, revision):
            nonlocal active_workspace, changed
            value = recheck_original(lease, workspace, revision)
            if lease is owner.lease and lease._rechecks == 2:
                with workflow_witness(batch):
                    metadata_original(batch, owner, workspace, typed=False)
                    require(active_workspace is None and revision is checkout._revision)
                    active_workspace = workspace
                    events["recheckReturns"] += 1
                    if name == "noop-last-leaf-ctime-after-recheck":
                        leaf = root / seed_data["paths"][-1]
                        old = metadata_facts(batch, leaf)
                        leaf.chmod(stat.S_IMODE(old[2]))  # Same mode; actual Linux ctime must change.
                        new = metadata_facts(batch, leaf)
                        events["changedOnlyDeclaredFacts"] = old[:8] == new[:8] and old[9:] == new[9:] and old[8] != new[8]
                    else:
                        parent = (root / seed_data["paths"][0]).parent
                        old = parent.stat(follow_symlinks=False)
                        parent.chmod(0o700)
                        new = parent.stat(follow_symlinks=False)
                        events["changedOnlyDeclaredFacts"] = (old.st_dev == new.st_dev and old.st_ino == new.st_ino
                            and old.st_uid == new.st_uid and old.st_gid == new.st_gid
                            and stat.S_IMODE(old.st_mode) == 0o750 and stat.S_IMODE(new.st_mode) == 0o700)
                    require(events["changedOnlyDeclaredFacts"])  # No fabricated ctime, sleep or retry.
                    changed = metadata_snapshot(batch, root)
                    events["injections"] += 1
            return value

        def current(workspace, path, *, directory=False):
            target = seed_data["paths"][-1] if name == "noop-last-leaf-ctime-after-recheck" else seed_data["paths"][0]
            if workspace is active_workspace and path == target and not directory:
                with workflow_witness(batch):
                    metadata_original(batch, owner, workspace)
                    events["consumingTargetChecks"] += 1
            return current_original(workspace, path, directory=directory)  # Actual consuming _parent/_binding/raw facts.

        def rename():
            events["renameProbes"] += 1
            return rename_original()

        before = metadata_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            checkout, plan = metadata_prepare(batch, owner, seed_data)
            require(metadata_snapshot(batch, root) == before)
            with patch.object(lease_type, "_recheck", recheck), patch.object(workspace_type, "_current", current), \
                 patch.object(runtime.transaction, "_rename_function", rename):
                result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
        metadata_finish(batch, owner, result, {**events,
            "unchangedMarked": active_workspace is not None and active_workspace._unchanged,
            "journalAbsent": metadata_no_state(batch, root),
            "snapshotUnchangedAfterInjection": changed is not None and metadata_snapshot(batch, root) == changed,
            "scopesClosed": metadata_scopes_closed(owner)})


def metadata_unreadable_case(batch: Batch) -> None:
    root = batch.case_root("unreadable-leaf-before-prepare")
    seed_data = metadata_seed(batch, root)
    runtime = batch.runtime
    read_original = runtime.transaction.InitWorkspace._read
    events = {"permissionErrorObserved": False, "deniedOriginalReads": 0}

    def read(workspace, fd, name, limit=runtime.transaction.MAX_FILE_BYTES):
        try:
            return read_original(workspace, fd, name, limit)
        except PermissionError:
            if workspace._scope is not None and workspace._scope.lease is owner.lease and name == seed_data["ids"][0]:
                with workflow_witness(batch):
                    require(workspace._typed_profile is runtime.transaction.TypedEditProfile.METADATA_TEXT
                            and workspace._scope is owner.lease._active and os.geteuid() != 0)
                    events["permissionErrorObserved"] = True
                    events["deniedOriginalReads"] += 1
            raise  # Genuine unchanged original exception, not an injected IO error.

    with owned_lease(batch, root) as owner:
        checkout = metadata_capture(batch, owner, seed_data)
        (root / seed_data["paths"][0]).chmod(0)
        changed = metadata_snapshot(batch, root)  # Unreadable leaf is lstat-only.
        with patch.object(runtime.transaction.InitWorkspace, "_read", read):
            result = refusal(batch, owner, "filesystem_error", lambda: metadata_prepare(batch, owner, seed_data, checkout))
    metadata_finish(batch, owner, result, {**events, "snapshotUnchanged": metadata_snapshot(batch, root) == changed,
        "journalAbsent": metadata_no_state(batch, root), "scopesClosed": metadata_scopes_closed(owner)})


def metadata_original_backup(batch: Batch, root: Path, seed_data: dict[str, Any], *, index: int = 0) -> bool:
    require(type(index) is int and 0 <= index < len(seed_data["ids"]))
    value = metadata_facts(batch, root / batch.runtime.transaction.METADATA_READY / f"old-{index}")
    original = seed_data["originalFacts"][index]
    # Renaming the actual old leaf changes ctime; it must preserve every other
    # captured raw fact, including original mtime/ownership/mode, and its bytes.
    return value is not None and original is not None and value[:8] == original[:8] and value[9:] == original[9:]


def metadata_partial_rollback_case(batch: Batch) -> None:
    root = batch.case_root("first-replacement-installed-rollback")
    seed_data = metadata_seed(batch, root)
    before = workflow_snapshot(batch, root)  # Owned rename/restore may change original file ctime.
    dependencies = metadata_dependencies(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    recovery_original = workspace_type._fixed_recovery
    events = {"firstLeafInstalled": False, "originalBackupBound": False,
              "rollbackReturned": False, "recoveryAttempts": 0, "injections": 0}

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                metadata_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started and destination == seed_data["ids"][0])
                leaf = root / seed_data["paths"][0]
                installed = leaf.stat(follow_symlinks=False)
                events["firstLeafInstalled"] = (workflow_read(leaf, 32 * 1024) == seed_data["payloads"][0]
                    and (installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["originalBackupBound"] = metadata_original_backup(batch, root, seed_data)
                require(events["firstLeafInstalled"] and events["originalBackupBound"])
                events["injections"] += 1
            raise OSError("fixed first metadata replacement installed injection")
        return value

    def rollback(workspace, *args):
        value = rollback_original(workspace, *args)
        with workflow_witness(batch):
            metadata_original(batch, owner, workspace)
            events["rollbackReturned"] = workspace._terminal_seen == "ROLLED_BACK" and workspace._terminal_durable
        return value

    def recovery(workspace):
        events["recoveryAttempts"] += 1
        return recovery_original(workspace)

    with owned_lease(batch, root) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)
        require(workflow_snapshot(batch, root) == before and metadata_dependencies(batch, root) == dependencies)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "_rollback", rollback), \
             patch.object(workspace_type, "_fixed_recovery", recovery):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
        scope_count = len(owner.lease._scopes)
        again = runtime.metadata.apply_metadata_text_edit(owner.lease, plan)
        second_refused = (again.effect, again.journal, again.resources, again.reason) == (
            "not_started", "not_created", "settled", "invalid_params")
        no_scope = len(owner.lease._scopes) == scope_count
    require(metadata_dependencies(batch, root) == dependencies)
    metadata_finish(batch, owner, result, {**events, "snapshotRestored": workflow_snapshot(batch, root) == before,
        "journalAbsent": metadata_no_state(batch, root), "secondApplyRefused": second_refused,
        "secondApplyNoScope": no_scope, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_incomplete_case(batch: Batch) -> None:
    root = batch.case_root("incomplete-metadata-preparing-retained")
    seed_data = metadata_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    write_original, recover_original, unlink_original = workspace_type._write, workspace_type.recover, workspace_type._unlink
    dependencies = metadata_dependencies(batch, root)
    originals = tuple(metadata_facts(batch, root / path) for path in seed_data["paths"])
    unselected = metadata_unselected_snapshot(batch, root, seed_data)
    events = {"recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    active_workspace = None

    def write(workspace, fd, name, data, mode=0o600, **kwargs):
        nonlocal active_workspace
        value = write_original(workspace, fd, name, data, mode, **kwargs)
        if name == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                metadata_original(batch, owner, workspace)
                require(not workspace._workflow_complete and workspace._workflow_header is None)
                active_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed incomplete metadata preparation injection")
        return value

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_write", write), patch.object(workspace_type, "recover", recover), \
             patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
    preparing = root / runtime.transaction.METADATA_PREPARING
    require(all(workflow_absent(batch, root / name) for name in runtime.transaction.STATE_NAMES))
    require(metadata_unselected_snapshot(batch, root, seed_data) == unselected)
    metadata_finish(batch, owner, result, {"preparingRetained": stat.S_ISDIR(preparing.stat(follow_symlinks=False).st_mode),
        "completeProof": active_workspace is not None and active_workspace._workflow_complete,
        "numberedSlotRetained": workflow_read(preparing / "new-0", 32 * 1024) == seed_data["payloads"][0],
        "targetsPreserved": tuple(metadata_facts(batch, root / path) for path in seed_data["paths"]) == originals,
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        **events, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_cleanup_backup_case(batch: Batch) -> None:
    root = batch.case_root("committed-old-backup-replaced-at-cleanup-entry")
    seed_data = metadata_seed(batch, root, platform="ios")
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    cleanup_original, unlink_original = workspace_type._cleanup, workspace_type._unlink
    dependencies = metadata_dependencies(batch, root)
    unselected = metadata_unselected_snapshot(batch, root, seed_data)
    events = {"committedObserved": False, "durabilityConfirmed": False, "sameBytesForeignInode": False,
              "originalBackupRetained": False, "cleanupUnlinks": 0, "injections": 0}
    active_workspace = None
    mutated = None
    original_backup = None

    def cleanup(workspace):
        nonlocal active_workspace, mutated, original_backup
        with workflow_witness(batch):
            metadata_original(batch, owner, workspace)
            require(active_workspace is None and workspace._workflow_complete and workspace._cleanup_mode
                    and workspace._recovery_claimed and workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
            active_workspace = workspace
            journal = root / runtime.transaction.METADATA_CLEANUP
            require(stat.S_ISDIR(journal.stat(follow_symlinks=False).st_mode))
            original = journal / "old-0"
            raw = workflow_read(original, 32 * 1024)
            before = original.stat(follow_symlinks=False)
            original_backup = root / "fixture-original-old-0"
            original.rename(original_backup)
            with original.open("xb") as stream:
                stream.write(raw)
            original.chmod(stat.S_IMODE(before.st_mode))
            after = original.stat(follow_symlinks=False)
            events["committedObserved"] = workspace._terminal_seen == "COMMITTED"
            events["durabilityConfirmed"] = workspace._terminal_durable
            events["sameBytesForeignInode"] = (workflow_read(original, 32 * 1024) == raw
                and after.st_dev == before.st_dev and after.st_ino != before.st_ino and after.st_mode == before.st_mode
                and after.st_uid == before.st_uid and after.st_gid == before.st_gid and after.st_nlink == before.st_nlink == 1)
            saved = metadata_facts(batch, original_backup)
            captured = seed_data["originalFacts"][0]
            events["originalBackupRetained"] = (saved[:8] == captured[:8] and saved[9:] == captured[9:])
            require(events["sameBytesForeignInode"] and events["originalBackupRetained"])
            mutated = metadata_snapshot(batch, journal)
            events["injections"] += 1
        return cleanup_original(workspace)  # Its original entry capture must reject before any unlink.

    def unlink(workspace, *args, **kwargs):
        if workspace is active_workspace:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_cleanup", cleanup), patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
    require(original_backup is not None and workflow_read(original_backup, 32 * 1024) == seed_data["originals"][0])
    require(metadata_unselected_snapshot(batch, root, seed_data, retained_backup=True) == unselected)
    metadata_finish(batch, owner, result, {**events,
        "allSelectedPayloadsInstalled": metadata_installed(batch, root, active_workspace, seed_data),
        "proofRetained": mutated is not None and metadata_snapshot(batch, root / runtime.transaction.METADATA_CLEANUP) == mutated,
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        "scopesClosed": metadata_scopes_closed(owner)})


def metadata_pending_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _METADATA_CASES["ordinary"][16:18]:
        root = batch.case_root(name)
        originals = []
        unchanged = retained = True
        for domain in ("configuration", "github_workflows"):
            child = root / domain
            child.mkdir(mode=0o700)
            metadata_seed(batch, child)
            pending = child / runtime.transaction.METADATA_PREPARING
            pending.mkdir(mode=0o700)
            if name == "legacy-domains-refuse-header-tmp-metadata-prepare":
                (pending / "header.tmp").write_bytes(b'{"fixed":"incomplete metadata preparation"}\n')
            before = metadata_snapshot(batch, child)
            state_before = metadata_snapshot(batch, pending)
            with owned_lease(batch, child, domain=domain) as owner:
                capture = runtime.edit.capture_config_edit if domain == "configuration" else runtime.workflow.capture_github_workflow_edit
                result = refusal(batch, owner, "pending_state", lambda: capture(owner.lease))
            originals.append(owner)
            unchanged = unchanged and metadata_snapshot(batch, child) == before
            retained = retained and metadata_snapshot(batch, pending) == state_before
        metadata_finish(batch, originals[-1], result, {"legacyDomains": [owner.domain for owner in originals],
            "originalOwners": len(originals),
            "bothOwnersSettled": all(owner.closed and owner.restored and not owner.fatal for owner in originals),
            "bothRefused": all(owner.outcome.reason == "pending_state" for owner in originals),
            "stateRetained": retained, "snapshotUnchanged": unchanged,
            "targetDescriptorsAbsent": all(owner.lease._metadata_targets is None for owner in originals),
            "scopesClosed": sum(metadata_scopes_closed(owner) for owner in originals)})
    root = batch.case_root("metadata-refuses-legacy-ready")
    seed_data = metadata_seed(batch, root)
    pending = root / runtime.transaction.READY
    pending.mkdir(mode=0o700)
    (pending / "header.json").write_bytes(b'{"fixed":"foreign legacy READY, must not be parsed"}\n')
    before, state_before = metadata_snapshot(batch, root), metadata_snapshot(batch, pending)
    with owned_lease(batch, root) as owner:
        result = refusal(batch, owner, "pending_state", lambda: metadata_capture(batch, owner, seed_data))
    metadata_finish(batch, owner, result, {"legacyStateRetained": metadata_snapshot(batch, pending) == state_before,
        "snapshotUnchanged": metadata_snapshot(batch, root) == before,
        "metadataStateAbsent": metadata_no_state(batch, root, metadata_only=True),
        "targetDescriptorAbsent": owner.lease._metadata_targets is None, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_dependency_drift_case(batch: Batch) -> None:
    root = batch.case_root("dependency-drift-after-first-replacement")
    seed_data = metadata_seed(batch, root, variant="mixed", writable_config=True)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, recover_original, unlink_original = workspace_type._move, workspace_type.recover, workspace_type._unlink
    events = {"firstLeafInstalled": False, "originalBackupBound": False, "dependencyChanged": False,
              "partialTreeRetainedInsideOriginal": False, "laterInstallMoves": 0,
              "recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    changed = None

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        nonlocal changed
        already_injected = events["injections"] == 1
        try:
            value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        except runtime.transaction.InitConflict:
            if already_injected:
                with workflow_witness(batch):
                    metadata_original(batch, owner, workspace)
                    require(workspace._installing and workspace._install_started and not workspace._recovery_claimed)
                    events["partialTreeRetainedInsideOriginal"] = changed is not None and metadata_snapshot(batch, root) == changed
            raise
        if already_injected and workspace._installing:
            events["laterInstallMoves"] += 1  # Only an actual returned original move is an effect receipt.
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                metadata_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started and destination == seed_data["ids"][0])
                leaf = root / seed_data["paths"][0]
                value_stat = leaf.stat(follow_symlinks=False)
                events["firstLeafInstalled"] = (workflow_read(leaf, 32 * 1024) == seed_data["payloads"][0]
                    and (value_stat.st_dev, value_stat.st_ino, stat.S_IMODE(value_stat.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["originalBackupBound"] = metadata_original_backup(batch, root, seed_data)
                raw = seed_data["config"] + b" \n"
                (root / "release/mobile-release.json").write_bytes(raw)
                events["dependencyChanged"] = workflow_read(root / "release/mobile-release.json", 512 * 1024) == raw != seed_data["config"]
                require(events["firstLeafInstalled"] and events["originalBackupBound"] and events["dependencyChanged"])
                changed = metadata_snapshot(batch, root)
                events["injections"] += 1
        return value

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "recover", recover), \
             patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan), expected_unknown=True)
        # Effect-Unknown is already sticky. Only this original prearmed lease
        # cleanup may continue; no new fixture read/probe/owner or recovery.
    metadata_finish(batch, owner, result, {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes,
        "scopesClosed": metadata_scopes_closed(owner)})


def metadata_committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("metadata-committed-fsync-injection")
    seed_data = metadata_seed(batch, root, platform="ios", metadata_root="release/store", variant="mixed")
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    fsync_original, rollback_original = workspace_type._fsync, workspace_type._rollback
    dependencies = metadata_dependencies(batch, root)
    unselected = metadata_unselected_snapshot(batch, root, seed_data)
    events = {"rollbackCalls": 0, "injections": 0}
    active_workspace = None
    retained = None

    def fsync(workspace, fd):
        nonlocal active_workspace, retained
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injections"] == 0):
            with workflow_witness(batch):
                metadata_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started)
                active_workspace = workspace
                retained = metadata_snapshot(batch, root / runtime.transaction.METADATA_READY)
                events["injections"] += 1
            raise OSError("fixed metadata postdecision pre-fsync injection")
        return fsync_original(workspace, fd)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    with owned_lease(batch, root) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_fsync", fsync), patch.object(workspace_type, "_rollback", rollback):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan))
    marker = root / runtime.transaction.METADATA_READY / "COMMITTED"
    require(retained is not None and metadata_snapshot(batch, marker.parent) == retained
            and all(metadata_original_backup(batch, root, seed_data, index=index) for index in (0, 1))
            and metadata_unselected_snapshot(batch, root, seed_data) == unselected)
    metadata_finish(batch, owner, result, {
        "committedObserved": active_workspace is not None and active_workspace._terminal_seen == "COMMITTED",
        "durabilityConfirmed": active_workspace is not None and active_workspace._terminal_durable,
        "allSelectedPayloadsInstalled": metadata_installed(batch, root, active_workspace, seed_data),
        "journalRetained": stat.S_ISREG(marker.stat(follow_symlinks=False).st_mode),
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        **events, "scopesClosed": metadata_scopes_closed(owner)})


def metadata_committed_close_case(batch: Batch) -> None:
    root = batch.case_root("metadata-committed-close-return-injection")
    seed_data = metadata_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    close_original = runtime.custody.LockedInitScope.close
    publish_original, apply_original = workspace_type._publish_terminal, workspace_type.apply_metadata_text_typed
    dependencies = metadata_dependencies(batch, root)
    unselected = metadata_unselected_snapshot(batch, root, seed_data)
    events = {"actualScopeCloseReturned": False, "cancelledAfterCommit": 0, "committedCarrier": False, "injections": 0}
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = metadata_prepare(batch, owner, seed_data)

        def publish(workspace, fd, manifest, state):
            value = publish_original(workspace, fd, manifest, state)
            if state == "COMMITTED":
                with workflow_witness(batch):
                    metadata_original(batch, owner, workspace)
                    require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                    events["cancelledAfterCommit"] += 1
                    owner.guard.cancelled = True
                raise KeyboardInterrupt  # Labelled original-guard injection, never stdin-EOF evidence.
            return value

        def apply(workspace, changes):
            try:
                return apply_original(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                with workflow_witness(batch):
                    metadata_original(batch, owner, workspace)
                    events["committedCarrier"] = (error.outcome.effect == "committed"
                        and error.outcome.journal == "clean" and error.outcome.reason == "cancelled")
                    require(metadata_installed(batch, root, workspace, seed_data)
                            and metadata_dependencies(batch, root) == dependencies
                            and metadata_unselected_snapshot(batch, root, seed_data) == unselected
                            and metadata_no_state(batch, root))
                raise

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injections"] == 0:
                close_original(scope)
                with workflow_witness(batch):
                    events["actualScopeCloseReturned"] = scope.closed is True
                    events["injections"] += 1
                raise OSError("fixed metadata positive scope-close return loss injection")
            return close_original(scope)

        with patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "apply_metadata_text_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.metadata.apply_metadata_text_edit(owner.lease, plan), expected_unknown=True)
        # Lane-last resource Unknown: no filesystem probe, read, retry, second
        # controller, recovery or cleanup adoption after this original result.
    metadata_finish(batch, owner, result, {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes,
        "scopesClosed": metadata_scopes_closed(owner)})


# Saved-version fixtures reuse only the donor's bounded DATA readers and
# original Runtime/Owner/Batch. Metadata targets/plans never authorize version.
def version_no_state(batch: Batch, root: Path, *, version_only: bool = False) -> bool:
    names = (batch.runtime.transaction.VERSION_STATE_NAMES if version_only
             else batch.runtime.transaction.ALL_STATE_NAMES)
    return all(workflow_absent(batch, root / name) for name in names)


def version_unselected_snapshot(batch: Batch, root: Path, seed_data: dict[str, Any], *,
                                retained_backup: bool = False) -> tuple[Any, ...]:
    # All transactional cases have existing parents. Exclude only the one
    # selected leaf and finite original version state/fixture backup slots.
    # Directory link counts can change when the original journal is retained;
    # device/inode/full-mode/uid/gid and every unselected raw file fact cannot.
    states = batch.runtime.transaction.VERSION_STATE_NAMES
    rows = []
    for row in metadata_snapshot(batch, root):
        name, identity = row[:2]
        if (name == seed_data["path"] or retained_backup and name == "fixture-original-old-0"
                or any(name == state or name.startswith(state + "/") for state in states)):
            continue
        rows.append((name, identity[:5]) if stat.S_ISDIR(identity[2]) else row)
    return tuple(rows)


def version_seed(batch: Batch, root: Path, *, selection: str = "publicVersion", variant: str = "edit",
                 ignore_kind: str = "current", writable_config: bool = False,
                 writable_ignore: bool = False) -> dict[str, Any]:
    """Finite private DATA seeds, never a supplied target roster or backend."""
    workflow_probe(batch)
    require(selection in _VERSION_PATHS and variant in {"edit", "noop", "missing-parent"}
            and ignore_kind in {"current", "legacy"}
            and (variant != "missing-parent" or selection == "nestedVersion"))
    config = _VERSION_CONFIG_TEXT[selection].encode("utf-8")
    ignored = _VERSION_IGNORE if ignore_kind == "current" else _METADATA_IGNORE
    metadata_directory(batch, root, "release")
    (root / "release/mobile-release.json").write_bytes(config)
    (root / "release/mobile-release.json").chmod(0o640 if writable_config else 0o440)
    (root / ".gitignore").write_bytes(ignored)
    (root / ".gitignore").chmod(0o600 if writable_ignore else 0o400)
    (root / "unrelated.txt").write_bytes(b"fixed version fixture public sibling\n")
    (root / "release/unrelated.json").write_bytes(b'{"fixed":"unselected configuration sibling"}\n')
    metadata_directory(batch, root, ".github/workflows")
    (root / ".github/workflows/unrelated.yml").write_bytes(b"# fixed unselected workflow sibling\n")
    sibling = metadata_directory(batch, root, "public/store/android/en-US")
    (sibling / "title.txt").write_bytes(b"Fixed unselected metadata title\n")
    path = _VERSION_PATHS[selection]
    parts = path.split("/")
    directories = tuple("/".join(parts[:n]) for n in range(1, len(parts)))
    original = (None if variant == "missing-parent" else
                _VERSION_TEXT["edited" if variant == "noop" else "original"].encode("utf-8"))
    payload = _VERSION_TEXT["created" if original is None else "edited"].encode("utf-8")
    missing = ("public/version-tree",) if variant == "missing-parent" else ()
    if original is not None:
        metadata_directory(batch, root, directories[-1])
        (root / path).write_bytes(original)
        (root / path).chmod(0o640)
    else:
        require(workflow_absent(batch, root / "public/version-tree"))
    return {"path": path, "directories": directories, "missingDirectories": missing,
            "config": config, "ignore": ignored, "original": original, "payload": payload,
            "intent": "create" if original is None else "edit",
            "originalValues": None if original is None else
                dict(_VERSION_VALUES) if variant == "noop" else {"name": "1.2.3", "build": "7"},
            "originalFacts": metadata_facts(batch, root / path)}


def version_baseline(seed_data: dict[str, Any]) -> dict[str, Any]:
    def digest(raw: bytes) -> dict[str, Any]:
        return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    original = seed_data["original"]
    return {"savedConfig": digest(seed_data["config"]), "savedVersion":
            {"state": "absent"} if original is None else {"state": "present", **digest(original)}}


def version_capture_binding(batch: Batch, owner: Owner, seed_data: dict[str, Any]) -> bool:
    """Retained original capture identities, not a substitute active scope."""
    runtime = batch.runtime
    targets = owner.lease._version_targets
    if type(targets) is not runtime.custody.VersionTargets:
        return False
    selection, workspace = targets.selection, targets._capture_workspace
    return (type(owner.lease) is runtime.custody.InitRootLease and targets._identity is targets
            and targets._lease is owner.lease and owner.lease.profile is runtime.transaction.TypedEditProfile.RELEASE_VERSION
            and type(workspace) is runtime.transaction.InitWorkspace and workspace._version_targets is targets
            and workspace._guard is owner.guard and type(workspace._scope) is runtime.custody.LockedInitScope
            and len(owner.lease._scopes) >= 1 and workspace._scope is owner.lease._scopes[0]
            and workspace._scope.workspace is workspace and workspace._scope.lease is owner.lease
            and workspace._typed_profile is owner.lease.profile
            and owner.lease._metadata_targets is None and workspace._metadata_targets is None
            and type(selection) is runtime.version_text.VersionSelection
            and selection.source == seed_data["path"] and selection.paths == (seed_data["path"],)
            and selection.directories == seed_data["directories"]
            and selection.name_key == "VERSION_NAME" and selection.build_key == "BUILD_NUMBER"
            and selection.ios_enabled is True)


def version_capture(batch: Batch, owner: Owner, seed_data: dict[str, Any]):
    before = metadata_snapshot(batch, owner.lease.root)
    checkout = batch.runtime.version.capture_release_version_edit(owner.lease)
    revision, targets = owner.lease._revision, owner.lease._version_targets
    require(type(checkout) is batch.runtime.version.VersionCheckout and checkout._identity is checkout
            and checkout._lease is owner.lease and checkout._revision is revision
            and type(revision) is batch.runtime.custody.RootedRevision and revision._lease is owner.lease
            and revision._version_targets is targets and revision._metadata_targets is None
            and revision.profile is owner.lease.profile and checkout.revision == revision.token
            and checkout._selection is targets.selection is revision.version_selection
            and version_capture_binding(batch, owner, seed_data)
            and workflow_equal(checkout.baseline, version_baseline(seed_data))
            and workflow_equal(checkout.values, seed_data["originalValues"])
            and tuple((item.path, item.data) for item in checkout._files) == ((seed_data["path"], seed_data["original"]),)
            and tuple((item.path, item.data) for item in checkout._dependencies) == (
                ("release/mobile-release.json", seed_data["config"]), (".gitignore", seed_data["ignore"]))
            and metadata_snapshot(batch, owner.lease.root) == before)
    return checkout


def version_prepare(batch: Batch, owner: Owner, seed_data: dict[str, Any], checkout=None):
    if checkout is None:
        checkout = version_capture(batch, owner, seed_data)
    before = metadata_snapshot(batch, owner.lease.root)
    plan = batch.runtime.version.prepare_release_version_edit(owner.lease, checkout, checkout.revision,
        version_baseline(seed_data), seed_data["intent"], dict(_VERSION_VALUES))
    require(type(plan) is batch.runtime.version.PreparedVersionEdit and plan._identity is plan
            and plan._checkout is checkout and checkout._prepared is plan)
    old, new, captured = seed_data["original"], seed_data["payload"], seed_data["originalFacts"]

    def digest(raw: bytes) -> dict[str, Any]:
        return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    expected = {"schemaVersion": 1, "source": seed_data["path"], "nameKey": "VERSION_NAME",
        "buildKey": "BUILD_NUMBER", "iosEnabled": True, "intent": seed_data["intent"], "values": dict(_VERSION_VALUES),
        "file": {"path": seed_data["path"], "action": "create" if old is None else "preserve" if old == new else "replace",
                 "before": {"state": "absent"} if old is None else {"state": "present", "text": old.decode("utf-8"), **digest(old)},
                 "after": {"text": new.decode("utf-8"), **digest(new)},
                 "requestedMode": 0o644 if captured is None else stat.S_IMODE(captured[2]),
                 "preserveMode": captured is not None},
        "createDirectories": list(seed_data["missingDirectories"]),
        "lineEndings": {"before": [] if old is None else ["crlf", "lf"],
                        "after": ["lf"] if old is None else ["crlf", "lf"],
                        "finalNewlineBefore": False, "finalNewlineAfter": old is None, "preserved": old is not None},
        "validation": {"valid": True, "state": "format-valid", "issues": []}}
    require(workflow_equal(plan.view, expected) and plan._payloads == (None if old == new else new,)
            and version_capture_binding(batch, owner, seed_data)
            and metadata_snapshot(batch, owner.lease.root) == before)
    return checkout, plan


def version_original(batch: Batch, owner: Owner, workspace: Any, *, typed: bool = True) -> None:
    runtime = batch.runtime
    scope = workspace._scope
    require(runtime.domain == owner.domain == "release_version"
            and type(workspace) is runtime.transaction.InitWorkspace
            and type(owner.lease) is runtime.custody.InitRootLease
            and type(scope) is runtime.custody.LockedInitScope and scope is owner.lease._active
            and scope.lease is owner.lease and scope.workspace is workspace and scope.locked
            and not scope.claimed and not scope.closed and workspace._guard is owner.guard
            and owner.lease.guard is owner.guard and type(owner.guard) is runtime.cancellation.DefaultCancellation
            and not owner.guard.lifetime_ledger.fatal
            and workspace._typed_profile is owner.lease.profile is runtime.transaction.TypedEditProfile.RELEASE_VERSION
            and workspace._state_names == runtime.transaction.VERSION_STATE_NAMES and workspace._typed_claimed is typed
            and type(workspace._rooted_revision) is runtime.custody.RootedRevision
            and workspace._rooted_revision is owner.lease._revision and workspace._rooted_revision._lease is owner.lease
            and type(workspace._version_targets) is runtime.custody.VersionTargets
            and workspace._version_targets is owner.lease._version_targets
            and workspace._rooted_revision._version_targets is workspace._version_targets
            and workspace._metadata_targets is None and owner.lease._metadata_targets is None
            and workspace._rooted_revision._metadata_targets is None)
    workspace._version_targets._check_workspace(workspace)  # Actual original identity admission, no stand-in.


def version_finish(batch: Batch, owner: Owner, outcome: Any, observed: dict[str, Any]) -> None:
    expected = _VERSION_EXPECTED[batch.current]
    workflow_finish(batch, owner, outcome, tuple(expected["outcome"][key] for key in ("effect", "journal", "resources", "reason")),
                    observed, expected["observed"])


def version_installed(batch: Batch, root: Path, workspace: Any, seed_data: dict[str, Any]) -> bool:
    workflow_probe(batch)
    require(workspace is not None and workspace._workflow_complete and type(workspace._workflow_plan) is bytes
            and type(workspace._workflow_header) is bytes)
    header, manifest = json.loads(workspace._workflow_header), json.loads(workspace._workflow_plan)
    require(header["domain"] == manifest["domain"] == "release_version"
            and tuple(row["path"] for row in manifest["files"]) == (seed_data["path"],)
            and tuple(row["path"] for row in manifest["directories"]) == seed_data["directories"])
    row = manifest["files"][0]
    prior, raw, captured = seed_data["original"], seed_data["payload"], seed_data["originalFacts"]
    # These core transaction fault cases replace an existing mode-0640 source.
    # Actual Create/umask effect proof belongs to the separate Rust owner case.
    require(prior is not None and captured is not None and stat.S_IMODE(captured[2]) == 0o640)
    before = {"device": captured[0], "inode": captured[1], "mode": stat.S_IMODE(captured[2]),
              "size": len(prior), "sha256": hashlib.sha256(prior).hexdigest()}
    after = row["after"]
    if (not workflow_equal(row["before"], before) or type(after) is not dict
            or after["mode"] != stat.S_IMODE(captured[2]) or after["size"] != len(raw)
            or after["sha256"] != hashlib.sha256(raw).hexdigest()):
        return False
    leaf = root / seed_data["path"]
    value = leaf.stat(follow_symlinks=False)
    return (workflow_read(leaf, 64 * 1024) == raw
            and (value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_size)
                == (after["device"], after["inode"], after["mode"], len(raw))
            and value.st_uid == os.geteuid() and value.st_gid == os.getegid() and value.st_nlink == 1)


def version_original_backup(batch: Batch, root: Path, seed_data: dict[str, Any]) -> bool:
    current = metadata_facts(batch, root / batch.runtime.transaction.VERSION_READY / "old-0")
    original = seed_data["originalFacts"]
    # A writer-owned rename changes ctime, not original bytes/mtime/mode/owner.
    return current is not None and original is not None and current[:8] == original[:8] and current[9:] == original[9:]


def version_selection_refusals(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _VERSION_CASES["ordinary"][:3]:
        root = batch.case_root(name)
        seed_data = version_seed(batch, root, ignore_kind="legacy" if name == "legacy-seven-ignore-rules-refused" else "current")
        leaf = root / seed_data["path"]
        if name == "present-malformed-source-refused":
            leaf.write_bytes(b"VERSION_NAME=1.2.3\nOTHER=keep\n")  # Present, missing its configured build key.
        elif name == "present-nonregular-source-refused":
            leaf.unlink()
            os.mkfifo(leaf, 0o600)  # lstat-only fixture DATA; the real bounded native reader refuses it.
        before = metadata_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            reason = _VERSION_EXPECTED[name]["outcome"]["reason"]
            result = refusal(batch, owner, reason, lambda: runtime.version.capture_release_version_edit(owner.lease))
        after = metadata_snapshot(batch, root)
        observed = {"snapshotUnchanged": after == before, "journalAbsent": version_no_state(batch, root),
                    "scopesClosed": metadata_scopes_closed(owner)}
        if name == "legacy-seven-ignore-rules-refused":
            observed.update(targetDescriptorAbsent=owner.lease._version_targets is None,
                            revisionAbsent=owner.lease._revision is None)
        else:
            original_row = next((row for row in before if row[0] == seed_data["path"]), None)
            current_row = next((row for row in after if row[0] == seed_data["path"]), None)
            revision = owner.lease._revision
            observed.update(presentSourcePreserved=original_row is not None and current_row == original_row,
                targetDescriptorBound=version_capture_binding(batch, owner, seed_data),
                revisionBound=type(revision) is runtime.custody.RootedRevision
                    and revision._lease is owner.lease and revision.profile is owner.lease.profile
                    and revision._version_targets is owner.lease._version_targets and revision._metadata_targets is None)
        version_finish(batch, owner, result, observed)


def version_stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _VERSION_CASES["ordinary"][3:8]:
        root = batch.case_root(name)
        seed_data = version_seed(batch, root,
            selection="nestedVersion" if name in {"target-parent-inode-before-prepare", "missing-target-parent-appears-before-apply"}
                else "publicVersion",
            variant="missing-parent" if name == "missing-target-parent-appears-before-apply" else "edit",
            writable_config=name == "config-retarget-before-prepare", writable_ignore=name == "ignore-bytes-before-apply")
        before = metadata_snapshot(batch, root)
        prepare_failure = name in {"config-retarget-before-prepare", "target-parent-inode-before-prepare"}
        plan = None
        with owned_lease(batch, root) as owner:
            checkout = version_capture(batch, owner, seed_data)
            targets = owner.lease._version_targets
            if not prepare_failure:
                _, plan = version_prepare(batch, owner, seed_data, checkout)
            require(metadata_snapshot(batch, root) == before and version_no_state(batch, root))
            if name == "config-retarget-before-prepare":
                require(workflow_absent(batch, root / "release/version.properties"))
                raw = _VERSION_CONFIG_TEXT["releaseVersion"].encode("utf-8")
                (root / "release/mobile-release.json").write_bytes(raw)
                change_observed = (workflow_read(root / "release/mobile-release.json", 512 * 1024) == raw != seed_data["config"]
                                   and workflow_absent(batch, root / "release/version.properties"))
            elif name == "ignore-bytes-before-apply":
                raw = seed_data["ignore"] + b"# fixed external version ignore drift\n"
                (root / ".gitignore").write_bytes(raw)
                change_observed = workflow_read(root / ".gitignore", 1024 * 1024) == raw != seed_data["ignore"]
            elif name == "target-parent-mode-before-apply":
                parent = (root / seed_data["path"]).parent
                old = parent.stat(follow_symlinks=False)
                require(stat.S_IMODE(old.st_mode) == 0o750)
                parent.chmod(0o700)
                new = parent.stat(follow_symlinks=False)
                change_observed = (new.st_dev == old.st_dev and new.st_ino == old.st_ino
                    and stat.S_IMODE(new.st_mode) == 0o700 and new.st_uid == old.st_uid and new.st_gid == old.st_gid)
            elif name == "target-parent-inode-before-prepare":
                parent = (root / seed_data["path"]).parent
                old = parent.stat(follow_symlinks=False)
                retained = root / "fixture-original-target-parent"
                parent.rename(retained)
                parent.mkdir(mode=0o750)
                parent.chmod(stat.S_IMODE(old.st_mode))
                original = retained / "version.properties"
                replacement = parent / "version.properties"
                replacement.write_bytes(workflow_read(original, 64 * 1024))
                replacement.chmod(stat.S_IMODE(original.stat(follow_symlinks=False).st_mode))
                new = parent.stat(follow_symlinks=False)
                change_observed = (new.st_dev == old.st_dev and new.st_ino != old.st_ino and new.st_mode == old.st_mode
                    and new.st_uid == old.st_uid and new.st_gid == old.st_gid
                    and retained.stat(follow_symlinks=False).st_ino == old.st_ino
                    and workflow_read(replacement, 64 * 1024) == workflow_read(original, 64 * 1024))
            else:
                parent = (root / seed_data["path"]).parent
                require(workflow_absent(batch, parent))
                parent.mkdir(mode=0o700)
                change_observed = (stat.S_ISDIR(parent.stat(follow_symlinks=False).st_mode)
                                   and workflow_absent(batch, root / seed_data["path"]))
            changed = metadata_snapshot(batch, root)
            if prepare_failure:
                result = refusal(batch, owner, "stale_revision", lambda: version_prepare(batch, owner, seed_data, checkout))
            else:
                result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
                count = len(owner.lease._scopes)
                again = runtime.version.apply_release_version_edit(owner.lease, plan)
                require((again.effect, again.journal, again.resources, again.reason) == (
                    "not_started", "not_created", "settled", "invalid_params") and len(owner.lease._scopes) == count)
            selection_retained = (owner.lease._version_targets is targets and checkout._selection is targets.selection
                                  and targets.paths == (seed_data["path"],) and version_capture_binding(batch, owner, seed_data))
            retired = checkout._state == runtime.edit._RETIRED and (plan is None or plan._state == runtime.edit._RETIRED)
        version_finish(batch, owner, result, {"snapshotUnchanged": metadata_snapshot(batch, root) == changed,
            "journalAbsent": version_no_state(batch, root), "selectionNotRetargeted": selection_retained,
            "changeObserved": change_observed, "authorityRetired": retired, "scopesClosed": metadata_scopes_closed(owner)})


def version_late_noop_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name in _VERSION_CASES["ordinary"][8:10]:
        root = batch.case_root(name)
        seed_data = version_seed(batch, root, variant="noop")
        lease_type, workspace_type = runtime.custody.InitRootLease, runtime.transaction.InitWorkspace
        recheck_original, current_original = lease_type._recheck, workspace_type._current
        rename_original = runtime.transaction._rename_function
        events = {"recheckReturns": 0, "injections": 0, "changedOnlyDeclaredFacts": False,
                  "consumingTargetChecks": 0, "renameProbes": 0}
        active_workspace = None
        changed = None

        def recheck(lease, workspace, revision):
            nonlocal active_workspace, changed
            value = recheck_original(lease, workspace, revision)
            if lease is owner.lease and lease._rechecks == 2:
                with workflow_witness(batch):
                    version_original(batch, owner, workspace, typed=False)
                    require(active_workspace is None and revision is checkout._revision)
                    active_workspace = workspace
                    events["recheckReturns"] += 1
                    if name == "noop-leaf-ctime-after-recheck":
                        leaf = root / seed_data["path"]
                        old = metadata_facts(batch, leaf)
                        leaf.chmod(stat.S_IMODE(old[2]))
                        new = metadata_facts(batch, leaf)
                        events["changedOnlyDeclaredFacts"] = old[:8] == new[:8] and old[9:] == new[9:] and old[8] != new[8]
                    else:
                        parent = (root / seed_data["path"]).parent
                        old = parent.stat(follow_symlinks=False)
                        parent.chmod(0o700)
                        new = parent.stat(follow_symlinks=False)
                        events["changedOnlyDeclaredFacts"] = (old.st_dev == new.st_dev and old.st_ino == new.st_ino
                            and old.st_uid == new.st_uid and old.st_gid == new.st_gid
                            and stat.S_IMODE(old.st_mode) == 0o750 and stat.S_IMODE(new.st_mode) == 0o700)
                    require(events["changedOnlyDeclaredFacts"])  # Actual changed ctime/mode; no sleep, retry or forged clock.
                    changed = metadata_snapshot(batch, root)
                    events["injections"] += 1
            return value

        def current(workspace, path, *, directory=False):
            if workspace is active_workspace and path == seed_data["path"] and not directory:
                with workflow_witness(batch):
                    version_original(batch, owner, workspace)
                    events["consumingTargetChecks"] += 1
            return current_original(workspace, path, directory=directory)

        def rename():
            events["renameProbes"] += 1
            return rename_original()

        before = metadata_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            checkout, plan = version_prepare(batch, owner, seed_data)
            require(metadata_snapshot(batch, root) == before)
            with patch.object(lease_type, "_recheck", recheck), patch.object(workspace_type, "_current", current), \
                 patch.object(runtime.transaction, "_rename_function", rename):
                result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
        version_finish(batch, owner, result, {**events,
            "unchangedMarked": active_workspace is not None and active_workspace._unchanged,
            "journalAbsent": version_no_state(batch, root),
            "snapshotUnchangedAfterInjection": changed is not None and metadata_snapshot(batch, root) == changed,
            "scopesClosed": metadata_scopes_closed(owner)})


def version_unreadable_case(batch: Batch) -> None:
    root = batch.case_root("unreadable-source-before-prepare")
    seed_data = version_seed(batch, root)
    runtime = batch.runtime
    read_original = runtime.transaction.InitWorkspace._read
    events = {"permissionErrorObserved": False, "deniedOriginalReads": 0}

    def read(workspace, fd, name, limit=runtime.transaction.MAX_FILE_BYTES):
        try:
            return read_original(workspace, fd, name, limit)
        except PermissionError:
            if workspace._scope is not None and workspace._scope.lease is owner.lease and name == "version.properties":
                with workflow_witness(batch):
                    require(type(workspace._scope) is runtime.custody.LockedInitScope
                            and workspace._typed_profile is owner.lease.profile is runtime.transaction.TypedEditProfile.RELEASE_VERSION
                            and workspace._scope is owner.lease._active and workspace._scope.workspace is workspace
                            and workspace._version_targets is owner.lease._version_targets
                            and type(workspace._version_targets) is runtime.custody.VersionTargets
                            and workspace._metadata_targets is None and os.geteuid() != 0)
                    workspace._version_targets._check_workspace(workspace)
                    events["permissionErrorObserved"] = True
                    events["deniedOriginalReads"] += 1
            raise  # The genuine original read exception is preserved, never replaced with an injected IO result.

    with owned_lease(batch, root) as owner:
        checkout = version_capture(batch, owner, seed_data)
        (root / seed_data["path"]).chmod(0)
        changed = metadata_snapshot(batch, root)  # lstat only for the unreadable leaf; no chmod-around-denial.
        with patch.object(runtime.transaction.InitWorkspace, "_read", read):
            result = refusal(batch, owner, "filesystem_error", lambda: version_prepare(batch, owner, seed_data, checkout))
    version_finish(batch, owner, result, {**events, "snapshotUnchanged": metadata_snapshot(batch, root) == changed,
        "journalAbsent": version_no_state(batch, root), "scopesClosed": metadata_scopes_closed(owner)})


def version_partial_rollback_case(batch: Batch) -> None:
    root = batch.case_root("version-replacement-installed-rollback")
    seed_data = version_seed(batch, root)
    before = workflow_snapshot(batch, root)  # A writer-owned rename/restore may change original file ctime.
    dependencies = metadata_dependencies(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    recovery_original = workspace_type._fixed_recovery
    events = {"versionLeafInstalled": False, "originalBackupBound": False,
              "rollbackReturned": False, "recoveryAttempts": 0, "injections": 0}

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                version_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started and destination == "version.properties")
                leaf = root / seed_data["path"]
                installed = leaf.stat(follow_symlinks=False)
                events["versionLeafInstalled"] = (workflow_read(leaf, 64 * 1024) == seed_data["payload"]
                    and (installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["originalBackupBound"] = version_original_backup(batch, root, seed_data)
                require(events["versionLeafInstalled"] and events["originalBackupBound"])
                events["injections"] += 1
            raise OSError("fixed version replacement installed injection")
        return value

    def rollback(workspace, *args):
        value = rollback_original(workspace, *args)
        with workflow_witness(batch):
            version_original(batch, owner, workspace)
            events["rollbackReturned"] = workspace._terminal_seen == "ROLLED_BACK" and workspace._terminal_durable
        return value

    def recovery(workspace):
        events["recoveryAttempts"] += 1
        return recovery_original(workspace)

    with owned_lease(batch, root) as owner:
        _, plan = version_prepare(batch, owner, seed_data)
        require(workflow_snapshot(batch, root) == before and metadata_dependencies(batch, root) == dependencies)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "_rollback", rollback), \
             patch.object(workspace_type, "_fixed_recovery", recovery):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
        scope_count = len(owner.lease._scopes)
        again = runtime.version.apply_release_version_edit(owner.lease, plan)
        second_refused = (again.effect, again.journal, again.resources, again.reason) == (
            "not_started", "not_created", "settled", "invalid_params")
        no_scope = len(owner.lease._scopes) == scope_count
    restored = metadata_facts(batch, root / seed_data["path"])
    original = seed_data["originalFacts"]
    require(restored is not None and restored[:8] == original[:8] and restored[9:] == original[9:]
            and metadata_dependencies(batch, root) == dependencies)
    version_finish(batch, owner, result, {**events, "snapshotRestored": workflow_snapshot(batch, root) == before,
        "journalAbsent": version_no_state(batch, root), "secondApplyRefused": second_refused,
        "secondApplyNoScope": no_scope, "scopesClosed": metadata_scopes_closed(owner)})


def version_incomplete_case(batch: Batch) -> None:
    root = batch.case_root("incomplete-version-preparing-retained")
    seed_data = version_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    write_original, recover_original, unlink_original = workspace_type._write, workspace_type.recover, workspace_type._unlink
    dependencies = metadata_dependencies(batch, root)
    original = metadata_facts(batch, root / seed_data["path"])
    unselected = version_unselected_snapshot(batch, root, seed_data)
    events = {"recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    active_workspace = None

    def write(workspace, fd, name, data, mode=0o600, **kwargs):
        nonlocal active_workspace
        value = write_original(workspace, fd, name, data, mode, **kwargs)
        if name == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                version_original(batch, owner, workspace)
                require(not workspace._workflow_complete and workspace._workflow_header is None)
                active_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed incomplete version preparation injection")
        return value

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = version_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_write", write), patch.object(workspace_type, "recover", recover), \
             patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
    preparing = root / runtime.transaction.VERSION_PREPARING
    require(all(workflow_absent(batch, root / name) for name in runtime.transaction.ALL_STATE_NAMES
                if name != runtime.transaction.VERSION_PREPARING)
            and version_unselected_snapshot(batch, root, seed_data) == unselected)
    version_finish(batch, owner, result, {
        "preparingRetained": stat.S_ISDIR(preparing.stat(follow_symlinks=False).st_mode),
        "completeProof": active_workspace is not None and active_workspace._workflow_complete,
        "numberedSlotRetained": workflow_read(preparing / "new-0", 64 * 1024) == seed_data["payload"],
        "targetPreserved": metadata_facts(batch, root / seed_data["path"]) == original,
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        **events, "scopesClosed": metadata_scopes_closed(owner)})


def version_cleanup_backup_case(batch: Batch) -> None:
    root = batch.case_root("committed-version-backup-replaced-at-cleanup-entry")
    seed_data = version_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    cleanup_original, unlink_original = workspace_type._cleanup, workspace_type._unlink
    dependencies = metadata_dependencies(batch, root)
    unselected = version_unselected_snapshot(batch, root, seed_data)
    events = {"committedObserved": False, "durabilityConfirmed": False, "sameBytesForeignInode": False,
              "originalBackupRetained": False, "cleanupUnlinks": 0, "injections": 0}
    active_workspace = None
    mutated = None
    original_backup = None

    def cleanup(workspace):
        nonlocal active_workspace, mutated, original_backup
        with workflow_witness(batch):
            version_original(batch, owner, workspace)
            require(active_workspace is None and workspace._workflow_complete and workspace._cleanup_mode
                    and workspace._recovery_claimed and workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
            active_workspace = workspace
            journal = root / runtime.transaction.VERSION_CLEANUP
            require(stat.S_ISDIR(journal.stat(follow_symlinks=False).st_mode))
            original = journal / "old-0"
            raw = workflow_read(original, 64 * 1024)
            before = original.stat(follow_symlinks=False)
            original_backup = root / "fixture-original-old-0"
            original.rename(original_backup)
            with original.open("xb") as stream:
                stream.write(raw)
            original.chmod(stat.S_IMODE(before.st_mode))
            after = original.stat(follow_symlinks=False)
            events["committedObserved"] = workspace._terminal_seen == "COMMITTED"
            events["durabilityConfirmed"] = workspace._terminal_durable
            events["sameBytesForeignInode"] = (workflow_read(original, 64 * 1024) == raw
                and after.st_dev == before.st_dev and after.st_ino != before.st_ino and after.st_mode == before.st_mode
                and after.st_uid == before.st_uid and after.st_gid == before.st_gid and after.st_nlink == before.st_nlink == 1)
            saved = metadata_facts(batch, original_backup)
            captured = seed_data["originalFacts"]
            events["originalBackupRetained"] = saved[:8] == captured[:8] and saved[9:] == captured[9:]
            require(events["sameBytesForeignInode"] and events["originalBackupRetained"])
            mutated = metadata_snapshot(batch, journal)
            events["injections"] += 1
        return cleanup_original(workspace)  # Original cleanup entry must refuse before any unlink.

    def unlink(workspace, *args, **kwargs):
        if workspace is active_workspace:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = version_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_cleanup", cleanup), patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
    require(original_backup is not None and workflow_read(original_backup, 64 * 1024) == seed_data["original"]
            and version_unselected_snapshot(batch, root, seed_data, retained_backup=True) == unselected)
    version_finish(batch, owner, result, {**events,
        "selectedPayloadInstalled": version_installed(batch, root, active_workspace, seed_data),
        "proofRetained": mutated is not None and metadata_snapshot(batch, root / runtime.transaction.VERSION_CLEANUP) == mutated,
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        "scopesClosed": metadata_scopes_closed(owner)})


def version_pending_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for name, state in zip(_VERSION_CASES["ordinary"][14:17], runtime.transaction.VERSION_STATE_NAMES):
        root = batch.case_root(name)
        originals = []
        entrypoints = []
        unchanged = retained = True
        legacy_apply = legacy_recover = legacy_closed = False
        for domain in ("legacy", "configuration", "github_workflows", "metadata_text"):
            child = root / domain
            child.mkdir(mode=0o700)
            version_seed(batch, child)
            pending = child / state
            pending.mkdir(mode=0o700)
            # Empty PREPARING is already foreign authority. READY/CLEANUP have
            # unparseable-as-control DATA; no foreign entrypoint may adopt it.
            if state != runtime.transaction.VERSION_PREPARING:
                (pending / "header.json").write_bytes(b'{"fixed":"foreign version state, must not be parsed"}\n')
            before, state_before = metadata_snapshot(batch, child), metadata_snapshot(batch, pending)
            with owned_lease(batch, child, domain="configuration" if domain == "legacy" else domain) as owner:
                if domain == "legacy":
                    # This idle original lease supplies only the real cancellation
                    # cleanup ledger; the existing public InitWorkspace owns its
                    # own legacy flock/fd and gets no typed or version authority.
                    with actual_lock_holder(batch, child, owner.guard, "init") as legacy:
                        observed = legacy.observe("release/mobile-release.json")
                        require(observed.data is not None and legacy._scope is None and legacy._guard is None)
                        try:
                            legacy.apply([(observed, observed.data + b" \n")])
                        except runtime.errors.ValidationError:
                            legacy_apply = True
                        require(legacy_apply)
                        try:
                            legacy.recover()
                        except runtime.errors.ValidationError:
                            legacy_recover = True
                        require(legacy_recover)
                    legacy_closed = legacy.fd == -1
                    require(owner.outcome is None and not owner.lease._scopes)
                    entrypoints.append("legacy")  # Actual two public calls above; no fabricated typed outcome.
                else:
                    if domain == "configuration":
                        action = lambda: runtime.edit.capture_config_edit(owner.lease)
                    elif domain == "github_workflows":
                        action = lambda: runtime.workflow.capture_github_workflow_edit(owner.lease)
                    else:
                        action = lambda: runtime.metadata.capture_metadata_text_edit(owner.lease, "android", "en-US")
                    result = refusal(batch, owner, "pending_state", action)
                    entrypoints.append(owner.domain)
            originals.append(owner)
            unchanged = (metadata_snapshot(batch, child) == before) and unchanged
            retained = (metadata_snapshot(batch, pending) == state_before) and retained
        version_finish(batch, originals[-1], result, {"entrypoints": entrypoints, "originalOwners": len(originals),
            "allOwnersSettled": all(owner.closed and owner.restored and not owner.fatal for owner in originals),
            "legacyApplyRefused": legacy_apply, "legacyRecoverRefused": legacy_recover, "legacyWorkspaceClosed": legacy_closed,
            "typedRefusals": sum(owner.outcome is not None and (owner.outcome.effect, owner.outcome.journal,
                owner.outcome.resources, owner.outcome.reason) == ("not_started", "not_created", "settled", "pending_state")
                for owner in originals),
            "stateRetained": retained, "snapshotUnchanged": unchanged,
            "targetDescriptorsAbsent": all(owner.lease._version_targets is None and owner.lease._metadata_targets is None
                                            for owner in originals),
            "scopesClosed": sum(metadata_scopes_closed(owner) for owner in originals)})

    root = batch.case_root("version-refuses-foreign-ready")
    originals = []
    foreign_domains = []
    unchanged = retained = absent = True
    for domain, state in (("legacy", runtime.transaction.READY), ("metadata_text", runtime.transaction.METADATA_READY)):
        child = root / domain
        child.mkdir(mode=0o700)
        seed_data = version_seed(batch, child)
        pending = child / state
        pending.mkdir(mode=0o700)
        (pending / "header.json").write_bytes(b'{"fixed":"foreign READY, must not be parsed"}\n')
        before, state_before = metadata_snapshot(batch, child), metadata_snapshot(batch, pending)
        with owned_lease(batch, child) as owner:
            result = refusal(batch, owner, "pending_state", lambda: version_capture(batch, owner, seed_data))
        originals.append(owner)
        foreign_domains.append(domain)
        unchanged = (metadata_snapshot(batch, child) == before) and unchanged
        retained = (metadata_snapshot(batch, pending) == state_before) and retained
        absent = version_no_state(batch, child, version_only=True) and absent
    version_finish(batch, originals[-1], result, {"foreignDomains": foreign_domains, "originalOwners": len(originals),
        "allOwnersSettled": all(owner.closed and owner.restored and not owner.fatal for owner in originals),
        "bothRefused": all((owner.outcome.effect, owner.outcome.journal, owner.outcome.resources, owner.outcome.reason)
                           == ("not_started", "not_created", "settled", "pending_state") for owner in originals),
        "foreignStateRetained": retained, "snapshotUnchanged": unchanged, "versionStateAbsent": absent,
        "targetDescriptorsAbsent": all(owner.lease._version_targets is None and owner.lease._metadata_targets is None
                                       for owner in originals),
        "scopesClosed": sum(metadata_scopes_closed(owner) for owner in originals)})


def version_dependency_drift_case(batch: Batch) -> None:
    root = batch.case_root("dependency-drift-after-version-install")
    seed_data = version_seed(batch, root, writable_config=True)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, locations_original = workspace_type._move, workspace_type._locations
    recover_original, unlink_original = workspace_type.recover, workspace_type._unlink
    events = {"versionLeafInstalled": False, "originalBackupBound": False, "dependencyChanged": False,
              "conflictObservedInsideOriginal": False, "retainedTreeInsideOriginal": False,
              "laterInstallMoves": 0, "recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    active_workspace = None
    changed = None

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        nonlocal active_workspace, changed
        already_injected = events["injections"] == 1
        value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        if already_injected and workspace._installing:
            events["laterInstallMoves"] += 1  # Count only actual returned original effects.
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                version_original(batch, owner, workspace)
                require(active_workspace is None and workspace._workflow_complete and workspace._install_started
                        and destination == "version.properties" and not workspace._recovery_claimed)
                active_workspace = workspace
                leaf = root / seed_data["path"]
                installed = leaf.stat(follow_symlinks=False)
                events["versionLeafInstalled"] = (workflow_read(leaf, 64 * 1024) == seed_data["payload"]
                    and (installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["originalBackupBound"] = version_original_backup(batch, root, seed_data)
                raw = seed_data["config"] + b" \n"
                (root / "release/mobile-release.json").write_bytes(raw)
                events["dependencyChanged"] = workflow_read(root / "release/mobile-release.json", 512 * 1024) == raw != seed_data["config"]
                require(events["versionLeafInstalled"] and events["originalBackupBound"] and events["dependencyChanged"])
                changed = metadata_snapshot(batch, root)
                events["injections"] += 1
        return value

    def locations(workspace, fd, manifest, *, final=None):
        # A version edit has ONE leaf: there is no next installation _move.
        # Observe the genuine final="new" dependency refusal inside the saved
        # original _locations, before its actual outcome latches Unknown.
        try:
            return locations_original(workspace, fd, manifest, final=final)
        except runtime.transaction.InitConflict:
            if workspace is active_workspace and events["injections"] == 1 and final == "new":
                with workflow_witness(batch):
                    version_original(batch, owner, workspace)
                    require(workspace._installing and workspace._install_started and not workspace._recovery_claimed
                            and workspace._terminal_seen is None and not workspace._terminal_durable)
                    events["conflictObservedInsideOriginal"] = True
                    events["retainedTreeInsideOriginal"] = changed is not None and metadata_snapshot(batch, root) == changed
                    require(events["retainedTreeInsideOriginal"])
            raise  # Preserve the original exception; never inject a synthetic stale result.

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = version_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "_locations", locations), \
             patch.object(workspace_type, "recover", recover), patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan), expected_unknown=True)
        # Only original prearmed lease cleanup follows this effect-Unknown.
        # No filesystem reads, new owner, recovery, or cleanup adoption follow.
    version_finish(batch, owner, result, {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes,
        "scopesClosed": metadata_scopes_closed(owner)})


def version_committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("version-committed-fsync-injection")
    seed_data = version_seed(batch, root, selection="releaseVersion")
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    fsync_original, rollback_original = workspace_type._fsync, workspace_type._rollback
    dependencies = metadata_dependencies(batch, root)
    unselected = version_unselected_snapshot(batch, root, seed_data)
    events = {"rollbackCalls": 0, "injections": 0}
    active_workspace = None
    retained = None

    def fsync(workspace, fd):
        nonlocal active_workspace, retained
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injections"] == 0):
            with workflow_witness(batch):
                version_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started)
                active_workspace = workspace
                retained = metadata_snapshot(batch, root / runtime.transaction.VERSION_READY)
                events["injections"] += 1
            raise OSError("fixed version postdecision pre-fsync injection")
        return fsync_original(workspace, fd)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    with owned_lease(batch, root) as owner:
        _, plan = version_prepare(batch, owner, seed_data)
        with patch.object(workspace_type, "_fsync", fsync), patch.object(workspace_type, "_rollback", rollback):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan))
    marker = root / runtime.transaction.VERSION_READY / "COMMITTED"
    require(retained is not None and metadata_snapshot(batch, marker.parent) == retained
            and version_original_backup(batch, root, seed_data)
            and version_unselected_snapshot(batch, root, seed_data) == unselected)
    version_finish(batch, owner, result, {
        "committedObserved": active_workspace is not None and active_workspace._terminal_seen == "COMMITTED",
        "durabilityConfirmed": active_workspace is not None and active_workspace._terminal_durable,
        "selectedPayloadInstalled": version_installed(batch, root, active_workspace, seed_data),
        "journalRetained": stat.S_ISREG(marker.stat(follow_symlinks=False).st_mode),
        "dependenciesPreserved": metadata_dependencies(batch, root) == dependencies,
        **events, "scopesClosed": metadata_scopes_closed(owner)})


def version_committed_close_case(batch: Batch) -> None:
    root = batch.case_root("version-committed-close-return-injection")
    seed_data = version_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    close_original = runtime.custody.LockedInitScope.close
    publish_original, apply_original = workspace_type._publish_terminal, workspace_type.apply_version_typed
    dependencies = metadata_dependencies(batch, root)
    unselected = version_unselected_snapshot(batch, root, seed_data)
    events = {"actualScopeCloseReturned": False, "cancelledAfterCommit": 0, "committedCarrier": False, "injections": 0}
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = version_prepare(batch, owner, seed_data)

        def publish(workspace, fd, manifest, state):
            value = publish_original(workspace, fd, manifest, state)
            if state == "COMMITTED":
                with workflow_witness(batch):
                    version_original(batch, owner, workspace)
                    require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                    events["cancelledAfterCommit"] += 1
                    owner.guard.cancelled = True
                raise KeyboardInterrupt  # Labelled fault injection, never stdin-EOF evidence.
            return value

        def apply(workspace, changes):
            try:
                return apply_original(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                with workflow_witness(batch):
                    version_original(batch, owner, workspace)
                    events["committedCarrier"] = (error.outcome.effect == "committed"
                        and error.outcome.journal == "clean" and error.outcome.reason == "cancelled")
                    require(version_installed(batch, root, workspace, seed_data)
                            and metadata_dependencies(batch, root) == dependencies
                            and version_unselected_snapshot(batch, root, seed_data) == unselected
                            and version_no_state(batch, root))
                raise

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injections"] == 0:
                close_original(scope)
                with workflow_witness(batch):
                    events["actualScopeCloseReturned"] = scope.closed is True
                    events["injections"] += 1
                raise OSError("fixed version positive scope-close return loss injection")
            return close_original(scope)

        with patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "apply_version_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.version.apply_release_version_edit(owner.lease, plan), expected_unknown=True)
        # Lane-last resources Unknown: the original prearmed owner cleanup is
        # the only further operation. No project/tool read, retry or reopen.
    version_finish(batch, owner, result, {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes,
        "scopesClosed": metadata_scopes_closed(owner)})


def hosted_parameters(argv: list[str]) -> tuple[Path, str]:
    if (not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or os.environ.get("MRK_DESKTOP_CONFIG_NATIVE") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise FixtureRefused()
    platform = "Linux" if sys.platform.startswith("linux") else "macOS" if sys.platform == "darwin" else None
    if platform is None or os.environ.get("RUNNER_OS") != platform:
        raise FixtureRefused()
    if len(argv) not in {2, 4} or argv[0] != "--task-root" or (len(argv) == 4 and argv[2] != "--case"):
        raise FixtureRefused()
    partition = argv[3] if len(argv) == 4 else "ordinary"
    if partition not in _PARTITIONS:
        raise FixtureRefused()
    root = Path(argv[1])
    temp_value = os.environ.get("RUNNER_TEMP")
    if not temp_value or not root.is_absolute() or str(root) != argv[1] or root.resolve(strict=True) != root:
        raise FixtureRefused()
    runner_temp = Path(temp_value).resolve(strict=True)
    if root == runner_temp or not root.is_relative_to(runner_temp):
        raise FixtureRefused()
    value = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise FixtureRefused()
    return root, partition


def workflow_selection(argv: list[str]) -> tuple[str, str] | None:
    """Pure closed grammar; native admission additionally needs original facts."""
    if (type(argv) is not list or len(argv) != 6 or any(type(item) is not str for item in argv)
            or argv[0] != "--task-root" or argv[2:5] != ["--domain", "github_workflows", "--case"]
            or argv[5] not in _PARTITIONS):
        return None
    return argv[1], argv[5]


def metadata_selection(argv: list[str]) -> tuple[str, str] | None:
    """Only the existing core partitions in the closed third domain."""
    if (type(argv) is not list or len(argv) != 6 or any(type(item) is not str for item in argv)
            or argv[0] != "--task-root" or argv[2:5] != ["--domain", "metadata_text", "--case"]
            or argv[5] not in _PARTITIONS):
        return None
    return argv[1], argv[5]


def version_selection(argv: list[str]) -> tuple[str, str] | None:
    """Only the three fixed core partitions in the saved-version domain."""
    if (type(argv) is not list or len(argv) != 6 or any(type(item) is not str for item in argv)
            or argv[0] != "--task-root" or argv[2:5] != ["--domain", "release_version", "--case"]
            or argv[5] not in _PARTITIONS):
        return None
    return argv[1], argv[5]


def workflow_hosted_parameters(argv: list[str], *, domain: str = "github_workflows") -> tuple[Path, str, Path, str, dict[str, Any]]:
    # Reuse the same original hosted/root/host admission, not another native
    # launcher. The default workflow entry keeps its exact original contract.
    selections = {"github_workflows": (workflow_selection, "MRK_DESKTOP_WORKFLOW"),
                  "metadata_text": (metadata_selection, "MRK_DESKTOP_METADATA_TEXT"),
                  "release_version": (version_selection, "MRK_DESKTOP_RELEASE_VERSION")}
    if domain not in selections:
        raise FixtureRefused()
    select_domain, prefix = selections[domain]
    selected = select_domain(argv)
    source_sha = os.environ.get(prefix + "_SOURCE_SHA", "")
    if (selected is None or sys.version_info < (3, 11)
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or sys.platform != "linux" or os.uname().machine != "x86_64"
            or os.getuid() == 0 or os.geteuid() != os.getuid()
            or threading.current_thread() is not threading.main_thread()
            or os.environ.get(prefix + "_NATIVE") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64"
            or len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha)
            or source_sha != os.environ.get("GITHUB_SHA")):
        raise FixtureRefused()
    root_text, partition = selected
    root = Path(root_text)
    fixture = Path(__file__)
    repository = fixture.parents[1]
    temp_value = os.environ.get("RUNNER_TEMP")
    workspace_value = os.environ.get("GITHUB_WORKSPACE")
    if (not temp_value or not workspace_value or not fixture.is_absolute()
            or fixture.resolve(strict=True) != fixture
            or fixture != repository / "tests/native_desktop_config.py"
            or str(repository) != workspace_value or repository.resolve(strict=True) != repository
            or not root.is_absolute() or str(root) != root_text or root.resolve(strict=True) != root):
        raise FixtureRefused()
    runner_temp = Path(temp_value)
    if (not runner_temp.is_absolute() or runner_temp.resolve(strict=True) != runner_temp
            or root == runner_temp or not root.is_relative_to(runner_temp)
            or root.is_relative_to(repository)):
        raise FixtureRefused()
    value = root.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700):
        raise FixtureRefused()
    # Only observed kernel/statvfs facts, NOT filesystem type, rename semantics,
    # runtime custody, ordinary startup, or a production capability qualification.
    release = os.uname().release
    filesystem = os.statvfs(root)
    if (not 0 < len(release.encode("utf-8")) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in release)
            or not 0 <= value.st_dev < 2**64
            or any(type(v) is not int or v <= 0 for v in (filesystem.f_bsize, filesystem.f_frsize, filesystem.f_namemax))
            or type(filesystem.f_flag) is not int or filesystem.f_flag < 0):
        raise FixtureRefused()
    host = {"kernelRelease": release, "machine": os.uname().machine, "nonRoot": os.geteuid() != 0,
            "filesystem": {"device": str(value.st_dev), "blockSize": filesystem.f_bsize,
                           "fragmentSize": filesystem.f_frsize, "nameMax": filesystem.f_namemax,
                           "flags": filesystem.f_flag}}
    return root, partition, repository, source_sha, host


def workflow_runtime(repository: Path, source_sha: str) -> tuple[Runtime, dict[str, Any]]:
    source = repository / "src"
    if not source.is_dir() or source.resolve(strict=True) != source:
        raise FixtureRefused()
    originals: dict[str, bytes] = {}
    for identity, relative in _WORKFLOW_SOURCES.items():
        path = repository / relative
        value = path.stat(follow_symlinks=False)
        if (path.resolve(strict=True) != path or not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid() or value.st_mode & 0o022):
            raise FixtureRefused()
        originals[identity] = workflow_read(path, 1024 * 1024)
    # The exact source beside the admitted fixture is the sole subject import
    # path. There is no ZIP selector, ambient path or environment fallback here.
    sys.path.insert(0, str(source))
    runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
        "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
        "cancellation", "errors", "config_payloads")))
    runtime.domain = "github_workflows"
    runtime.workflow = importlib.import_module("mobile_release.github_workflow_edit")
    runtime.workflow_payloads = importlib.import_module("mobile_release.workflow_payloads")
    runtime.workflow_setup = importlib.import_module("mobile_release.api._github_setup")
    modules = ((runtime.edit, "config_edit.py"), (runtime.transaction, "init_transaction.py"),
               (runtime.custody, "init_workspace_custody.py"), (runtime.build, "build_inputs.py"),
               (runtime.cancellation, "cancellation.py"), (runtime.errors, "errors.py"),
               (runtime.payloads, "config_payloads.py"), (runtime.workflow, "github_workflow_edit.py"),
               (runtime.workflow_payloads, "workflow_payloads.py"), (runtime.workflow_setup, "api/_github_setup.py"))
    for module, relative in modules:
        require(Path(module.__file__).resolve(strict=True) == source / "mobile_release" / relative)
    require(runtime.workflow_payloads.GITHUB_WORKFLOWS == _WORKFLOW_FILES)
    draft = workflow_document()
    draft_bytes = json.dumps(draft, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    draft_digest = hashlib.sha256(draft_bytes).hexdigest()
    require(draft_digest == _WORKFLOW_DRAFT_SHA256)
    proposal = runtime.workflow_setup.propose_github_setup(draft, _WORKFLOW_REPOSITORY, _WORKFLOW_SHA, None)
    require(proposal["state"] == "proposed" and proposal["validation"]["valid"] is True
            and workflow_equal(proposal["templateSet"], _WORKFLOW_TEMPLATE_SET)
            and len(proposal["workflows"]) == 4)
    resource = json.loads(originals["resource"])
    require(hashlib.sha256(originals["resource"]).hexdigest() == proposal["templateSet"]["resourceSha256"])
    payloads = []
    payload_hashes = {}
    canonical_ids = ("canonicalPreflight", "canonicalCandidate", "canonicalExternalTesting", "canonicalProductionSubmit")
    for (identity, path), row, canonical, expected_digest in zip(
            _WORKFLOW_FILES, proposal["workflows"], canonical_ids, _WORKFLOW_PAYLOAD_SHA256):
        template = originals[canonical]
        require(template == resource["workflows"][identity].encode("utf-8"))
        rendered = runtime.workflow_payloads.render_workflow_caller(template, _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
        data = row["content"].encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        require(row["id"] == identity and row["path"] == path and row["comparison"] == "not-supplied"
                and data == rendered and 0 < len(data) <= 16 * 1024 and row["byteLength"] == len(data)
                and row["sha256"] == digest == expected_digest)
        payloads.append(data)
        payload_hashes[identity] = digest
    runtime.workflow_bytes = tuple(payloads)
    python = Path(sys.executable).resolve(strict=True)
    bindings = {"sourceSha": source_sha, "sourceKind": "source",
                "sourceHashes": {identity: hashlib.sha256(data).hexdigest() for identity, data in originals.items()},
                "pythonSha256": hashlib.sha256(workflow_read(python, 64 * 1024 * 1024)).hexdigest(),
                "draftSha256": draft_digest, "toolingRepository": _WORKFLOW_REPOSITORY,
                "toolingSha": _WORKFLOW_SHA, "templateSet": proposal["templateSet"], "payloadHashes": payload_hashes}
    return runtime, bindings


def metadata_runtime(repository: Path, source_sha: str) -> tuple[Runtime, dict[str, Any]]:
    source = repository / "src"
    if not source.is_dir() or source.resolve(strict=True) != source:
        raise FixtureRefused()
    originals: dict[str, bytes] = {}
    for identity, relative in _METADATA_SOURCES.items():
        path = repository / relative
        value = path.stat(follow_symlinks=False)
        if (path.resolve(strict=True) != path or not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid() or value.st_mode & 0o022):
            raise FixtureRefused()
        originals[identity] = workflow_read(path, 1024 * 1024)
    # Sole source path, established before any subject import. Helper binds the
    # complete package closure; these twenty named keys are the component map,
    # not a claim that only twenty files can be reached by ordinary imports.
    sys.path.insert(0, str(source))
    runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
        "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
        "cancellation", "errors", "config_payloads")))
    runtime.domain = "metadata_text"
    runtime.metadata = importlib.import_module("mobile_release.metadata_text_edit")
    runtime.metadata_text = importlib.import_module("mobile_release.metadata_text")
    runtime.workflow = importlib.import_module("mobile_release.github_workflow_edit")  # Only C17/C18 foreign-state admission.
    policy = importlib.import_module("mobile_release.metadata")
    modules = ((runtime.edit, "config_edit.py"), (runtime.transaction, "init_transaction.py"),
               (runtime.custody, "init_workspace_custody.py"), (runtime.build, "build_inputs.py"),
               (runtime.cancellation, "cancellation.py"), (runtime.errors, "errors.py"),
               (runtime.payloads, "config_payloads.py"), (runtime.metadata, "metadata_text_edit.py"),
               (runtime.metadata_text, "metadata_text.py"), (runtime.workflow, "github_workflow_edit.py"),
               (policy, "metadata.py"))
    for module, relative in modules:
        require(Path(module.__file__).resolve(strict=True) == source / "mobile_release" / relative)
    require(workflow_equal(policy.REQUIRED_LOCALE_TEXT, _METADATA_FILES)
            and runtime.metadata_text.DEPENDENCY_PATHS == ("release/mobile-release.json", ".gitignore")
            and runtime.metadata_text.MAX_TEXT_BYTES == 32 * 1024
            and ("\n".join(runtime.transaction.METADATA_IGNORE_LINES) + "\n").encode("utf-8") == _METADATA_IGNORE)
    config_hashes = {key: hashlib.sha256(raw.encode("utf-8")).hexdigest() for key, raw in _METADATA_CONFIG_TEXT.items()}
    field_hashes = {platform: {identity: hashlib.sha256(_METADATA_TEXT[platform][identity].encode("utf-8")).hexdigest()
                              for identity in ids} for platform, ids in _METADATA_FILES.items()}
    ignore_sha = hashlib.sha256(_METADATA_IGNORE).hexdigest()
    require(workflow_equal(config_hashes, _METADATA_CONFIG_HASHES)
            and workflow_equal(field_hashes, _METADATA_FIELD_HASHES) and ignore_sha == _METADATA_IGNORE_SHA256)
    python = Path(sys.executable).resolve(strict=True)
    bindings = {"sourceSha": source_sha, "sourceKind": "source",
                "sourceHashes": {identity: hashlib.sha256(raw).hexdigest() for identity, raw in originals.items()},
                "pythonSha256": hashlib.sha256(workflow_read(python, 64 * 1024 * 1024)).hexdigest(),
                "configHashes": config_hashes, "ignoreSha256": ignore_sha, "fieldHashes": field_hashes}
    return runtime, bindings


def version_runtime(repository: Path, source_sha: str) -> tuple[Runtime, dict[str, Any]]:
    source = repository / "src"
    if not source.is_dir() or source.resolve(strict=True) != source:
        raise FixtureRefused()
    originals: dict[str, bytes] = {}
    for identity, relative in _VERSION_SOURCES.items():
        path = repository / relative
        value = path.stat(follow_symlinks=False)
        if (path.resolve(strict=True) != path or not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid() or value.st_mode & 0o022):
            raise FixtureRefused()
        originals[identity] = workflow_read(path, 1024 * 1024)
    # Sole source import root. The helper separately binds the complete package
    # closure; this closed 25-entry component map is not a replacement for it.
    sys.path.insert(0, str(source))
    runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
        "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
        "cancellation", "errors", "config_payloads")))
    runtime.domain = "release_version"
    runtime.version = importlib.import_module("mobile_release.release_version_edit")
    runtime.version_text = importlib.import_module("mobile_release.version_text")
    runtime.metadata = importlib.import_module("mobile_release.metadata_text_edit")  # Only foreign-state capture refusal.
    runtime.metadata_text = importlib.import_module("mobile_release.metadata_text")
    runtime.workflow = importlib.import_module("mobile_release.github_workflow_edit")  # Only foreign-state capture refusal.
    modules = ((runtime.edit, "config_edit.py"), (runtime.transaction, "init_transaction.py"),
               (runtime.custody, "init_workspace_custody.py"), (runtime.build, "build_inputs.py"),
               (runtime.cancellation, "cancellation.py"), (runtime.errors, "errors.py"),
               (runtime.payloads, "config_payloads.py"), (runtime.version, "release_version_edit.py"),
               (runtime.version_text, "version_text.py"), (runtime.metadata, "metadata_text_edit.py"),
               (runtime.metadata_text, "metadata_text.py"), (runtime.workflow, "github_workflow_edit.py"))
    for module, relative in modules:
        require(Path(module.__file__).resolve(strict=True) == source / "mobile_release" / relative)
    require(len(originals) == 25 and runtime.version_text.DEPENDENCY_PATHS == ("release/mobile-release.json", ".gitignore")
            and runtime.version_text.MAX_VERSION_BYTES == 64 * 1024
            and ("\n".join(runtime.transaction.IGNORE_LINES) + "\n").encode("utf-8") == _VERSION_IGNORE
            and ("\n".join(runtime.transaction.METADATA_IGNORE_LINES) + "\n").encode("utf-8") == _METADATA_IGNORE)
    config_hashes = {key: hashlib.sha256(raw.encode("utf-8")).hexdigest() for key, raw in _VERSION_CONFIG_TEXT.items()}
    version_hashes = {key: hashlib.sha256(raw.encode("utf-8")).hexdigest() for key, raw in _VERSION_TEXT.items()}
    ignore_sha = hashlib.sha256(_VERSION_IGNORE).hexdigest()
    require(workflow_equal(config_hashes, _VERSION_CONFIG_HASHES)
            and workflow_equal(version_hashes, _VERSION_HASHES) and ignore_sha == _VERSION_IGNORE_SHA256)
    python = Path(sys.executable).resolve(strict=True)
    bindings = {"sourceSha": source_sha, "sourceKind": "source",
                "sourceHashes": {identity: hashlib.sha256(raw).hexdigest() for identity, raw in originals.items()},
                "pythonSha256": hashlib.sha256(workflow_read(python, 64 * 1024 * 1024)).hexdigest(),
                "configHashes": config_hashes, "ignoreSha256": ignore_sha, "versionHashes": version_hashes}
    return runtime, bindings


def version_main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    batch = None
    bindings = host = None
    partition = "unadmitted"
    status, reason = "failed", "unexpected_failure"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True
        task_root, partition, repository, source_sha, host = workflow_hosted_parameters(argv, domain="release_version")
        runtime, bindings = version_runtime(repository, source_sha)
        root = task_root / ("python-release-version-edit-" + partition)
        root.mkdir(mode=0o700)
        batch = Batch(runtime, root, partition)
        batch.retain = True  # Every version partition retains the original synthetic tree for VM disposal.
        _RETAINED_BATCH = batch
        if partition == "ordinary":
            for case in (version_selection_refusals, version_stale_cases, version_late_noop_cases,
                         version_unreadable_case, version_partial_rollback_case, version_incomplete_case,
                         version_cleanup_backup_case, version_pending_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            version_dependency_drift_case(batch)  # Invocation-last effect Unknown, never recovered by the fixture.
        elif partition == "committed-fsync":
            version_committed_fsync_case(batch)
        else:
            version_committed_close_case(batch)  # Entire native lane-last resources Unknown.
        # Only retained scalar DATA follows either Unknown. No source/tool/file
        # observation, child, fresh lease or cleanup operation may start here.
        require(tuple(batch.completed) == _VERSION_CASES[partition]
                and len(batch.workflow_rows) == len(batch.completed)
                and not batch.workflow_fixture_failed and batch.retain
                and batch.blocked is (partition != "committed-fsync")
                and all(owner.closed and owner.restored for owner in batch.owners))
        require(all(not owner.fatal for owner in batch.owners) if partition != "committed-close"
                else len(batch.owners) == 1 and batch.owners[0].fatal)
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass  # No exception, native transcript, selected private bytes or project paths.
    report = {
        "schemaVersion": 1, "suite": "desktop-release-version-native", "domain": "release_version",
        "partition": partition, "status": status, "reason": reason, "bindings": bindings, "host": host,
        "completed": batch.completed if batch is not None else [],
        "cases": batch.workflow_rows if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "fixed-original-version-boundaries", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 32 * 1024:
        report.update(status="failed", reason="fixed_case_failed", bindings=None, host=None,
                      completed=[], cases=[], failedAt=batch.current if batch is not None else None,
                      retained=batch is not None)
        encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        status = "failed"
    print(encoded)
    return 0 if status == "passed" else 1


def metadata_main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    batch = None
    bindings = host = None
    partition = "unadmitted"
    status, reason = "failed", "unexpected_failure"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True
        task_root, partition, repository, source_sha, host = workflow_hosted_parameters(argv, domain="metadata_text")
        runtime, bindings = metadata_runtime(repository, source_sha)
        root = task_root / ("python-metadata-text-edit-" + partition)
        root.mkdir(mode=0o700)
        batch = Batch(runtime, root, partition)
        batch.retain = True  # Every metadata partition retains its original synthetic tree for VM disposal.
        _RETAINED_BATCH = batch
        if partition == "ordinary":
            for case in (metadata_selection_refusals, metadata_stale_cases, metadata_late_noop_cases,
                         metadata_unreadable_case, metadata_partial_rollback_case, metadata_incomplete_case,
                         metadata_cleanup_backup_case, metadata_pending_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            metadata_dependency_drift_case(batch)  # Ordinary invocation-last effect Unknown.
        elif partition == "committed-fsync":
            metadata_committed_fsync_case(batch)
        else:
            metadata_committed_close_case(batch)  # Entire lane-last resources Unknown.
        # Only already retained original DATA follows either Unknown. No file,
        # source, tool, process or cleanup observer can start another operation.
        require(tuple(batch.completed) == _METADATA_CASES[partition]
                and len(batch.workflow_rows) == len(batch.completed)
                and not batch.workflow_fixture_failed and batch.retain
                and batch.blocked is (partition != "committed-fsync")
                and all(owner.closed and owner.restored for owner in batch.owners))
        require(all(not owner.fatal for owner in batch.owners) if partition != "committed-close"
                else len(batch.owners) == 1 and batch.owners[0].fatal)
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass
    report = {
        "schemaVersion": 1, "suite": "desktop-metadata-text-native", "domain": "metadata_text",
        "partition": partition, "status": status, "reason": reason, "bindings": bindings, "host": host,
        "completed": batch.completed if batch is not None else [],
        "cases": batch.workflow_rows if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "fixed-original-metadata-boundaries", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 32 * 1024:
        report.update(status="failed", reason="fixed_case_failed", bindings=None, host=None,
                      completed=[], cases=[], failedAt=batch.current if batch is not None else None,
                      retained=batch is not None)
        encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        status = "failed"
    print(encoded)
    return 0 if status == "passed" else 1


def workflow_main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    batch = None
    bindings = host = None
    partition = "unadmitted"
    status, reason = "failed", "unexpected_failure"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True
        task_root, partition, repository, source_sha, host = workflow_hosted_parameters(argv)
        runtime, bindings = workflow_runtime(repository, source_sha)
        root = task_root / ("python-workflow-edit-" + partition)
        root.mkdir(mode=0o700)
        batch = Batch(runtime, root, partition)
        _RETAINED_BATCH = batch
        if partition == "ordinary":
            for case in (workflow_capture_case, workflow_conflict_case, workflow_observation_cases,
                         workflow_registered_root_case, workflow_stale_cases, workflow_pending_cases,
                         workflow_contention_cases, workflow_partial_rollback_case, workflow_incomplete_case,
                         workflow_ready_corruption_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            workflow_pending_replaced_case(batch, committed=False)
            workflow_cleanup_missing_cases(batch)
            workflow_pending_replaced_case(batch, committed=True)  # LAST: effect-Unknown.
        elif partition == "committed-fsync":
            workflow_committed_fsync_case(batch)
        else:
            workflow_committed_close_case(batch)  # LAST in the entire native lane.
        # Only retained original DATA is inspected after either uncertainty.
        # All workflow partitions intentionally retain their private trees. No
        # successful late wait/close supplies permission to adopt or delete them.
        require(tuple(batch.completed) == _WORKFLOW_CASES[partition]
                and len(batch.workflow_rows) == len(batch.completed)
                and not batch.workflow_fixture_failed and batch.retain
                and batch.blocked is (partition != "committed-fsync")
                and all(owner.closed and owner.restored for owner in batch.owners))
        require(all(not owner.fatal for owner in batch.owners) if partition != "committed-close"
                else len(batch.owners) == 1 and batch.owners[0].fatal)
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass
    report = {
        "schemaVersion": 1, "suite": "desktop-workflow-native", "domain": "github_workflows",
        "partition": partition, "status": status, "reason": reason, "bindings": bindings, "host": host,
        "completed": batch.completed if batch is not None else [],
        "cases": batch.workflow_rows if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "fixed-original-workflow-boundaries", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 32 * 1024:
        report.update(status="failed", reason="fixed_case_failed", bindings=None, host=None,
                      completed=[], cases=[], failedAt=batch.current if batch is not None else None,
                      retained=batch is not None)
        encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        status = "failed"
    print(encoded)
    return 0 if status == "passed" else 1


def main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    if type(argv) is list and "--domain" in argv:
        if argv[2:4] == ["--domain", "release_version"]:
            return version_main(argv)
        if argv[2:4] == ["--domain", "metadata_text"]:
            return metadata_main(argv)
        return workflow_main(argv)
    batch = None
    status, reason = "failed", "unexpected_failure"
    partition = "unadmitted"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True  # No entrypoint replay in this interpreter, even on refusal.
        task_root, partition = hosted_parameters(argv)
        # -I -S excludes ambient PYTHONPATH/site packages. The only added path
        # is the exact source beside this reviewed fixed fixture, not a project.
        source = Path(__file__).resolve(strict=True).parents[1] / "src"
        require(source.is_dir() and not source.is_symlink())
        sys.path.insert(0, str(source))
        runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
            "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
            "cancellation", "errors", "config_payloads")))
        root = task_root / ("python-config-edit-" + partition)
        root.mkdir(mode=0o700)
        original = root.stat(follow_symlinks=False)
        batch = Batch(runtime, root, partition)
        _RETAINED_BATCH = batch  # Uncertainty/failure keeps original records to process exit.
        if partition == "ordinary":
            for case in (create_case, save_noop_ignore_cases, refusal_cases, stale_cases,
                         pending_cases, contention_cases, prepublication_rollback_case, legacy_public_apply_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            require(len(batch.completed) == 27)
        elif partition == "committed-fsync":
            committed_fsync_case(batch)
        else:
            committed_close_case(batch)
        if not batch.retain:
            require(not batch.blocked and all(owner.closed and owner.restored and not owner.fatal for owner in batch.owners))
            current = root.stat(follow_symlinks=False)
            require((current.st_dev, current.st_ino, current.st_mode) == (original.st_dev, original.st_ino, original.st_mode))
            shutil.rmtree(root)  # Only this exclusive fully settled synthetic root.
            _RETAINED_BATCH = None
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass  # No exception text, private path, file bytes or native transcript.
    report = {
        "suite": "desktop-config-native", "partition": partition, "status": status, "reason": reason,
        "completed": batch.completed if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "precommit-publication", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    print(json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
