#!/usr/bin/env python3
"""Closed DATA projection for verification artifacts, never native acceptance.

Original receipts/captures remain local and authoritative to their existing
validators. This script reads only the fixed roster below, never tool output,
source-binding.json, private native reports, credentials or directory listings.
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
    "prepare-removal-observers", "package-removal-fixture",
)
PHASE_STATUS = {
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
    *("normal-ui/" + role + suffix for role in ("project", "persistence", "diagnostics", "saved-checks",
      "saved-version-recovery", "github-local-bundle", "removal-ordinary") for suffix in ("-test.status", "-summary.status")),
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
    *REMOVAL_ROLES["ordinary"], *REMOVAL_ROLES["abrupt"],
    "build", "resident-image-sign", "resident-image-verify-signed", "entry-build", "desktop-facade-build",
    "resident-facade-build", "sign", "verify-signed", "verify-before", "verify-after",
    "verify-before-resident-image", "verify-after-resident-image", "verify-before-history-provider", "verify-before-github-seal",
    "verify-after-history-provider", "verify-after-github-seal", "resolve-notarytool", "resolve-stapler",
    "verify-inner-before", "verify-outer-before", "payload-zip", "payload-submit", "payload-log",
    "staple-inner", "validate-inner", "staple-outer", "validate-outer", "verify-inner-after", "verify-outer-after",
    "producer-build", "producer-emitter", "distribution-create", "distribution-sign", "distribution-verify-signature",
    "distribution-verify-image", "observation-create", "observation-sign", "observation-verify-signature",
    "observation-verify-image", "distribution-attach", "installer-log-cursor", "installer", "installer-log-capture",
    "distribution-detach", "final-package-productbuild",
    *(phase + suffix for phase in PHASES if phase.startswith("sign-") for suffix in ("", "-verify")),
    *("final-image-" + role for role in ("resolve-notarytool", "resolve-stapler", "signature-before", "submit", "log",
      "staple", "validate", "signature-after", "verify", "attach", "detach")),
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
STAGES = frozenset((*PHASES, *NATIVE_ROLES, "owned-directory-admission", "source-image-binding",
    "separate-resident-image-compiler", "compiler-original-copy", "resident-image-source-selected-signing",
    "fixed-installed-entry-compiler", "desktop-facade-compiler", "resident-facade-compiler",
    "helper-source-selected-signing", "notary-known-private-retirement", "final-image-owned-publication",
    "final-package-signed-output", "final-package-mode-and-publication", "install-product-original-adoption",
    "package-final-audit", "package-explicit-producer-compiler", "package-producer-emission",
    "package-readonly-attach", "standard-original-installer", "package-nonroot-v2-readback"))
REASONS = frozenset(("notary-submission-invalid", "notary-authentication-not-retired", "notary-group-deadline",
    "notary-group-hard-deadline", "notary-final-input-result", "notary-private-key-retained", "original-return-contract",
    "original-operation-refused", "helper-package-incomplete", "package-finality-incomplete",
    "package-signature-bound", "package-signature-utf8", "package-signature-format", "package-signature-header",
    "package-signature-trust-timestamp", "package-signature-chain-order", "package-signature-chain-format",
    "package-signature-fingerprint-repeated", "package-signature-fingerprint-position", "package-signature-fingerprint-bound",
    "package-signature-expiry-repeated", "package-signature-source-chain", "package-signature-source-fingerprint",
    "notary-submit-terminal", "notary-submit-metadata", "notary-submit-archive", "notary-uuid"))
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
    "originalMountDetached")
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
UI_OWNER_REASONS = frozenset(("incomplete-output", "output-bound", "protocol-or-ownership",
    "command-failed-or-incomplete", "cleanup-unconfirmed", "exec-rejected", "stopped-before-exec",
    "parent-ended", "observer-ended", "fence-collision", "unknown"))
UI_ADMISSION_ROLES = frozenset(("normal-ui-source-roster", "normal-ui-build", "normal-ui-summary",
    "saved-version-source-roster", "saved-version-core-interrupt", "verify-generated-runner", "generated-runner-entitlements",
    "one-admitted-ui-test", "normal-ui-test-tree", "normal-toolchain-xcode", "normal-toolchain-sdkPath",
    "normal-toolchain-sdkVersion", "normal-toolchain-sdkBuild"))
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


def project_ui_failure(value, phase):
    """Validate only the existing ordinary build/query writer's closed schema."""
    fields = {"schemaVersion", "scope", "phase", "selection", "originalReturncode", "stdoutBytes", "stdoutSha256",
        "stderrBytes", "stderrSha256", "status", "findingsTruncated", "errorCodes", "sourceFailures",
        "queryObservations", "requireObservations", "dashboardReadiness", "markers"}
    build_fields = {"compilerDiagnostics"} if phase == "build" else set()
    if phase == "build" and "buildFailureReasons" in value:
        build_fields.add("buildFailureReasons")  # Backward-compatible absence remains unproven, not empty.
    if phase == "build" and "destinationTable" in value:
        build_fields.add("destinationTable")  # Optional absence is not an empty table observation.
    need(phase in ("build", "query") and set(value) == fields | build_fields
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "normal-macos-ui-failure-diagnostic-only" and value["phase"] == phase
         and value["selection"] is None and value["status"] in ("unavailable", "classified", "unclassified"))
    integer(value["originalReturncode"], 255, 1)
    cap = 4096 if phase == "query" else 1024 * 1024
    size = integer(value["stdoutBytes"], cap)
    integer(value["stderrBytes"], cap - size)
    hex_value(value["stdoutSha256"]); hex_value(value["stderrSha256"])
    boolean(value["findingsTruncated"])
    need(value["sourceFailures"] == [] and type(value["sourceFailures"]) is list
         and value["requireObservations"] == [] and type(value["requireObservations"]) is list
         and value["dashboardReadiness"] is None)
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
            need(type(table) is dict and set(table) == {"state", "unknownRowObserved",
                 "malformedRowObserved", "rowsTruncated", "rows"}
                 and table["state"] in ("unavailable", "absent", "observed"))
            for name in ("unknownRowObserved", "malformedRowObserved", "rowsTruncated"):
                boolean(table[name])
            rows = table["rows"]
            need(type(rows) is list and len(rows) <= 8
                 and (not table["rowsTruncated"] or value["findingsTruncated"])
                 and (table["state"] == "observed" or not (rows or table["unknownRowObserved"]
                      or table["malformedRowObserved"] or table["rowsTruncated"])))
            for row in rows:
                need(type(row) is dict and set(row) == {"stream", "section", "platform", "architecture", "errorPresent"}
                     and row["stream"] in ("stdout", "stderr") and row["section"] in ("available", "ineligible")
                     and row["platform"] == "macos" and row["architecture"] in (None, "arm64", "x86_64"))
                boolean(row["errorPresent"])
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
    need(type(value) is dict and role in ("build", "toolchain", "admission")
         and type(caller_status) is dict and caller_status.get("receiptState") == "observed")
    status = integer(caller_status.get("returncode"), 255, 1)
    # Writers have no embedded source/run tuple. This is only parent-context
    # attribution from the fixed fresh work root, never independent attestation.
    try:
        row = project_ui_admission(value) if role == "admission" else project_ui_failure(value, "build" if role == "build" else "query")
    except KeyError:
        raise Refused("public-evidence-refused") from None
    if role != "admission":
        need(row["originalReturncode"] == status)
    return {**row, "receiptState": "observed", "binding": "same-work-root-parent-context-only", "nativeSuccessInferred": False}


def project_data_contract_failure(value, context, statuses, inventory_paths):
    """Failure-only sidecar observations; no raw captures or native acceptance."""
    fields = {"schemaVersion", "kind", "source", "workflowSource", "runId", "runAttempt", "target", "phase",
        "originalReturncode", "originalReturned", "outputComplete", "captureClosed", "timedOut", "outputOverflow",
        "stdoutBytes", "stdoutSha256", "stderrBytes", "stderrSha256", "guardCode", "python", "cargo",
        "diagnosticOnly", "productReady"}
    need(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
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
    return {**result, "receiptState": "observed", "binding": "same-source-run-target-context",
            "callerStatus": dict(caller), "statusMatched": matched, "nativeSuccessInferred": False}


def decode(body, budget, *, inventory=False):
    # Byte bounds precede stdlib parsing. Graph bounds are post-parse checks,
    # not a prospective allocation or hard-RSS guarantee.
    need(type(body) is bytes and 0 < len(body) <= (2 * 1024 * 1024 if inventory else 16384))
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
    result["failure"] = project_failure(value.get("failure"))
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


def read_input(root, name, limit, budget):
    clock(budget)
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


def project(work, *, profile, source, workflow_source, run_id, run_attempt, target, removal_case="disabled"):
    need(profile in ("installed", "aqua") and target in TARGETS)
    need(removal_case in ("disabled", "ordinary", "abrupt")
         and (removal_case == "disabled" or profile == "installed" and target == "aarch64-apple-darwin"))
    context = {"profile": profile, "source": hex_value(source, 40), "workflowSource": hex_value(workflow_source, 40),
               "runId": identifier(run_id), "runAttempt": identifier(run_attempt), "target": target,
               "expectedRemovalCase": removal_case}
    need(source == workflow_source and len(PHASES) <= 20 and len(STATUS_FILES) <= 100
         and len(set(STATUS_FILES)) == len(STATUS_FILES))
    budget = {"deadline": time.monotonic_ns() + 45_000_000_000, "files": 0, "bytes": 0, "nodes": 0,
              "outputBytes": 16384}  # Reserve the fixed roster keys/envelope/caller-status duplicates.
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
        for phase in PHASES:
            row = observe("android-helper-" + phase + ".json", 16384,
                          lambda body, phase=phase: project_receipt(decode(body, budget), context, phase))
            row["callerStatus"] = statuses.get(PHASE_STATUS.get(phase))
            phases[phase] = row
        inventory_paths = set()
        inventory = observe("source-inventory.json", 2 * 1024 * 1024,
            lambda body: project_inventory(decode(body, budget, inventory=True), body, context, collect_paths=inventory_paths))
        deliveries = {name: observe(path, 16384, lambda body, removal=removal:
            project_summary(decode(body, budget), context, removal)) for name, path, removal in
            (("preview", "preview/PREVIEW.json", False), ("removal", "remove-preview/REMOVAL.json", True))}
        ui_diagnostics = {role: observe(path, 4096, lambda body, role=role:
            project_ui_diagnostic(decode(body, budget), role, statuses["normal-ui/build.status"]))
            for role, path in UI_DIAGNOSTICS} if profile == "installed" else {}
        data_failure = observe("data-contracts/failure-diagnostics.json", 16384,
            lambda body: project_data_contract_failure(decode(body, budget), context, statuses, inventory_paths)) if profile == "installed" else None
        value = {"schemaVersion": 1, "kind": "mrk-public-verification-evidence-v1", **context,
                 "diagnosticOnly": True, "productReady": False, "sourceInventory": inventory,
                 "phases": phases, "statuses": statuses, "deliveries": deliveries, "normalUiBuildDiagnostics": ui_diagnostics,
                 "dataContractFailure": data_failure}
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
