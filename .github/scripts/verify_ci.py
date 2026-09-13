"""Fixed, credential-free CI sequence for disposable GitHub-hosted job VMs.

The platform adapter owns isolation and real child finality. This module owns
source provenance, the finite product-check sequence and a permanently failing
result when any command, parser, inspection or final cleanup fails. Import is
inert; no old verification framework, account service or PASS-file is used.
"""
from __future__ import annotations

import argparse
import base64
import csv
import dataclasses
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback
from typing import Callable


AGGREGATE_SECONDS = 3300
DISK_RESERVE = 4 * 1024**3 + 512 * 1024**2
MINITEST_FOOTER = (r"(?m)^(\d{1,9}) runs, (\d{1,9}) assertions, (\d{1,9}) failures, "
                   r"(\d{1,9}) errors, (\d{1,9}) skips[ \t]*$")
NATIVE_DIAGNOSTIC_PREFIX = "MRK_NATIVE_DIAGNOSTIC="
NATIVE_PYTHON_RUNTIME_PREFIX = "MRK_NATIVE_PYTHON_RUNTIME="
NATIVE_RUBY_RUNTIME_PREFIX = "MRK_NATIVE_RUBY_RUNTIME="
PROFILE_FIXTURE_FAILURE_PREFIX = "MRK_PROFILE_FIXTURE_FAILURE="
PROFILE_FIXTURE_FAILURE_ID = (
    "workflow.test_profile_processes.ProfileProcessTests."
    "test_failure_overflow_and_io_failure_reject_partial_content_without_leaking_workers"
)
PROFILE_FIXTURE_FAILURE_CALLBACK_MODES = {
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_group_ownership_is_established_before_spawn_and_never_kills_someone_elses_group"): (
        "before-admit-cancel", "before-run-cancel",
    ),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_success_and_custom_handlers_still_reap_live_descendants_and_keep_capabilities_out"): (
        "success", "custom-handler",
    ),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_timeout_observes_a_real_orphaned_pipe_before_cleanup"): ("pipe-timeout",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_cancellation_during_spawn_registration_and_active_native_work_is_contained"): (
        "spawn-return-cancel", "payload-register-cancel", "cancel", "completion-cancel", "completion-interrupt",
    ),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_parent_capture_deadline_still_overrides_a_complete_success_frame"): ("committed-timeout",),
    PROFILE_FIXTURE_FAILURE_ID: (
        "failure", "read-failure", "partial-write-failure", "overflow", "partial-marker",
        "extra-frame", "concatenated-frame",
    ),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_unknown_malformed_c_full_zero_retains_scratch"): ("full-zero",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_unknown_malformed_c_full_failure_retains_scratch"): ("full-failure",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_unknown_marker_parent_death_requires_domain_disposal"): ("marker-parent-death",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_unknown_committed_parent_death_requires_domain_disposal"): ("committed-parent-death",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_killed_ancestor_cannot_strand_independent_native_worker_group"): ("orphan",),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_independent_supervisor_deadline_and_backpressure_kill_native_workers_without_inheriting_payload"): (
        "supervisor-timeout", "backpressure",
    ),
    ("workflow.test_profile_processes.ProfileProcessTests."
     "test_commit_follows_actual_payload_eof_and_withheld_commit_cannot_deadlock_writer_close"): (
        "commit-after-eof", "withhold-commit", "short-write",
    ),
    ("workflow.test_profile_processes.ProfileGroupCleanupTests."
     "test_actual_zombie_is_observed_before_its_owning_keeper_consumes_the_wait"): ("zombie",),
    ("workflow.test_profile_processes.ProfileGroupCleanupTests."
     "test_unknown_payload_writer_close_failure_retains_scratch"): ("payload-writer-close-failure",),
    ("workflow.test_profile_processes.ProfileGroupCleanupTests."
     "test_unknown_payload_reader_close_failure_retains_scratch"): ("payload-reader-close-failure",),
    ("workflow.test_profile_processes.ProfileGroupCleanupTests."
     "test_unknown_payload_reader_close_unresolved_retains_scratch"): ("payload-reader-close-unresolved",),
}
PROFILE_FIXTURE_FAILURE_MODES = frozenset(
    mode for modes in PROFILE_FIXTURE_FAILURE_CALLBACK_MODES.values() for mode in modes
)
PROFILE_FIXTURE_FAILURE_FILES = (
    "tests/workflow/profile_process_fixture.py", "tests/workflow/process_fixture.py",
    *("src/mobile_release/" + name + ".py" for name in
      ("_profile_process", "_native_process", "ios_profiles", "inspection", "errors")),
)
FIXTURE_BOOTSTRAP_FAILURE_PREFIX = "MRK_FIXTURE_BOOTSTRAP_FAILURE="
FIXTURE_BOOTSTRAP_FAILURE_CONDITIONS = {
    "configuration": ("directory_read", "record_read", "record_parse", "record_schema",
                      "directory_identity", "parent_identity", "deadline_type", "request_schema",
                      "stdio_identity", "deadline"),
    "admission_open": ("fifo_open", "fifo_cloexec", "fifo_identity"),
    "session": ("setsid", "session_identity", "chdir", "cwd_identity", "ready_record"),
    "admission_wait": ("deadline", "grant_read", "grant_select", "grant_value"),
    "admission_close": ("close",),
    "exec_attempt": ("attempt_record", "deadline", "exec"),
}
ISOLATED_COLLECTOR_FAILURE_PREFIX = "MRK_ISOLATED_COLLECTOR_FAILURE="
ISOLATED_COLLECTOR_FAILURE_ID = (
    "NativeUploadValidationTest#test_raw_collector_keeps_actual_failed_transcripts_status_and_first_error"
)
ISOLATED_COLLECTOR_FAILURE_STAGES = (
    "cli-admission", "request-contract", "source-bindings", "deadline-bound", "collector-execution",
    "capture-contract", "cleanup-contract", "reporting-contract", "custody-contract", "final-recheck",
    "proof-publication",
    "capture-primary", "capture-retained-files", "capture-retained-lifetime", "capture-retained-streams",
    "capture-record-read", "capture-record-status", "capture-record-flags", "capture-dispatch-contract",
    "capture-dispatch-environment", "capture-source-identities", "capture-stream-identities",
    "capture-child-receipt", "capture-creator", "capture-lifetime-endpoints", "capture-provenance",
    "capture-bootstrap-header", "capture-bootstrap-request", "capture-bootstrap-sources", "capture-bootstrap-directory",
    "capture-bootstrap-dispatch", "capture-bootstrap-descriptors", "capture-bootstrap-configuration",
    "capture-bootstrap-ready", "capture-bootstrap-grant", "capture-bootstrap-exec",
    "capture-bootstrap-directory-finality", "capture-error-contract", "capture-readiness", "capture-transcript",
    "capture-termination",
)
ISOLATED_COLLECTOR_FAILURE_CATEGORIES = (
    "assertion-error", "fixture-error", "native-lifecycle-error", "io-error", "os-error", "interrupt",
    "system-exit", "json-parser-error", "key-error", "no-method-error", "type-error", "argument-error", "runtime-error",
    "standard-error", "exception", "unknown",
)
NATIVE_PRIMARY_FAILURE_PREFIX = "MRK_NATIVE_PRIMARY_FAILURE="
NATIVE_PRIMARY_FAILURE_CALLBACK_MODES = {
    ("NativeUploadValidationTest#"
     "test_unexpected_pre_entry_failures_preserve_original_through_real_cleanup"): tuple(
        f"native-proof-{boundary}-{kind}-{secondary}"
        for boundary in ("publication", "readiness", "watchdog")
        for kind in ("standard", "io", "interrupt", "system-exit")
        for secondary in ("none", "close")
    ),
    ("NativeUploadValidationTest#"
     "test_unexpected_primary_outlives_late_teardown_and_lookalike_diagnostics"): (
        "native-proof-late-cleanup", "native-proof-lookalike",
    ),
    ("NativeUploadValidationTest#"
     "test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike"): ("native-proof-entered-io",),
    ("NativeUploadValidationTest#"
     "test_nested_lifetime_preserves_pre_grant_ioerror_without_native_acquisition"): (
        "native-proof-frame-io", "native-proof-frame-io-close",
    ),
}
NATIVE_PRIMARY_FAILURE_MODES = frozenset(
    mode for modes in NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.values() for mode in modes
)
NATIVE_PRIMARY_IO_MODES = frozenset({
    *(f"native-proof-{boundary}-io-{secondary}"
      for boundary in ("publication", "readiness", "watchdog") for secondary in ("none", "close")),
    "native-proof-entered-io", "native-proof-frame-io", "native-proof-frame-io-close",
})
NATIVE_PRIMARY_FAILURE_PREDICATES = ("case", "proof-failures", "proof-status", "result-kind", "driver-status")
NATIVE_PRIMARY_PROOF_FAILURES = (
    "actual failed native result", "one real injection/final boundary", "framePublishedBeforeFault",
    "outerPrimarySameObject", "nestedPrimarySameObject", "taskPrimarySameObject", "originalMessagePreserved",
    "originalStatusPreserved", "originalNotIntentional", "actualTaskJoins", "actualDescriptorsClosed",
    "secondary identity", "ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined",
    "handlersRestored", "registryInactive", "no pending cancellation", "unchanged IOError redaction",
    "actual non-IOError return", "native cleanup without fixture fallback", "actual capture finality", "first-close boundary",
)
NATIVE_ORDER_FAILURE_PREFIX = "MRK_NATIVE_ORDER_FAILURE="
NATIVE_ORDER_FAILURE_CALLBACK_MODES = {
    ("NativeUploadValidationTest#"
     "test_native_task_error_precedes_later_caller_cancellation_at_the_original_latch"): (
        "native-order-task-before-caller-interrupt", "native-order-task-before-caller-system-exit",
    ),
    ("NativeUploadValidationTest#"
     "test_native_caller_cancellation_precedes_later_task_ioerror_at_the_original_latch"): (
        "native-order-caller-before-task-interrupt", "native-order-caller-before-task-system-exit",
    ),
    ("NativeUploadValidationTest#"
     "test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown"): (
        "native-order-cleanup-before-caller-interrupt",
    ),
    ("NativeUploadValidationTest#"
     "test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown"): (
        "native-order-cleanup-before-caller-system-exit",
    ),
}
NATIVE_ORDER_FAILURE_MODES = frozenset(
    mode for modes in NATIVE_ORDER_FAILURE_CALLBACK_MODES.values() for mode in modes
)
NATIVE_ORDER_CLEANUP_MODES = frozenset({
    "native-order-cleanup-before-caller-interrupt", "native-order-cleanup-before-caller-system-exit",
})
NATIVE_ORDER_FAILURE_PREDICATES = (
    "proof-version", "proof-kind", "case", "source-binding", "proof-failures", "proof-status", "expected-unknown",
    "original-accepted", "result-kind", "driver-status",
)
NATIVE_ORDER_PROOF_FAILURES = (
    "original failed fixture result", "same first object through original boundaries", "unchanged original first message/status",
    "unchanged original caller message/status", "no original upload acceptance", "original shared creator/capture latch",
    "actual first and later latch returns", "actual latch released later fault", "actual caller delivery and rescue",
    "actual original stdin close", "actual capture/creator joins", "actual original native closes", "actual original native EOFs",
    "actual original C wait", "no fixture fallback or pending cancellation", "ownedDescriptorsClosed", "watchdogJoined",
    "injectorsJoined", "handlersRestored", "registryInactive", "no fixture cleanup errors", "observation restored",
    "unchanged original sources",
    # The original proof appends only its own family's three or two labels.
    "actual clean body then original cleanup fault", "unknown original task/session retained", "real pre-tail native success not finality",
    "actual body error recorded", "actual settled native cancellation",
)
NATIVE_SETUP_FAILURE_PREFIX = "MRK_NATIVE_SETUP_FAILURE="
NATIVE_SETUP_FAILURE_CALLBACK_MODES = {
    ("NativeUploadValidationTest#"
     "test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child"): (
        "native-setup-interrupt", "native-setup-system-exit", "native-setup-io-error",
    ),
}
NATIVE_SETUP_FAILURE_MODES = frozenset(
    mode for modes in NATIVE_SETUP_FAILURE_CALLBACK_MODES.values() for mode in modes
)
NATIVE_SETUP_FAILURE_FIELDS = (
    "schema", "mode", "failedPredicates", "resultKind", "driverExitStatus",
    "errorCategory", "nativeErrorCategory", "resultChecks", "nativeChecks",
)
NATIVE_SETUP_FAILURE_PREDICATES = ("result-kind", "driver-status")
NATIVE_SETUP_RESULT_KINDS = (
    "pass", "fixture-cleanup", "readiness", "setup-fixture-fault", "process-observation",
    "process-ownership", "fixture-result", "unexpected", "other", "missing", "invalid",
)
NATIVE_SETUP_ERROR_CATEGORIES = (
    "none", "fixture-error", "contract-error", "native-lifecycle-error", "io-error",
    "interrupt", "system-exit", "other", "missing", "invalid",
)
NATIVE_SETUP_RESULT_CHECKS = (
    "ready", "firstCloseEntered", "originalCloseCompleted", "nativeOriginalErrorPreserved",
    "watchdogStarted", "watchdogIntervened", "fallbackUsed", "deadBeforeFallback",
    "ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined",
    "handlersRestored", "registryInactive", "pendingInterrupt", "cleanupErrorsEmpty",
)
NATIVE_SETUP_NATIVE_CHECKS = ("finalized", "noProducers", "settled", "unknown", "hooksRestored")
ADAPTER_FAILURE_PREFIX = "MRK_ADAPTER_FAILURE="
ADAPTER_FAILURE_PLATFORMS = {
    "ios": ("ruby-ios_upload_validation", "IosUploadValidationTest"),
    "android": ("ruby-android_upload_validation", "AndroidUploadValidationTest"),
}
ADAPTER_FAILURE_MODE_CONTRACTS = {
    "real-deadline": ("test_deadline_terminates_validator_without_authorizing_upload", "pass"),
    "inherited": ("test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits", "pass"),
    "delayed-start": ("test_descendant_boundary_survives_delayed_start_and_late_parent_record", "pass"),
    "late-record": ("test_descendant_boundary_survives_delayed_start_and_late_parent_record", "pass"),
    "unready": ("test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record", "readiness"),
    "leader-only": ("test_fixture_detects_leader_only_cleanup_and_missing_deadline", "descendant-alive"),
    "no-deadline": ("test_fixture_detects_leader_only_cleanup_and_missing_deadline", "capture-watchdog"),
    "immediate-deadline": ("test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed", "elapsed-bound"),
    "real-deadline-slow-cleanup": ("test_slow_cleanup_cannot_supply_a_positive_deadline_wait", "pass"),
    "immediate-deadline-slow-cleanup": ("test_slow_cleanup_cannot_supply_a_positive_deadline_wait", "elapsed-bound"),
}
ADAPTER_FAILURE_FIELDS = (
    "schema", "platform", "mode", "expectedKind", "failedPredicates", "resultKind", "driverExitStatus",
    "retainedDriverErrorCategory", "retainedDriverErrorCode", "adapterErrorCategory",
    "resultChecks", "nativeChecks", "timingChecks", "nativeOutcomes", "slowChecks",
)
ADAPTER_FAILURE_PREDICATES = ("result-kind", "driver-status")
ADAPTER_FAILURE_RESULT_KINDS = (
    "pass", "readiness", "descendant-alive", "capture-watchdog", "elapsed-bound", "fixture-cleanup",
    "setup-fixture-fault", "process-observation", "process-ownership", "fixture-result", "fixture-source",
    "fixture-input", "fixture-observation", "fixture-control", "signal-policy", "diagnostic", "control",
    "unexpected", "other", "missing", "invalid",
)
ADAPTER_FAILURE_DRIVER_CODES = {
    "missing": frozenset({"missing"}),
    "none": frozenset({"missing", "none", "invalid"}),
    "invalid": frozenset({"missing", "invalid"}),
    **dict.fromkeys(("contract-error", "io-error", "interrupt", "system-exit", "other"),
                   frozenset({"missing", "invalid", "other"})),
    "fixture-error": frozenset({
        "missing", "invalid", "other", "source-size", "mutation-anchor", "capture-contract", "parser-contract",
        "capture-clock-binding", "record-cutoff", "validator-marker", "validator-cutoff", "validator-live",
        "descendant-marker", "descendant-cutoff", "descendant-live", "native-ready", "deliberately-unready",
        "dispatch-contract", "descendant-fork", "pipe-interval", "pipes-not-blocked", "watchdog-admission",
        "timeout-construction-count", "omission-binding", "omission-not-live", "native-unknown",
        "watchdog-intervened", "omission-unobserved", "omission-fallback", "ready-timeout-unobserved",
        "premature-interval-consumed", "elapsed-bound", "inherited-progress", "worker-delay",
        "fallback-before-finality", "slow-cleanup-budget", "watchdog-join", "injector-join",
    }),
    **dict.fromkeys(("native-error", "native-lifecycle-error"), frozenset({
        "missing", "invalid", "other",
        *("native-" + reason for reason in ("cancelled", "deadline", "parent_lost", "protocol", "io", "creation", "lifecycle")),
    })),
    "native-protocol-error": frozenset({"missing", "invalid", "other", "native-protocol"}),
    "native-spawn-error": frozenset({
        "missing", "invalid", "other",
        *("spawn-" + code for code in ("abi", "runtime", "origin", "symbol", "spec", "launch", "deadline", "state", "io",
                                      "fd", "busy", "native", "waitability", "spawn", "wait", "join", "close", "unknown")),
    }),
}
ADAPTER_FAILURE_RESULT_CHECKS = (
    "ready", "stdinClosedAfterReady", "deadlinePrimarySameObject", "deadlineResultSameObject",
    "watchdogStarted", "watchdogIntervened", "fallbackUsed", "deadBeforeFallback", "nativeFinalityBeforeFallback",
    "adapterRejected", "adapterCallObserved", "captureEntered", "descendantLiveBeforeRelease",
    "inheritedPipeBlockObserved", "validatorReapedAfterRelease", "commitAfterDataEOF", "ownedDescriptorsClosed",
    "watchdogJoined", "tasksJoined", "injectorsJoined", "handlersRestored", "registryInactive",
    "pendingInterrupt", "cleanupErrorsEmpty",
)
ADAPTER_FAILURE_NATIVE_CHECKS = (
    "finalized", "noProducers", "settled", "unknown", "hooksRestored", "observerErrorsEmpty",
    "productionFinality", "retainedUnknown", "statusValid", "statusDecodedEOF", "cleanupErrorsEmpty",
    "originalWaitObserved", "tasksJoined", "leasesClosed", "allActualEOFObserved",
    "captureSettled", "captureFinished", "captureJoined", "captureActualJoinObserved",
    "creatorSettled", "creatorFinished", "creatorJoined", "creatorActualJoinObserved",
    "stdoutEOF", "stdoutActualEOFObserved", "stderrEOF", "stderrActualEOFObserved",
    "statusEOF", "statusActualEOFObserved", "groupAbsent",
)
ADAPTER_FAILURE_TIMING_CHECKS = (
    "runSpanMatchesMode", "firstTimeoutCutoff", "selectedTimeoutCutoff", "blockedDataWaitsPositive",
    "firstBlockedDataWithinRun", "captureWithinLimit", "slowCleanupAtLeastFour", "captureCoversSlowCleanup",
    "slowCleanupWithinOriginalCutoff",
)
ADAPTER_FAILURE_CUTOFF_CHECKS = ("firstTimeoutCutoff", "selectedTimeoutCutoff")
ADAPTER_FAILURE_CUTOFF_VALUES = frozenset({"before-start", "before-cutoff", "at-or-after-cutoff", "missing", "invalid"})
ADAPTER_FAILURE_NATIVE_OUTCOMES = {
    **dict.fromkeys(("custodian", "keeper", "validator"), frozenset({
        "missing", "invalid", "not-attempted", "unknown", "exit0", "exit1", "exit2", "other-exit", "signal",
    })),
    "finalOutcome": frozenset({"missing", "invalid", "ok", "rejected", "failed"}),
    "finalCleanup": frozenset({"missing", "invalid", "confirmed", "unknown"}),
    "groupState": frozenset({"missing", "invalid", "not-created", "retired", "unknown"}),
    **dict.fromkeys(("captureState", "creatorState"), frozenset({
        "missing", "invalid", "unpublished", "not-constructed", "not-started", "attempted",
    })),
}
ADAPTER_FAILURE_SLOW_CHECKS = (
    "handoffPerformed", "delayEntered", "delayGuardPassed", "delayFailed", "delayFinished",
    "originalCleanupCalled", "originalCleanupFinished",
)
PYTHON_POISON_PARTITIONS = (
    "poison-wait-loss",
    "poison-startup-error",
    "poison-full-zero",
    "poison-full-failure",
    "poison-marker-parent-death",
    "poison-committed-parent-death",
    "poison-orphan",
    "poison-payload-writer-close-failure",
    "poison-payload-reader-close-failure",
    "poison-payload-reader-close-unresolved",
    "poison-read-restored-int",
    "poison-source-restored-int",
    "poison-capture-restored-int",
    "poison-read-restored-term-fatal",
    "poison-source-restored-term-fatal",
    "poison-capture-restored-term-fatal",
    "poison-capture-control-close-failure",
    "poison-capture-status-close-failure",
    "poison-capture-payload-close-failure",
    "poison-capture-payload-close-unresolved",
    "poison-source-control-close-failure",
    "poison-source-status-close-failure",
    "poison-source-payload-close-failure",
    "poison-source-payload-close-unresolved",
    "poison-source-scratch-cleanup-failure",
    "poison-source-scratch-cleanup-unresolved",
    "poison-read-raw-close-before-completion",
    "poison-read-raw-close-after-completion",
    "poison-source-raw-close-before-completion",
    "poison-source-raw-close-after-completion",
    "poison-unpublished-scratch",
    "poison-directory-replacement",
    "poison-symlink-replacement",
    "poison-unexpected-child",
    "poison-keyboard-interrupt-cleanup-failure",
    "poison-keyboard-interrupt-restore-failure",
    "poison-keyboard-interrupt-cleanup-and-restore-failure",
    "poison-system-exit-cleanup-failure",
    "poison-system-exit-restore-failure",
    "poison-system-exit-cleanup-and-restore-failure",
)
RUBY_OWNER_POISON_PARTITIONS = (
    ("custodian-preoffer-close", "NativeUploadRoleTest#test_native_custodian_preoffer_close_fault_cannot_claim_settled_failure"),
    ("custodian-postoffer-tail", "NativeUploadRoleTest#test_native_custodian_postoffer_tail_fault_downgrades_intended_two_to_unknown_one"),
    ("keeper-preoffer-close", "NativeUploadRoleTest#test_native_keeper_preoffer_close_fault_preserves_v_receipt_but_not_cleanup"),
    ("keeper-postoffer-tail", "NativeUploadRoleTest#test_native_keeper_postoffer_tail_fault_cannot_launder_confirmed_cleanup"),
    ("custodian-before-exit-arm", "NativeUploadRoleTest#test_native_custodian_before_exit_arm_callback_rejects_saved_settled_failure"),
    ("custodian-after-exit-arm", "NativeUploadRoleTest#test_native_custodian_after_exit_arm_signal_cannot_accept_saved_settled_failure"),
    ("keeper-before-exit-arm", "NativeUploadRoleTest#test_native_keeper_before_exit_arm_callback_invalidates_saved_release"),
    ("keeper-after-exit-arm", "NativeUploadRoleTest#test_native_keeper_after_exit_arm_signal_cannot_accept_saved_release"),
)
RUBY_PROBE_POISON_PARTITIONS = (
    ("ownership-unknown-capture-spawn", "test_process_ownership_unknown_creation_through_real_capture"),
    ("ownership-unknown-capture-reap", "test_process_ownership_unknown_wait_through_real_capture"),
    ("ownership-unknown-capture-echild", "test_process_ownership_echild_after_original_wait_through_real_capture"),
    ("ownership-unknown-run-spawn", "test_process_ownership_unknown_creation_through_real_run"),
    ("ownership-unknown-run-reap", "test_process_ownership_unknown_wait_through_real_run"),
    ("ownership-unknown-run-echild", "test_process_ownership_echild_after_original_wait_through_real_run"),
    ("kill-startup", "test_driver_loss_during_startup_retains_unknown_native_custody"),
    ("kill-descendant", "test_driver_loss_with_inherited_pipes_retains_unknown_native_custody"),
    ("ownership-observation", "test_indeterminate_observations_never_prove_readiness_or_renew_native_death_budget"),
)
RUBY_NATIVE_CAPTURE_POISON_PARTITIONS = (
    ("native-setup-no-cleanup", "NativeUploadValidationTest#test_missing_native_cleanup_requires_eof_and_cannot_pass_the_production_oracle"),
    ("kill-native-setup", "NativeUploadValidationTest#test_hard_driver_loss_stops_all_previously_bound_native_roles"),
    ("native-order-cleanup-before-caller-interrupt", "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown"),
    ("native-order-cleanup-before-caller-system-exit", "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown"),
)
# One gate, not five renewed 180-second invocations. Each singleton includes its
# original driver15/cleanup5 plus bounded outer startup/result/finality overhead.
RUBY_NATIVE_CAPTURE_BUDGETS = (
    ("healthy", 180),
    ("native-setup-no-cleanup", 30),
    ("kill-native-setup", 30),
    ("native-order-cleanup-before-caller-interrupt", 30),
    ("native-order-cleanup-before-caller-system-exit", 30),
)
RUBY_NATIVE_CAPTURE_SHARED_SECONDS = 10
RUBY_PARTITION_CONTRACTS = (
    ("ruby-native-owner", "test_native_upload_process.rb", 52, 44, 120, None),
    ("ruby-native-capture", "test_native_upload_validation.rb", 21, 17, 310, "NativeUploadValidationTest"),
    ("ruby-ios_upload_validation", "test_ios_upload_validation.rb", 32, 23, 300, "IosUploadValidationTest"),
    ("ruby-android_upload_validation", "test_android_upload_validation.rb", 32, 23, 300, "AndroidUploadValidationTest"),
)
PARTITIONED_RUBY_GATES = tuple(row[0] for row in RUBY_PARTITION_CONTRACTS)
RUBY_SUITES = (
    ("ruby-support", "test_fastlane_support.rb", 12),
    ("ruby-native-spawn", "test_native_process_spawn.rb", 0),
    ("ruby-native-owner", "test_native_upload_process.rb", 0),
    ("ruby-native-capture", "test_native_upload_validation.rb", 0),
    # Separate process: proof instrumentation never changes the original suite.
    ("ruby-native-signal-observation", "test_native_signal_observation.rb", 1),
    ("ruby-play_store", "test_play_store.rb", 0),
    ("ruby-play_lanes", "test_play_lanes.rb", 0),
    ("ruby-apple_store", "test_apple_store.rb", 0),
    ("ruby-apple_lanes", "test_apple_lanes.rb", 0),
    ("ruby-apple_production", "test_apple_production.rb", 0),
    ("ruby-apple_production_lane", "test_apple_production_lane.rb", 0),
    ("ruby-apple_asset_upload", "test_apple_asset_upload.rb", 0),
    ("ruby-ios_upload_validation", "test_ios_upload_validation.rb", 0),
    ("ruby-android_upload_validation", "test_android_upload_validation.rb", 0),
    ("ruby-workflow-yaml", "test_workflow_yaml.rb", 0),
    ("ruby-supply-wif", "test_supply_wif.rb", 0),
)
NATIVE_RUBY_IDS = (
    "ruby-native-spawn", "ruby-native-owner", "ruby-native-capture", "ruby-native-signal-observation",
    "ruby-ios_upload_validation", "ruby-android_upload_validation",
)
RUBY_PUBLIC_API_IDS = tuple(sorted((
    "NativeProcessSpawnTests#test_public_atomic_cloexec_duplication_uses_independent_creator_functions",
    "NativeProcessSpawnTests#test_public_spawn_containers_and_read_only_sigchld_admission",
)))
PACKAGED_RUBY_COMMON_IDS = tuple(sorted(
    "PackagedRubyCaptureTest#" + name for name in (
        "test_actual_capture_and_helper_origins_are_bound",
        "test_success_through_both_adapters_has_true_finality",
        "test_rejection_through_both_adapters_is_private_and_finalized",
        "test_reaped_validator_descendant_is_cleaned_before_fallback",
        "test_independent_stdout_stderr_bounds_preserve_cleanup",
        "test_source_app_path_and_preload_poison_cannot_replace_helpers",
    )
))
PACKAGED_RUBY_MISSING_IDS = tuple(sorted(
    "InstalledRubyCaptureMissingHelperTest#" + name for name in (
        "test_missing_installed_process_helper_refuses_fallback",
        "test_missing_installed_spawn_helper_refuses_fallback",
    )
))
PACKAGED_RUBY_GATES = ("ruby-packaged-capture-source", "ruby-packaged-capture-wheel")
COMPATIBILITY_SOURCE_GATES = tuple(f"python-compat-{line}-source" for line in ("312", "313", "314"))
COMPATIBILITY_WHEEL_GATES = tuple(f"python-compat-{line}-wheel" for line in ("312", "313", "314"))
RUBY_ABI_DECLARATION = r'''require "json"
require "digest"
raise "fixed ABI declaration arguments" unless ARGV.length == 2 && %w[source wheel].include?(ARGV[1])
helper, phase = ARGV
raise "fixed ABI helper origin" unless helper.start_with?("/") && File.realpath(helper) == helper
require helper
native = MobileReleaseKit::NativeProcessSpawn
abi = native.declared_abi
runtime = native.runtime_info
locations = %i[declared_abi runtime_info].to_h do |name|
  location = native.method(name).source_location
  raise "fixed ABI method origin" unless location && location[0] == helper && location[1].is_a?(Integer) && location[1] > 0
  [name.to_s, location]
end
raise "fixed ABI loaded origin" unless $LOADED_FEATURES.count { |path| path == helper } == 1
raise "fixed ABI declaration stability" unless abi == native.declared_abi
record = JSON.generate(abi) + "\n"
observation = {"schema" => "mrk-native-ruby-runtime-v1", "phase" => phase,
  "helper_sha256" => Digest::SHA256.file(helper).hexdigest, "source_locations" => locations, "runtime" => runtime}
metadata = "MRK_NATIVE_RUBY_RUNTIME=" + JSON.generate(observation) + "\n"
raise "fixed ABI output bound" unless record.bytesize.between?(1, 8192) && metadata.bytesize <= 65536
raise "fixed ABI short publication" unless STDOUT.write(record) == record.bytesize && STDERR.write(metadata) == metadata.bytesize
STDOUT.flush
STDERR.flush
'''
_BEFORE_TESTS = (
    "source-copy", "source-environment", "source-dependencies", "bundler",
    "bundle-install", "editable-install", "source-freeze", "source-pip-check", "bundle-check",
)
_WHEEL = (
    "wheel-copy", "wheel-build", "wheel-inspect", "wheel-environment", "wheel-pip",
    "wheel-install", "wheel-freeze", "wheel-pip-check",
)


class VerificationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", code) else "VERIFICATION_FAILURE"
        super().__init__(self.code)


@dataclasses.dataclass(frozen=True)
class Paths:
    source: Path
    work: Path
    inputs: Path
    python: Path
    ruby: Path
    version: str = "0.3.0"
    java_home: Path | None = None
    compatibility_runtimes: tuple[tuple[Path, Path], ...] = ()

    @property
    def source_python(self) -> Path:
        return self.work / "source-venv/bin/python"

    @property
    def wheel_python(self) -> Path:
        return self.work / "wheel-venv/bin/python"

    @property
    def checks(self) -> Path:
        return self.source / ".github/scripts/ci_checks.py"

    @property
    def wheel(self) -> Path:
        return self.work / f"wheels/mobile_release_kit-{self.version}-py3-none-any.whl"

    @property
    def bundle(self) -> tuple[str, ...]:
        base = self.work / "bundler/gems/bundler-4.0.16"
        return str(self.ruby), "-I", str(base / "lib"), str(base / "exe/bundle")


@dataclasses.dataclass(frozen=True)
class Step:
    id: str
    kind: str = "command"
    argv: tuple[str, ...] = ()
    cwd: Path | None = None
    env: tuple[tuple[str, str], ...] = ()
    seconds: int = 120
    parser: str = "exit"
    expected_tests: int = 0
    native_partition: str = "all"


@dataclasses.dataclass(frozen=True)
class CheckResult:
    ok: bool
    details: dict = dataclasses.field(default_factory=dict)
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class Report:
    ok: bool
    rows: tuple[dict, ...]
    error: str | None


@dataclasses.dataclass
class NativeABIState:
    """Outside-owner memory retaining originals, never a serialized receipt."""
    compiler_capture: object | None = None
    build_capture: object | None = None
    header_capture: object | None = None
    compiler: Path | None = None
    compiler_sha256: str | None = None
    source_sha256: str | None = None
    binary_sha256: str | None = None
    platform: str | None = None
    architecture: str | None = None
    phases: dict[str, tuple[object, object, object]] = dataclasses.field(default_factory=dict)


def required_gate_ids(platform: str) -> tuple[str, ...]:
    if platform == "linux":
        return (*_BEFORE_TESTS, "native-process-abi-source", *COMPATIBILITY_SOURCE_GATES,
                "python-full", *(row[0] for row in RUBY_SUITES), "ruby-packaged-capture-source",
                "fastfile", "actionlint", "jdk-signers", *_WHEEL, "native-process-abi-wheel",
                *COMPATIBILITY_WHEEL_GATES, "wheel-smoke", "wheel-consumer", "ruby-packaged-capture-wheel",
                "python-wheel", "source-integrity")
    if platform == "macos":
        return (*_BEFORE_TESTS, "native-tools", "native-process-abi-source", *COMPATIBILITY_SOURCE_GATES,
                *NATIVE_RUBY_IDS, "ruby-packaged-capture-source", "native-profile-source",
                *_WHEEL, "native-process-abi-wheel", *COMPATIBILITY_WHEEL_GATES,
                "wheel-smoke", "wheel-consumer", "ruby-packaged-capture-wheel",
                "native-profile-wheel", "source-integrity")
    raise VerificationError("UNSUPPORTED_PLATFORM")


def compatibility_paths(paths: Paths) -> tuple[tuple[Path, Path], ...]:
    """Only the three prebound narrow provider roles, with no ambient lookup."""
    pairs = paths.compatibility_runtimes
    if (type(pairs) is not tuple or len(pairs) != 3
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts for path in pair)
                   or pair[0].parent.name != "bin" or pair[0].parent.parent != pair[1] for pair in pairs)):
        raise VerificationError("COMPATIBILITY_RUNTIME_BINDING")
    roots = [paths.python.parent.parent, paths.ruby.parent.parent,
             *((paths.java_home,) if paths.java_home is not None else ()), *(pair[1] for pair in pairs)]
    if any(left == right or left.is_relative_to(right) or right.is_relative_to(left)
           for index, left in enumerate(roots) for right in roots[index + 1:]):
        raise VerificationError("COMPATIBILITY_RUNTIME_BINDING")
    return pairs


def environment(paths: Paths, platform: str) -> tuple[tuple[str, str], ...]:
    work = paths.work
    binary_roots = [paths.source_python.parent, work / "bundler/bin", paths.ruby.parent]
    if paths.java_home is not None:
        binary_roots.append(paths.java_home / "bin")
    binary_roots.extend(map(Path, ("/usr/bin", "/bin", "/usr/sbin", "/sbin")))
    env = {
        "PATH": ":".join(map(str, binary_roots)), "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"), "TMP": str(work / "tmp"), "TEMP": str(work / "tmp"),
        "TZ": "UTC", "CI": "1",
        "LANG": "en_US.UTF-8" if platform == "macos" else "C.UTF-8",
        "LC_ALL": "en_US.UTF-8" if platform == "macos" else "C.UTF-8", "TERM": "dumb",
        "PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1",
        "PIP_FIND_LINKS": str(paths.inputs / "python"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GEM_HOME": str(work / "bundler"), "GEM_PATH": str(work / "bundler"),
        "GEM_SPEC_CACHE": str(work / "gem-cache"), "GEMRC": "/dev/null",
        "BUNDLE_GEMFILE": str(paths.source / "Gemfile"), "BUNDLE_PATH": str(work / "bundle"),
        "BUNDLE_CACHE_PATH": str(paths.inputs / "gems"), "BUNDLE_FROZEN": "1",
        "BUNDLE_IGNORE_CONFIG": "1", "BUNDLE_DISABLE_SHARED_GEMS": "1",
        "BUNDLE_APP_CONFIG": str(work / "bundle-config"), "BUNDLE_USER_HOME": str(work / "bundle-home"),
        "BUNDLE_RETRY": "0", "BUNDLE_VERSION": "4.0.16",
        "FASTLANE_HIDE_CHANGELOG": "true", "FASTLANE_OPT_OUT_USAGE": "true",
        "FASTLANE_SKIP_UPDATE_CHECK": "true", "FASTLANE_SKIP_REPORTING": "true",
        "MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS": "1",
        "MOBILE_RELEASE_TEST_PYTHON": str(paths.source_python),
    }
    if platform == "macos":
        env["DEVELOPER_DIR"] = "/Applications/Xcode_26.3.app/Contents/Developer"
    if paths.java_home is not None:
        env["JAVA_HOME"] = str(paths.java_home)
    return tuple(sorted(env.items()))


def packaged_ruby_argv(paths: Paths, phase: str, *, deadline: float) -> tuple[str, ...]:
    """Closed fixture CLI: project source root, or the actual wheel prefix."""
    if phase not in {"source", "wheel"}:
        raise VerificationError("PACKAGED_RUBY_GATE_CONTRACT")
    prefix = paths.source if phase == "source" else paths.work / "wheel-venv"
    tooling = paths.source / "fastlane" if phase == "source" else prefix / "share/mobile-release-kit/fastlane"
    filter_ = (r"/\APackagedRubyCaptureTest#/" if phase == "source"
               else r"/\A(?:PackagedRubyCaptureTest|InstalledRubyCaptureMissingHelperTest)#/")
    return tuple(map(str, (*paths.bundle, "exec", paths.ruby,
        paths.source / "tests/workflow/test_installed_ruby_capture.rb",
        "--capture-phase", phase, "--capture-tooling-root", tooling, "--capture-prefix", prefix,
        "--capture-source-root", paths.source, "--capture-python",
        paths.source_python if phase == "source" else paths.wheel_python,
        *(("--capture-wheel", paths.wheel, "--negative-prefix", paths.work / "ruby-negative")
          if phase == "wheel" else ()),
        "--capture-deadline", repr(deadline), "--verbose", "--name", filter_)))


def catalog(paths: Paths, platform: str, *, deadline: float) -> tuple[Step, ...]:
    """Finite data-only dispatch; materialization/launches belong to the caller."""
    required_gate_ids(platform)
    if (paths.source / "src/mobile_release/local_signing.py").exists():
        # The separate QA-003 patch needs its complete native-active matrix.
        # Refuse it until that issue deliberately integrates its own catalog.
        raise VerificationError("LOCAL_SIGNING_MATRIX_REQUIRES_CATALOG_AMENDMENT")
    if type(deadline) is not float or not math.isfinite(deadline):
        raise VerificationError("INVALID_DEADLINE")
    pairs = compatibility_paths(paths)
    env = environment(paths, platform)
    steps: dict[str, Step] = {}

    def command(name, argv, *, seconds=120, parser="exit", tests=0, cwd=None):
        steps[name] = Step(name, argv=tuple(map(str, argv)), cwd=cwd or paths.work,
                           env=env, seconds=seconds, parser=parser, expected_tests=tests)

    def operation(name):
        steps[name] = Step(name, kind="inspection")

    def python(executable, *args):
        return (str(executable), "-I", "-B", *map(str, args))

    def check(name, executable, *, seconds=300, more=()):
        command(name, python(executable, paths.checks, "--check", name,
                            "--source-root", paths.source, "--work-root", paths.work / "checks",
                            "--deadline", repr(deadline), *more), seconds=seconds, parser="check")

    for name in ("source-copy", "source-freeze", "wheel-copy", "wheel-inspect", "wheel-freeze",
                 "wheel-consumer", "source-integrity"):
        operation(name)
    for phase in ("source", "wheel"):
        name = "native-process-abi-" + phase
        steps[name] = Step(name, kind="native-abi", seconds=300)
        for line, (executable, _prefix) in zip(("312", "313", "314"), pairs):
            name = f"python-compat-{line}-{phase}"
            steps[name] = Step(name, kind="python-compatibility", seconds=120,
                               argv=(str(executable), "-I", "-S", "-B",
                                     str(paths.source / "tests/workflow/run_native_profile_checks.py"),
                                     f"--compat-{line}-{phase}"), cwd=paths.work, env=env)
    command("source-environment", python(paths.python, "-m", "venv", "--copies", paths.work / "source-venv"), seconds=180)
    command("source-dependencies", python(paths.source_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--require-hashes",
            "-r", paths.inputs / "python/pip-requirements.txt",
            "-r", paths.inputs / "python/build-requirements.txt",
            "-r", paths.inputs / "python/test-requirements.txt"), seconds=1200)
    command("bundler", (paths.ruby, paths.ruby.parent / "gem", "install", "--local", "--no-document",
            "--install-dir", paths.work / "bundler", paths.inputs / "gems/bundler-4.0.16.gem"), seconds=300)
    command("bundle-install", (*paths.bundle, "install", "--local", "--jobs", "2", "--retry", "0"), seconds=1200)
    command("editable-install", python(paths.source_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--no-deps", "--editable", paths.work / "source-build"), seconds=900)
    command("source-pip-check", python(paths.source_python, "-m", "pip", "check"))
    command("bundle-check", (*paths.bundle, "check"))
    check("python-full", paths.source_python, seconds=900)
    native = paths.source / "tests/workflow/run_native_profile_checks.py"
    command("native-tools", ("/usr/bin/xcodebuild", "-version"), parser="xcode")
    command("native-profile-source", python(paths.source_python, native), seconds=900, parser="native")
    for name, filename, count in RUBY_SUITES:
        if not count and name != "ruby-supply-wif":
            # Immutable source supplies exact identities, not runtime test counts.
            count = len(ruby_expected_ids(paths.source, name))
        command(name, (*paths.bundle, "exec", paths.ruby, paths.source / "tests/workflow" / filename,
                        *(("--verbose",) if name != "ruby-supply-wif" else ())),
                seconds=120 if name == "ruby-native-owner" else
                310 if name == "ruby-native-capture" else
                180 if name in {"ruby-native-signal-observation", "ruby-native-spawn"}
                else 300 if name in NATIVE_RUBY_IDS else 180,
                parser="supply" if name == "ruby-supply-wif" else "minitest", tests=count)
    for phase, name in zip(("source", "wheel"), PACKAGED_RUBY_GATES):
        command(name, packaged_ruby_argv(paths, phase, deadline=deadline),
                seconds=300, parser="minitest", tests=len(ruby_expected_ids(paths.source, name)))
    command("fastfile", (*paths.bundle, "exec", paths.ruby, paths.source / "fastlane/run_lane.rb", "--validate"), seconds=180)
    workflow_paths = sorted((paths.source / ".github/workflows").glob("*.yml"))
    workflow_paths += sorted((paths.source / "templates/workflows").glob("*.yml"))
    command("actionlint", (paths.inputs / "actionlint/actionlint", "-no-color", "-ignore",
            'property "workflow_(repository|sha|ref)" is not defined in object type', *workflow_paths))
    check("jdk-signers", paths.source_python, seconds=600)
    command("wheel-build", python(paths.source_python, "-m", "pip", "wheel", "--no-index",
            "--find-links", paths.inputs / "python", "--no-deps", "--wheel-dir", paths.work / "wheels",
            paths.work / "wheel-build"), seconds=900)
    command("wheel-environment", python(paths.python, "-m", "venv", "--copies", paths.work / "wheel-venv"), seconds=180)
    command("wheel-pip", python(paths.wheel_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--find-links", paths.inputs / "python", "--require-hashes", "-r", paths.inputs / "python/pip-requirements.txt"), seconds=300)
    command("wheel-install", python(paths.wheel_python, "-m", "pip", "install", "--no-index", "--no-compile",
            "--no-deps", paths.wheel), seconds=300)
    command("wheel-pip-check", python(paths.wheel_python, "-m", "pip", "check"))
    check("wheel-smoke", paths.wheel_python, more=("--wheel", str(paths.wheel), "--ruby", str(paths.ruby)))
    check("python-wheel", paths.wheel_python, seconds=900)
    command("native-profile-wheel", python(paths.wheel_python, native, "--installed-wheel"), seconds=900, parser="native")
    wheel_env = dict(env)
    wheel_env["PATH"] = str(paths.wheel_python.parent) + ":" + wheel_env["PATH"]
    wheel_env["MOBILE_RELEASE_TEST_PYTHON"] = str(paths.wheel_python)
    for name in ("wheel-pip", "wheel-install", "wheel-pip-check", "wheel-smoke", "python-wheel", "native-profile-wheel",
                 "ruby-packaged-capture-wheel", *COMPATIBILITY_WHEEL_GATES):
        steps[name] = dataclasses.replace(steps[name], env=tuple(sorted(wheel_env.items())))
    installed_env = dict(steps["ruby-packaged-capture-wheel"].env)
    installed_env["BUNDLE_GEMFILE"] = str(paths.work / "wheel-venv/share/mobile-release-kit/Gemfile")
    steps["ruby-packaged-capture-wheel"] = dataclasses.replace(
        steps["ruby-packaged-capture-wheel"], env=tuple(sorted(installed_env.items())))
    return tuple(steps[name] for name in required_gate_ids(platform))


def ruby_literal_tests(path: Path) -> int:
    source = path.read_text(encoding="utf-8")
    count = len(re.findall(r"^\s*def test_[A-Za-z0-9_]+\s*(?:\([^\n]*\))?\s*$", source, re.MULTILINE))
    if count < 1:
        raise VerificationError("RUBY_SUITE_EMPTY")
    return count


def ruby_expected_ids(source: Path, gate: str) -> tuple[str, ...]:
    """The fixed suite's real method identities, including its shared contracts."""
    if gate in PACKAGED_RUBY_GATES:
        filename = "test_installed_ruby_capture.rb"
    elif gate in {"ruby-native-public-source", "ruby-native-public-wheel"}:
        filename = "test_native_process_spawn.rb"
    else:
        rows = [row for row in RUBY_SUITES if row[0] == gate and row[0] != "ruby-supply-wif"]
        if len(rows) != 1:
            raise VerificationError("RUBY_SUITE_UNKNOWN")
        filename = rows[0][1]
    raw = (source / "tests/workflow" / filename).read_text(encoding="utf-8")
    classes = list(re.finditer(r"(?m)^class ([A-Za-z0-9_:]+) < Minitest::Test[^\S\n]*$", raw))
    if not classes:
        raise VerificationError("RUBY_STATIC_INVENTORY")
    extra = []
    if gate in {"ruby-ios_upload_validation", "ruby-android_upload_validation"}:
        if raw.count("  include UploadProcessFixture::Contracts\n") != 1:
            raise VerificationError("RUBY_SHARED_CONTRACT_MISSING")
        shared = (source / "tests/workflow/upload_process_fixture.rb").read_text(encoding="utf-8")
        sections = shared.split("  module Contracts\n")
        if len(sections) != 2:
            raise VerificationError("RUBY_SHARED_CONTRACT_AMBIGUOUS")
        shared = sections[1].split("\nif $PROGRAM_NAME == __FILE__", 1)[0]
        literal = re.findall(r"(?m)^    def (test_[A-Za-z0-9_]+)\s*$", shared)
        if (len(literal) != 18 or not {name for _mode, name in RUBY_PROBE_POISON_PARTITIONS} <= set(literal)
                or shared.count("%w[async signals policies].each do |family|") != 1
                or shared.count('define_method("test_process_ownership_#{family}_through_both_real_fixture_callers")') != 1):
            raise VerificationError("RUBY_DYNAMIC_CONTRACT_DRIFT")
        extra.extend(literal)
        extra.extend(f"test_process_ownership_{family}_through_both_real_fixture_callers"
                     for family in ("async", "signals", "policies"))
    result = []
    for owner in classes:
        # These reviewed files use ordinary top-level classes and unindented
        # closing `end`; unsupported construction fails rather than inventing IDs.
        body = raw[owner.end():].split("\nend\n", 1)[0]
        names = re.findall(r"(?m)^  def (test_[A-Za-z0-9_]+)\s*$", body)
        if "  include UploadProcessFixture::Contracts\n" in body:
            names.extend(extra)
        if not names or len(names) != len(set(names)):
            raise VerificationError("RUBY_STATIC_INVENTORY")
        result.extend(f"{owner[1]}#{name}" for name in names)
    if len(result) != len(set(result)):
        raise VerificationError("RUBY_DUPLICATE_METHOD")
    if gate in PACKAGED_RUBY_GATES:
        if tuple(sorted(result)) != tuple(sorted(PACKAGED_RUBY_COMMON_IDS + PACKAGED_RUBY_MISSING_IDS)):
            raise VerificationError("PACKAGED_RUBY_STATIC_INVENTORY")
        return PACKAGED_RUBY_COMMON_IDS if gate.endswith("-source") else tuple(sorted(result))
    if gate in {"ruby-native-public-source", "ruby-native-public-wheel"}:
        if not set(RUBY_PUBLIC_API_IDS) <= set(result):
            raise VerificationError("RUBY_NATIVE_PUBLIC_INVENTORY")
        return RUBY_PUBLIC_API_IDS
    return tuple(sorted(result))


def _ruby_partition_contract(gate: str) -> tuple:
    """The only four admitted Ruby partition gates; no caller-owned contract."""
    if type(gate) is not str or gate not in PARTITIONED_RUBY_GATES:
        raise VerificationError("RUBY_PARTITION_GATE_CONTRACT")
    _gate, filename, total, healthy, seconds, owner = next(row for row in RUBY_PARTITION_CONTRACTS if row[0] == gate)
    poison = (RUBY_OWNER_POISON_PARTITIONS if gate == "ruby-native-owner" else
              RUBY_NATIVE_CAPTURE_POISON_PARTITIONS if gate == "ruby-native-capture" else
              tuple((mode, owner + "#" + method) for mode, method in RUBY_PROBE_POISON_PARTITIONS))
    return filename, total, healthy, seconds, poison


def ruby_capture_ids(source: Path, gate: str, partition: str = "all", *, deadline: float | None = None) -> tuple[str, ...]:
    """Complete source inventory, its exact healthy complement and fixed singletons."""
    _filename, total, healthy_count, _seconds, parts = _ruby_partition_contract(gate)
    if type(partition) is not str or partition not in {"all", "healthy", *dict(parts)}:
        raise VerificationError("RUBY_PARTITION_SELECTION")
    if deadline is not None:
        check_clock(deadline)
    complete = ruby_expected_ids(source, gate)
    poison = tuple(identifier for _name, identifier in parts)
    if (type(complete) is not tuple or len(complete) != total
            or any(type(identifier) is not str or not re.fullmatch(r"[A-Za-z0-9_:]+#test_[A-Za-z0-9_]+", identifier)
                   for identifier in complete)
            or tuple(sorted(set(complete))) != complete or not set(poison) <= set(complete)):
        raise VerificationError("RUBY_PARTITION_STATIC_INVENTORY")
    healthy = tuple(identifier for identifier in complete if identifier not in poison)
    if len(healthy) != healthy_count or tuple(sorted(healthy + poison)) != complete:
        raise VerificationError("RUBY_PARTITION_UNION")
    if deadline is not None:
        check_clock(deadline)
    return {"all": complete, "healthy": healthy,
            **{name: (identifier,) for name, identifier in parts}}[partition]


def ruby_capture_argv(paths: Paths, gate: str, partition: str, *, deadline: float) -> tuple[str, ...]:
    """Source-bound complete-ID filters only, never a caller-supplied method."""
    if partition == "all":
        raise VerificationError("RUBY_MIXED_CAPTURE")
    filename, _total, _healthy, _seconds, _parts = _ruby_partition_contract(gate)
    expected = ruby_capture_ids(paths.source, gate, partition, deadline=deadline)
    # The static identity grammar above contains no regexp metacharacters.
    # Match complete class#method IDs; an identically named method in another
    # class is not a substitute for this original source obligation.
    filter_ = "/\\A(?:" + "|".join(expected) + ")\\z/"
    return (*paths.bundle, "exec", str(paths.ruby),
            str(paths.source / "tests/workflow" / filename), "--verbose", "--name", filter_)


def execute_pipeline(steps: tuple[Step, ...], perform: Callable[[Step], CheckResult], *, platform: str) -> Report:
    """A recorder seam tests dispatch/failure semantics without starting workers."""
    if tuple(step.id for step in steps) != required_gate_ids(platform):
        raise VerificationError("REQUIRED_GATE_INVENTORY")
    rows = [{"id": step.id, "status": "UNEXECUTED"} for step in steps]
    error = None
    for index, step in enumerate(steps):
        rows[index]["status"] = "RUNNING"
        try:
            value = perform(step)
            if type(value) is not CheckResult or type(value.ok) is not bool:
                raise VerificationError("INVALID_CHECK_RESULT")
            if not value.ok:
                rows[index]["details"] = value.details
                raise VerificationError(value.error or "CHECK_FAILED")
            rows[index].update(status="PASS", details=value.details)
        except BaseException as exc:
            error = exc.code if isinstance(exc, VerificationError) else "CHECK_EXECUTION_FAILED"
            rows[index].update(status="FAIL", error=error)
            if not isinstance(exc, VerificationError):
                frames = traceback.extract_tb(exc.__traceback__)
                rows[index]["location"] = [Path(frames[-1].filename).name, frames[-1].lineno] if frames else []
                rows[index]["exception"] = type(exc).__name__
            break
    return Report(error is None, tuple(rows), error)


def check_clock(deadline: float) -> None:
    if type(deadline) is not float or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise VerificationError("AGGREGATE_DEADLINE")


def check_capacity(path: Path, prospective: int = 0) -> None:
    if shutil.disk_usage(path).free - prospective < DISK_RESERVE:
        raise VerificationError("DISK_HEADROOM")


def _module(directory: Path, name: str):
    spec = importlib.util.spec_from_file_location(f"_mrk_disposable_{name}", directory / f"{name}.py")
    if spec is None or spec.loader is None:
        raise VerificationError("HELPER_MODULE_MISSING")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def read_regular(path: Path, *, deadline: float, maximum: int = 8 * 1024**2) -> bytes:
    """Ordinary bounded read; callers already own immutable source or finality."""
    check_clock(deadline)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise VerificationError("FILE_PARENT_ALIAS")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= maximum:
            raise VerificationError("FILE_TYPE_OR_BOUND")
        chunks = []
        left = before.st_size
        while left:
            check_clock(deadline)
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                raise VerificationError("FILE_SHORT_READ")
            chunks.append(chunk)
            left -= len(chunk)
        if os.read(fd, 1):
            raise VerificationError("FILE_GREW")
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                   value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after):
            raise VerificationError("FILE_CHANGED_DURING_READ")
        return b"".join(chunks)
    finally:
        # A close is attempted once; ambiguity fails the enclosing operation.
        close_owned(fd)


def create_file(path: Path, data: bytes, *, mode: int, deadline: float) -> None:
    check_clock(deadline)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            check_clock(deadline)
            written = os.write(fd, view[:65536])
            if not 0 < written <= min(len(view), 65536):
                raise VerificationError("FILE_SHORT_WRITE")
            view = view[written:]
        os.fchmod(fd, mode)
    finally:
        close_owned(fd)


def close_owned(fd: int) -> None:
    """One close attempt, with an earlier exception kept as the first failure."""
    primary = sys.exc_info()[1]
    try:
        os.close(fd)
    except BaseException as cleanup:
        if primary is not None:
            raise BaseExceptionGroup("operation and descriptor close failed", [primary, cleanup]) from None
        raise


def trusted_command(argv: tuple[str, ...], *, deadline: float, cwd: Path | None = None) -> bytes:
    """Only fixed provider/Git introspection; never project/build/test commands."""
    check_clock(deadline)
    allowed = {"/usr/bin/git", str(Path(sys.executable).resolve())}
    if argv[0] not in allowed:
        raise VerificationError("TRUSTED_COMMAND_NOT_FIXED")
    result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, timeout=min(30, deadline - time.monotonic()),
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty",
                                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                                 "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 4 * 1024**2:
        raise VerificationError("TRUSTED_INTROSPECTION_FAILED")
    return result.stdout


def snapshot_source(checkout: Path, destination: Path, commit: str, *, deadline: float) -> tuple[dict, dict]:
    """Copy the exact committed ordinary-file tree; no worktree/index mutation."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise VerificationError("COMMIT_BINDING")
    git = ("/usr/bin/git", "-c", f"safe.directory={checkout}", "-C", str(checkout))
    actual = trusted_command((*git, "rev-parse", "HEAD"), deadline=deadline).strip().decode("ascii")
    tree = trusted_command((*git, "rev-parse", "HEAD^{tree}"), deadline=deadline).strip().decode("ascii")
    if actual != commit or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise VerificationError("CHECKOUT_COMMIT_MISMATCH")
    if trusted_command((*git, "status", "--porcelain=v1", "--untracked-files=all"), deadline=deadline):
        raise VerificationError("CHECKOUT_NOT_CLEAN")
    entries = trusted_command((*git, "ls-tree", "-rz", "--full-tree", "HEAD"), deadline=deadline).split(b"\0")
    if entries[-1] or not 1 <= len(entries) - 1 <= 512:
        raise VerificationError("SOURCE_INVENTORY_BOUND")
    check_capacity(destination.parent, 16 * 1024**2)
    destination.mkdir(mode=0o755)
    inventory = {}
    for entry in entries[:-1]:
        check_clock(deadline)
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        name = raw_name.decode("utf-8")
        relative = Path(name)
        if (mode not in ("100644", "100755") or kind != "blob" or relative.is_absolute()
                or ".." in relative.parts or ".git" in relative.parts or relative.as_posix() != name
                or re.search(r"[\x00-\x1f\x7f\\]", name) or name in inventory):
            raise VerificationError("SOURCE_ENTRY")
        raw = read_regular(checkout / relative, deadline=deadline)
        if bool((checkout / relative).stat().st_mode & 0o111) != (mode == "100755"):
            raise VerificationError("SOURCE_CHECKOUT_MODE")
        if hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest() != blob:
            raise VerificationError("SOURCE_BLOB_MISMATCH")
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        create_file(target, raw, mode=0o555 if mode == "100755" else 0o444, deadline=deadline)
        inventory[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "git_mode": mode}
    freeze_tree(destination, deadline=deadline)
    return inventory, {"commit": actual, "tree": tree, "files": len(inventory)}


def freeze_tree(root: Path, *, deadline: float, link_roots: tuple[Path, ...] = ()) -> None:
    """Root makes a genuinely quiescent owned tree read-only, never follows links."""
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise VerificationError("FREEZE_ROOT_NOT_DIRECTORY")
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + files:
            path = Path(directory) / name
            value = path.lstat()
            if stat.S_ISLNK(value.st_mode):
                target = path.resolve(strict=True)
                if not link_roots or not any(target == allowed or target.is_relative_to(allowed)
                                              for allowed in link_roots):
                    raise VerificationError("FREEZE_UNAPPROVED_LINK")
                os.chown(path, 0, 0, follow_symlinks=False)
                continue  # Standard venv links stay links; immutable parents bind names.
            if not (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)):
                raise VerificationError("FREEZE_SPECIAL_FILE")
            if stat.S_ISREG(value.st_mode) and value.st_nlink != 1:
                raise VerificationError("FREEZE_HARDLINK")
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o555 if stat.S_ISDIR(value.st_mode) or value.st_mode & 0o111 else 0o444)
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o555)


def verify_source(root: Path, inventory: dict, *, deadline: float, generated: bool = False) -> None:
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise VerificationError("SOURCE_ROOT_NOT_DIRECTORY")
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise VerificationError("SOURCE_SYMLINK")
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if generated and (relative.startswith("build/") or relative.startswith("src/mobile_release_kit.egg-info/")):
                continue
            actual.add(relative)
            expected = inventory.get(relative)
            if expected is None:
                raise VerificationError("SOURCE_UNEXPECTED_FILE")
            raw = read_regular(path, deadline=deadline)
            if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise VerificationError("SOURCE_CONTENT_DRIFT")
            if bool(path.stat().st_mode & 0o111) != (expected["git_mode"] == "100755"):
                raise VerificationError("SOURCE_MODE_DRIFT")
    if actual != set(inventory):
        raise VerificationError("SOURCE_INVENTORY_DRIFT")


def walk_error(_error: OSError) -> None:
    raise VerificationError("FILESYSTEM_WALK_FAILED")


def copy_build(source: Path, destination: Path, inventory: dict, uid: int, gid: int, *, deadline: float) -> None:
    destination.mkdir(mode=0o700)
    for relative, expected in inventory.items():
        check_clock(deadline)
        path = destination / relative
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        data = read_regular(source / relative, deadline=deadline)
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise VerificationError("BUILD_COPY_SOURCE_CHANGED")
        create_file(path, data, mode=0o755 if expected["git_mode"] == "100755" else 0o644, deadline=deadline)
    for directory, dirs, files in os.walk(destination, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in files:
            os.chown(Path(directory) / name, uid, gid)
        os.chown(directory, uid, gid)


def validate_inputs(root: Path, value: dict, *, deadline: float) -> dict:
    """Validate only the live return of the original DATA producer, not inputs.json."""
    files = value["files"]
    expected = {item["path"]: item for item in files}
    if len(expected) != len(files) or not 100 <= len(files) <= 150:
        raise VerificationError("INPUT_INVENTORY_BOUND")
    actual = set()
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        check_clock(deadline)
        for name in dirs + names:
            if (Path(directory) / name).is_symlink():
                raise VerificationError("INPUT_SYMLINK")
        actual.update((Path(directory) / name).relative_to(root).as_posix() for name in names)
    if actual != set(expected):
        raise VerificationError("INPUT_INVENTORY_MISMATCH")
    for name, item in expected.items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise VerificationError("INPUT_PATH")
        raw = read_regular(path, deadline=deadline, maximum=16 * 1024**2)
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise VerificationError("INPUT_BYTES_CHANGED")
    if value["actionlint"] is not None:
        os.chmod(root / value["actionlint"], 0o555)
    freeze_tree(root, deadline=deadline)
    return {"files": len(files), "bytes": sum(item["bytes"] for item in files),
            "tools_sha256": value["manifest_sha256"], "lock_sha256": value["lock_sha256"]}


def minitest_records(stdout: str, expected: tuple[str, ...], *, deadline: float | None = None) -> tuple[list, dict]:
    """Associate each verbose start with its own terminal, despite body logging.

    A terminal from the next test cannot finish a missing record. Ambiguous
    structural text fails closed; ordinary line-oriented diagnostics are not
    themselves results. Returned diagnostics contain only source-known names.
    """
    if deadline is not None:
        check_clock(deadline)
    expected_set = set(expected)
    starts = list(re.finditer(r"(?m)^([A-Za-z0-9_:]+#test_[A-Za-z0-9_]+)[ \t]*=[ \t]*", stdout))
    footers = list(re.finditer(MINITEST_FOOTER, stdout))
    boundary = footers[0].start() if footers else len(stdout)
    reasons, completed, seen, duplicates, unknown = set(), [], set(), set(), 0
    terminal_pattern = r"(?m)^([0-9]{1,9}\.[0-9]{2}) s = ([.FES])[ \t]*$"
    terminal_names = {".": "success", "F": "failure", "E": "error", "S": "skip"}
    start_records, adverse_records = [], []
    known_starts = known_adverse = 0

    def remember_record(ordinal: int, identifier: str, terminal: str) -> None:
        # Bounded syntactic observations never authorize completion or reuse.
        nonlocal known_starts, known_adverse
        if identifier not in expected_set:
            return
        row = {"ordinal": ordinal, "id": identifier, "terminal": terminal}
        known_starts += 1
        if len(start_records) < 16:
            start_records.append(row)
        if terminal != "success":
            known_adverse += 1
            if len(adverse_records) < 16:
                adverse_records.append(row)

    if len(footers) != 1:
        reasons.add("footer-count")
    if (re.search(terminal_pattern, stdout[:starts[0].start()] if starts else stdout)
            or footers and re.search(terminal_pattern, stdout[footers[0].end():])):
        reasons.add("unscoped-terminal")
    for index, start in enumerate(starts):
        if deadline is not None:
            check_clock(deadline)
        identifier = start[1]
        if identifier not in expected_set:
            unknown += 1
            reasons.add("unknown-id")
        if identifier in seen:
            reasons.add("duplicate-id")
            if identifier in expected_set:
                duplicates.add(identifier)
        seen.add(identifier)
        if start.start() >= boundary:
            reasons.add("record-after-footer")
            remember_record(index + 1, identifier, "after-footer")
            continue
        end = min(starts[index + 1].start() if index + 1 < len(starts) else len(stdout), boundary)
        body = stdout[start.end():end]
        terminals = re.findall(terminal_pattern, body)
        terminal = (terminal_names[terminals[0][1]] if len(terminals) == 1
                    else "ambiguous" if terminals else "missing")
        remember_record(index + 1, identifier, terminal)
        if len(terminals) != 1:
            reasons.add("terminal-count")
        elif terminals[0][1] != ".":
            reasons.add("terminal-status")
        elif identifier in expected_set:
            completed.append(identifier)
    missing = expected_set - set(completed)
    if missing:
        reasons.add("missing-ids")
    if len(starts) != len(expected):
        reasons.add("record-count")
    if deadline is not None:
        check_clock(deadline)
    return completed, {"reasons": sorted(reasons), "expected_count": len(expected),
                       "started_count": len(starts), "completed_count": len(completed),
                       "missing_ids": sorted(missing)[:16], "duplicate_ids": sorted(duplicates)[:16],
                       "unknown_count": unknown,
                       "start_records": start_records, "adverse_records": adverse_records,
                       "start_records_omitted": known_starts - len(start_records),
                       "adverse_records_omitted": known_adverse - len(adverse_records)}


def parse_capture(step: Step, result, paths: Paths, platform: str, checks, *, deadline: float | None = None) -> CheckResult:
    if deadline is not None:
        check_clock(deadline)
    if (not result.ok or type(result.returncode) is not int or result.returncode != 0
            or result.waited is not True or result.stdout_eof is not True or result.stderr_eof is not True
            or result.domain_finality is not True or result.primary_error is not None or result.cleanup_errors):
        raise VerificationError("COMMAND_EXIT_OR_FINALITY")
    stdout = result.stdout.decode("utf-8", "strict")
    stderr = result.stderr.decode("utf-8", "strict")
    details = {"returncode": result.returncode, "stdout_bytes": len(result.stdout),
               "stderr_bytes": len(result.stderr), "seconds": round(result.duration, 3)}
    if step.parser == "minitest":
        matches = re.findall(MINITEST_FOOTER, stdout)
        if len(matches) != 1:
            raise VerificationError("MINITEST_RESULT_MISSING")
        runs, assertions, failures, errors, skips = map(int, matches[0])
        if runs != step.expected_tests or assertions < 1 or failures or errors or skips:
            raise VerificationError("MINITEST_RESULT_REJECTED")
        expected = (ruby_capture_ids(paths.source, step.id, step.native_partition, deadline=deadline)
                    if step.id in PARTITIONED_RUBY_GATES else ruby_expected_ids(paths.source, step.id))
        completed, structure = minitest_records(stdout, expected, deadline=deadline)
        if structure["reasons"] or len(completed) != runs or len(expected) != runs or tuple(sorted(completed)) != expected:
            raise VerificationError("MINITEST_COMPLETION_INVENTORY")
        details.update(tests=runs, assertions=assertions, completed=completed)
    elif step.parser == "supply":
        if stdout != "locked Fastlane Supply WIF contract: PASS\n":
            raise VerificationError("SUPPLY_RESULT")
    elif step.parser == "native":
        if any(line.startswith(NATIVE_DIAGNOSTIC_PREFIX) for line in (stdout + "\n" + stderr).splitlines()):
            raise VerificationError("NATIVE_FAILURE_DIAGNOSTIC_ON_SUCCESS")
        expected = checks.native_partition_ids(paths.source, step.native_partition, deadline=deadline)
        footers = re.findall(r"(?m)^Ran (\d+) tests? in [0-9.]+s\s*$", stderr)
        if footers != [str(len(expected))] or not re.search(r"(?m)^OK\s*$", stderr) or "skipped" in stderr:
            raise VerificationError("NATIVE_PYTHON_RESULT")
        completed = re.findall(r"(?m)^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\s*$", stderr)
        observed = tuple(sorted(owner if owner.endswith("." + name) else f"{owner}.{name}"
                                for name, owner in completed))
        if observed != expected:
            raise VerificationError("NATIVE_PYTHON_INVENTORY")
        details.update(tests=len(expected), completed=list(observed))
    elif step.parser == "xcode":
        if stdout.strip().splitlines() != ["Xcode 26.3", "Build version 17C529"]:
            raise VerificationError("XCODE_VERSION")
        details["version"] = "Xcode26.3/17C529"
    elif step.parser == "check":
        lines = [line[len("MRK_CHECK_RESULT="):] for line in stdout.splitlines() if line.startswith("MRK_CHECK_RESULT=")]
        if len(lines) != 1 or len(lines[0]) > 256 * 1024:
            raise VerificationError("CHECK_SUMMARY_BOUND")
        summary = strict_json(lines[0])
        if (type(summary) is not dict or set(summary) != {"check", "ok", "tests", "details"}
                or summary.get("check") != step.id or summary.get("ok") is not True
                or type(summary["tests"]) is not list or type(summary["details"]) is not dict):
            raise VerificationError("CHECK_SUMMARY_REJECTED")
        # The source-anchored entrypoint checks actual methods/outcomes; parent
        # independently verifies expected complete identities after real finality.
        if step.id in ("python-full", "python-wheel"):
            selection = "full" if step.id == "python-full" else "wheel"
            expected = checks.python_capture_ids(paths.source, selection, "healthy", deadline=deadline)
            tests = summary.get("tests")
            if (type(tests) is not list
                    or any(type(row) is not dict or set(row) != {"id", "outcome"}
                           or type(row["id"]) is not str or type(row["outcome"]) is not str for row in tests)
                    or tuple(sorted(row["id"] for row in tests)) != expected):
                raise VerificationError("PYTHON_COMPLETION_INVENTORY")
            allowed = checks.linux_allowed_skips() if platform == "linux" and selection == "full" else frozenset()
            skips = {row["id"] for row in tests if row["outcome"] == "skip"}
            if skips != allowed or any(row["outcome"] not in ("ok", "skip") for row in tests):
                raise VerificationError("PYTHON_UNEXPECTED_SKIP_OR_FAILURE")
            callbacks = python_failure_callbacks(summary["details"].get("failure_callbacks"), expected)
            if callbacks != []:
                raise VerificationError("PYTHON_FAILURE_CALLBACKS_ON_SUCCESS")
            summary["details"]["failure_callbacks"] = callbacks
            if platform == "linux" and selection == "full":
                profile = python_storage_profile(summary["details"].get("storage_profile"))
                if profile is None:
                    raise VerificationError("PYTHON_STORAGE_PROFILE_MISSING_OR_INVALID")
                summary["details"]["storage_profile"] = profile
        details["summary"] = summary
    elif step.parser != "exit":
        raise VerificationError("UNKNOWN_RESULT_PARSER")
    if deadline is not None:
        check_clock(deadline)
    return CheckResult(True, details)


def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationError("JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value):
        raise VerificationError("JSON_NONFINITE")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def python_failure_callbacks(data: object, expected: tuple[str, ...]) -> list[dict] | None:
    """Filter diagnostic callbacks, never acceptance or raw exception values."""
    if type(data) is not list or len(data) > 16:
        return None
    identifiers = set(expected)
    outcomes = {"error", "failure", "expected-failure", "unexpected-success", "skip"}
    categories = {"os-error", "assertion-error", "value-error", "type-error", "memory-error",
                  "exception", "base-exception", "none"}
    result = []
    for row in data:
        if type(row) is not dict or set(row) != {"id", "outcome", "category", "errno"}:
            return None
        identifier, outcome, category, number = (row[key] for key in ("id", "outcome", "category", "errno"))
        if (type(identifier) is not str or identifier not in identifiers
                or type(outcome) is not str or outcome not in outcomes
                or type(category) is not str or category not in categories
                or number is not None and (type(number) is not int or not 0 < number < 4096)
                or category != "os-error" and number is not None
                or (outcome in {"skip", "unexpected-success"}) != (category == "none")):
            return None
        result.append({"id": identifier, "outcome": outcome, "category": category, "errno": number})
    return result


def python_storage_profile(data: object) -> dict | None:
    """Closed native-control observations, not an alternate execution receipt."""
    expected = {"name": "linux-python-full-v1", "logical_file_bytes": (1 << 32) + 1024**2,
                "file_data_bytes": 912 * 1024**2, "tmpfs_mounts": 11, "write_controls": 11,
                "readonly_errno": 30, "capacity_errno": 28, "capacity_bytes": 16 * 1024**2,
                "max_user_namespaces": 0}
    if type(data) is not dict or set(data) != set(expected):
        return None
    if any(type(data[key]) is not type(value) or data[key] != value for key, value in expected.items()):
        return None
    return dict(data)


def _fixture_failure_record(raw: bytes, prefix: str, maximum: int,
                            *, deadline: float | None = None,
                            canonical_fields: tuple[str, ...] | None = None) -> dict | None:
    """One bounded record from the original capture, never a success receipt."""
    if deadline is not None:
        check_clock(deadline)
    try:
        if type(raw) is not bytes:
            return None
        marker, found, record = prefix.encode("ascii"), False, None
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if deadline is not None:
                check_clock(deadline)
            if not line.startswith(marker):
                continue
            if (found or len(line) + 1 > maximum
                    or canonical_fields is not None and index == len(lines) - 1):
                return None
            found = True
            try:
                payload = line[len(marker):]
                record = strict_json(payload.decode("ascii"))
                if canonical_fields is not None:
                    if type(record) is not dict or set(record) != set(canonical_fields):
                        return None
                    record = {key: record[key] for key in canonical_fields}
                    if json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") != payload:
                        return None
            except (UnicodeError, ValueError, VerificationError, RecursionError):
                return None
        return record if type(record) is dict else None
    finally:
        # Malformed optional observations cannot absorb the original cutoff.
        if deadline is not None:
            check_clock(deadline)


def profile_fixture_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    data = _fixture_failure_record(raw, PROFILE_FIXTURE_FAILURE_PREFIX, 2048, deadline=deadline)
    if (type(data) is not dict or set(data) != {"schema", "mode", "returncode", "category", "locations"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["mode"]) is not str or data["mode"] not in PROFILE_FIXTURE_FAILURE_MODES
            or type(data["returncode"]) is not int or not -255 <= data["returncode"] <= 255 or data["returncode"] == 0
            or type(data["category"]) is not str or data["category"] not in {
                "assertion-error", "os-error", "value-error", "type-error", "memory-error",
                "exception", "base-exception", "unknown"}
            or type(data["locations"]) is not list or len(data["locations"]) > 4):
        return None
    locations = []
    for row in data["locations"]:
        if (type(row) is not dict or set(row) != {"file", "line"}
                or type(row["file"]) is not str or row["file"] not in PROFILE_FIXTURE_FAILURE_FILES
                or type(row["line"]) is not int or not 0 < row["line"] < 1000000):
            return None
        locations.append({"file": row["file"], "line": row["line"]})
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "mode": data["mode"], "returncode": data["returncode"],
            "category": data["category"], "locations": locations}


def _profile_failure_for_callbacks(raw: bytes, callbacks: list[dict], *, deadline: float | None = None) -> dict | None:
    """Pair only already source-validated adverse callbacks with their modes."""
    eligible = [row for row in callbacks
                if row["id"] in PROFILE_FIXTURE_FAILURE_CALLBACK_MODES and row["outcome"] in {"error", "failure"}]
    if eligible:
        diagnostic = profile_fixture_failure(raw, deadline=deadline)
        if diagnostic is not None and any(
                diagnostic["mode"] in PROFILE_FIXTURE_FAILURE_CALLBACK_MODES[row["id"]] for row in eligible):
            return diagnostic
    return None


def fixture_bootstrap_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    data = _fixture_failure_record(raw, FIXTURE_BOOTSTRAP_FAILURE_PREFIX, 256, deadline=deadline)
    if (type(data) is not dict or set(data) != {"schema", "stage", "condition"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["stage"]) is not str or data["stage"] not in FIXTURE_BOOTSTRAP_FAILURE_CONDITIONS
            or type(data["condition"]) is not str
            or data["condition"] not in FIXTURE_BOOTSTRAP_FAILURE_CONDITIONS[data["stage"]]):
        return None
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "stage": data["stage"], "condition": data["condition"]}


def isolated_collector_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    data = _fixture_failure_record(raw, ISOLATED_COLLECTOR_FAILURE_PREFIX, 256, deadline=deadline,
                                   canonical_fields=("schema", "stage", "category"))
    if (type(data) is not dict or set(data) != {"schema", "stage", "category"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["stage"]) is not str or data["stage"] not in ISOLATED_COLLECTOR_FAILURE_STAGES
            or type(data["category"]) is not str or data["category"] not in ISOLATED_COLLECTOR_FAILURE_CATEGORIES):
        return None
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "stage": data["stage"], "category": data["category"]}


def native_primary_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    """Finite primary-proof rejections, not the retained proof or its values."""
    data = _fixture_failure_record(raw, NATIVE_PRIMARY_FAILURE_PREFIX, 2048, deadline=deadline,
                                   canonical_fields=("schema", "mode", "failedPredicates", "proofFailures"))
    if (type(data) is not dict or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["mode"]) is not str or data["mode"] not in NATIVE_PRIMARY_FAILURE_MODES
            or type(data["failedPredicates"]) is not list or not 1 <= len(data["failedPredicates"]) <= 5
            or type(data["proofFailures"]) is not list or len(data["proofFailures"]) > 23):
        return None
    predicates, failures = data["failedPredicates"], data["proofFailures"]
    if (any(type(name) is not str for name in predicates + failures)
            or predicates != [name for name in NATIVE_PRIMARY_FAILURE_PREDICATES if name in predicates]
            or failures != [name for name in NATIVE_PRIMARY_PROOF_FAILURES if name in failures]
            or ("proof-failures" in predicates) != bool(failures)
            or ("actual non-IOError return" if data["mode"] in NATIVE_PRIMARY_IO_MODES
                else "unchanged IOError redaction") in failures):
        return None
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "mode": data["mode"], "failedPredicates": predicates, "proofFailures": failures}


def native_order_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    """Project only finite, mode-applicable checks from a rejected order proof."""
    data = _fixture_failure_record(raw, NATIVE_ORDER_FAILURE_PREFIX, 2048, deadline=deadline,
                                   canonical_fields=("schema", "mode", "failedPredicates", "proofFailures"))
    if (type(data) is not dict or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["mode"]) is not str or data["mode"] not in NATIVE_ORDER_FAILURE_MODES
            or type(data["failedPredicates"]) is not list or not 1 <= len(data["failedPredicates"]) <= 10
            or type(data["proofFailures"]) is not list):
        return None
    # Twenty-three common checks precede either the cleanup three or body two.
    applicable = (NATIVE_ORDER_PROOF_FAILURES[:26] if data["mode"] in NATIVE_ORDER_CLEANUP_MODES
                  else NATIVE_ORDER_PROOF_FAILURES[:23] + NATIVE_ORDER_PROOF_FAILURES[26:])
    predicates, failures = data["failedPredicates"], data["proofFailures"]
    if (len(failures) > len(applicable) or any(type(name) is not str for name in predicates + failures)
            or predicates != [name for name in NATIVE_ORDER_FAILURE_PREDICATES if name in predicates]
            or failures != [name for name in applicable if name in failures]
            or ("proof-failures" in predicates) != bool(failures)):
        return None
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "mode": data["mode"], "failedPredicates": predicates, "proofFailures": failures}


def native_setup_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    """Finite original kind/status operands, never success or cleanup authority."""
    try:
        data = _fixture_failure_record(raw, NATIVE_SETUP_FAILURE_PREFIX, 2048, deadline=deadline,
                                       canonical_fields=NATIVE_SETUP_FAILURE_FIELDS)
        if (type(data) is not dict or type(data["schema"]) is not int or data["schema"] != 1
                or type(data["mode"]) is not str or data["mode"] not in NATIVE_SETUP_FAILURE_MODES
                or type(data["resultKind"]) is not str or data["resultKind"] not in NATIVE_SETUP_RESULT_KINDS
                or type(data["driverExitStatus"]) is not int or not 0 <= data["driverExitStatus"] <= 255
                or any(type(data[key]) is not str or data[key] not in NATIVE_SETUP_ERROR_CATEGORIES
                       for key in ("errorCategory", "nativeErrorCategory"))):
            return None
        predicates = [name for name, failed in zip(NATIVE_SETUP_FAILURE_PREDICATES,
                      (data["resultKind"] != "pass", data["driverExitStatus"] != 0)) if failed]
        if (not predicates or type(data["failedPredicates"]) is not list
                or any(type(name) is not str for name in data["failedPredicates"])
                or data["failedPredicates"] != predicates):
            return None
        for key, fields in (("resultChecks", NATIVE_SETUP_RESULT_CHECKS),
                            ("nativeChecks", NATIVE_SETUP_NATIVE_CHECKS)):
            checks = data[key]
            if (type(checks) is not dict or tuple(checks) != fields
                    or any(type(value) is not bool and not (type(value) is str and value in {"missing", "invalid"})
                           for value in checks.values())):
                return None
        return data
    finally:
        # Invalid optional projections cannot consume the original cutoff.
        if deadline is not None:
            check_clock(deadline)


def adapter_failure(raw: bytes, *, deadline: float | None = None) -> dict | None:
    """Closed original guard operands, not a native cause or acceptance receipt."""
    try:
        data = _fixture_failure_record(raw, ADAPTER_FAILURE_PREFIX, 4096, deadline=deadline,
                                       canonical_fields=ADAPTER_FAILURE_FIELDS)
        if (type(data) is not dict or type(data["schema"]) is not int or data["schema"] != 2
                or type(data["platform"]) is not str or data["platform"] not in ADAPTER_FAILURE_PLATFORMS
                or type(data["mode"]) is not str or data["mode"] not in ADAPTER_FAILURE_MODE_CONTRACTS
                or type(data["expectedKind"]) is not str
                or data["expectedKind"] != ADAPTER_FAILURE_MODE_CONTRACTS[data["mode"]][1]
                or type(data["resultKind"]) is not str or data["resultKind"] not in ADAPTER_FAILURE_RESULT_KINDS
                or type(data["driverExitStatus"]) is not int or not 0 <= data["driverExitStatus"] <= 255
                or any(type(data[key]) is not str or data[key] not in ADAPTER_FAILURE_DRIVER_CODES
                       for key in ("retainedDriverErrorCategory", "adapterErrorCategory"))
                or type(data["retainedDriverErrorCode"]) is not str
                or data["retainedDriverErrorCode"] not in ADAPTER_FAILURE_DRIVER_CODES[data["retainedDriverErrorCategory"]]):
            return None
        expected_status = 0 if data["expectedKind"] == "pass" else 1
        predicates = [name for name, failed in zip(ADAPTER_FAILURE_PREDICATES,
                      (data["resultKind"] != data["expectedKind"], data["driverExitStatus"] != expected_status)) if failed]
        if (not predicates or type(data["failedPredicates"]) is not list
                or any(type(name) is not str for name in data["failedPredicates"])
                or data["failedPredicates"] != predicates):
            return None
        for key, fields in (("resultChecks", ADAPTER_FAILURE_RESULT_CHECKS),
                            ("nativeChecks", ADAPTER_FAILURE_NATIVE_CHECKS),
                            ("timingChecks", ADAPTER_FAILURE_TIMING_CHECKS),
                            ("slowChecks", ADAPTER_FAILURE_SLOW_CHECKS)):
            checks = data[key]
            if type(checks) is not dict or tuple(checks) != fields:
                return None
            for name, value in checks.items():
                if key == "timingChecks" and name in ADAPTER_FAILURE_CUTOFF_CHECKS:
                    if type(value) is not str or value not in ADAPTER_FAILURE_CUTOFF_VALUES:
                        return None
                elif type(value) is not bool and not (type(value) is str and value in {"missing", "invalid"}):
                    return None
        outcomes = data["nativeOutcomes"]
        if (type(outcomes) is not dict or tuple(outcomes) != tuple(ADAPTER_FAILURE_NATIVE_OUTCOMES)
                or any(type(value) is not str or value not in ADAPTER_FAILURE_NATIVE_OUTCOMES[name]
                       for name, value in outcomes.items())):
            return None
        # Detached original-snapshot facts may disagree on a failed capture.
        # Never turn their diagnostic projection into a new acceptance gate.
        return data
    finally:
        if deadline is not None:
            check_clock(deadline)


def _minitest_failed_target(text: str, identifier: str, *, deadline: float | None = None) -> bool:
    # Scan the SAME original bytes under the SAME cutoff. A target beyond the
    # public first16 rows still counts, as does a late duplicate. No receipt.
    _, target = minitest_records(text, (identifier,), deadline=deadline)
    starts = target["start_records"]
    return (len(starts) == 1 and target["start_records_omitted"] == 0 and not target["duplicate_ids"]
            and starts[0]["id"] == identifier and starts[0]["terminal"] in {"failure", "error"})


def native_failure_diagnostic(text: str, expected: tuple[str, ...], *, deadline: float | None = None) -> dict | None:
    """Accept only bounded actual-failure attribution, never execution authority."""
    if deadline is not None:
        check_clock(deadline)
    lines = [line[len(NATIVE_DIAGNOSTIC_PREFIX):] for line in text.splitlines()
             if line.startswith(NATIVE_DIAGNOSTIC_PREFIX)]
    if len(lines) != 1 or len(lines[0]) > 16 * 1024:
        return None
    data = strict_json(lines[0])
    if (type(data) is not dict or set(data) != {"schema", "phase", "records"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["phase"]) is not str or data["phase"] not in {"prerequisite", "tests"}
            or type(data["records"]) is not list or not 1 <= len(data["records"]) <= 16):
        return None
    phase, records = data["phase"], []
    if phase == "prerequisite":
        allowed = {"openssl-version", "clang-discovery", "dsymutil-discovery", "system-code"}
        if len(data["records"]) != 1:
            return None
    else:
        allowed = set(expected)
        classes = {identifier.rsplit(".", 1)[0] for identifier in expected}
        modules = {identifier.rsplit(".", 2)[0] for identifier in expected}
        allowed.update(f"{action} ({name})" for action in ("setUpClass", "tearDownClass") for name in classes)
        allowed.update(f"{action} ({name})" for action in ("setUpModule", "tearDownModule") for name in modules)
    outcomes = {"error", "failure", "skip", "expected-failure", "unexpected-success"}
    categories = {"nonzero-exit", "timeout", "os-error", "assertion-error", "value-error", "type-error",
                  "memory-error", "exception", "base-exception", "none"}
    for row in data["records"]:
        if deadline is not None:
            check_clock(deadline)
        if type(row) is not dict or set(row) != {"id", "outcome", "category", "errno", "returncode"}:
            return None
        identifier, outcome, category, number, code = (row[k] for k in ("id", "outcome", "category", "errno", "returncode"))
        if (type(identifier) is not str or identifier not in allowed or len(identifier) > 512
                or type(outcome) is not str or outcome not in outcomes
                or type(category) is not str or category not in categories
                or phase == "prerequisite" and outcome != "error"
                or (outcome in {"skip", "unexpected-success"}) != (category == "none")
                or number is not None and (type(number) is not int or not 0 < number < 4096)
                or code is not None and (type(code) is not int or not -255 <= code <= 255 or code == 0)
                or category != "os-error" and number is not None
                or category != "nonzero-exit" and code is not None):
            return None
        # Repeated failing subtests can legitimately share a parent method ID.
        records.append({"id": identifier, "outcome": outcome, "category": category,
                        "errno": number, "returncode": code})
    if deadline is not None:
        check_clock(deadline)
    return {"schema": 1, "phase": phase, "records": records}


def capture_observations(result) -> dict:
    """Original capture facts, retained even when later parsing/inspection fails."""
    return {"returncode": result.returncode, "waited": result.waited,
            "stdout_eof": result.stdout_eof, "stderr_eof": result.stderr_eof,
            "domain_finality": result.domain_finality, "timed_out": result.timed_out,
            "cancelled": result.cancelled, "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr), "persisted": list(result.persisted),
            "seconds": round(result.duration, 3), "cleanup_error_count": len(result.cleanup_errors)}


def require_original_finality(result) -> None:
    if (result.ok is not True or type(result.returncode) is not int or result.returncode != 0
            or result.waited is not True or result.stdout_eof is not True or result.stderr_eof is not True
            or result.domain_finality is not True or result.timed_out is not False or result.cancelled is not False
            or result.primary_error is not None or result.cleanup_errors
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes):
        raise VerificationError("COMMAND_EXIT_OR_FINALITY")


def original_native_capture(session, argv, paths: Paths, rows: list[dict], name: str, *,
                            deadline: float, seconds: int, env: dict, output_limit: int = 65536):
    """One original ordinary capture plus idle closure under the same cutoff.

    Never synthesize/merge CapturedRun objects. Semantic parsing follows this
    function; even later rejection retains the original wait/EOF facts.
    """
    check_clock(deadline)
    session.ensure_idle(deadline=deadline)
    row = {"stage": name, "status": "RUNNING"}
    rows.append(row)
    result = session.run(list(map(str, argv)), cwd=paths.work, env=env, seconds=seconds,
                         cpu_seconds=180, output_limit=output_limit, profile="ordinary", absolute_deadline=deadline)
    row["capture"] = capture_observations(result)
    primary = None
    try:
        require_original_finality(result)
    except BaseException as exc:
        primary = exc
    try:
        session.ensure_idle(deadline=deadline)
    except BaseException as exc:
        if primary is None:
            primary = exc
        else:
            row["idle_error"] = error_details(exc)
    if primary is not None:
        row["status"] = "FAIL"
        raise primary
    check_clock(deadline)
    row["status"] = "FINALIZED"
    return result


def native_runtime_record(raw: bytes, prefix: str) -> dict:
    if (type(raw) is not bytes or not 0 < len(raw) <= 64 * 1024 or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1 or any(value < 0x20 or value > 0x7e for value in raw[:-1])):
        raise VerificationError("NATIVE_RUNTIME_RECORD")
    text = raw.decode("ascii")
    if not text.startswith(prefix):
        raise VerificationError("NATIVE_RUNTIME_RECORD")
    try:
        value = strict_json(text[len(prefix):-1])
    except (ValueError, TypeError, RecursionError):
        raise VerificationError("NATIVE_RUNTIME_RECORD") from None
    if type(value) is not dict:
        raise VerificationError("NATIVE_RUNTIME_RECORD")
    return value


def native_python_observation(raw: bytes, paths: Paths, *, minor: int, phase: str,
                              executable: Path, prefix: Path) -> dict:
    """Compare actual child metadata with the prebound narrow provider pair."""
    data = native_runtime_record(raw, NATIVE_PYTHON_RUNTIME_PREFIX)
    package = (paths.work / "source-build/src/mobile_release" if phase == "source"
               else paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
    expected = {"schema", "phase", "implementation", "version", "executable", "base_prefix", "base_exec_prefix",
                "prefix", "exec_prefix", "isolated", "package_root", "origins"}
    if (set(data) != expected or data["schema"] != "mrk-native-python-runtime-v1"
            or type(data["phase"]) is not str or data["phase"] != phase
            or data["implementation"] != "cpython" or data["isolated"] is not True
            or type(data["version"]) is not list or len(data["version"]) != 3
            or any(type(value) is not int for value in data["version"])
            or data["version"][:2] != [3, minor] or not 0 <= data["version"][2] < 1000
            or data["executable"] != str(executable) or data["base_prefix"] != str(prefix)
            or data["base_exec_prefix"] != str(prefix)
            or data["prefix"] != str(prefix) or data["exec_prefix"] != str(prefix)
            or data["package_root"] != str(package) or type(data["origins"]) is not dict
            or not {"mobile_release", "mobile_release._native_process"} <= data["origins"].keys()
            or len(data["origins"]) > 128):
        raise VerificationError("NATIVE_PYTHON_RUNTIME_ORIGIN")
    for name, origin in data["origins"].items():
        if type(name) is not str or not re.fullmatch(r"mobile_release(?:\.[A-Za-z_][A-Za-z0-9_]*)?", name):
            raise VerificationError("NATIVE_PYTHON_RUNTIME_ORIGIN")
        wanted = package / ("__init__.py" if name == "mobile_release" else name.split(".")[1] + ".py")
        if type(origin) is not str or origin != str(wanted):
            raise VerificationError("NATIVE_PYTHON_RUNTIME_ORIGIN")
    return {"phase": phase, "version": ".".join(map(str, data["version"])), "implementation": "cpython",
            "isolated": True, "origin_scope": "measured-loaded-modules", "module_count": len(data["origins"])}


def native_ruby_observation(raw: bytes, paths: Paths, *, phase: str, bundled: bool,
                            platform: str, deadline: float) -> dict:
    data = native_runtime_record(raw, NATIVE_RUBY_RUNTIME_PREFIX)
    tooling = paths.source if phase == "source" else paths.work / "wheel-venv/share/mobile-release-kit"
    helper = tooling / "fastlane/native_process_spawn.rb"
    if (set(data) != {"schema", "phase", "helper_sha256", "source_locations", "runtime"}
            or data["schema"] != "mrk-native-ruby-runtime-v1" or data["phase"] != phase
            or type(data["source_locations"]) is not dict
            or set(data["source_locations"]) != {"declared_abi", "runtime_info"}
            or type(data["runtime"]) is not dict
            or data["helper_sha256"] != hashlib.sha256(read_regular(helper, deadline=deadline)).hexdigest()):
        raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
    for location in data["source_locations"].values():
        if (type(location) is not list or len(location) != 2 or location[0] != str(helper)
                or type(location[1]) is not int or not 0 < location[1] <= 100000):
            raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
    runtime = data["runtime"]
    fields = {"schema", "ruby_engine", "ruby_version", "fiddle_version", "family", "architecture",
              "ruby_executable", "origin", "ruby_library_root", "native_extension_roots", "fiddle_features", "gemfile"}
    if (set(runtime) != fields or runtime["schema"] != "mrk-native-process-runtime-v1"
            or runtime["ruby_engine"] != "ruby" or runtime["ruby_version"] != "3.3.12"
            or runtime["fiddle_version"] != "1.1.2"
            or runtime["family"] != ("linux-glibc" if platform == "linux" else "darwin")
            or runtime["architecture"] != os.uname().machine or runtime["ruby_executable"] != str(paths.ruby)
            or runtime["origin"] != ("bundle" if bundled else "default")
            or runtime["gemfile"] != (str(tooling / "Gemfile") if bundled else None)
            or type(runtime["fiddle_features"]) is not dict
            or set(runtime["fiddle_features"]) != {"fiddle", "version", "function", "closure", "extension"}
            or type(runtime["native_extension_roots"]) is not list
            or not 1 <= len(runtime["native_extension_roots"]) <= 2):
        raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
    allowed = (paths.ruby.parent.parent, paths.work / "bundle") if bundled else (paths.ruby.parent.parent,)

    def origin_path(value):
        if type(value) is not str or not value.startswith("/") or len(value) > 4096:
            raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
        path = Path(value)
        if (path.resolve(strict=True) != path or not any(path.is_relative_to(root) for root in allowed)):
            raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
        return path

    library = origin_path(runtime["ruby_library_root"])
    extensions = tuple(origin_path(value) for value in runtime["native_extension_roots"])
    if len(set(extensions)) != len(extensions):
        raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
    feature_hashes = {}
    for name, value in runtime["fiddle_features"].items():
        path = origin_path(value)
        if name == "extension":
            if path.parent not in extensions or path.name not in {"fiddle.so", "fiddle.bundle"}:
                raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
        elif path != library / ("fiddle.rb" if name == "fiddle" else f"fiddle/{name}.rb"):
            raise VerificationError("NATIVE_RUBY_RUNTIME_ORIGIN")
        feature_hashes[name] = hashlib.sha256(read_regular(path, deadline=deadline, maximum=64 * 1024**2)).hexdigest()
    return {"phase": phase, "version": "3.3.12", "fiddle_version": "1.1.2",
            "origin": runtime["origin"], "origin_scope": "measured-loaded-methods-and-features",
            "helper_sha256": data["helper_sha256"], "feature_sha256": feature_hashes}


def failure_details(result, step: Step | None = None, paths: Paths | None = None,
                    *, checks=None, deadline: float | None = None, platform: str | None = None) -> dict:
    """Public-safe observations only; never forward raw child diagnostics."""
    value = capture_observations(result)
    # These are fixed source file/line and exception-class observations, not
    # raw exceptions, fixture logs, private paths, environment or signing data.
    text = result.stderr.decode("utf-8", "replace")
    value["locations"] = [[name, int(line)] for name, line in re.findall(
        r'File "[^"\r\n]*/(ci_sandbox\.py|ci_checks\.py)", line ([0-9]{1,6})', text)][-8:]
    value["exception_types"] = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)):", text)[-8:]
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if not line.startswith("MRK_CHECK_RESULT=") or len(line) > 256 * 1024:
            continue
        try:
            data = strict_json(line.split("=", 1)[1])
            if type(data) is not dict or type(data.get("details")) is not dict:
                continue
            detail = data["details"]
            code = detail.get("error")
            if type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", code):
                value["helper_error"] = code
            locations = detail.get("failure_locations", [])
            value["helper_locations"] = [row for row in locations if type(row) is dict
                and set(row) == {"file", "line"} and type(row["file"]) is str
                and re.fullmatch(r"(?:tests/|src/|\.github/scripts/)[A-Za-z0-9_./-]{1,180}", row["file"])
                and ".." not in Path(row["file"]).parts and type(row["line"]) is int and 0 < row["line"] < 1000000][-16:]
            if (platform == "linux" and step is not None and step.id == "python-full"
                    and data.get("check") == step.id and data.get("ok") is False):
                profile = python_storage_profile(detail.get("storage_profile"))
                if profile is not None:
                    value["storage_profile"] = profile
            if (step is not None and paths is not None and checks is not None
                    and step.id in {"python-full", "python-wheel"} and step.parser == "check"
                    and data.get("check") == step.id and data.get("ok") is False
                    and "failure_callbacks" in detail):
                try:
                    expected = checks.python_capture_ids(paths.source,
                        "full" if step.id == "python-full" else "wheel", "healthy", deadline=deadline)
                    callbacks = python_failure_callbacks(detail["failure_callbacks"], expected)
                    if callbacks is not None:
                        value["failure_callbacks"] = callbacks
                        diagnostic = _profile_failure_for_callbacks(result.stderr, callbacks, deadline=deadline)
                        if diagnostic is not None:
                            value["profile_fixture_failure"] = diagnostic
                except Exception:
                    # Optional diagnostics must not replace the original failure.
                    # Do not absorb expiry of the original aggregate timer.
                    if deadline is not None:
                        check_clock(deadline)
                    value["python_diagnostics_unavailable"] = True
        except VerificationError as exc:
            if exc.code == "AGGREGATE_DEADLINE":
                raise
        except (ValueError, KeyError, TypeError, RecursionError):
            pass
    if step is not None and paths is not None and step.parser == "minitest":
        try:
            if deadline is not None:
                check_clock(deadline)
            expected_ids = (ruby_capture_ids(paths.source, step.id, step.native_partition, deadline=deadline)
                            if step.id in PARTITIONED_RUBY_GATES else ruby_expected_ids(paths.source, step.id))
            expected = set(expected_ids)
            text = result.stdout.decode("utf-8", "replace")
            _, value["minitest_structure"] = minitest_records(text, expected_ids, deadline=deadline)
            # Only source-known test IDs and first-party relative locations.
            # Exception messages, assertion values and raw captures stay private.
            failed = re.findall(r"(?m)^([A-Za-z0-9_:]+#test_[A-Za-z0-9_]+)(?: \[[^\r\n]{1,512}\])?:\s*$", text)
            value["failed_tests"] = sorted(expected.intersection(failed))
            allowed = {"tests/workflow/" + row[1] for row in RUBY_SUITES}
            allowed.update("tests/workflow/" + name for name in
                           ("upload_process_fixture.rb", "upload_process_ownership.rb",
                            "test_installed_ruby_capture.rb", "installed_ruby_capture_fixture.rb"))
            allowed.update("fastlane/" + name for name in
                           ("native_upload_validation.rb", "ios_upload_validation.rb",
                            "native_process_spawn.rb", "native_upload_process.rb",
                            "android_upload_validation.rb", "release_support.rb"))
            locations = set()
            for stream in (text, result.stderr.decode("utf-8", "replace")):
                if deadline is not None:
                    check_clock(deadline)
                for match in re.finditer(r"((?:tests/workflow|fastlane)/[A-Za-z0-9_]+\.rb):([1-9][0-9]{0,5})", stream):
                    if deadline is not None:
                        check_clock(deadline)
                    if match[1] in allowed:
                        locations.add((match[1], int(match[2])))
                        if len(locations) > 32:
                            locations.remove(max(locations))
                if deadline is not None:
                    check_clock(deadline)
            value["ruby_locations"] = sorted(locations)
            footers = re.findall(MINITEST_FOOTER, text)
            value["minitest_observations"] = [list(map(int, row)) for row in footers[:2]]
            if (step.id in {"ruby-native-capture", "ruby-ios_upload_validation", "ruby-android_upload_validation"}
                    and (getattr(result, "ok", None) is False or result.returncode != 0
                         or result.timed_out or result.cancelled or not result.domain_finality
                         or not result.waited or not result.stdout_eof or not result.stderr_eof
                         or result.cleanup_errors or value["minitest_structure"]["reasons"])):
                diagnostic = fixture_bootstrap_failure(result.stderr, deadline=deadline)
                if diagnostic is not None:
                    value["fixture_bootstrap_failure"] = diagnostic
            if (step.id == "ruby-native-capture" and step.native_partition == "healthy"
                    and ISOLATED_COLLECTOR_FAILURE_ID in expected):
                diagnostic = isolated_collector_failure(result.stderr, deadline=deadline)
                if diagnostic is not None and _minitest_failed_target(text, ISOLATED_COLLECTOR_FAILURE_ID, deadline=deadline):
                    value["isolated_collector_failure"] = diagnostic
            if step.id == "ruby-native-capture" and step.native_partition == "healthy":
                diagnostic = native_primary_failure(result.stderr, deadline=deadline)
                if diagnostic is not None:
                    targets = [identifier for identifier, modes in NATIVE_PRIMARY_FAILURE_CALLBACK_MODES.items()
                               if diagnostic["mode"] in modes]
                    if (len(targets) == 1 and targets[0] in expected
                            and _minitest_failed_target(text, targets[0], deadline=deadline)):
                        value["native_primary_failure"] = diagnostic
            if (step.id == "ruby-native-capture"
                    and (step.native_partition == "healthy" or step.native_partition in NATIVE_ORDER_CLEANUP_MODES)):
                diagnostic = native_order_failure(result.stderr, deadline=deadline)
                if diagnostic is not None:
                    partition = (diagnostic["mode"] if diagnostic["mode"] in NATIVE_ORDER_CLEANUP_MODES else "healthy")
                    targets = [identifier for identifier, modes in NATIVE_ORDER_FAILURE_CALLBACK_MODES.items()
                               if diagnostic["mode"] in modes]
                    if (step.native_partition == partition and len(targets) == 1 and targets[0] in expected
                            and _minitest_failed_target(text, targets[0], deadline=deadline)):
                        value["native_order_failure"] = diagnostic
            if step.id == "ruby-native-capture" and step.native_partition == "healthy":
                diagnostic = native_setup_failure(result.stderr, deadline=deadline)
                if diagnostic is not None:
                    targets = [identifier for identifier, modes in NATIVE_SETUP_FAILURE_CALLBACK_MODES.items()
                               if diagnostic["mode"] in modes]
                    if (len(targets) == 1 and targets[0] in expected
                            and _minitest_failed_target(text, targets[0], deadline=deadline)):
                        value["native_setup_failure"] = diagnostic
            if (step.id in {"ruby-ios_upload_validation", "ruby-android_upload_validation"}
                    and step.native_partition == "healthy"):
                diagnostic = adapter_failure(result.stderr, deadline=deadline)
                if diagnostic is not None:
                    gate, class_name = ADAPTER_FAILURE_PLATFORMS[diagnostic["platform"]]
                    callback, _ = ADAPTER_FAILURE_MODE_CONTRACTS[diagnostic["mode"]]
                    target = class_name + "#" + callback
                    if (step.id == gate and target in expected
                            and _minitest_failed_target(text, target, deadline=deadline)):
                        value["adapter_failure"] = diagnostic
        except (VerificationError, OSError, UnicodeError):
            if deadline is not None:
                check_clock(deadline)
            value["ruby_diagnostics_unavailable"] = True
    if (step is not None and paths is not None and checks is not None
            and (step.id in {"native-profile-source", "native-profile-wheel"}
                 or step.id in {"python-full", "python-wheel"} and step.parser == "native"
                 and step.native_partition in PYTHON_POISON_PARTITIONS)):
        stderr = result.stderr.decode("utf-8", "replace")
        lowered = stderr.lower()
        # These fixed tokens are observations of captured text, not diagnoses
        # of a kernel/service cause. Never forward surrounding native output.
        tokens = (("permission-denied", "permission denied"),
                  ("operation-not-permitted", "operation not permitted"),
                  ("code-signing-internal", "internal error in code signing subsystem"),
                  ("unsigned-code", "code object is not signed at all"),
                  ("altered-code", "code or signature modified"),
                  ("untrusted-chain", "cssmerr_tp_not_trusted"),
                  ("chain-build-failed", "unable to build chain to self-signed root"),
                  ("interaction-not-allowed", "user interaction is not allowed"))
        value["native_error_tokens"] = [label for label, token in tokens if token in lowered]
        try:
            if deadline is not None:
                check_clock(deadline)
            expected = checks.native_partition_ids(paths.source, step.native_partition, deadline=deadline)
            diagnostic = native_failure_diagnostic(result.stdout.decode("utf-8", "replace") + "\n" + stderr,
                                                   expected, deadline=deadline)
            if diagnostic is not None:
                value["native_diagnostic"] = diagnostic
                if diagnostic["phase"] == "tests":
                    profile = _profile_failure_for_callbacks(result.stderr, diagnostic["records"], deadline=deadline)
                    if profile is not None:
                        value["profile_fixture_failure"] = profile
        except Exception:
            if deadline is not None:
                check_clock(deadline)
            value["native_diagnostics_unavailable"] = True
    return value


def canonical_directory(value: Path) -> Path:
    if not value.is_absolute():
        raise VerificationError("ABSOLUTE_DIRECTORY_REQUIRED")
    result = value.resolve(strict=True)
    if not stat.S_ISDIR(result.lstat().st_mode):
        raise VerificationError("DIRECTORY_REQUIRED")
    return result


def make_layout(paths: Paths, session, *, deadline: float) -> None:
    """Hold the immutable children's parent; only designated leaves are mutable.

    Root ownership of child files alone is insufficient if the subject can
    rename their parent entries. Admission uses its initial private work tree;
    before project execution root permanently takes custody of its top level.
    """
    session.ensure_idle()
    os.chown(paths.work, 0, 0)
    os.chmod(paths.work, 0o755)
    for name in ("source-venv", "wheel-venv", "bundler", "bundle", "gem-cache",
                 "bundle-config", "bundle-home", "wheels", "checks", "native-process-abi", "ruby-negative"):
        check_clock(deadline)
        path = paths.work / name
        path.mkdir(mode=0o700)
        os.chown(path, session.uid, session.gid)


def inspect_editable(paths: Paths, *, deadline: float) -> dict:
    site = paths.work / "source-venv/lib/python3.11/site-packages"
    metadata = site / f"mobile_release_kit-{paths.version}.dist-info"
    direct = strict_json(read_regular(metadata / "direct_url.json", deadline=deadline).decode("utf-8"))
    if direct != {"dir_info": {"editable": True}, "url": (paths.work / "source-build").as_uri()}:
        raise VerificationError("EDITABLE_ORIGIN")
    pth = site / f"__editable__.mobile_release_kit-{paths.version}.pth"
    if read_regular(pth, deadline=deadline) != (str(paths.work / "source-build/src") + "\n").encode("utf-8"):
        raise VerificationError("EDITABLE_PROJECTION")
    return {"editable": True, "backend": "setuptools==80.9.0", "source_copy": "source-build/src"}


def protected_optional_header_alias(root: Path, session, *, framework_name: str,
                                    inspect: Callable) -> str | None:
    """Prove one explicitly optional Mac Tk/Tcl header leaf, without changing it.

    The caller has already selected this exact optional path/role after ENOENT.
    This finite read-only proof assumes the admitted, trusted provider boundary;
    it is not an atomic pathname guarantee against a hostile host administrator.
    Every operation, including absent-leaf inspection, is charged by the caller.
    """
    if type(framework_name) is not str or framework_name not in {"Tk.framework", "Tcl.framework"}:
        return None
    framework = root / "Frameworks" / framework_name
    versions = framework / "Versions"
    alias = framework / "PrivateHeaders"
    version_pattern = r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}"
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                              value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def directory(path):
        state = inspect(path.lstat)
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid == session.uid
                or state.st_mode & 0o002 or state.st_gid == session.gid and state.st_mode & 0o020):
            return None
        return identity(state)

    def link(path):
        state = inspect(path.lstat)
        # Symlink write bits (normally0777 on Darwin) are not content-write
        # permission. The ordinary protected parent controls replacement.
        if not stat.S_ISLNK(state.st_mode) or state.st_uid == session.uid or not 1 <= state.st_size <= 128:
            return None
        raw = inspect(lambda: os.readlink(path))
        if type(raw) is not str or not 1 <= len(raw) <= 128:
            return None
        return identity(state), raw

    def observe():
        records = []
        for path in (root, root / "Frameworks", framework, versions):
            state = directory(path)
            if state is None:
                return None
            records.append(state)
        outer = link(alias)
        if outer is None:
            return None
        records.append(outer)
        match = re.fullmatch(r"Versions/(" + version_pattern + r")/PrivateHeaders", outer[1])
        if match is None:
            return None
        version = match[1]
        layout = "direct-version"
        if version == "Current":
            current = link(versions / "Current")
            if current is None or re.fullmatch(version_pattern, current[1]) is None or current[1] == "Current":
                return None
            records.append(current)
            version, layout = current[1], "current-version"
        state = directory(versions / version)
        if state is None:
            return None
        records.append(state)
        try:
            inspect((versions / version / "PrivateHeaders").lstat)
        except FileNotFoundError as missing:
            if missing.errno != 2:
                return None
        else:
            return None  # Another dangling leaf is not positive absence.
        return layout, tuple(records)

    try:
        before = observe()
        if before is None:
            return None
        after = observe()
        return before[0] if after == before else None
    except OSError:
        return None  # Preserve the original following-stat failure at the caller.


def validate_tool_permissions(prefixes: tuple[Path, ...], session, *, deadline: float,
                              roles: tuple[tuple[str, Path], ...] = (), platform: str = "") -> list[dict]:
    """Provider runtimes are trusted, but the numerical subject cannot edit them.

    This is a bounded permissions check, not a homemade OS/package source map.
    System runtime symlinks are allowed; their actual destinations are checked.
    Only positively protected absent optional Mac Tk/Tcl header aliases are excepted.
    """
    count = 0
    observations = []

    def inspect(operation):
        nonlocal count
        check_clock(deadline)
        count += 1
        if count > 100000:
            raise VerificationError("PROVIDER_RUNTIME_INVENTORY_BOUND")
        try:
            return operation()
        finally:
            check_clock(deadline)

    for prefix_index, root in enumerate(prefixes):
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            check_clock(deadline)
            for path in (Path(directory), *(Path(directory) / name for name in dirs + files)):
                count += 1
                if count > 100000:
                    raise VerificationError("PROVIDER_RUNTIME_INVENTORY_BOUND")
                try:
                    info = path.stat()  # Provider-controlled links, not mutable outputs.
                except OSError as original:
                    # Preserve the original failed operation/index. Optional
                    # proof inspections cannot rewrite its diagnostic location.
                    role, components = "unbound", None
                    try:
                        selected = tuple(role for role, prefix in roles if prefix == root)
                        role = selected[0] if len(selected) == 1 else "unbound"
                        components = path.relative_to(root).parts
                        original._mrk_provider_stat = (role, prefix_index, count, components)
                    except VerificationError:
                        raise  # Deadline/budget failure cannot become optional success.
                    except Exception:
                        if getattr(session, "failure", None) is not None:
                            raise  # Includes the owner's latched alarm exception.
                        # A failed diagnostic cannot supply partial eligibility.
                        # Cancellation is intentionally not caught now that a
                        # positive proof could continue beyond the original error.
                        role, components = "unbound", None
                    if (original.errno == 2 and platform == "macos"
                            and role in {"python", "python312", "python313", "python314"}
                            and components in {("Frameworks", "Tk.framework", "PrivateHeaders"),
                                               ("Frameworks", "Tcl.framework", "PrivateHeaders")}
                            and (role, components) not in {(item["runtime_role"], tuple(item["relative_components"]))
                                                           for item in observations}):
                        layout = protected_optional_header_alias(root, session, framework_name=components[1],
                                                                 inspect=inspect)
                        if layout is not None:
                            observations.append({"runtime_role": role, "relative_components": list(components),
                                                 "layout": layout, "state": "protected-absent-optional-header"})
                            continue
                    raise
                if (info.st_uid == session.uid or info.st_mode & 0o002
                        or info.st_gid == session.gid and info.st_mode & 0o020):
                    raise VerificationError("PROVIDER_RUNTIME_SUBJECT_WRITABLE")
    return observations


def tool_evidence(paths: Paths, session, platform: str, *, deadline: float) -> dict:
    roles = (("python", paths.python.parent.parent), ("ruby", paths.ruby.parent.parent))
    if paths.java_home is not None:
        roles += (("jdk", paths.java_home),)
    roles += tuple((role, pair[1]) for role, pair in zip(
        ("python312", "python313", "python314"), paths.compatibility_runtimes))
    optional_headers = validate_tool_permissions(session.tool_prefixes, session, deadline=deadline,
                                                 roles=roles, platform=platform)
    data = {"python": {"version": sys.version.split()[0], "sha256": hashlib.sha256(
                read_regular(paths.python, deadline=deadline, maximum=64 * 1024**2)).hexdigest()},
            "ruby": {"sha256": hashlib.sha256(read_regular(paths.ruby, deadline=deadline,
                                                             maximum=64 * 1024**2)).hexdigest()}}
    ruby = session.run([str(paths.ruby), "--version"], cwd=paths.work,
                       env=dict(environment(paths, platform)), seconds=15)
    version = ruby.stdout.decode("utf-8", "strict").strip()
    if not ruby.ok or ruby.stderr or not re.fullmatch(r"ruby 3\.3\.12 \([^\r\n]{1,150}\) \[[A-Za-z0-9_.-]+\]", version):
        raise VerificationError("RUBY_VERSION_OR_FINALITY")
    data["ruby"]["version"] = version
    data["protected_absent_optional_headers"] = optional_headers
    data["platform"] = dict(zip(("system", "node", "release", "version", "machine"), os.uname()))
    data["platform"].pop("node")  # A host name is not useful public evidence.
    return data


def native_compiler_binding(session, platform: str, *, deadline: float) -> tuple[Path, dict, str]:
    """Consume only the successfully admitted toolchain map; no rediscovery."""
    tools = session.native_process_toolchain
    expected = {"gcc", "evidence"} if platform == "linux" else {"clang", "linker", "sdk", "toolchain", "evidence"}
    if type(tools) is not dict or set(tools) != expected or type(tools["evidence"]) is not dict:
        raise VerificationError("NATIVE_COMPILER_BINDING")
    compiler = tools["gcc" if platform == "linux" else "clang"]
    if not isinstance(compiler, Path) or not compiler.is_absolute() or compiler.resolve(strict=True) != compiler:
        raise VerificationError("NATIVE_COMPILER_BINDING")
    if platform == "linux":
        if (os.uname().machine != "x86_64" or not compiler.is_relative_to(Path("/usr"))
                or compiler != Path("/usr/bin/x86_64-linux-gnu-gcc-13").resolve(strict=True)
                or set(tools["evidence"]) != {"gcc_sha256", "provider", "compiler_family"}
                or tools["evidence"]["provider"] != "ubuntu-24.04-distribution"
                or tools["evidence"]["compiler_family"] != "gcc-13"):
            raise VerificationError("NATIVE_COMPILER_BINDING")
    elif platform != "macos" or not compiler.is_relative_to(tools["toolchain"]):
        raise VerificationError("NATIVE_COMPILER_BINDING")
    digest = hashlib.sha256(read_regular(compiler, deadline=deadline, maximum=512 * 1024**2)).hexdigest()
    if tools["evidence"].get("gcc_sha256" if platform == "linux" else "clang_sha256") != digest:
        raise VerificationError("NATIVE_COMPILER_CHANGED")
    return compiler, tools, digest


def native_compiler_version(result, platform: str) -> str:
    require_original_finality(result)
    text = result.stdout.decode("ascii", "strict")
    lines = text.splitlines()
    pattern = (r"x86_64-linux-gnu-gcc-13 \([ -~]{1,160}\) 13\.[0-9]{1,3}\.[0-9]{1,3}"
               if platform == "linux" else r"Apple clang version [A-Za-z0-9 ._()+-]{1,160}")
    if (result.stderr or not text.endswith("\n") or not 1 <= len(lines) <= 10
            or not re.fullmatch(pattern, lines[0])
            or any(len(line) > 1024 or any(ord(char) < 32 or ord(char) > 126 for char in line) for line in lines)):
        raise VerificationError("NATIVE_COMPILER_VERSION")
    return lines[0]


def retain_native_header(paths: Paths, session, checks, platform: str, state: NativeABIState,
                         rows: list[dict], *, deadline: float) -> dict:
    if (type(state) is not NativeABIState or any(value is not None for value in (
            state.compiler_capture, state.build_capture, state.header_capture, state.compiler,
            state.compiler_sha256, state.source_sha256, state.binary_sha256, state.platform, state.architecture))
            or state.phases):
        raise VerificationError("NATIVE_ABI_REPEATED_PRODUCER")
    compiler, tools, compiler_hash = native_compiler_binding(session, platform, deadline=deadline)
    source = paths.source / "tests/workflow/native_process_abi.c"
    source_hash = hashlib.sha256(read_regular(source, deadline=deadline, maximum=65536)).hexdigest()
    binary = paths.work / "native-process-abi/header-record"
    if list(binary.parent.iterdir()):
        raise VerificationError("NATIVE_ABI_OUTPUT_EXISTS")
    # GCC's assembler/linker must never search mutable work, venv or Bundler
    # directories. No CPATH/GCC_EXEC_PREFIX/COMPILER_PATH or arbitrary -B/-I.
    env = {"PATH": "/usr/bin:/bin"} if platform == "linux" else {
        "DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer",
    }
    version_argv = (compiler, "--version") if platform == "linux" else (compiler, "--no-default-config", "--version")
    version = original_native_capture(session, version_argv, paths, rows, "compiler-version",
                                      deadline=deadline, seconds=15, env=env)
    compiler_version = native_compiler_version(version, platform)
    rows[-1]["status"] = "PASS"
    architecture = os.uname().machine
    if platform == "linux":
        argv = (compiler, "-D_GNU_SOURCE", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                source, "-o", binary)
    else:
        if architecture not in {"arm64", "x86_64"}:
            raise VerificationError("NATIVE_ABI_ARCHITECTURE")
        argv = (compiler, "--no-default-config", "-fno-modules", "-std=c11", "-D_DARWIN_C_SOURCE",
                "-O2", "-Wall", "-Wextra", "-Werror", "-arch", architecture,
                "-isysroot", tools["sdk"], "-B", tools["toolchain"] / "usr/bin",
                "-Wl,-adhoc_codesign", source, "-o", binary)
    compiled = original_native_capture(session, argv, paths, rows, "compiler-build", deadline=deadline,
                                       seconds=120, env=env)
    if compiled.stdout or compiled.stderr or list(binary.parent.iterdir()) != [binary]:
        raise VerificationError("NATIVE_ABI_BUILD_OUTPUT")
    # Reading/sealing is legal only now: the original compiler is waited, both
    # captures ended, and the Session verified every producer is gone.
    binary_hash = hashlib.sha256(read_regular(binary, deadline=deadline, maximum=8 * 1024**2)).hexdigest()
    if not binary.stat().st_mode & 0o111:
        raise VerificationError("NATIVE_ABI_BINARY_MODE")
    freeze_tree(binary.parent, deadline=deadline)
    if hashlib.sha256(read_regular(binary, deadline=deadline, maximum=8 * 1024**2)).hexdigest() != binary_hash:
        raise VerificationError("NATIVE_ABI_BINARY_CHANGED")
    rows[-1]["status"] = "PASS"
    header = original_native_capture(session, (binary,), paths, rows, "public-header-and-no-child-controls",
                                     deadline=deadline, seconds=30, env={}, output_limit=8192)
    if header.stderr:
        raise VerificationError("NATIVE_ABI_HEADER_OUTPUT")
    record = checks.parse_abi_record(header.stdout)
    if record["family"] != ("linux-glibc" if platform == "linux" else "darwin") or record["architecture"] != architecture:
        raise VerificationError("NATIVE_ABI_HOST_MISMATCH")
    rows[-1]["status"] = "PASS"
    state.compiler_capture, state.build_capture, state.header_capture = version, compiled, header
    state.compiler, state.compiler_sha256, state.source_sha256 = compiler, compiler_hash, source_hash
    state.binary_sha256, state.platform, state.architecture = binary_hash, platform, architecture
    return {"compiler_version": compiler_version, "compiler_sha256": compiler_hash,
            "source_sha256": source_hash, "binary_sha256": binary_hash,
            "header_sha256": hashlib.sha256(header.stdout).hexdigest(),
            "family": record["family"], "architecture": architecture, "toolchain": tools["evidence"]}


def require_retained_header(paths: Paths, session, platform: str, state: NativeABIState, *, deadline: float) -> None:
    if (type(state) is not NativeABIState or state.platform != platform or state.architecture != os.uname().machine
            or state.header_capture is None or state.compiler_capture is None or state.build_capture is None):
        raise VerificationError("NATIVE_ABI_ORIGINAL_HEADER_REQUIRED")
    for result in (state.compiler_capture, state.build_capture, state.header_capture):
        require_original_finality(result)
    compiler, _tools, digest = native_compiler_binding(session, platform, deadline=deadline)
    if compiler != state.compiler or digest != state.compiler_sha256:
        raise VerificationError("NATIVE_ABI_COMPILER_DRIFT")
    for path, maximum, wanted in (
        (paths.source / "tests/workflow/native_process_abi.c", 65536, state.source_sha256),
        (paths.work / "native-process-abi/header-record", 8 * 1024**2, state.binary_sha256),
    ):
        info = path.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o222
                or hashlib.sha256(read_regular(path, deadline=deadline, maximum=maximum)).hexdigest() != wanted):
            raise VerificationError("NATIVE_ABI_FROZEN_SOURCE_OR_BINARY_DRIFT")


def python_declaration_argv(paths: Paths, executable: Path, minor: int, phase: str) -> tuple[str, ...]:
    return (str(executable), "-I", "-S", "-B", str(paths.source / "tests/workflow/run_native_profile_checks.py"),
            f"--abi-3{minor}-{phase}")


def parse_native_python_controls(result, expected: tuple[str, ...]) -> list[str]:
    require_original_finality(result)
    stderr = result.stderr.decode("utf-8", "strict")
    if any(line.startswith(NATIVE_DIAGNOSTIC_PREFIX) for line in stderr.splitlines()):
        raise VerificationError("NATIVE_FAILURE_DIAGNOSTIC_ON_SUCCESS")
    footers = re.findall(r"(?m)^Ran (\d+) tests? in [0-9.]+s\s*$", stderr)
    if footers != [str(len(expected))] or re.findall(r"(?m)^(OK)[ \t]*$", stderr) != ["OK"] or "skipped" in stderr:
        raise VerificationError("NATIVE_COMPATIBILITY_RESULT")
    completed = re.findall(r"(?m)^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok\s*$", stderr)
    observed = tuple(sorted(owner if owner.endswith("." + name) else f"{owner}.{name}" for name, owner in completed))
    if observed != expected:
        raise VerificationError("NATIVE_COMPATIBILITY_INVENTORY")
    return list(observed)


def native_phase_environment(paths: Paths, platform: str, phase: str, *, ruby: bool = False) -> dict:
    env = dict(environment(paths, platform))
    if phase == "wheel":
        env["PATH"] = str(paths.wheel_python.parent) + ":" + env["PATH"]
        env["MOBILE_RELEASE_TEST_PYTHON"] = str(paths.wheel_python)
        if ruby:
            env["BUNDLE_GEMFILE"] = str(paths.work / "wheel-venv/share/mobile-release-kit/Gemfile")
    return env


def perform_native_abi_gate(step: Step, paths: Paths, session, checks, platform: str,
                            state: NativeABIState, *, deadline: float) -> CheckResult:
    cutoff = min(deadline, time.monotonic() + 300.0)
    details = {"stage": "contract", "captures": []}
    rows = details["captures"]
    try:
        phase = {"native-process-abi-source": "source", "native-process-abi-wheel": "wheel"}.get(step.id)
        if phase is None or step != Step(step.id, kind="native-abi", seconds=300) or type(state) is not NativeABIState:
            raise VerificationError("NATIVE_ABI_GATE_CONTRACT")
        check_clock(cutoff)
        session.ensure_idle(deadline=cutoff)
        check_clock(cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        if phase == "source":
            details["header"] = retain_native_header(paths, session, checks, platform, state, rows, deadline=cutoff)
        elif set(state.phases) != {"source"}:
            raise VerificationError("NATIVE_ABI_PHASE_ORDER")
        require_retained_header(paths, session, platform, state, deadline=cutoff)
        details["stage"] = "package"
        package = (paths.work / "source-build/src/mobile_release" if phase == "source"
                   else paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
        details["package"] = checks.inspect_native_package(paths.source, package, deadline=cutoff)
        tooling = paths.source if phase == "source" else paths.work / "wheel-venv/share/mobile-release-kit"
        for name in ("Gemfile", "Gemfile.lock", "fastlane/native_process_spawn.rb",
                     "fastlane/native_upload_process.rb", "fastlane/native_upload_validation.rb"):
            if read_regular(tooling / name, deadline=cutoff) != read_regular(paths.source / name, deadline=cutoff):
                raise VerificationError("NATIVE_ABI_TOOLING_BYTES")
        python = paths.source_python if phase == "source" else paths.wheel_python
        python_prefix = Path(sys.base_prefix).resolve(strict=True)
        env = native_phase_environment(paths, platform, phase)
        details["stage"] = "declarations"
        py = original_native_capture(session, python_declaration_argv(paths, python, 11, phase), paths, rows,
                                     "python-declaration", deadline=cutoff, seconds=30, env=env)
        python_info = native_python_observation(py.stderr, paths, minor=11, phase=phase,
                                                executable=python, prefix=python_prefix)
        declarations, ruby_info = [], []
        for bundled in (True, False):
            argv = ((*paths.bundle, "exec", str(paths.ruby)) if bundled else
                    (str(paths.ruby), "--disable-gems", "--disable=rubyopt"))
            ruby = original_native_capture(session, (*argv, "-e", RUBY_ABI_DECLARATION,
                                            tooling / "fastlane/native_process_spawn.rb", phase), paths, rows,
                                            "ruby-bundle-declaration" if bundled else "ruby-default-declaration",
                                            deadline=cutoff, seconds=30,
                                            env=native_phase_environment(paths, platform, phase, ruby=True) if bundled else {})
            ruby_info.append(native_ruby_observation(ruby.stderr, paths, phase=phase, bundled=bundled,
                                                     platform=platform, deadline=cutoff))
            checks.compare_abi_records(state.header_capture.stdout, py.stdout, ruby.stdout)
            rows[-1]["status"] = "PASS"
            declarations.append(ruby)
        # The Python observation is not marked complete merely by parsing its
        # JSON. Both actual Ruby contexts and the actual C header must agree.
        next(row for row in rows if row["stage"] == "python-declaration")["status"] = "PASS"
        details.update(python=python_info, ruby=ruby_info, stage="public-controls")
        public_ids = checks.native_compatibility_ids(paths.source, public_only=True, deadline=cutoff)
        public = original_native_capture(session, (str(python), "-I", "-S", "-B",
                                          str(paths.source / "tests/workflow/run_native_profile_checks.py"),
                                          f"--public-311-{phase}"), paths, rows, "python-public-controls",
                                          deadline=cutoff, seconds=60, env=env)
        native_python_observation(public.stdout, paths, minor=11, phase=phase, executable=python, prefix=python_prefix)
        completed = parse_native_python_controls(public, public_ids)
        rows[-1].update(status="PASS", completed=completed)
        ruby_ids = ruby_expected_ids(paths.source, "ruby-native-public-" + phase)
        names = "|".join(re.escape(identifier.split("#", 1)[1]) for identifier in ruby_ids)
        filter_ = "/\\A(?:" + names + ")\\z/"
        ruby_argv = (*paths.bundle, "exec", str(paths.ruby),
                     str(paths.source / "tests/workflow/test_native_process_spawn.rb"),
                     *(("--installed-tooling-root", str(paths.work / "wheel-venv")) if phase == "wheel" else ()),
                     "--name", filter_, "--verbose")
        ruby_env = native_phase_environment(paths, platform, phase, ruby=True)
        ruby_step = Step("ruby-native-public-" + phase, argv=ruby_argv, cwd=paths.work,
                         env=tuple(sorted(ruby_env.items())), seconds=60, parser="minitest", expected_tests=len(ruby_ids))
        ruby_public = original_native_capture(session, ruby_argv, paths, rows, "ruby-public-controls",
                                              deadline=cutoff, seconds=60, env=ruby_env)
        parsed = parse_capture(ruby_step, ruby_public, paths, platform, checks, deadline=cutoff)
        rows[-1].update(status="PASS", completed=parsed.details["completed"])
        # Both original declaration objects remain in outside-owner memory;
        # consumers never reopen a producer-created JSON/PASS file as evidence.
        state.phases[phase] = (py, *declarations)
        details.update(stage="complete", phase=phase,
                       header_sha256=hashlib.sha256(state.header_capture.stdout).hexdigest())
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if rows and rows[-1]["status"] in {"RUNNING", "FINALIZED"}:
            rows[-1]["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "NATIVE_ABI_GATE_FAILURE")


def perform_compatibility_gate(step: Step, paths: Paths, session, checks, platform: str,
                               state: NativeABIState, *, deadline: float) -> CheckResult:
    cutoff = min(deadline, time.monotonic() + 120.0)
    details = {"stage": "contract", "captures": []}
    rows = details["captures"]
    try:
        fixed = {f"python-compat-{line}-{phase}": (minor, phase, pair)
                 for line, minor, pair in zip(("312", "313", "314"), (12, 13, 14), compatibility_paths(paths))
                 for phase in ("source", "wheel")}
        if step.id not in fixed:
            raise VerificationError("NATIVE_COMPATIBILITY_GATE_CONTRACT")
        minor, phase, (python, prefix) = fixed[step.id]
        argv = (str(python), "-I", "-S", "-B", str(paths.source / "tests/workflow/run_native_profile_checks.py"),
                f"--compat-3{minor}-{phase}")
        env = native_phase_environment(paths, platform, phase)
        expected_step = Step(step.id, kind="python-compatibility", argv=argv, cwd=paths.work,
                             env=tuple(sorted(env.items())), seconds=120)
        if step != expected_step or type(state) is not NativeABIState or phase not in state.phases:
            raise VerificationError("NATIVE_COMPATIBILITY_GATE_CONTRACT")
        check_clock(cutoff)
        session.ensure_idle(deadline=cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        require_retained_header(paths, session, platform, state, deadline=cutoff)
        details["stage"] = "declaration"
        declaration = original_native_capture(session, python_declaration_argv(paths, python, minor, phase),
                                               paths, rows, "python-declaration", deadline=cutoff, seconds=120, env=env)
        info = native_python_observation(declaration.stderr, paths, minor=minor, phase=phase,
                                         executable=python, prefix=prefix)
        for ruby in state.phases[phase][1:]:
            require_original_finality(ruby)
            checks.compare_abi_records(state.header_capture.stdout, declaration.stdout, ruby.stdout)
        rows[-1]["status"] = "PASS"
        details.update(runtime=info, executable_sha256=hashlib.sha256(
            read_regular(python, deadline=cutoff, maximum=64 * 1024**2)).hexdigest(), stage="controls")
        expected = checks.native_compatibility_ids(paths.source, deadline=cutoff)
        controls = original_native_capture(session, argv, paths, rows, "python-controls", deadline=cutoff,
                                            seconds=120, env=env, output_limit=8 * 1024**2)
        native_python_observation(controls.stdout, paths, minor=minor, phase=phase, executable=python, prefix=prefix)
        completed = parse_native_python_controls(controls, expected)
        rows[-1].update(status="PASS", completed=completed)
        details.update(stage="complete", tests=len(completed), completed=completed)
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if rows and rows[-1]["status"] in {"RUNNING", "FINALIZED"}:
            rows[-1]["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "NATIVE_COMPATIBILITY_GATE_FAILURE")


def perform_native_gate(step: Step, paths: Paths, session, checks,
                        platform: str, *, deadline: float) -> CheckResult:
    """Authority, healthy and literal singleton originals share one logical cutoff.

    The catalog retains its representative command. Only these two fixed gate
    identities use this native protocol; authority5 keeps its independently
    admitted argv. Each intentional-UNKNOWN proof has its own ordinary domain.
    """
    started = time.monotonic()
    details = {"stage": "contract", "partitions": [
        {"partition": name, "status": "UNEXECUTED"}
        for name in ("authority", "ordinary", *PYTHON_POISON_PARTITIONS)
    ]}
    active = None
    originals = []  # Root each original capture through the complete logical proof.
    try:
        check_clock(deadline)
        cutoff = min(deadline, started + 900.0)
        phase = {"native-profile-source": "source", "native-profile-wheel": "wheel"}.get(step.id)
        if platform != "macos" or phase is None:
            raise VerificationError("NATIVE_GATE_CONTRACT")
        python = paths.source_python if phase == "source" else paths.wheel_python
        entry = paths.source / "tests/workflow/run_native_profile_checks.py"
        tail = () if phase == "source" else ("--installed-wheel",)
        env = dict(environment(paths, platform))
        if phase == "wheel":
            env["PATH"] = str(paths.wheel_python.parent) + ":" + env["PATH"]
            env["MOBILE_RELEASE_TEST_PYTHON"] = str(paths.wheel_python)
        expected = Step(step.id, argv=(str(python), "-I", "-B", str(entry), *tail),
                        cwd=paths.work, env=tuple(sorted(env.items())), seconds=900, parser="native")
        if step != expected:
            raise VerificationError("NATIVE_GATE_CONTRACT")
        session.ensure_idle(deadline=cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        details["stage"] = "inventory"
        inventories = {name: checks.native_partition_ids(paths.source, name, deadline=cutoff)
                       for name in ("all", "authority", "ordinary", *PYTHON_POISON_PARTITIONS)}
        joined = tuple(identifier for row in details["partitions"] for identifier in inventories[row["partition"]])
        if (any(type(ids) is not tuple or not ids or tuple(sorted(set(ids))) != ids
                for ids in inventories.values())
                or len(inventories["authority"]) != 5
                or any(len(inventories[name]) != 1 for name in PYTHON_POISON_PARTITIONS)
                or len(joined) != len(set(joined)) or tuple(sorted(joined)) != inventories["all"]):
            raise VerificationError("NATIVE_PARTITION_UNION")
        details["stage"] = "package"
        package = (paths.work / "source-build/src/mobile_release" if phase == "source"
                   else paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
        details["package"] = checks.inspect_native_package(paths.source, package, deadline=cutoff)
        details["stage"] = "preparation"
        session.prepare_native_authority(phase, deadline=cutoff)
        completed = []
        for row in details["partitions"]:
            active = row
            partition = row["partition"]
            details["stage"] = partition
            check_clock(cutoff)
            session.ensure_idle(deadline=cutoff)
            authority = partition == "authority"
            poison = partition in PYTHON_POISON_PARTITIONS
            part = dataclasses.replace(step, native_partition=partition,
                argv=(str(python), "-I", *(("-S",) if authority or poison else ()), "-B", str(entry),
                      *((f"--{partition}-{phase}",) if poison else ("--" + partition, *tail))),
                cwd=paths.work / f"native-authority-{phase}" if authority else step.cwd,
                env=() if authority else step.env)
            row["status"] = "RUNNING"
            value = session.run(list(part.argv), cwd=part.cwd, env=dict(part.env), seconds=900,
                                output_limit=8 * 1024**2, cpu_seconds=180,
                                 profile=f"native-authority-{phase}" if authority else "ordinary",
                                 absolute_deadline=cutoff)
            originals.append(value)
            row["capture"] = capture_observations(value)
            primary = None
            try:
                require_original_finality(value)
                parsed = parse_capture(part, value, paths, platform, checks, deadline=cutoff)
                if poison:
                    row["runtime"] = native_python_observation(value.stdout, paths, minor=11, phase=phase,
                        executable=python, prefix=paths.python.parent.parent)
            except BaseException as exc:
                primary = exc
            try:
                session.ensure_idle(deadline=cutoff)
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    row["idle_error"] = error_details(exc)
            if primary is not None:
                try:
                    row["capture"] = failure_details(value, part, paths, checks=checks,
                                                     deadline=cutoff, platform=platform)
                except BaseException as exc:
                    # Original wait/EOF/persisted counts and first failure stay
                    # available even if the diagnostic parser is interrupted.
                    row["diagnostic_error"] = error_details(exc)
                raise primary
            check_clock(cutoff)
            observed = tuple(parsed.details["completed"])
            if observed != inventories[partition]:
                raise VerificationError("NATIVE_PARTITION_RESULT")
            row.update(status="PASS", tests=len(observed), completed=list(observed))
            completed.extend(observed)
        details["stage"] = "union"
        check_clock(cutoff)
        if tuple(sorted(completed)) != inventories["all"] or len(completed) != len(set(completed)):
            raise VerificationError("NATIVE_PARTITION_UNION")
        details.update(stage="complete", tests=len(completed), completed=sorted(completed))
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if active is not None and active["status"] == "RUNNING":
            active["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "NATIVE_GATE_FAILURE")


def perform_python_gate(step: Step, paths: Paths, session, checks,
                        platform: str, *, deadline: float) -> CheckResult:
    """Healthy Linux full/wheel plus fixed original ordinary singleton domains.

    The full healthy capture keeps its exact admitted aggregate-deadline argv
    and storage profile. The original gate cutoff is an independent, tighter
    Session bound for every part, preparation, stream/domain finality and idle.
    """
    started = time.monotonic()
    details = {"stage": "contract", "partitions": [
        {"partition": name, "status": "UNEXECUTED"} for name in ("healthy", *PYTHON_POISON_PARTITIONS)
    ]}
    active = None
    originals = []
    try:
        check_clock(deadline)
        cutoff = min(deadline, started + 900.0)
        phase = {"python-full": "source", "python-wheel": "wheel"}.get(step.id)
        if platform != "linux" or phase is None:
            raise VerificationError("PYTHON_GATE_CONTRACT")
        selection = "full" if phase == "source" else "wheel"
        python = paths.source_python if phase == "source" else paths.wheel_python
        env = tuple(sorted(native_phase_environment(paths, platform, phase).items()))
        expected = Step(step.id, argv=(str(python), "-I", "-B", str(paths.checks), "--check", step.id,
            "--source-root", str(paths.source), "--work-root", str(paths.work / "checks"), "--deadline", repr(deadline)),
            cwd=paths.work, env=env, seconds=900, parser="check")
        if step != expected:
            raise VerificationError("PYTHON_GATE_CONTRACT")
        session.ensure_idle(deadline=cutoff)
        check_clock(cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        details["stage"] = "inventory"
        inventories = {name: checks.python_capture_ids(paths.source, selection, name, deadline=cutoff)
                       for name in ("all", "healthy", *PYTHON_POISON_PARTITIONS)}
        joined = tuple(identifier for row in details["partitions"] for identifier in inventories[row["partition"]])
        if (any(type(ids) is not tuple or not ids or tuple(sorted(set(ids))) != ids for ids in inventories.values())
                or any(len(inventories[name]) != 1 for name in PYTHON_POISON_PARTITIONS)
                or len(joined) != len(set(joined)) or tuple(sorted(joined)) != inventories["all"]):
            raise VerificationError("PYTHON_CAPTURE_UNION")
        details["stage"] = "package"
        package = (paths.work / "source-build/src/mobile_release" if phase == "source"
                   else paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
        details["package"] = checks.inspect_native_package(paths.source, package, deadline=cutoff)
        completed = []
        for row in details["partitions"]:
            active = row
            partition = row["partition"]
            healthy = partition == "healthy"
            details["stage"] = partition
            check_clock(cutoff)
            session.ensure_idle(deadline=cutoff)
            part = step if healthy else dataclasses.replace(step, parser="native", native_partition=partition,
                argv=(str(python), "-I", "-S", "-B", str(paths.source / "tests/workflow/run_native_profile_checks.py"),
                      f"--{partition}-{phase}"))
            row["status"] = "RUNNING"
            value = session.run(list(part.argv), cwd=part.cwd, env=dict(part.env), seconds=900,
                output_limit=8 * 1024**2, cpu_seconds=300 if healthy and selection == "full" else 180,
                profile="python-full" if healthy and selection == "full" else "ordinary", absolute_deadline=cutoff)
            originals.append(value)
            row["capture"] = capture_observations(value)
            primary = None
            try:
                require_original_finality(value)
                parsed = parse_capture(part, value, paths, platform, checks, deadline=cutoff)
                if not healthy:
                    row["runtime"] = native_python_observation(value.stdout, paths, minor=11, phase=phase,
                        executable=python, prefix=paths.python.parent.parent)
            except BaseException as exc:
                primary = exc
            try:
                session.ensure_idle(deadline=cutoff)
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    row["idle_error"] = error_details(exc)
            if primary is not None:
                try:
                    row["capture"] = failure_details(value, part, paths, checks=checks,
                        deadline=cutoff, platform=platform)
                except BaseException as exc:
                    row["diagnostic_error"] = error_details(exc)
                raise primary
            check_clock(cutoff)
            if healthy:
                row["summary"] = parsed.details["summary"]
                observed = tuple(sorted(item["id"] for item in row["summary"]["tests"]))
            else:
                observed = tuple(parsed.details["completed"])
            if observed != inventories[partition]:
                raise VerificationError("PYTHON_CAPTURE_RESULT")
            row.update(status="PASS", tests=len(observed), completed=list(observed))
            completed.extend(observed)
        details["stage"] = "union"
        check_clock(cutoff)
        if tuple(sorted(completed)) != inventories["all"] or len(completed) != len(set(completed)):
            raise VerificationError("PYTHON_CAPTURE_UNION")
        details.update(stage="complete", tests=len(completed), completed=sorted(completed))
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if active is not None and active["status"] == "RUNNING":
            active["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "PYTHON_GATE_FAILURE")


def perform_partitioned_ruby_gate(step: Step, paths: Paths, session, checks, platform: str,
                                  state: NativeABIState | None, *, deadline: float) -> CheckResult:
    """One of four closed Ruby gates, with a fixed total cutoff before entry.

    The catalog keeps every original logical gate. No child exit, parsed footer or
    retained UNKNOWN is a substitute for each original Session's finality/idle.
    Filenames, method partitions, counts and budgets come only from the literal
    per-gate contract, never from caller-provided IDs, paths or options.
    """
    started = time.monotonic()
    details = {"stage": "contract", "partitions": []}
    active = None
    originals = []
    try:
        check_clock(deadline)
        filename, total, healthy_count, seconds, poison = _ruby_partition_contract(step.id)
        gate_cutoff = min(deadline, started + seconds)
        native_capture = step.id == "ruby-native-capture"
        cutoff = min(gate_cutoff, started + RUBY_NATIVE_CAPTURE_SHARED_SECONDS) if native_capture else gate_cutoff
        details["partitions"] = [{"partition": name, "status": "UNEXECUTED"} for name in ("healthy", *dict(poison))]
        expected = Step(step.id, argv=(*paths.bundle, "exec", str(paths.ruby),
            str(paths.source / "tests/workflow" / filename), "--verbose"),
            cwd=paths.work, env=environment(paths, platform), seconds=seconds, parser="minitest", expected_tests=total)
        if (platform not in {"linux", "macos"} or step != expected
                or type(state) is not NativeABIState or "source" not in state.phases):
            raise VerificationError("RUBY_PARTITION_GATE_CONTRACT")
        if native_capture and (tuple(name for name, _seconds in RUBY_NATIVE_CAPTURE_BUDGETS)
                != tuple(row["partition"] for row in details["partitions"])
                or RUBY_NATIVE_CAPTURE_SHARED_SECONDS + sum(value for _name, value in RUBY_NATIVE_CAPTURE_BUDGETS) != seconds):
            raise VerificationError("RUBY_PARTITION_GATE_CONTRACT")
        session.ensure_idle(deadline=cutoff)
        check_clock(cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        details["stage"] = "header"
        require_retained_header(paths, session, platform, state, deadline=cutoff)
        if type(state.phases["source"]) is not tuple or len(state.phases["source"]) != 3:
            raise VerificationError("RUBY_PARTITION_SOURCE_ABI_REQUIRED")
        for original in state.phases["source"]:
            require_original_finality(original)
        details["stage"] = "inventory"
        inventories = {name: ruby_capture_ids(paths.source, step.id, name, deadline=cutoff)
                       for name in ("all", "healthy", *dict(poison))}
        joined = tuple(identifier for row in details["partitions"] for identifier in inventories[row["partition"]])
        if (any(type(ids) is not tuple or not ids or tuple(sorted(set(ids))) != ids for ids in inventories.values())
                or len(inventories["all"]) != total or len(inventories["healthy"]) != healthy_count
                or any(inventories[name] != (identifier,) for name, identifier in poison)
                or len(joined) != len(set(joined)) or tuple(sorted(joined)) != inventories["all"]):
            raise VerificationError("RUBY_PARTITION_UNION")
        completed = []
        if native_capture:
            boundary = time.monotonic()
            if boundary >= cutoff:
                raise VerificationError("AGGREGATE_DEADLINE")
            shared_remaining = RUBY_NATIVE_CAPTURE_SHARED_SECONDS - (boundary - started)
        for row in details["partitions"]:
            active = row
            partition = row["partition"]
            details["stage"] = partition
            part_seconds = seconds
            if native_capture:
                part_seconds = dict(RUBY_NATIVE_CAPTURE_BUDGETS)[partition]
                # Carry the previous completion sample: a scheduling gap cannot
                # renew this phase, nor can another part donate unused time.
                cutoff = min(gate_cutoff, boundary + part_seconds)
            check_clock(cutoff)
            session.ensure_idle(deadline=cutoff)
            part = dataclasses.replace(step, native_partition=partition, seconds=part_seconds,
                argv=ruby_capture_argv(paths, step.id, partition, deadline=cutoff), expected_tests=len(inventories[partition]))
            if native_capture:
                check_clock(cutoff)
            row["status"] = "RUNNING"
            value = session.run(list(part.argv), cwd=part.cwd, env=dict(part.env), seconds=part_seconds,
                output_limit=8 * 1024**2, cpu_seconds=180, profile="ordinary", absolute_deadline=cutoff)
            originals.append(value)
            row["capture"] = capture_observations(value)
            primary = None
            try:
                require_original_finality(value)
                parsed = parse_capture(part, value, paths, platform, checks, deadline=cutoff)
            except BaseException as exc:
                primary = exc
            try:
                session.ensure_idle(deadline=cutoff)
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    row["idle_error"] = error_details(exc)
            if primary is not None:
                try:
                    row["capture"] = failure_details(value, part, paths, checks=checks, deadline=cutoff, platform=platform)
                except BaseException as exc:
                    row["diagnostic_error"] = error_details(exc)
                raise primary
            check_clock(cutoff)
            observed = tuple(sorted(parsed.details["completed"]))
            if observed != inventories[partition]:
                raise VerificationError("RUBY_PARTITION_RESULT")
            row.update(status="RUNNING" if native_capture else "PASS",
                tests=len(observed), completed=list(observed), assertions=parsed.details["assertions"])
            completed.extend(observed)
            if native_capture:
                boundary = time.monotonic()
                if boundary >= cutoff:
                    raise VerificationError("AGGREGATE_DEADLINE")
                row["status"] = "PASS"
        details["stage"] = "union"
        if native_capture:
            cutoff = min(gate_cutoff, boundary + shared_remaining)
        check_clock(cutoff)
        if tuple(sorted(completed)) != inventories["all"] or len(completed) != len(set(completed)):
            raise VerificationError("RUBY_PARTITION_UNION")
        details.update(stage="complete", tests=len(completed), completed=sorted(completed))
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if active is not None and active["status"] == "RUNNING":
            active["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "RUBY_PARTITION_GATE_FAILURE")


def negative_prefix_custody(paths: Paths, session, *, deadline: float) -> tuple[int, ...]:
    """A fixed mutable leaf below the root-held work parent, never a caller path."""
    check_clock(deadline)
    prefix = paths.work / "ruby-negative"
    info = prefix.lstat()
    if (prefix.resolve(strict=True) != prefix or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != session.uid or info.st_gid != session.gid or stat.S_IMODE(info.st_mode) != 0o700):
        raise VerificationError("NEGATIVE_PREFIX_CUSTODY")
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def dispose_negative_ruby_prefix(paths: Paths, session, identity: tuple[int, ...], *, deadline: float) -> None:
    """Only outer Session finality permits root's descriptor-safe disposal."""
    check_clock(deadline)
    session.ensure_idle(deadline=deadline)
    if negative_prefix_custody(paths, session, deadline=deadline) != identity:
        raise VerificationError("NEGATIVE_PREFIX_CUSTODY_CHANGED")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise VerificationError("SAFE_DISPOSAL_UNAVAILABLE")
    parent = os.open(paths.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.stat("ruby-negative", dir_fd=parent, follow_symlinks=False)
        if (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) != identity:
            raise VerificationError("NEGATIVE_PREFIX_CUSTODY_CHANGED")
        check_clock(deadline)
        shutil.rmtree("ruby-negative", dir_fd=parent)
        try:
            os.stat("ruby-negative", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise VerificationError("NEGATIVE_PREFIX_NOT_REMOVED")
    finally:
        close_owned(parent)
    check_clock(deadline)


def inspect_negative_ruby_prefix(paths: Paths, session, checks, wheel_sha256: str, *, deadline: float) -> dict:
    """Actual same-wheel installation, inspected only after outer producer idle.

    The prefix stays subject-owned/private for the two missing-helper tests.
    Its positive counterpart remains frozen; no permission change or copying
    of repository helpers can establish this negative installation.
    """
    prefix = paths.work / "ruby-negative"
    negative_prefix_custody(paths, session, deadline=deadline)
    files, directories = checks._tree(prefix, deadline=deadline)
    site = prefix / "lib/python3.11/site-packages"
    relative_site = "lib/python3.11/site-packages/"
    dist = relative_site + f"mobile_release_kit-{paths.version}.dist-info/"
    package = checks._source_package(paths.source, deadline=deadline)
    expected = {relative_site + "mobile_release/" + name: data for name, data in package.items()}
    expected.update({"share/mobile-release-kit/" + name: read_regular(paths.source / name, deadline=deadline)
                     for name in checks.TOOLING_FILES})
    generated = {dist + name for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD",
                                         "licenses/LICENSE", "INSTALLER", "REQUESTED", "direct_url.json")}
    generated.add("bin/mobile-release")
    names = set(expected) | generated
    parents = {parent.as_posix() for name in names for parent in Path(name).parents if parent != Path(".")}
    if (set(files) != names or directories != parents
            or any(files[name] != data for name, data in expected.items())):
        raise VerificationError("NEGATIVE_PREFIX_INVENTORY")
    for relative in (*sorted(directories), *sorted(files)):
        check_clock(deadline)
        path = prefix / relative
        current = path.lstat()
        if (current.st_uid != session.uid or current.st_gid != session.gid or current.st_mode & 0o7022
                or stat.S_ISREG(current.st_mode) and current.st_nlink != 1):
            raise VerificationError("NEGATIVE_PREFIX_CUSTODY")
        if relative in files:
            if read_regular(path, deadline=deadline) != files[relative]:
                raise VerificationError("NEGATIVE_PREFIX_CHANGED")
            if relative != dist + "RECORD" and files[relative] != read_regular(
                    paths.work / "wheel-venv" / relative, deadline=deadline):
                raise VerificationError("NEGATIVE_PREFIX_POSITIVE_BYTES")
    direct = strict_json(files[dist + "direct_url.json"].decode("utf-8", "strict"))
    if (type(direct) is not dict or direct.get("url") != paths.wheel.as_uri()
            or type(direct.get("archive_info")) is not dict
            or type(direct["archive_info"].get("hashes")) is not dict
            or direct["archive_info"]["hashes"].get("sha256") != wheel_sha256):
        raise VerificationError("NEGATIVE_PREFIX_WHEEL_ORIGIN")
    raw = files[dist + "RECORD"]
    if len(raw) > 256 * 1024:
        raise VerificationError("NEGATIVE_PREFIX_RECORD_BOUND")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8", "strict")), strict=True))
    if len(rows) != len(files) or any(len(row) != 3 for row in rows):
        raise VerificationError("NEGATIVE_PREFIX_RECORD_INVENTORY")
    seen = set()
    for name, digest, size in rows:
        check_clock(deadline)
        if (not name or len(name) > 4096 or name.startswith("/") or "\\" in name
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise VerificationError("NEGATIVE_PREFIX_RECORD_PATH")
        path = (site / name).resolve(strict=True)
        if not path.is_relative_to(prefix):
            raise VerificationError("NEGATIVE_PREFIX_RECORD_PATH")
        relative = path.relative_to(prefix).as_posix()
        if relative not in files or relative in seen:
            raise VerificationError("NEGATIVE_PREFIX_RECORD_INVENTORY")
        seen.add(relative)
        if relative == dist + "RECORD":
            if digest or size:
                raise VerificationError("NEGATIVE_PREFIX_RECORD_SELF")
        else:
            wanted = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(files[relative]).digest()).rstrip(b"=").decode("ascii")
            if digest != wanted or size != str(len(files[relative])):
                raise VerificationError("NEGATIVE_PREFIX_RECORD_BYTES")
    if seen != set(files):
        raise VerificationError("NEGATIVE_PREFIX_RECORD_INVENTORY")
    return {"files": len(files), "wheel_sha256": wheel_sha256,
            "record_sha256": hashlib.sha256(raw).hexdigest(), "positive_prefix_untouched": True}


def perform_packaged_ruby_gate(step: Step, paths: Paths, session, checks, platform: str,
                               *, deadline: float) -> CheckResult:
    cutoff = min(deadline, time.monotonic() + 300.0)
    details = {"captures": []}
    rows = details["captures"]
    try:
        phase = {"ruby-packaged-capture-source": "source", "ruby-packaged-capture-wheel": "wheel"}.get(step.id)
        if (phase is None or step.kind != "command" or step.seconds != 300
                or step.cwd != paths.work or step.parser != "minitest"
                or step.argv != packaged_ruby_argv(paths, phase, deadline=deadline)
                or step.env != tuple(sorted(native_phase_environment(paths, platform, phase, ruby=True).items()))
                or step.expected_tests != len(ruby_expected_ids(paths.source, step.id))):
            raise VerificationError("PACKAGED_RUBY_GATE_CONTRACT")
        bounded = dataclasses.replace(step, argv=packaged_ruby_argv(paths, phase, deadline=cutoff))
        check_clock(cutoff)
        session.ensure_idle(deadline=cutoff)
        check_capacity(paths.work, 64 * 1024**2)
        wheel_sha256 = None
        if step.id == "ruby-packaged-capture-wheel":
            prefix = paths.work / "ruby-negative"
            identity = negative_prefix_custody(paths, session, deadline=cutoff)
            with os.scandir(prefix) as entries:
                if next(entries, None) is not None:
                    raise VerificationError("NEGATIVE_PREFIX_GATE_CONTRACT")
            wheel_sha256 = checks.inspect_project_wheel(paths.wheel, paths.source, deadline=cutoff)["sha256"]
            pip = (paths.wheel_python, "-I", "-B", "-m", "pip", "install", "--ignore-installed", "--no-index",
                   "--no-deps", "--no-compile", "--no-cache-dir", "--prefix", prefix, paths.wheel)
            original_native_capture(session, pip, paths, rows, "negative-prefix-install", deadline=cutoff,
                                    seconds=300, env=dict(bounded.env), output_limit=8 * 1024**2)
            details["negative_prefix"] = inspect_negative_ruby_prefix(paths, session, checks, wheel_sha256, deadline=cutoff)
            if negative_prefix_custody(paths, session, deadline=cutoff) != identity:
                raise VerificationError("NEGATIVE_PREFIX_CUSTODY_CHANGED")
            rows[-1]["status"] = "PASS"
        value = original_native_capture(session, bounded.argv, paths, rows, "actual-packaged-capture",
                                        deadline=cutoff, seconds=300, env=dict(bounded.env), output_limit=8 * 1024**2)
        parsed = parse_capture(bounded, value, paths, platform, checks, deadline=cutoff)
        if wheel_sha256 is not None:
            # Local task/child closure allowed the suite's own mutations. Only
            # now does genuine OUTER Session finality permit root reinspection.
            after = inspect_negative_ruby_prefix(paths, session, checks, wheel_sha256, deadline=cutoff)
            if after != details["negative_prefix"]:
                raise VerificationError("NEGATIVE_PREFIX_NOT_RESTORED")
            dispose_negative_ruby_prefix(paths, session, identity, deadline=cutoff)
            details["negative_prefix"]["removed_after_outer_finality"] = True
        rows[-1].update(status="PASS", completed=parsed.details["completed"])
        details.update(tests=parsed.details["tests"], completed=parsed.details["completed"],
                       origin_scope={"outer": "measured-loaded-methods", "custodian": "genuine-fixed-spawn",
                                     "keeper": "source-bound-by-fixed-custodian", "child_local_measurement": False})
        check_clock(cutoff)
        return CheckResult(True, details)
    except BaseException as exc:
        if rows and rows[-1]["status"] in {"RUNNING", "FINALIZED"}:
            rows[-1]["status"] = "FAIL"
        details["failure"] = error_details(exc)
        return CheckResult(False, details, exc.code if isinstance(exc, VerificationError) else "PACKAGED_RUBY_GATE_FAILURE")


def perform_step(step: Step, paths: Paths, session, checks, inventory: dict,
                 platform: str, *, deadline: float, native_abi: NativeABIState | None = None) -> CheckResult:
    if step.id in {"native-process-abi-source", "native-process-abi-wheel"}:
        return perform_native_abi_gate(step, paths, session, checks, platform, native_abi, deadline=deadline)
    if step.id in {*COMPATIBILITY_SOURCE_GATES, *COMPATIBILITY_WHEEL_GATES}:
        return perform_compatibility_gate(step, paths, session, checks, platform, native_abi, deadline=deadline)
    if step.id in PACKAGED_RUBY_GATES:
        return perform_packaged_ruby_gate(step, paths, session, checks, platform, deadline=deadline)
    if step.id in {"native-profile-source", "native-profile-wheel"}:
        # Compute the native gate's absolute endpoint before any preparation,
        # census, capacity check or package inspection can consume its budget.
        return perform_native_gate(step, paths, session, checks, platform, deadline=deadline)
    if step.id in {"python-full", "python-wheel"}:
        return perform_python_gate(step, paths, session, checks, platform, deadline=deadline)
    if step.id in PARTITIONED_RUBY_GATES:
        return perform_partitioned_ruby_gate(step, paths, session, checks, platform, native_abi, deadline=deadline)
    check_clock(deadline)
    session.ensure_idle()
    # Allow room for this gate's finite install/build rather than filling the VM.
    check_capacity(paths.work, 1024**3 if step.id in {"bundle-install", "wheel-build"} else 64 * 1024**2)
    if step.kind == "command":
        value = session.run(list(step.argv), cwd=step.cwd, env=dict(step.env), seconds=step.seconds,
                            output_limit=(16 if "install" in step.id or step.id == "source-dependencies" else 8) * 1024**2,
                            cpu_seconds=300 if step.id in {"bundle-install", "wheel-build", "python-full"} else 180,
                            profile="python-full" if platform == "linux" and step.id == "python-full" else "ordinary")
        if not value.ok:
            return CheckResult(False, failure_details(value, step, paths, checks=checks, deadline=deadline, platform=platform),
                               "COMMAND_EXIT_OR_FINALITY")
        try:
            return parse_capture(step, value, paths, platform, checks, deadline=deadline)
        except VerificationError as exc:
            return CheckResult(False, failure_details(value, step, paths, checks=checks, deadline=deadline, platform=platform), exc.code)
    if step.kind != "inspection":
        raise VerificationError("UNKNOWN_GATE_KIND")
    details = {}
    if step.id in {"source-copy", "wheel-copy"}:
        destination = paths.work / ("source-build" if step.id == "source-copy" else "wheel-build")
        copy_build(paths.source, destination, inventory, session.uid, session.gid, deadline=deadline)
        details = {"files": len(inventory)}
    elif step.id == "source-freeze":
        verify_source(paths.work / "source-build", inventory, generated=True, deadline=deadline)
        # Seal all installed code AND root-owned parent names before any test.
        for name in ("source-build", "source-venv", "bundler", "bundle"):
            current = paths.work / name
            links = (current, *session.tool_prefixes) if name != "source-build" else ()
            freeze_tree(current, deadline=deadline, link_roots=links)
        details = inspect_editable(paths, deadline=deadline)
    elif step.id == "wheel-inspect":
        freeze_tree(paths.work / "wheels", deadline=deadline)
        if list((paths.work / "wheels").iterdir()) != [paths.wheel]:
            raise VerificationError("WHEEL_OUTPUT_INVENTORY")
        details = checks.inspect_project_wheel(paths.wheel, paths.source, deadline=deadline)
    elif step.id == "wheel-freeze":
        current = paths.work / "wheel-venv"
        freeze_tree(current, deadline=deadline, link_roots=(current, *session.tool_prefixes))
    elif step.id == "wheel-consumer":
        details = checks.inspect_wheel_consumer(paths.work / "checks/wheel-consumer", paths.source, deadline=deadline)
    elif step.id == "source-integrity":
        verify_source(paths.source, inventory, deadline=deadline)
        verify_source(paths.work / "source-build", inventory, generated=True, deadline=deadline)
        verify_source(paths.work / "wheel-build", inventory, generated=True, deadline=deadline)
        details = {"files": len(inventory), "golden_and_build_copies": True}
    else:
        raise VerificationError("UNIMPLEMENTED_INSPECTION")
    check_clock(deadline)
    return CheckResult(True, details)


def error_details(exc: BaseException) -> dict:
    frames = traceback.extract_tb(exc.__traceback__)
    details = {"error": exc.code if isinstance(exc, VerificationError) else "CONTROLLER_FAILURE",
               "exception": type(exc).__name__,
               "location": [Path(frames[-1].filename).name, frames[-1].lineno] if frames else []}
    # Only an exact trusted controller filename supplies this extra callsite;
    # never publish absolute paths or trust an unrelated matching basename.
    own_frames = [frame for frame in frames if frame.filename == __file__]
    if own_frames:
        details["controller_location"] = ["verify_ci.py", own_frames[-1].lineno]
    if isinstance(exc, OSError):
        try:
            if type(exc.errno) is int and 0 <= exc.errno <= 4095:
                details["errno"] = exc.errno
            context = getattr(exc, "_mrk_provider_stat", None)
            if type(context) is tuple and len(context) == 4:
                role, prefix_index, node_index, components = context
                if (type(role) is str and role in {"python", "ruby", "jdk", "python312", "python313", "python314", "unbound"}
                        and type(prefix_index) is int and 0 <= prefix_index < 16
                        and type(node_index) is int and 1 <= node_index <= 100000):
                    note = {"operation": "provider-stat", "runtime_role": role,
                            "prefix_index": prefix_index, "node_index": node_index}
                    if (type(components) is tuple and len(components) <= 32
                            and all(type(part) is str and part not in {".", ".."}
                                    and re.fullmatch(r"[A-Za-z0-9_.+@-]{1,128}", part) for part in components)
                            and sum(map(len, components)) <= 1024):
                        note["relative_components"] = list(components)
                    else:
                        note["relative_components_omitted"] = True
                    details["provider_stat"] = note
        except BaseException:
            pass  # No diagnostic/property/formatting error may mask the real OSError.
    return details


def publish_summary(path: Path, report: dict, *, runner_temp: Path, deadline: float) -> None:
    check_clock(deadline)
    if (path.resolve(strict=True) != path or not path.is_relative_to(runner_temp)
            or not re.fullmatch(r"step_summary_[A-Za-z0-9_-]+", path.name)):
        raise VerificationError("SUMMARY_DESTINATION")
    encoded = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > 768 * 1024:
        raise VerificationError("PUBLIC_SUMMARY_BOUND")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        check_clock(deadline)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128 * 1024:
            raise VerificationError("SUMMARY_FILE_STATE")
        text = b"## Mobile Release Kit isolated verification\n\n```json\n" + encoded + b"\n```\n"
        pending = memoryview(text)
        while pending:
            check_clock(deadline)
            count = os.write(fd, pending[:65536])
            if not 0 < count <= min(len(pending), 65536):
                raise VerificationError("SUMMARY_SHORT_WRITE")
            pending = pending[count:]
        os.fsync(fd)
        check_clock(deadline)
    finally:
        close_owned(fd)
    check_clock(deadline)
    # Only this sanitized report, never raw private captures, enters job logs.
    print("MRK_CI_RESULT=" + encoded.decode("ascii"), flush=True)
    check_clock(deadline)


def finalize_report(report: dict, session, *, summary: Path | None, runner_temp: Path | None,
                    start: float, deadline: float) -> int:
    """Final close, publication and timer restoration cannot turn failure green."""
    def fail(exc: BaseException, *, cleanup: bool = False) -> None:
        report["ok"] = False
        if cleanup:
            report["cleanup_errors"].append(error_details(exc))
        elif "error" not in report:
            report.update(error_details(exc))

    try:
        if session is not None:
            try:
                # Keep the original independent alarm during final publication.
                session.close(keep_timer=True)
                check_clock(deadline)
            except BaseException as exc:
                fail(exc, cleanup=True)
            report["finality"] = session.domain_finality
            report["persisted_capture_bytes"] = session.persisted_bytes
            if session.domain_finality is not True or session.failure is not None or session.cleanup_errors:
                report["cleanup_errors"].append({"session_cleanup_error_count": len(session.cleanup_errors)})
                report["ok"] = False
        elif report["ok"]:
            raise VerificationError("SUCCESS_WITHOUT_ORIGINAL_SESSION")
        report["seconds"] = round(time.monotonic() - start, 3)
        if summary is None or runner_temp is None:
            raise VerificationError("NO_SAFE_SUMMARY_DESTINATION")
        publish_summary(summary, report, runner_temp=runner_temp, deadline=deadline)
    except BaseException as exc:
        fail(exc)
        print("MRK_CI_PUBLICATION_FAILED=" + json.dumps(error_details(exc), sort_keys=True), flush=True)
    finally:
        if session is not None:
            try:
                session.finish()
            except BaseException as exc:
                fail(exc, cleanup=True)
                print("MRK_CI_FINAL_CLEANUP_FAILED=" + json.dumps(error_details(exc), sort_keys=True), flush=True)
            if session.failure is not None or session.cleanup_errors:
                report["ok"] = False
        try:
            check_clock(deadline)
        except BaseException as exc:
            fail(exc)
            print("MRK_CI_FINAL_DEADLINE_FAILED", flush=True)
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--platform", choices=("linux", "macos"), required=True)
    for name in ("source", "python", "ruby", "runner-home", "runner-temp", "summary",
                 "python-312", "python-313", "python-314"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("commit", "run-id", "run-attempt", "image"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--java-home", type=Path)
    args = parser.parse_args(argv)
    start = time.monotonic()
    deadline = start + AGGREGATE_SECONDS
    session = None
    report = {"schema": 1, "ok": False, "platform": args.platform, "rows": [], "cleanup_errors": []}
    runner_temp = summary = None
    try:
        if (os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.dont_write_bytecode
                or sys.version_info[:2] != (3, 11)
                or sys.platform != {"linux": "linux", "macos": "darwin"}[args.platform]):
            raise VerificationError("ROOT_HOSTED_PYTHON_PLATFORM_REQUIRED")
        if (not re.fullmatch(r"[1-9][0-9]{0,19}", args.run_id)
                or not re.fullmatch(r"[1-9][0-9]{0,5}", args.run_attempt)
                or not re.fullmatch(r"[A-Za-z0-9_.+/-]{1,100}", args.image)
                or not re.fullmatch(r"[0-9a-f]{40}", args.commit)):
            raise VerificationError("HOSTED_RUN_BINDING")
        os.umask(0o077)
        checkout = canonical_directory(args.source)
        runner_home = canonical_directory(args.runner_home)
        runner_temp = canonical_directory(args.runner_temp)
        summary = args.summary.resolve(strict=True)
        python, ruby = args.python.resolve(strict=True), args.ruby.resolve(strict=True)
        if python != Path(sys.executable).resolve() or python.parent.name != "bin" or ruby.parent.name != "bin":
            raise VerificationError("TRUSTED_RUNTIME_BINDING")
        compatibility = []
        for line in ("312", "313", "314"):
            selected = getattr(args, "python_" + line)
            if not selected.is_absolute() or ".." in selected.parts:
                raise VerificationError("COMPATIBILITY_RUNTIME_BINDING")
            executable = selected.resolve(strict=True)
            info = executable.lstat()
            if executable.parent.name != "bin" or not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise VerificationError("COMPATIBILITY_RUNTIME_BINDING")
            compatibility.append((executable, canonical_directory(executable.parent.parent)))
        compatibility = tuple(compatibility)
        if (args.platform == "linux") != (args.java_home is not None):
            raise VerificationError("PLATFORM_TOOL_CONTRACT")
        java = canonical_directory(args.java_home) if args.java_home else None
        prefixes = tuple(dict.fromkeys((Path(sys.base_prefix).resolve(strict=True), ruby.parent.parent,
                                       *((java,) if java else ()), *(pair[1] for pair in compatibility))))
        parent = Path("/tmp" if args.platform == "linux" else "/private/tmp")
        check_capacity(parent, 256 * 1024**2)
        root = Path(tempfile.mkdtemp(prefix=f"mrk-ci-{args.run_id}-{args.run_attempt}-", dir=parent))
        os.chmod(root, 0o755)
        inventory, source_binding = snapshot_source(checkout, root / "source", args.commit, deadline=deadline)
        report.update(source=source_binding, run_id=args.run_id, run_attempt=args.run_attempt, image=args.image)
        directory = root / "source/.github/scripts"
        sandbox = _module(directory, "ci_sandbox")
        prepare = _module(directory, "ci_prepare")
        checks = _module(directory, "ci_checks")
        session = sandbox.Session("linux" if args.platform == "linux" else "darwin", root,
                                  python=python, ruby=ruby, runner_home=runner_home, runner_temp=runner_temp,
                                  tool_prefixes=prefixes, compatibility_runtimes=compatibility, deadline=deadline)
        paths = Paths(root / "source", session.work, root / "inputs", python, ruby, java_home=java,
                      compatibility_runtimes=compatibility)
        steps = catalog(paths, args.platform, deadline=deadline)
        report["rows"] = [{"id": step.id, "status": "UNEXECUTED"} for step in steps]
        report["phase"] = "input-preparation"
        produced = prepare.prepare_inputs(source_root=paths.source, destination=paths.inputs,
                                          platform=args.platform, deadline=deadline)
        report["inputs"] = validate_inputs(paths.inputs, produced, deadline=deadline)
        report["phase"] = "native-admission"
        session.admit()
        report["admission"] = session.admission_results
        report["phase"] = "work-layout"
        make_layout(paths, session, deadline=deadline)
        report["phase"] = "tool-evidence"
        report["tools"] = tool_evidence(paths, session, args.platform, deadline=deadline)
        report["phase"] = "product-gates"
        native_abi = NativeABIState()

        def perform(step):
            print("MRK_CI_GATE=" + step.id, flush=True)
            return perform_step(step, paths, session, checks, inventory, args.platform,
                                deadline=deadline, native_abi=native_abi)

        result = execute_pipeline(steps, perform, platform=args.platform)
        report["rows"] = list(result.rows)
        if not result.ok:
            raise VerificationError(result.error or "PIPELINE_FAILED")
        session.ensure_idle()
        # The checkout has never been a project execution or mutable output root.
        git = ("/usr/bin/git", "-c", f"safe.directory={checkout}", "-C", str(checkout))
        if trusted_command((*git, "status", "--porcelain=v1", "--untracked-files=all"), deadline=deadline):
            raise VerificationError("ORIGINAL_CHECKOUT_CHANGED")
        if trusted_command((*git, "rev-parse", "HEAD"), deadline=deadline).strip().decode() != args.commit:
            raise VerificationError("ORIGINAL_CHECKOUT_COMMIT_CHANGED")
        # No walk/removal until all actual subject writers are gone. Python's
        # descriptor-relative rmtree never follows a project-created symlink.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise VerificationError("SAFE_DISPOSAL_UNAVAILABLE")
        for disposable in (paths.work, paths.inputs):
            check_clock(deadline)
            shutil.rmtree(disposable)
        report["disposal"] = {"work_and_inputs_removed": True, "private_control": "VM-disposal"}
        check_clock(deadline)
        report["ok"] = True
    except BaseException as exc:
        report.update(error_details(exc))
        report["ok"] = False
        if session is not None:
            session.fail(report["error"])
            report["admission"] = session.admission_results
    return finalize_report(report, session, summary=summary, runner_temp=runner_temp,
                           start=start, deadline=deadline)


if __name__ == "__main__":
    raise SystemExit(main())
