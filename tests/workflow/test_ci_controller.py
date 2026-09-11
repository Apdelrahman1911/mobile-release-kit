"""Pure coordinator regressions, not hosted isolation or native-test evidence.

Filesystem cases use only task-owned temporary data; root chown is always an
inert double and chmod is either forbidden or confined to enumerated fixtures.
Finalization uses an inert Session double, never the real owner or a process.
Ruby completion text is synthetic parser input, never a native test receipt.
"""
from __future__ import annotations

import base64
import copy
from contextlib import nullcontext, redirect_stdout
import csv
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from .test_ci_verification import ROOT, controller_module, fixture_paths


def report_fixture(ok=True):
    result = {"schema": 1, "ok": ok, "cleanup_errors": [],
              "rows": [{"id": "source-integrity", "status": "PASS" if ok else "FAIL"}]}
    if not ok:
        result["error"] = "UPSTREAM_FIXTURE_FAILURE"
    return result


def session_fixture(events, *, close_action=None, finish_action=None):
    """Only the finalizer's tiny result contract; no Session construction/import."""
    session = SimpleNamespace(domain_finality=False, persisted_bytes=0, failure=None, cleanup_errors=[])

    def close(*, keep_timer):
        events.append(("close", keep_timer))
        session.domain_finality, session.persisted_bytes = True, 37
        if close_action is not None:
            close_action(session)

    def finish():
        events.append(("finish",))
        if finish_action is not None:
            finish_action(session)

    session.close, session.finish = close, finish
    return session


def native_capture_fixture(stdout=b"", stderr=b"", **changes):
    """Data only: never a CapturedRun constructor, child, FD or live receipt."""
    fields = dict(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                  domain_finality=True, timed_out=False, cancelled=False, primary_error=None, cleanup_errors=(),
                  stdout=stdout, stderr=stderr, persisted=(len(stdout), len(stderr)), duration=.01)
    fields.update(changes)
    return SimpleNamespace(**fields)


def python_runtime_fixture(paths, *, minor=12, phase="source"):
    executable, prefix = paths.compatibility_runtimes[minor - 12]
    package = (paths.work / "source-build/src/mobile_release" if phase == "source"
               else paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
    return {"schema": "mrk-native-python-runtime-v1", "phase": phase, "implementation": "cpython",
            "version": [3, minor, 1], "executable": str(executable), "base_prefix": str(prefix),
            "base_exec_prefix": str(prefix), "prefix": str(prefix), "exec_prefix": str(prefix), "isolated": True,
            "package_root": str(package), "origins": {
                "mobile_release": str(package / "__init__.py"),
                "mobile_release._native_process": str(package / "_native_process.py"),
            }}


def runtime_wire(controller, data):
    return (controller.NATIVE_PYTHON_RUNTIME_PREFIX + json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def minitest_fixture(identifiers):
    """Synthetic completion text, never an invocation or a passing receipt."""
    text = "".join(identifier + " = 0.00 s = .\n" for identifier in identifiers)
    return (text + f"\n{len(identifiers)} runs, {3 * len(identifiers)} assertions, 0 failures, 0 errors, 0 skips\n").encode("ascii")


_RUBY_PARTITION_FIXTURES = (
    ("ruby-native-owner", "test_native_upload_process.rb", 52, 44, 120, None),
    ("ruby-native-capture", "test_native_upload_validation.rb", 21, 17, 180, "NativeUploadValidationTest"),
    ("ruby-ios_upload_validation", "test_ios_upload_validation.rb", 32, 23, 300, "IosUploadValidationTest"),
    ("ruby-android_upload_validation", "test_android_upload_validation.rb", 32, 23, 300, "AndroidUploadValidationTest"),
)


class NativeProcessCIIntegrationTests(unittest.TestCase):
    def _ruby_partition_fixture(self, platform="linux", *, gate="ruby-native-owner"):
        """Synthetic inventories/original capture doubles; no Ruby DATA or execution."""
        controller = controller_module()
        paths = fixture_paths(controller)
        _gate, filename, total, healthy_count, seconds, owner = next(row for row in _RUBY_PARTITION_FIXTURES if row[0] == gate)
        healthy = tuple(f"{owner or 'HealthyFixture'}#test_{number:02d}" for number in range(healthy_count))
        poison = (controller.RUBY_OWNER_POISON_PARTITIONS if gate == "ruby-native-owner" else
                  controller.RUBY_NATIVE_CAPTURE_POISON_PARTITIONS if gate == "ruby-native-capture" else
                  tuple((mode, owner + "#" + method) for mode, method in controller.RUBY_PROBE_POISON_PARTITIONS))
        partitions = {"healthy": healthy, **{name: (identifier,)
                      for name, identifier in poison}}
        complete = tuple(sorted(identifier for ids in partitions.values() for identifier in ids))
        step = controller.Step(gate, argv=(*paths.bundle, "exec", str(paths.ruby),
            str(paths.source / "tests/workflow" / filename), "--verbose"),
            cwd=paths.work, env=controller.environment(paths, platform), seconds=seconds, parser="minitest", expected_tests=total)
        state = controller.NativeABIState(phases={"source": tuple(native_capture_fixture() for _ in range(3))})
        rig = SimpleNamespace(controller=controller, paths=paths, platform=platform, complete=complete,
            partitions=partitions, step=step, state=state, clock=10.0, events=[], captures=[], parsed=[], changes={},
            header_error=None, header_advance=0.0, run_error=None, run_advance=10.0, idle_error_after=None,
            gate=gate, seconds=seconds, total=total, healthy_count=healthy_count)

        def run(argv, **options):
            index = len(rig.captures)
            partition = tuple(partitions)[index]
            rig.events.append(("run", partition, tuple(argv), options))
            if rig.run_error is not None:
                raise rig.run_error
            capture = native_capture_fixture(**{"stdout": minitest_fixture(partitions[partition]),
                                                **rig.changes.get(partition, {})})
            rig.captures.append(capture)
            rig.clock += rig.run_advance
            return capture

        def idle(*, deadline):
            rig.events.append(("idle", deadline))
            if rig.idle_error_after is not None and len(rig.captures) >= rig.idle_error_after:
                raise controller.VerificationError("RUBY_PARTITION_NOT_IDLE")

        rig.session = SimpleNamespace(run=run, ensure_idle=idle)
        return rig

    def _perform_ruby_partition_fixture(self, rig, *, step=None, deadline=1000.0):
        controller = rig.controller
        original_parser = controller.parse_capture

        def header(paths, session, platform, state, *, deadline):
            self.assertEqual(paths, rig.paths)
            self.assertIs(session, rig.session)
            self.assertEqual(platform, rig.platform)
            self.assertIs(state, rig.state)
            rig.events.append(("header", deadline))
            rig.clock += rig.header_advance
            if rig.header_error is not None:
                raise rig.header_error

        def parse(part, capture, *args, **kwargs):
            rig.parsed.append(capture)
            return original_parser(part, capture, *args, **kwargs)

        with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: rig.clock), check_capacity=Mock(),
                require_retained_header=header, ruby_expected_ids=Mock(return_value=rig.complete),
                parse_capture=Mock(side_effect=parse)):
            return controller.perform_step(step or rig.step, rig.paths, rig.session, SimpleNamespace(), {}, rig.platform,
                                           deadline=deadline, native_abi=rig.state)

    def test_ruby_owner_capture_partitions_are_source_bound_exact_and_cannot_pool(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        literals = (
            ("custodian-preoffer-close", "NativeUploadRoleTest#test_native_custodian_preoffer_close_fault_cannot_claim_settled_failure"),
            ("custodian-postoffer-tail", "NativeUploadRoleTest#test_native_custodian_postoffer_tail_fault_downgrades_intended_two_to_unknown_one"),
            ("keeper-preoffer-close", "NativeUploadRoleTest#test_native_keeper_preoffer_close_fault_preserves_v_receipt_but_not_cleanup"),
            ("keeper-postoffer-tail", "NativeUploadRoleTest#test_native_keeper_postoffer_tail_fault_cannot_launder_confirmed_cleanup"),
            ("custodian-before-exit-arm", "NativeUploadRoleTest#test_native_custodian_before_exit_arm_callback_rejects_saved_settled_failure"),
            ("custodian-after-exit-arm", "NativeUploadRoleTest#test_native_custodian_after_exit_arm_signal_cannot_accept_saved_settled_failure"),
            ("keeper-before-exit-arm", "NativeUploadRoleTest#test_native_keeper_before_exit_arm_callback_invalidates_saved_release"),
            ("keeper-after-exit-arm", "NativeUploadRoleTest#test_native_keeper_after_exit_arm_signal_cannot_accept_saved_release"),
        )
        self.assertEqual(controller.RUBY_OWNER_POISON_PARTITIONS, literals)
        healthy = tuple(f"HealthyFixture#test_{number:02d}" for number in range(44))
        complete = tuple(sorted(healthy + tuple(identifier for _, identifier in literals)))
        with patch.object(controller, "ruby_expected_ids", return_value=complete) as source, \
                patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            self.assertEqual(controller.ruby_capture_ids(ROOT, "ruby-native-owner", "all", deadline=130.0), complete)
            selected = []
            for partition, expected in (("healthy", healthy), *((name, (identifier,)) for name, identifier in literals)):
                self.assertEqual(controller.ruby_capture_ids(ROOT, "ruby-native-owner", partition, deadline=130.0), expected)
                argv = controller.ruby_capture_argv(paths, "ruby-native-owner", partition, deadline=130.0)
                self.assertEqual(argv, (*paths.bundle, "exec", str(paths.ruby),
                    str(paths.source / "tests/workflow/test_native_upload_process.rb"), "--verbose", "--name",
                    "/\\A(?:" + "|".join(expected) + ")\\z/"))
                selected.extend(expected)
            self.assertEqual(tuple(sorted(selected)), complete)
            self.assertEqual(len(set(selected)), 52)
            self.assertTrue(all(call.args == (ROOT, "ruby-native-owner") and not call.kwargs
                                for call in source.call_args_list))
            for partition in ("all", "pooled", "/.*/", literals[0][1], None, True, [], {}):
                with self.subTest(rejected=partition), self.assertRaises(controller.VerificationError):
                    controller.ruby_capture_argv(paths, "ruby-native-owner", partition, deadline=130.0)
        for mutated in (complete[:-1], tuple(sorted((*complete, complete[0]))), tuple(reversed(complete)), list(complete),
                        tuple(sorted(healthy + tuple(identifier for _, identifier in literals[1:]) + ("Other#test_replacement",))),
                        tuple(sorted(complete[1:] + ("Foreign#test_.*",)))):
            with patch.object(controller, "ruby_expected_ids", return_value=mutated), \
                    self.assertRaises(controller.VerificationError):
                controller.ruby_capture_ids(ROOT, "ruby-native-owner", "healthy")

    def test_ruby_owner_gate_retains_nine_originals_and_exact_filters_after_original_header(self):
        for platform, deadline, cutoff in (("linux", 1000.0, 130.0), ("macos", 110.0, 110.0)):
            with self.subTest(platform=platform):
                rig = self._ruby_partition_fixture(platform)
                result = self._perform_ruby_partition_fixture(rig, deadline=deadline)
                self.assertTrue(result.ok, result)
                rows = result.details["partitions"]
                self.assertEqual([row["partition"] for row in rows], list(rig.partitions))
                self.assertEqual([row["status"] for row in rows], ["PASS"] * 9)
                self.assertEqual([row["tests"] for row in rows], [44, 1, 1, 1, 1, 1, 1, 1, 1])
                self.assertEqual((result.details["tests"], result.details["completed"]), (52, list(rig.complete)))
                self.assertNotIn("returncode", result.details)
                self.assertNotIn("summary", result.details)
                calls = [event for event in rig.events if event[0] == "run"]
                self.assertEqual(len(calls), 9)
                self.assertEqual([event for event in rig.events if event[0] == "header"], [("header", cutoff)])
                self.assertLess(rig.events.index(("header", cutoff)), rig.events.index(calls[0]))
                for index, (_, partition, argv, options) in enumerate(calls):
                    self.assertEqual(argv, (*rig.step.argv, "--name", "/\\A(?:" + "|".join(rig.partitions[partition]) + ")\\z/"))
                    self.assertEqual(options, {"cwd": rig.paths.work, "env": dict(rig.step.env), "seconds": 120,
                        "output_limit": 8 * 1024**2, "cpu_seconds": 180, "profile": "ordinary", "absolute_deadline": cutoff})
                    self.assertIs(rig.parsed[index], rig.captures[index])
                    self.assertEqual(rows[index]["capture"], rig.controller.capture_observations(rig.captures[index]))
                    position = rig.events.index(calls[index])
                    self.assertEqual(rig.events[position - 1], ("idle", cutoff))
                    self.assertEqual(rig.events[position + 1], ("idle", cutoff))

    def test_ruby_owner_gate_rejects_contract_header_and_partition_drift_before_capture(self):
        for fault in ("argv", "cwd", "environment", "kind", "parser", "seconds", "count", "partition",
                      "state", "phase", "source-finality", "header", "inventory", "pooled", "missing", "overlap"):
            with self.subTest(fault=fault):
                rig = self._ruby_partition_fixture()
                step = rig.step
                changes = {"argv": {"argv": (*step.argv, "--name", "/.*/")}, "cwd": {"cwd": rig.paths.source},
                    "environment": {"env": ()}, "kind": {"kind": "inspection"}, "parser": {"parser": "exit"},
                    "seconds": {"seconds": 121}, "count": {"expected_tests": 51}, "partition": {"native_partition": "healthy"}}
                if fault in changes:
                    step = dataclasses.replace(step, **changes[fault])
                elif fault == "state":
                    rig.state = None
                elif fault == "phase":
                    rig.state.phases = {}
                elif fault == "source-finality":
                    rig.state.phases["source"][1].waited = False
                elif fault == "header":
                    rig.header_error = rig.controller.VerificationError("ORIGINAL_HEADER_REQUIRED")
                elif fault == "inventory":
                    rig.complete = rig.complete[:-1]
                first, second = tuple(rig.partitions)[1:3]
                inventories = {"all": rig.complete, **rig.partitions}
                if fault == "pooled":
                    inventories[first] += inventories[second]
                elif fault == "missing":
                    inventories[second] = ()
                elif fault == "overlap":
                    inventories["healthy"] = (*inventories["healthy"][:-1], inventories[first][0])
                selected = (patch.object(rig.controller, "ruby_capture_ids", side_effect=
                    lambda _source, _gate, partition, **_kwargs: inventories[partition]) if fault in {"pooled", "missing", "overlap"}
                    else nullcontext())
                with selected:
                    result = self._perform_ruby_partition_fixture(rig, step=step)
                self.assertFalse(result.ok)
                self.assertEqual(rig.captures, [])
                self.assertEqual([row["status"] for row in result.details["partitions"]], ["UNEXECUTED"] * 9)

    def test_ruby_owner_gate_stops_after_each_failed_original_and_never_renews_its_cutoff(self):
        for platform in ("linux", "macos"):
            for failed in range(9):
                for fault in ("exit", "wait", "stdout", "stderr", "domain", "timeout", "cancel", "primary", "cleanup",
                              "skip", "count", "wrong-id", "idle", "deadline"):
                    with self.subTest(platform=platform, failed=failed, fault=fault):
                        rig = self._ruby_partition_fixture(platform)
                        partition = tuple(rig.partitions)[failed]
                        fields = {"exit": {"returncode": 1}, "wait": {"waited": False},
                            "stdout": {"stdout_eof": False}, "stderr": {"stderr_eof": False}, "domain": {"domain_finality": False},
                            "timeout": {"timed_out": True}, "cancel": {"cancelled": True}, "primary": {"primary_error": "ORIGINAL_ERROR"},
                            "cleanup": {"cleanup_errors": ("ORIGINAL_CLOSE",)}}
                        if fault in fields:
                            rig.changes[partition] = fields[fault]
                        elif fault in {"skip", "count", "wrong-id"}:
                            output = minitest_fixture(rig.partitions[partition])
                            if fault == "skip":
                                output = output.replace(b"0 skips", b"1 skips")
                            elif fault == "count":
                                output = output.replace(f"{len(rig.partitions[partition])} runs".encode(), b"49 runs")
                            else:
                                output = output.replace(rig.partitions[partition][0].encode(), b"Foreign#test_not_the_required_case")
                            rig.changes[partition] = {"stdout": output}
                        elif fault == "idle":
                            rig.idle_error_after = failed + 1
                        else:
                            rig.run_advance = 121.0 / (failed + 1)
                        result = self._perform_ruby_partition_fixture(rig)
                        self.assertFalse(result.ok)
                        self.assertEqual(len(rig.captures), failed + 1)
                        rows = result.details["partitions"]
                        self.assertEqual([row["status"] for row in rows], ["PASS"] * failed + ["FAIL"] + ["UNEXECUTED"] * (8 - failed))
                        for index, capture in enumerate(rig.captures):
                            for name, value in rig.controller.capture_observations(capture).items():
                                self.assertEqual(rows[index]["capture"][name], value)
                        self.assertTrue(all(event[3]["absolute_deadline"] == 130.0 for event in rig.events if event[0] == "run"))
                        if fault == "deadline":
                            self.assertEqual(result.error, "AGGREGATE_DEADLINE")
        for fault in ("header-expiry", "final-union", "launch"):
            with self.subTest(fault=fault):
                rig = self._ruby_partition_fixture()
                reconciliations = []
                if fault == "header-expiry":
                    rig.header_advance = 120.0
                elif fault == "launch":
                    rig.run_error = OSError("PRIVATE_ORIGINAL_LAUNCH_ERROR")

                def late_sorted(values, *args, **kwargs):
                    result = sorted(values, *args, **kwargs)
                    if type(values) is list and tuple(result) == rig.complete:
                        reconciliations.append(True)
                        if len(reconciliations) == 2:
                            rig.clock = 130.0
                    return result

                with patch.object(rig.controller, "sorted", create=True, side_effect=late_sorted) if fault == "final-union" else nullcontext():
                    result = self._perform_ruby_partition_fixture(rig)
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "RUBY_PARTITION_GATE_FAILURE" if fault == "launch" else "AGGREGATE_DEADLINE")
                self.assertEqual(len(rig.captures), 9 if fault == "final-union" else 0)
                self.assertNotIn("PRIVATE_ORIGINAL_LAUNCH_ERROR", json.dumps(result.details))
                self.assertEqual([row["status"] for row in result.details["partitions"]],
                    ["PASS"] * 9 if fault == "final-union" else ["FAIL", *(["UNEXECUTED"] * 8)] if fault == "launch" else ["UNEXECUTED"] * 9)

    def test_ruby_partition_contracts_and_non_owner_filters_are_closed_and_class_qualified(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        literals = (
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
        native_literals = (
            ("native-setup-no-cleanup", "NativeUploadValidationTest#test_missing_native_cleanup_requires_eof_and_cannot_pass_the_production_oracle"),
            ("kill-native-setup", "NativeUploadValidationTest#test_hard_driver_loss_stops_all_previously_bound_native_roles"),
            ("native-order-cleanup-before-caller-interrupt", "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown"),
            ("native-order-cleanup-before-caller-system-exit", "NativeUploadValidationTest#test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown"),
        )
        self.assertEqual(controller.RUBY_PARTITION_CONTRACTS, _RUBY_PARTITION_FIXTURES)
        self.assertEqual(controller.PARTITIONED_RUBY_GATES, tuple(row[0] for row in _RUBY_PARTITION_FIXTURES))
        self.assertEqual(controller.RUBY_PROBE_POISON_PARTITIONS, literals)
        self.assertEqual(controller.RUBY_NATIVE_CAPTURE_POISON_PARTITIONS, native_literals)
        for gate, filename, total, healthy_count, _seconds, owner in _RUBY_PARTITION_FIXTURES[1:]:
            with self.subTest(gate=gate):
                healthy = tuple(f"{owner}#test_{number:02d}" for number in range(healthy_count))
                poison = (native_literals if gate == "ruby-native-capture" else
                          tuple((name, owner + "#" + method) for name, method in literals))
                complete = tuple(sorted(healthy + tuple(identifier for _name, identifier in poison)))
                with patch.object(controller, "ruby_expected_ids", return_value=complete) as source, \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                    self.assertEqual(controller.ruby_capture_ids(ROOT, gate, deadline=310.0), complete)
                    selected = []
                    for partition, expected in (("healthy", healthy), *((name, (identifier,)) for name, identifier in poison)):
                        self.assertEqual(controller.ruby_capture_ids(ROOT, gate, partition, deadline=310.0), expected)
                        self.assertEqual(controller.ruby_capture_argv(paths, gate, partition, deadline=310.0),
                            (*paths.bundle, "exec", str(paths.ruby), str(paths.source / "tests/workflow" / filename),
                             "--verbose", "--name", "/\\A(?:" + "|".join(expected) + ")\\z/"))
                        selected.extend(expected)
                    self.assertEqual(tuple(sorted(selected)), complete)
                    self.assertEqual(len(set(selected)), total)
                    self.assertTrue(all(call.args == (ROOT, gate) and not call.kwargs for call in source.call_args_list))
                    for rejected in ("all", "ownership-unknown", "custodian-preoffer-close", "/.*/", poison[0][1],
                                     poison[0][1].partition("#")[2], None, True, [], {}):
                        with self.subTest(rejected=rejected), self.assertRaises(controller.VerificationError):
                            controller.ruby_capture_argv(paths, gate, rejected, deadline=310.0)
                replaced = tuple(sorted(healthy + tuple(identifier for _name, identifier in poison[1:])
                                        + ("ForeignSuite#" + poison[0][1].partition("#")[2],)))
                with patch.object(controller, "ruby_expected_ids", return_value=replaced), \
                        self.assertRaisesRegex(controller.VerificationError, "RUBY_PARTITION_STATIC_INVENTORY"):
                    controller.ruby_capture_ids(ROOT, gate, "healthy")
        with patch.object(controller, "ruby_expected_ids", side_effect=AssertionError("unadmitted source lookup")):
            for gate in ("ruby-native-spawn", "ruby-packaged-capture-source", "ruby-custom", "test_ios_upload_validation.rb",
                         "/private/test.rb", None, True, [], {}):
                with self.subTest(gate=gate), self.assertRaisesRegex(controller.VerificationError, "RUBY_PARTITION_GATE_CONTRACT"):
                    controller.ruby_capture_argv(paths, gate, "healthy", deadline=310.0)

    def test_ruby_non_owner_gates_retain_originals_filters_and_their_unchanged_cutoffs(self):
        for gate, _filename, total, healthy_count, seconds, _owner in _RUBY_PARTITION_FIXTURES[1:]:
            for platform, deadline, cutoff in (("linux", 1000.0, 10.0 + seconds), ("macos", 180.0, 180.0)):
                with self.subTest(gate=gate, platform=platform):
                    rig = self._ruby_partition_fixture(platform, gate=gate)
                    result = self._perform_ruby_partition_fixture(rig, deadline=deadline)
                    self.assertTrue(result.ok, result)
                    rows = result.details["partitions"]
                    self.assertEqual([row["partition"] for row in rows], list(rig.partitions))
                    self.assertEqual([row["status"] for row in rows], ["PASS"] * len(rig.partitions))
                    self.assertEqual([row["tests"] for row in rows], [healthy_count] + [1] * (len(rig.partitions) - 1))
                    self.assertEqual((result.details["tests"], result.details["completed"]), (total, list(rig.complete)))
                    self.assertNotIn("returncode", result.details)
                    self.assertNotIn("summary", result.details)
                    calls = [event for event in rig.events if event[0] == "run"]
                    self.assertEqual(len(calls), len(rig.partitions))
                    self.assertEqual([event for event in rig.events if event[0] == "header"], [("header", cutoff)])
                    self.assertLess(rig.events.index(("header", cutoff)), rig.events.index(calls[0]))
                    for index, (_, partition, argv, options) in enumerate(calls):
                        self.assertEqual(argv, (*rig.step.argv, "--name", "/\\A(?:" + "|".join(rig.partitions[partition]) + ")\\z/"))
                        self.assertEqual(options, {"cwd": rig.paths.work, "env": dict(rig.step.env), "seconds": seconds,
                            "output_limit": 8 * 1024**2, "cpu_seconds": 180, "profile": "ordinary", "absolute_deadline": cutoff})
                        self.assertIs(rig.parsed[index], rig.captures[index])
                        self.assertEqual(rows[index]["capture"], rig.controller.capture_observations(rig.captures[index]))
                        position = rig.events.index(calls[index])
                        self.assertEqual(rig.events[position - 1], ("idle", cutoff))
                        self.assertEqual(rig.events[position + 1], ("idle", cutoff))

    def test_ruby_non_owner_failures_stop_later_originals_and_diagnostics_never_name_another_partition(self):
        for gate, _filename, _total, _healthy_count, seconds, _owner in _RUBY_PARTITION_FIXTURES[1:]:
            template = self._ruby_partition_fixture(gate=gate)
            for failed, partition in enumerate(template.partitions):
                for fault in ("original-failure", "foreign-class", "deadline"):
                    with self.subTest(gate=gate, partition=partition, fault=fault):
                        rig = self._ruby_partition_fixture(gate=gate)
                        selected = rig.partitions[partition][0]
                        other = next(identifier for name, identifiers in rig.partitions.items() if name != partition
                                     for identifier in identifiers)
                        if fault == "original-failure":
                            output = minitest_fixture(rig.partitions[partition]).replace(b"s = .", b"s = F", 1)
                            output = output.replace(b"0 failures", b"1 failures")
                            output += (f"1) Failure:\n{selected}:\nPRIVATE_CASE_MESSAGE\n"
                                       f"2) Failure:\n{other}:\nPRIVATE_OTHER_CASE\n").encode("ascii")
                            rig.changes[partition] = {"returncode": 1, "stdout": output}
                        elif fault == "foreign-class":
                            output = minitest_fixture(rig.partitions[partition]).replace(selected.encode("ascii"),
                                ("ForeignSuite#" + selected.partition("#")[2]).encode("ascii"), 1)
                            rig.changes[partition] = {"stdout": output}
                        else:
                            rig.run_advance = (seconds + 1.0) / (failed + 1)
                        result = self._perform_ruby_partition_fixture(rig)
                        self.assertFalse(result.ok)
                        self.assertEqual(len(rig.captures), failed + 1)
                        rows = result.details["partitions"]
                        self.assertEqual([row["status"] for row in rows], ["PASS"] * failed + ["FAIL"]
                            + ["UNEXECUTED"] * (len(rig.partitions) - failed - 1))
                        self.assertTrue(all(event[3]["absolute_deadline"] == 10.0 + seconds
                                            and event[3]["seconds"] == seconds for event in rig.events if event[0] == "run"))
                        details = rows[failed]["capture"]
                        for index, capture in enumerate(rig.captures):
                            for name, value in rig.controller.capture_observations(capture).items():
                                self.assertEqual(rows[index]["capture"][name], value)
                        if fault == "deadline":
                            self.assertEqual(result.error, "AGGREGATE_DEADLINE")
                        else:
                            self.assertEqual(details["minitest_structure"]["expected_count"], len(rig.partitions[partition]))
                            self.assertEqual(details["minitest_structure"]["missing_ids"], [selected])
                            self.assertEqual(details["minitest_structure"]["unknown_count"], int(fault == "foreign-class"))
                            self.assertEqual(details["failed_tests"], [selected] if fault == "original-failure" else [])
                            for private in (other, "PRIVATE_CASE_MESSAGE", "PRIVATE_OTHER_CASE", "ForeignSuite"):
                                self.assertNotIn(private, json.dumps(details))
            for changes in ({"seconds": 120}, {"expected_tests": 1}, {"native_partition": "healthy"},
                            {"argv": (*template.step.argv[:-2], "test_native_upload_process.rb", "--verbose")}):
                with self.subTest(gate=gate, changes=changes):
                    rig = self._ruby_partition_fixture(gate=gate)
                    result = self._perform_ruby_partition_fixture(rig, step=dataclasses.replace(rig.step, **changes))
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error, "RUBY_PARTITION_GATE_CONTRACT")
                    self.assertEqual(rig.captures, [])

    def test_compatibility_provider_bindings_are_closed_narrow_and_disjoint(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        self.assertIs(controller.compatibility_paths(paths), paths.compatibility_runtimes)
        pairs = paths.compatibility_runtimes
        invalid = ((), pairs[:2], pairs + pairs[:1], list(pairs), (pairs[0], pairs[0], pairs[2]),
                   ((pairs[0][0], Path("/fixture")), *pairs[1:]),
                   ((Path("relative/bin/python"), Path("relative")), *pairs[1:]),
                   ((Path("/fixture/alias/../python312/bin/python"), Path("/fixture/alias/../python312")), *pairs[1:]),
                   ((Path("/fixture/python/bin/python"), Path("/fixture/python")), *pairs[1:]),
                   ((Path("/fixture/python312/nested/bin/python"), Path("/fixture/python312/nested")), pairs[0], pairs[2]))
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(controller.VerificationError, "COMPATIBILITY_RUNTIME_BINDING"):
                controller.compatibility_paths(dataclasses.replace(paths, compatibility_runtimes=value))
        # Position alone is not runtime identity: swapped well-formed pairs
        # are rejected by actual version/executable metadata before controls.
        swapped = dataclasses.replace(paths, compatibility_runtimes=(pairs[1], pairs[0], pairs[2]))
        self.assertEqual(controller.compatibility_paths(swapped), swapped.compatibility_runtimes)

    def test_python_runtime_observation_rejects_foreign_lines_prefixes_and_product_origins(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        for phase in ("source", "wheel"):
            for minor in (12, 13, 14):
                data = python_runtime_fixture(paths, minor=minor, phase=phase)
                executable, prefix = paths.compatibility_runtimes[minor - 12]

                def check(value):
                    return controller.native_python_observation(runtime_wire(controller, value), paths,
                        minor=minor, phase=phase, executable=executable, prefix=prefix)

                self.assertEqual(check(data)["version"], f"3.{minor}.1")
                mutations = {"schema": 1, "phase": "wrong", "implementation": "pypy", "version": [3, minor + 1, 1],
                             "executable": str(paths.source_python), "base_prefix": "/fixture", "base_exec_prefix": "/fixture",
                             "prefix": str(paths.work / "wheel-venv"), "exec_prefix": "/foreign", "isolated": 1,
                             "package_root": str(paths.source / "src/mobile_release"), "origins": {}, "extra": True}
                for field, value in mutations.items():
                    with self.subTest(phase=phase, minor=minor, field=field), self.assertRaises(controller.VerificationError):
                        check({**data, field: value})
                for version in ([True, minor, 1], [3, float(minor), 1], [3, minor, True], [3, minor], "3.12.1"):
                    with self.assertRaises(controller.VerificationError):
                        check({**data, "version": version})
                for origins in ({"mobile_release": data["origins"]["mobile_release"]},
                                {**data["origins"], "mobile_release._native_process": "/private/substitute.py"},
                                {**data["origins"], "unrelated": "/private/unrelated.py"},
                                {**data["origins"], "mobile_release.nested.module": "/private/nested.py"}):
                    with self.assertRaises(controller.VerificationError):
                        check({**data, "origins": origins})

    def test_runtime_metadata_has_one_closed_ascii_record_and_no_duplicate_keys(self):
        controller = controller_module()
        raw = runtime_wire(controller, {"a": 1})
        self.assertEqual(controller.native_runtime_record(raw, controller.NATIVE_PYTHON_RUNTIME_PREFIX), {"a": 1})
        invalid = (raw[:-1], raw + b"\n", b"\n" + raw, b" " + raw, raw.replace(b"1", b"NaN"),
                   raw.replace(b'{"a":1}', b'{"a":1,"a":1}'), raw.replace(b'{"a":1}', b'[]'),
                   raw.replace(b"1", b"\xff"), raw.replace(b"1", b"\t1"), b"x" * 65537 + b"\n")
        for value in invalid:
            with self.subTest(value=value[:80]), self.assertRaises(controller.VerificationError):
                controller.native_runtime_record(value, controller.NATIVE_PYTHON_RUNTIME_PREFIX)

    def test_native_capture_keeps_original_facts_and_checks_idle_under_the_same_cutoff(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        facts = {"ok": False, "returncode": 1, "waited": False, "stdout_eof": False, "stderr_eof": False,
                 "domain_finality": False, "timed_out": True, "cancelled": True,
                 "primary_error": "PRIVATE_ERROR", "cleanup_errors": ("PRIVATE_CLEANUP",)}
        for field, value in facts.items():
            result = native_capture_fixture(b"PRIVATE_OUTPUT", **{field: value})
            session = SimpleNamespace(run=Mock(return_value=result), ensure_idle=Mock())
            rows = []
            with patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)), \
                    self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                controller.original_native_capture(session, ("/fixed/ordinary",), paths, rows, "fixture",
                    deadline=12.0, seconds=120, env={})
            self.assertEqual(session.ensure_idle.call_count, 2)
            self.assertTrue(all(call.kwargs == {"deadline": 12.0} for call in session.ensure_idle.call_args_list))
            self.assertEqual(session.run.call_args.kwargs["absolute_deadline"], 12.0)
            self.assertEqual(session.run.call_args.kwargs["profile"], "ordinary")
            self.assertEqual(rows[0]["status"], "FAIL")
            self.assertEqual(rows[0]["capture"]["stdout_bytes"], len(result.stdout))
            self.assertNotIn("PRIVATE", json.dumps(rows))
        first, second = native_capture_fixture(b"one"), native_capture_fixture(b"two")
        session = SimpleNamespace(run=Mock(side_effect=[first, second]), ensure_idle=Mock())
        rows = []
        with patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
            originals = [controller.original_native_capture(session, ("/fixed/ordinary",), paths, rows, name,
                         deadline=12.0, seconds=120, env={}) for name in ("one", "two")]
        self.assertIs(originals[0], first)
        self.assertIs(originals[1], second)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["status"] == "FINALIZED" for row in rows))

    def test_compatibility_requires_matching_original_declaration_before_any_control(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        ids = tuple(sorted("unit.test_native_process.NativeProcessCompatibilityTests." + name for name in (
            "test_native_public_api_atomic_duplication", "test_native_helper_and_validator_fd_maps",
            "test_native_exact_terminal_wait_receipts")))
        text = "".join(f"{identifier.rsplit('.', 1)[1]} ({identifier}) ... ok\n" for identifier in ids)
        text += "\nRan 3 tests in 0.001s\n\nOK\n"
        for phase in ("source", "wheel"):
            for fault in (None, "header", "declaration-finality", "origin", "abi", "skip", "control-finality", "expired"):
                with self.subTest(phase=phase, fault=fault):
                    clock, events = [10.0], []
                    python, prefix = paths.compatibility_runtimes[0]
                    data = python_runtime_fixture(paths, phase=phase)
                    if fault == "origin":
                        data["base_prefix"] = "/unselected/provider"
                    declaration = native_capture_fixture(b"actual-python-declaration\n", runtime_wire(controller, data),
                                                         waited=fault != "declaration-finality")
                    controls = native_capture_fixture(runtime_wire(controller, python_runtime_fixture(paths, phase=phase)),
                        text.replace("OK", "OK (skipped=1)").encode() if fault == "skip" else text.encode(),
                        domain_finality=fault != "control-finality")
                    originals = [declaration, controls]

                    def run(argv, **kwargs):
                        events.append(("capture", tuple(argv), kwargs))
                        value = originals[len([item for item in events if item[0] == "capture"]) - 1]
                        if fault == "expired":
                            clock[0] = 131.0
                        return value

                    def compare(header, actual, ruby):
                        events.append(("compare", header, actual, ruby))
                        if fault == "abi":
                            raise ValueError("PRIVATE_ABI_MISMATCH")

                    checks = SimpleNamespace(compare_abi_records=Mock(side_effect=compare),
                        native_compatibility_ids=Mock(return_value=ids))
                    session = SimpleNamespace(run=run, ensure_idle=Mock())
                    state = controller.NativeABIState(header_capture=native_capture_fixture(b"header\n"), phases={phase: (
                        native_capture_fixture(b"original-python\n"), native_capture_fixture(b"bundle\n"),
                        native_capture_fixture(b"default\n"))})
                    env = controller.native_phase_environment(paths, "linux", phase)
                    step = controller.Step(f"python-compat-312-{phase}", kind="python-compatibility", seconds=120,
                        cwd=paths.work, env=tuple(sorted(env.items())), argv=(str(python), "-I", "-S", "-B",
                        str(paths.source / "tests/workflow/run_native_profile_checks.py"), f"--compat-312-{phase}"))
                    with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: clock[0]),
                            check_capacity=Mock(), read_regular=Mock(return_value=b"immutable executable"),
                            require_retained_header=Mock(side_effect=controller.VerificationError("MISSING_HEADER")
                                                         if fault == "header" else None)):
                        result = controller.perform_compatibility_gate(step, paths, session, checks, "linux", state, deadline=1000.0)
                    self.assertEqual(result.ok, fault is None)
                    captures = [item for item in events if item[0] == "capture"]
                    expected_captures = 0 if fault == "header" else 1 if fault in {
                        "declaration-finality", "origin", "abi", "expired"} else 2
                    self.assertEqual(len(captures), expected_captures)
                    if len(captures) == 2:
                        self.assertEqual([item[0] for item in events], ["capture", "compare", "compare", "capture"])
                        self.assertEqual(captures[0][1][-1], f"--abi-312-{phase}")
                        self.assertEqual(captures[1][1][-1], f"--compat-312-{phase}")
                    self.assertTrue(all(item[2]["absolute_deadline"] == 130.0 for item in captures))
                    self.assertTrue(all(item[2]["profile"] == "ordinary" for item in captures))
                    self.assertNotIn("PRIVATE", json.dumps(result.details))

    def test_compiler_version_is_bound_to_actual_family_and_original_finality(self):
        controller = controller_module()
        gcc = native_capture_fixture(b"x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2) 13.3.0\nCopyright (C) 2023\n")
        clang = native_capture_fixture(b"Apple clang version 17.0.0 (clang-1700.6.3.2)\nTarget: arm64-apple-darwin\n")
        self.assertIn("13.3.0", controller.native_compiler_version(gcc, "linux"))
        self.assertIn("Apple clang", controller.native_compiler_version(clang, "macos"))
        for value, platform in ((gcc, "macos"), (clang, "linux"),
                                (native_capture_fixture(gcc.stdout.replace(b" 13.3.0\n", b" 14.3.0\n")), "linux"),
                                (native_capture_fixture(gcc.stdout, b"unexpected"), "linux"),
                                (native_capture_fixture(gcc.stdout, waited=False), "linux")):
            with self.assertRaises(controller.VerificationError):
                controller.native_compiler_version(value, platform)

    def test_abi_gate_compares_both_ruby_contexts_before_public_controls_and_retains_originals(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        public_ids = ("unit.test_native_process.NativeProcessCompatibilityTests.test_native_public_api_atomic_duplication",)
        ruby_ids = tuple(sorted((
            "NativeProcessSpawnTests#test_public_atomic_cloexec_duplication_uses_independent_creator_functions",
            "NativeProcessSpawnTests#test_public_spawn_containers_and_read_only_sigchld_admission",
        )))
        # Read actual fixed Ruby method definitions before mocking captures;
        # matching stale controller/test literals cannot authorize a renamed ID.
        for gate in ("ruby-native-public-source", "ruby-native-public-wheel"):
            self.assertEqual(controller.ruby_expected_ids(ROOT, gate), ruby_ids)
        for phase in ("source", "wheel"):
            for fault in (None, "phase-order", "header", "python-finality", "bundle-finality", "default-finality",
                          "bundle-abi", "default-abi", "python-control", "ruby-control", "expired"):
                with self.subTest(phase=phase, fault=fault):
                    if phase == "source" and fault == "phase-order":
                        continue
                    events, clock = [], [10.0]
                    python = paths.source_python if phase == "source" else paths.wheel_python
                    metadata = python_runtime_fixture(paths, phase=phase)
                    metadata.update(version=[3, 11, 1], executable=str(python),
                                    base_prefix=str(ROOT), base_exec_prefix=str(ROOT), prefix=str(ROOT), exec_prefix=str(ROOT))
                    declaration = native_capture_fixture(b"python ABI\n", runtime_wire(controller, metadata),
                                                         waited=fault != "python-finality")
                    bundle = native_capture_fixture(b"bundled Ruby ABI\n", b"bundle metadata\n",
                                                    waited=fault != "bundle-finality")
                    default = native_capture_fixture(b"default Ruby ABI\n", b"default metadata\n",
                                                     stderr_eof=fault != "default-finality")
                    public_text = (f"test_native_public_api_atomic_duplication ({public_ids[0]}) ... ok\n"
                                   "\nRan 1 test in 0.001s\n\nOK\n").encode()
                    public = native_capture_fixture(runtime_wire(controller, metadata), public_text,
                                                     domain_finality=fault != "python-control")
                    ruby_public = native_capture_fixture(minitest_fixture(ruby_ids),
                                                          waited=fault != "ruby-control")
                    originals = (declaration, bundle, default, public, ruby_public)
                    header = native_capture_fixture(b"original C header\n")
                    state = controller.NativeABIState(header_capture=header)
                    source_originals = tuple(native_capture_fixture(value) for value in (b"source Python", b"source bundle", b"source default"))
                    if phase == "wheel" and fault != "phase-order":
                        state.phases["source"] = source_originals

                    def run(argv, **kwargs):
                        events.append(("capture", tuple(argv), kwargs))
                        index = sum(item[0] == "capture" for item in events) - 1
                        if fault == "expired":
                            clock[0] = 311.0
                        return originals[index]

                    def compare(left, middle, right):
                        events.append(("compare", left, middle, right))
                        if (fault == "bundle-abi" and right == bundle.stdout
                                or fault == "default-abi" and right == default.stdout):
                            raise ValueError("PRIVATE_ABI_BODY")

                    session = SimpleNamespace(run=run, ensure_idle=Mock())
                    checks = SimpleNamespace(inspect_native_package=Mock(return_value={"bytes_bound": True}),
                        compare_abi_records=Mock(side_effect=compare), native_compatibility_ids=Mock(return_value=public_ids))
                    retain = Mock(return_value={"original": True})
                    with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: clock[0]),
                            sys=SimpleNamespace(base_prefix=str(ROOT)), check_capacity=Mock(),
                            read_regular=Mock(return_value=b"fixed immutable bytes"), retain_native_header=retain,
                            require_retained_header=Mock(side_effect=controller.VerificationError("HEADER_REQUIRED")
                                                         if fault == "header" else None),
                            native_ruby_observation=Mock(return_value={"actual_source_locations": True}),
                            ruby_expected_ids=Mock(return_value=ruby_ids)):
                        result = controller.perform_native_abi_gate(
                            controller.Step("native-process-abi-" + phase, kind="native-abi", seconds=300),
                            paths, session, checks, "linux", state, deadline=1000.0)
                    self.assertEqual(result.ok, fault is None)
                    captures = [item for item in events if item[0] == "capture"]
                    expected = {"phase-order": 0, "header": 0, "python-finality": 1, "bundle-finality": 2,
                                "default-finality": 3, "bundle-abi": 2, "default-abi": 3,
                                "python-control": 4, "ruby-control": 5, "expired": 1, None: 5}[fault]
                    self.assertEqual(len(captures), expected)
                    self.assertEqual(retain.call_count, int(phase == "source"))
                    self.assertTrue(all(item[2]["absolute_deadline"] == 310.0 and item[2]["profile"] == "ordinary"
                                        for item in captures))
                    if len(captures) >= 4:
                        self.assertEqual([item[0] for item in events[:6]],
                                         ["capture", "capture", "compare", "capture", "compare", "capture"])
                        self.assertEqual(captures[3][1][-1], "--public-311-" + phase)
                        self.assertEqual(events[2][1:], (header.stdout, declaration.stdout, bundle.stdout))
                        self.assertEqual(events[4][1:], (header.stdout, declaration.stdout, default.stdout))
                    if fault is None:
                        self.assertIs(state.header_capture, header)
                        self.assertIs(state.phases[phase][0], declaration)
                        self.assertIs(state.phases[phase][1], bundle)
                        self.assertIs(state.phases[phase][2], default)
                    else:
                        self.assertNotIn(phase, state.phases)
                    if phase == "wheel" and fault != "phase-order":
                        self.assertIs(state.phases["source"], source_originals)
                    self.assertNotIn("PRIVATE", json.dumps(result.details))

    def test_native_header_build_reads_and_freezes_only_after_original_compiler_finality(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        compiler = Path("/usr/bin/x86_64-linux-gnu-gcc-13")
        binary = paths.work / "native-process-abi/header-record"
        for fault in (None, "build-wait", "build-eof", "build-idle", "build-expiry", "header-finality"):
            with self.subTest(fault=fault):
                events, clock, stage = [], [1.0], [None]
                version = native_capture_fixture(b"x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0) 13.3.0\n")
                build = native_capture_fixture(waited=fault != "build-wait", stderr_eof=fault != "build-eof")
                header = native_capture_fixture(b"C header\n", waited=fault != "header-finality")
                results = iter((version, build, header))

                def run(argv, **kwargs):
                    value = next(results)
                    stage[0] = "version" if value is version else "build" if value is build else "header"
                    events.append(("capture", stage[0], tuple(argv), kwargs))
                    if stage[0] == "build" and fault == "build-expiry":
                        clock[0] = 21.0
                    return value

                def idle(**kwargs):
                    events.append(("idle", stage[0], kwargs))
                    if stage[0] == "build" and fault == "build-idle":
                        raise controller.VerificationError("SYNTHETIC_NOT_IDLE")

                def read(path, **_kwargs):
                    events.append(("read", path))
                    if path == binary:
                        self.assertIn(("idle", "build", {"deadline": 20.0}), events)
                        self.assertNotIn(fault, {"build-wait", "build-eof", "build-idle", "build-expiry"})
                    return b"immutable bytes"

                session = SimpleNamespace(run=run, ensure_idle=idle)
                state, rows = controller.NativeABIState(), []
                checks = SimpleNamespace(parse_abi_record=Mock(return_value={"family": "linux-glibc", "architecture": "x86_64"}))
                with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: clock[0]),
                        native_compiler_binding=Mock(return_value=(compiler, {"evidence": {}}, "a" * 64)),
                        read_regular=Mock(side_effect=read), freeze_tree=Mock(side_effect=lambda *_args, **_kwargs: events.append(("freeze",))),
                        os=SimpleNamespace(uname=lambda: SimpleNamespace(machine="x86_64"))), \
                        patch.object(Path, "iterdir", side_effect=[iter(()), iter((binary,))]), \
                        patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o555)):
                    if fault is None:
                        controller.retain_native_header(paths, session, checks, "linux", state, rows, deadline=20.0)
                    else:
                        with self.assertRaises(controller.VerificationError):
                            controller.retain_native_header(paths, session, checks, "linux", state, rows, deadline=20.0)
                captures = [item for item in events if item[0] == "capture"]
                self.assertTrue(all(item[3]["absolute_deadline"] == 20.0 and item[3]["profile"] == "ordinary"
                                    for item in captures))
                self.assertEqual(captures[0][2], (str(compiler), "--version"))
                self.assertEqual(captures[1][2], tuple(map(str, (compiler, "-D_GNU_SOURCE", "-std=c11", "-O2",
                    "-Wall", "-Wextra", "-Werror", paths.source / "tests/workflow/native_process_abi.c", "-o", binary))))
                self.assertEqual(captures[0][3]["env"], {"PATH": "/usr/bin:/bin"})
                self.assertEqual(captures[1][3]["env"], {"PATH": "/usr/bin:/bin"})
                if fault not in {None, "header-finality"}:
                    self.assertNotIn(("read", binary), events)
                    self.assertNotIn(("freeze",), events)
                    self.assertEqual(len(captures), 2)
                if fault is None:
                    self.assertIs(state.compiler_capture, version)
                    self.assertIs(state.build_capture, build)
                    self.assertIs(state.header_capture, header)
                else:
                    self.assertIsNone(state.header_capture)

    def test_packaged_ruby_cli_uses_exact_phase_roots_gemfile_and_class_selector(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        for phase in ("source", "wheel"):
            prefix = paths.source if phase == "source" else paths.work / "wheel-venv"
            tooling = paths.source / "fastlane" if phase == "source" else prefix / "share/mobile-release-kit/fastlane"
            selector = (r"/\APackagedRubyCaptureTest#/" if phase == "source" else
                        r"/\A(?:PackagedRubyCaptureTest|InstalledRubyCaptureMissingHelperTest)#/")
            expected = tuple(map(str, (*paths.bundle, "exec", paths.ruby,
                paths.source / "tests/workflow/test_installed_ruby_capture.rb", "--capture-phase", phase,
                "--capture-tooling-root", tooling, "--capture-prefix", prefix, "--capture-source-root", paths.source,
                "--capture-python", paths.source_python if phase == "source" else paths.wheel_python,
                *(("--capture-wheel", paths.wheel, "--negative-prefix", paths.work / "ruby-negative") if phase == "wheel" else ()),
                "--capture-deadline", "20.0", "--verbose", "--name", selector)))
            self.assertEqual(controller.packaged_ruby_argv(paths, phase, deadline=20.0), expected)
            env = controller.native_phase_environment(paths, "linux", phase, ruby=True)
            self.assertEqual(env["BUNDLE_GEMFILE"], str(tooling.parent / "Gemfile"))
            step = controller.Step("ruby-packaged-capture-" + phase, argv=expected, cwd=paths.work,
                                   env=tuple(sorted(env.items())), seconds=300, parser="minitest", expected_tests=1)
            changes = [("--negative-prefix", "/foreign"), ("--capture-prefix", "/foreign"),
                       ("--capture-deadline", "21.0"), ("--capture-tooling-root", str(tooling.parent)),
                       ("--name", "/.*/"), ("--capture-python", str(paths.python))]
            for flag, value in changes:
                argv = list(expected)
                if flag in argv:
                    argv[argv.index(flag) + 1] = value
                else:
                    argv.extend((flag, value))
                session = SimpleNamespace(run=Mock(), ensure_idle=Mock())
                with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: 1.0),
                        check_capacity=Mock(), ruby_expected_ids=Mock(return_value=("Fixture#test_one",))):
                    result = controller.perform_packaged_ruby_gate(dataclasses.replace(step, argv=tuple(argv)),
                        paths, session, SimpleNamespace(), "linux", deadline=20.0)
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "PACKAGED_RUBY_GATE_CONTRACT")
                session.run.assert_not_called()
                session.ensure_idle.assert_not_called()

    def test_negative_installation_and_suite_have_separate_originals_and_one_unrenewed_cutoff(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        ids = ("Fixture#test_one",)
        identity = (1, 2, 1234, 1234, stat.S_IFDIR | 0o700)
        for phase in ("source", "wheel"):
            faults = ((None, "suite-wait", "suite-eof", "suite-idle", "suite-skip") if phase == "source" else
                      (None, "nonprivate", "pip-wait", "pip-eof", "pip-idle", "pip-expiry", "install-record",
                       "suite-wait", "suite-eof", "suite-idle", "suite-skip", "not-restored", "dispose"))
            for fault in faults:
                with self.subTest(phase=phase, fault=fault):
                    events, clock, stage = [], [10.0], [None]
                    pip = native_capture_fixture(b"private installer output", waited=fault != "pip-wait",
                                                  stdout_eof=fault != "pip-eof")
                    suite = native_capture_fixture(minitest_fixture(ids), waited=fault != "suite-wait",
                                                    stderr_eof=fault != "suite-eof")
                    if fault == "suite-skip":
                        suite.stdout = suite.stdout.replace(b"0 skips", b"1 skips")

                    def run(argv, **kwargs):
                        name = "pip" if "--prefix" in argv else "suite"
                        stage[0] = name
                        events.append(("capture", name, tuple(argv), kwargs))
                        if name == "pip" and fault == "pip-expiry":
                            clock[0] = 311.0
                        return pip if name == "pip" else suite

                    def idle(**kwargs):
                        events.append(("idle", stage[0], kwargs))
                        if fault == str(stage[0]) + "-idle":
                            raise controller.VerificationError("NOT_IDLE")

                    def custody(*_args, **_kwargs):
                        events.append(("custody", stage[0]))
                        if fault == "nonprivate":
                            raise controller.VerificationError("NEGATIVE_PREFIX_CUSTODY")
                        return identity

                    def inspect(*_args, **_kwargs):
                        events.append(("inspect", stage[0]))
                        self.assertIn(("idle", stage[0], {"deadline": 310.0}), events)
                        if stage[0] == "pip" and fault == "install-record":
                            raise controller.VerificationError("NEGATIVE_PREFIX_RECORD_BYTES")
                        return {"files": 1, "record_sha256": "changed" if stage[0] == "suite" and fault == "not-restored" else "a" * 64}

                    def dispose(*_args, **_kwargs):
                        events.append(("dispose",))
                        self.assertEqual(_kwargs, {"deadline": 310.0})
                        self.assertIn(("inspect", "suite"), events)
                        if fault == "dispose":
                            raise controller.VerificationError("NEGATIVE_PREFIX_NOT_REMOVED")

                    session = SimpleNamespace(run=run, ensure_idle=idle, uid=1234, gid=1234)
                    checks = SimpleNamespace(inspect_project_wheel=Mock(return_value={"sha256": "b" * 64}))
                    step = controller.Step("ruby-packaged-capture-" + phase,
                        argv=controller.packaged_ruby_argv(paths, phase, deadline=1000.0), cwd=paths.work,
                        env=tuple(sorted(controller.native_phase_environment(paths, "linux", phase, ruby=True).items())),
                        seconds=300, parser="minitest", expected_tests=1)
                    with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: clock[0]),
                            check_capacity=Mock(), ruby_expected_ids=Mock(return_value=ids),
                            negative_prefix_custody=custody, inspect_negative_ruby_prefix=inspect,
                            dispose_negative_ruby_prefix=dispose), \
                            patch.object(controller.os, "scandir", return_value=nullcontext(iter(()))):
                        result = controller.perform_packaged_ruby_gate(step, paths, session, checks, "linux", deadline=1000.0)
                    self.assertEqual(result.ok, fault is None)
                    captures = [item for item in events if item[0] == "capture"]
                    self.assertTrue(all(item[3]["absolute_deadline"] == 310.0 and item[3]["profile"] == "ordinary"
                                        for item in captures))
                    self.assertTrue(all(item[2]["deadline"] == 310.0 for item in events if item[0] == "idle"))
                    if phase == "source":
                        self.assertEqual([item[1] for item in captures], ["suite"])
                        self.assertFalse(any(item[0] in {"custody", "inspect", "dispose"} for item in events))
                        checks.inspect_project_wheel.assert_not_called()
                    else:
                        names = [item[1] for item in captures]
                        expected = [] if fault == "nonprivate" else ["pip"] if fault in {
                            "pip-wait", "pip-eof", "pip-idle", "pip-expiry", "install-record"} else ["pip", "suite"]
                        self.assertEqual(names, expected)
                        if names:
                            self.assertEqual(captures[0][2], tuple(map(str, (paths.wheel_python, "-I", "-B", "-m", "pip",
                                "install", "--ignore-installed", "--no-index", "--no-deps", "--no-compile", "--no-cache-dir",
                                "--prefix", paths.work / "ruby-negative", paths.wheel))))
                        inspected = [item[1] for item in events if item[0] == "inspect"]
                        if fault in {"nonprivate", "pip-wait", "pip-eof", "pip-idle", "pip-expiry"}:
                            self.assertEqual(inspected, [])
                        elif fault in {"install-record", "suite-wait", "suite-eof", "suite-idle", "suite-skip"}:
                            self.assertEqual(inspected, ["pip"])
                        else:
                            self.assertEqual(inspected, ["pip", "suite"])
                        self.assertEqual(("dispose",) in events, fault in {None, "dispose"})
                        if result.ok:
                            self.assertTrue(result.details["negative_prefix"]["removed_after_outer_finality"])
                    if captures and captures[-1][1] == "suite":
                        argv = captures[-1][2]
                        self.assertEqual(argv[argv.index("--capture-deadline") + 1], "310.0")
                    self.assertNotIn("private installer output", json.dumps(result.details))

    def test_negative_prefix_custody_and_descriptor_disposal_fail_closed_without_real_removal(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        fields = dict(st_dev=1, st_ino=2, st_uid=1234, st_gid=1234, st_mode=stat.S_IFDIR | 0o700)
        identity = tuple(fields[name] for name in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode"))
        session = SimpleNamespace(uid=1234, gid=1234, ensure_idle=Mock())
        with patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)), \
                patch.object(Path, "resolve", lambda self, **_kwargs: self):
            with patch.object(Path, "lstat", return_value=SimpleNamespace(**fields)):
                self.assertEqual(controller.negative_prefix_custody(paths, session, deadline=20.0), identity)
            for field, value in (("st_uid", 0), ("st_gid", 0), ("st_mode", stat.S_IFDIR | 0o755),
                                 ("st_mode", stat.S_IFREG | 0o700), ("st_mode", stat.S_IFLNK | 0o700)):
                with patch.object(Path, "lstat", return_value=SimpleNamespace(**{**fields, field: value})), \
                        self.assertRaisesRegex(controller.VerificationError, "NEGATIVE_PREFIX_CUSTODY"):
                    controller.negative_prefix_custody(paths, session, deadline=20.0)
        for fault in (None, "idle", "identity", "unsafe", "entry", "remove", "still-present", "close"):
            events = []
            remove = Mock(side_effect=OSError("PRIVATE_REMOVE") if fault == "remove" else lambda *args, **kwargs: events.append(("remove", args, kwargs)))
            remove.avoids_symlink_attacks = fault != "unsafe"
            entry = SimpleNamespace(**{**fields, **({"st_ino": 3} if fault == "entry" else {})})
            stats = [entry, entry if fault == "still-present" else FileNotFoundError()]
            fake_os = SimpleNamespace(O_RDONLY=os.O_RDONLY, O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW,
                open=Mock(return_value=77), stat=Mock(side_effect=stats),
                close=Mock(side_effect=OSError("PRIVATE_CLOSE") if fault == "close" else None))
            session.ensure_idle = Mock(side_effect=controller.VerificationError("NOT_IDLE") if fault == "idle" else None)
            with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: 1.0), os=fake_os,
                    shutil=SimpleNamespace(rmtree=remove), negative_prefix_custody=Mock(return_value=(9,) if fault == "identity" else identity)):
                if fault is None:
                    controller.dispose_negative_ruby_prefix(paths, session, identity, deadline=20.0)
                else:
                    with self.assertRaises((controller.VerificationError, OSError)):
                        controller.dispose_negative_ruby_prefix(paths, session, identity, deadline=20.0)
            session.ensure_idle.assert_called_once_with(deadline=20.0)
            if fault in {"idle", "identity", "unsafe"}:
                fake_os.open.assert_not_called()
                fake_os.close.assert_not_called()
                remove.assert_not_called()
            else:
                fake_os.open.assert_called_once_with(paths.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                fake_os.close.assert_called_once_with(77)
                if fault == "entry":
                    remove.assert_not_called()
                else:
                    remove.assert_called_once_with("ruby-negative", dir_fd=77)
                self.assertTrue(all(call.args == ("ruby-negative",) and call.kwargs == {"dir_fd": 77, "follow_symlinks": False}
                                    for call in fake_os.stat.call_args_list))

    def test_negative_prefix_record_covers_exact_same_wheel_files_without_source_substitution(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        prefix, positive = paths.work / "ruby-negative", paths.work / "wheel-venv"
        site = "lib/python3.11/site-packages/"
        dist = site + "mobile_release_kit-0.3.0.dist-info/"
        package = {"__init__.py": b"inert package data", "_native_process.py": b"inert primitive data"}
        tooling = "fastlane/native_process_spawn.rb"
        wheel_hash = "a" * 64
        base = {site + "mobile_release/" + name: data for name, data in package.items()}
        base["share/mobile-release-kit/" + tooling] = b"inert Ruby data"
        base.update({dist + name: b"inert installed metadata" for name in (
            "METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "licenses/LICENSE", "INSTALLER", "REQUESTED")})
        base[dist + "direct_url.json"] = json.dumps({"url": paths.wheel.as_uri(),
            "archive_info": {"hashes": {"sha256": wheel_hash}}}).encode()
        base["bin/mobile-release"] = b"inert console data"
        base[dist + "RECORD"] = b""
        parents = {parent.as_posix() for name in base for parent in Path(name).parents if parent != Path(".")}
        table = []
        for name, data in sorted(base.items()):
            relative = os.path.relpath(prefix / name, prefix / site)
            digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            table.append([relative, "" if name == dist + "RECORD" else digest,
                          "" if name == dist + "RECORD" else str(len(data))])
        for fault in (None, "missing", "extra-directory", "source-bytes", "positive-bytes", "owner", "hardlink",
                      "wheel-origin", "record-missing", "record-duplicate", "record-outside", "record-digest",
                      "record-size", "record-self"):
            with self.subTest(fault=fault):
                files, directories, rows = dict(base), set(parents), copy.deepcopy(table)
                if fault == "missing":
                    del files["share/mobile-release-kit/" + tooling]
                elif fault == "extra-directory":
                    directories.add("unrecorded-empty-directory")
                elif fault == "source-bytes":
                    files[site + "mobile_release/_native_process.py"] = b"foreign substitute"
                elif fault == "wheel-origin":
                    files[dist + "direct_url.json"] = files[dist + "direct_url.json"].replace(wheel_hash.encode(), b"b" * 64)
                if fault == "record-missing":
                    rows.pop()
                elif fault == "record-duplicate":
                    rows[-1] = rows[0]
                elif fault == "record-outside":
                    rows[0][0] = "../../../../outside"
                elif fault == "record-digest":
                    rows[0][1] = "sha512=" + "a" * 64
                elif fault == "record-size":
                    rows[0][2] = "00001"
                elif fault == "record-self":
                    next(row for row in rows if row[0].endswith(".dist-info/RECORD"))[1] = "sha256=" + "a" * 43
                data = io.StringIO(newline="")
                csv.writer(data, lineterminator="\n").writerows(rows)
                files[dist + "RECORD"] = data.getvalue().encode()
                positive_files = dict(files)
                if fault == "positive-bytes":
                    positive_files["bin/mobile-release"] = b"different positive file"

                def read(path, **_kwargs):
                    if path == paths.source / tooling:
                        return base["share/mobile-release-kit/" + tooling]
                    root = prefix if path.is_relative_to(prefix) else positive
                    source = files if root == prefix else positive_files
                    return source[path.relative_to(root).as_posix()]

                checks = SimpleNamespace(_tree=Mock(return_value=(files, directories)),
                    _source_package=Mock(return_value=package), TOOLING_FILES=(tooling,))
                session = SimpleNamespace(uid=1234, gid=1234)
                info = SimpleNamespace(st_uid=0 if fault == "owner" else 1234, st_gid=1234,
                    st_mode=stat.S_IFREG | 0o600, st_nlink=2 if fault == "hardlink" else 1)
                with patch.multiple(controller, time=SimpleNamespace(monotonic=lambda: 1.0),
                        read_regular=Mock(side_effect=read), negative_prefix_custody=Mock(return_value=(1, 2, 1234, 1234, 0o40700))), \
                        patch.object(Path, "lstat", return_value=info), \
                        patch.object(Path, "resolve", lambda self, **_kwargs: Path(os.path.normpath(str(self)))):
                    if fault is None:
                        observed = controller.inspect_negative_ruby_prefix(paths, session, checks, wheel_hash, deadline=20.0)
                        self.assertEqual(observed, {"files": len(files), "wheel_sha256": wheel_hash,
                            "record_sha256": hashlib.sha256(files[dist + "RECORD"]).hexdigest(), "positive_prefix_untouched": True})
                    else:
                        with self.assertRaises(controller.VerificationError):
                            controller.inspect_negative_ruby_prefix(paths, session, checks, wheel_hash, deadline=20.0)
                checks._tree.assert_called_once_with(prefix, deadline=20.0)

    def test_gate_order_requires_both_abi_phases_and_all_six_ordinary_compatibility_gates(self):
        controller = controller_module()
        for platform in ("linux", "macos"):
            gates = controller.required_gate_ids(platform)
            self.assertEqual(len(gates), len(set(gates)))
            for phase in ("source", "wheel"):
                abi = gates.index("native-process-abi-" + phase)
                ordinary = "python-full" if phase == "source" else "python-wheel"
                terminal = gates.index(ordinary if platform == "linux" else "native-profile-" + phase)
                for line in ("312", "313", "314"):
                    control = gates.index(f"python-compat-{line}-{phase}")
                    self.assertLess(abi, control)
                    self.assertLess(control, terminal)
                self.assertLess(abi, gates.index("ruby-packaged-capture-" + phase))
            self.assertLess(gates.index("wheel-freeze"), gates.index("native-process-abi-wheel"))
            self.assertLess(gates.index("native-process-abi-wheel"), gates.index("wheel-smoke"))
        self.assertEqual(controller.AGGREGATE_SECONDS, 3300)


class CICoordinatorFilesystemTests(unittest.TestCase):
    def test_regular_reader_rejects_aliases_and_multiple_links_without_reading_the_target(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-reader-") as temporary:
            root = Path(temporary).resolve()
            actual = root / "actual"
            actual.mkdir()
            target = actual / "data"
            target.write_bytes(b"owned fixture bytes")
            alias = root / "ancestor-alias"
            alias.symlink_to(actual, target_is_directory=True)
            leaf = actual / "leaf-alias"
            leaf.symlink_to(target)
            opened, read = Mock(wraps=os.open), Mock(wraps=os.read)
            facade = SimpleNamespace(open=opened, read=read, fstat=os.fstat, close=os.close,
                                     O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
            with patch.object(controller, "os", facade), \
                    patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                self.assertEqual(controller.read_regular(target, deadline=2.0), b"owned fixture bytes")
                for path in (Path("relative-fixture"), alias / "data"):
                    opened.reset_mock()
                    read.reset_mock()
                    with self.subTest(path=path), self.assertRaisesRegex(controller.VerificationError, "FILE_PARENT_ALIAS"):
                        controller.read_regular(path, deadline=2.0)
                    opened.assert_not_called()
                    read.assert_not_called()
                read.reset_mock()
                with self.assertRaises(OSError):
                    controller.read_regular(leaf, deadline=2.0)
                read.assert_not_called()
                linked = root / "another-name"
                os.link(target, linked)
                with self.assertRaisesRegex(controller.VerificationError, "FILE_TYPE_OR_BOUND"):
                    controller.read_regular(target, deadline=2.0)
                read.assert_not_called()
            self.assertEqual(target.read_bytes(), b"owned fixture bytes")
            self.assertEqual(linked.stat().st_ino, target.stat().st_ino)

    def test_freeze_rejects_alias_roots_unapproved_links_hardlinks_and_walk_errors_before_changes(self):
        controller = controller_module()
        cases = {"root-link": "FREEZE_ROOT_NOT_DIRECTORY", "ancestor-link": "FREEZE_ROOT_NOT_DIRECTORY",
                 "regular-root": "FREEZE_ROOT_NOT_DIRECTORY", "unapproved-link": "FREEZE_UNAPPROVED_LINK",
                 "hardlink": "FREEZE_HARDLINK", "walk-error": "FILESYSTEM_WALK_FAILED"}
        with tempfile.TemporaryDirectory(prefix="mrk-ci-freeze-reject-") as temporary:
            base = Path(temporary).resolve()
            for case, error in cases.items():
                with self.subTest(case=case):
                    parent = base / case
                    parent.mkdir()
                    actual = parent / "actual"
                    actual.mkdir()
                    root = actual
                    foreign = parent / "outside-the-selected-tree"
                    foreign.write_bytes(b"must remain unchanged")
                    foreign.chmod(0o600)
                    if case == "root-link":
                        root = parent / "alias"
                        root.symlink_to(actual, target_is_directory=True)
                    elif case == "ancestor-link":
                        (actual / "child").mkdir()
                        (parent / "alias").symlink_to(actual, target_is_directory=True)
                        root = parent / "alias/child"
                    elif case == "regular-root":
                        root = foreign
                    elif case == "unapproved-link":
                        (root / "entry").symlink_to(foreign)
                    elif case == "hardlink":
                        os.link(foreign, root / "entry")

                    def broken_walk(_root, *, followlinks, onerror):
                        self.assertIs(followlinks, False)
                        onerror(OSError("synthetic directory enumeration failure"))
                        raise AssertionError("walk failure was ignored")

                    walk = Mock(wraps=broken_walk if case == "walk-error" else os.walk)
                    chown = Mock()
                    chmod = Mock(side_effect=AssertionError("rejected fixture must not be chmodded"))
                    with patch.object(controller, "os", SimpleNamespace(walk=walk, chown=chown, chmod=chmod)), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                        with self.assertRaisesRegex(controller.VerificationError, error):
                            controller.freeze_tree(root, deadline=2.0)
                    chown.assert_not_called()
                    chmod.assert_not_called()
                    if case in {"root-link", "ancestor-link", "regular-root"}:
                        walk.assert_not_called()
                    self.assertEqual(foreign.read_bytes(), b"must remain unchanged")
                    self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o600)

    def test_freeze_keeps_confined_venv_links_and_never_chmods_their_provider_targets(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-freeze-venv-") as temporary:
            base = Path(temporary).resolve()
            root, provider = base / "venv", base / "provider"
            directories = [root, root / "bin", root / "lib", root / "lib/python3.11",
                           root / "lib/python3.11/site-packages"]
            for directory in directories:
                directory.mkdir()
            provider.mkdir()
            external = provider / "python"
            external.write_bytes(b"provider fixture, never executed")
            external.chmod(0o700)
            binary = root / "bin/python"
            binary.write_bytes(b"owned fixture, never executed")
            binary.chmod(0o700)
            package = root / "lib/python3.11/site-packages/fixture.py"
            package.write_bytes(b"# data-only fixture\n")
            package.chmod(0o600)
            links = (root / "lib64", root / "bin/python3", root / "bin/provider-python")
            links[0].symlink_to("lib", target_is_directory=True)
            links[1].symlink_to("python")
            links[2].symlink_to(external)
            permitted = {*directories, binary, package}
            changed = []

            def chmod(path, mode):
                path = Path(path)
                self.assertIn(path, permitted)
                self.assertFalse(path.is_symlink())
                changed.append(path)
                os.chmod(path, mode)

            chown = Mock()  # Never attempt an actual root-only ownership change.
            try:
                with patch.object(controller, "os", SimpleNamespace(walk=os.walk, chown=chown, chmod=chmod)), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 1.0)):
                    controller.freeze_tree(root, deadline=2.0, link_roots=(root, provider))
                self.assertEqual(set(changed), permitted)
                for directory in directories:
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE(package.stat().st_mode), 0o444)
                self.assertTrue(all(path.is_symlink() for path in links))
                self.assertEqual([path.resolve() for path in links], [root / "lib", binary, external])
                for link in links:
                    calls = [call for call in chown.call_args_list if Path(call.args[0]) == link]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0].args[1:], (0, 0))
                    self.assertEqual(calls[0].kwargs, {"follow_symlinks": False})
                self.assertEqual(external.read_bytes(), b"provider fixture, never executed")
                self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o700)
            finally:
                # Restore only these pre-enumerated task-owned real directories,
                # so ordinary non-root TemporaryDirectory cleanup also works.
                for directory in directories:
                    directory.chmod(0o700)


class CICoordinatorResultTests(unittest.TestCase):
    def test_failed_ruby_diagnostics_keep_only_source_known_ids_and_locations(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        step = controller.Step("ruby-native-capture", parser="minitest")
        known, assertion = controller.ruby_expected_ids(ROOT, step.id)[:2]
        private = "private-fixture-value-must-not-be-published"
        text = (f"1) Error:\n{known}:\nRuntimeError: {private}\n"
                f" /private/{private}/source/tests/workflow/test_native_upload_validation.rb:42:in method\n"
                f"2) Failure:\n{assertion} [/private/{private}/source/tests/workflow/test_native_upload_validation.rb:45]:\n"
                "UnknownSuite#test_private_value:\n"
                f" /private/{private}/private_fixture.rb:17\n"
                "13 runs, 100 assertions, 1 failures, 1 errors, 0 skips\n"
                'MRK_CHECK_RESULT={"details":{},"details":{}}\n'
                'MRK_CHECK_RESULT={"details":null}\n'
                'MRK_CHECK_RESULT={"details":{"error":NaN}}\n')
        captured = SimpleNamespace(returncode=7, waited=True, stdout_eof=True, stderr_eof=True,
                                   domain_finality=True, timed_out=False, cancelled=False,
                                   stdout=text.encode(), stderr=b"",
                                   persisted=(len(text), 0), duration=0.2, cleanup_errors=())
        details = controller.failure_details(captured, step, paths)
        self.assertEqual(details["returncode"], 7)
        self.assertEqual(details["failed_tests"], sorted([known, assertion]))
        self.assertEqual(details["ruby_locations"], [("tests/workflow/test_native_upload_validation.rb", 42),
                                                    ("tests/workflow/test_native_upload_validation.rb", 45)])
        self.assertEqual(details["minitest_observations"], [[13, 100, 1, 1, 0]])
        for hidden in (private, "UnknownSuite", "test_private_value", "private_fixture.rb", "/private/"):
            self.assertNotIn(hidden, json.dumps(details))
        # Malformed diagnostic text or unavailable diagnostic source cannot
        # replace the actual failed command's status with a parser exception.
        with patch.object(controller, "ruby_expected_ids", side_effect=controller.VerificationError("RUBY_STATIC_INVENTORY")):
            unavailable = controller.failure_details(captured, step, paths)
        self.assertEqual(unavailable["returncode"], 7)
        self.assertTrue(unavailable["ruby_diagnostics_unavailable"])
        self.assertNotIn("failed_tests", unavailable)
        with patch.object(controller, "strict_json", side_effect=RecursionError):
            self.assertEqual(controller.failure_details(captured)["returncode"], 7)

    def test_every_ruby_suite_requires_its_exact_class_and_method_completion_inventory(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        suites = {
            "ruby-support": ("test_fastlane_support.rb", {"FastlaneReleaseSupportTest"}, 12),
            "ruby-native-spawn": ("test_native_process_spawn.rb", {"NativeProcessSpawnTests"}, 52),
            "ruby-native-owner": ("test_native_upload_process.rb",
                                  {"NativeUploadProtocolTest", "NativeUploadTaskSlotTest", "NativeUploadRoleTest"}, 52),
            "ruby-native-capture": ("test_native_upload_validation.rb", {"NativeUploadValidationTest"}, 21),
            "ruby-native-signal-observation": ("test_native_signal_observation.rb", {"NativeSignalObservationTest"}, 1),
            "ruby-play_store": ("test_play_store.rb", {"PreservingSupplyUploaderTests"}, 35),
            "ruby-play_lanes": ("test_play_lanes.rb", {"PlayReleaseLanesTest", "BoundedPlayImageTest"}, 46),
            "ruby-apple_store": ("test_apple_store.rb", {"AppleOperationTransportTest", "AppleStoreContractTest"}, 7),
            "ruby-apple_lanes": ("test_apple_lanes.rb", {"AppleReleaseLanesTest"}, 23),
            "ruby-apple_production": ("test_apple_production.rb", {"AppleProductionTest", "AppleCreateRetryContractTest"}, 47),
            "ruby-apple_production_lane": ("test_apple_production_lane.rb", {"AppleProductionLaneTest"}, 2),
            "ruby-apple_asset_upload": ("test_apple_asset_upload.rb", {"AppleAssetUploadTest"}, 8),
            "ruby-ios_upload_validation": ("test_ios_upload_validation.rb", {"IosUploadValidationTest"}, 32),
            "ruby-android_upload_validation": ("test_android_upload_validation.rb", {"AndroidUploadValidationTest"}, 32),
            "ruby-workflow-yaml": ("test_workflow_yaml.rb", {"WorkflowYamlStructureTest"}, 1),
            "ruby-packaged-capture-source": ("test_installed_ruby_capture.rb", {"PackagedRubyCaptureTest"}, 6),
            "ruby-packaged-capture-wheel": ("test_installed_ruby_capture.rb",
                                              {"PackagedRubyCaptureTest", "InstalledRubyCaptureMissingHelperTest"}, 8),
        }
        shared_literal = {
            "test_deadline_terminates_validator_without_authorizing_upload",
            "test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits",
            "test_descendant_boundary_survives_delayed_start_and_late_parent_record",
            "test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record",
            "test_fixture_detects_leader_only_cleanup_and_missing_deadline",
            "test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed",
            "test_slow_cleanup_cannot_supply_a_positive_deadline_wait",
            "test_driver_loss_during_startup_retains_unknown_native_custody",
            "test_driver_loss_with_inherited_pipes_retains_unknown_native_custody",
            "test_process_observation_rejects_errors_malformed_output_and_foreign_groups",
            "test_setup_primary_survives_cleanup_failure_and_real_queued_cancellation",
            "test_indeterminate_observations_never_prove_readiness_or_renew_native_death_budget",
            "test_process_ownership_unknown_creation_through_real_capture",
            "test_process_ownership_unknown_wait_through_real_capture",
            "test_process_ownership_echild_after_original_wait_through_real_capture",
            "test_process_ownership_unknown_creation_through_real_run",
            "test_process_ownership_unknown_wait_through_real_run",
            "test_process_ownership_echild_after_original_wait_through_real_run",
        }
        shared = (ROOT / "tests/workflow/upload_process_fixture.rb").read_text().split("  module Contracts\n")
        self.assertEqual(len(shared), 2)
        self.assertEqual({line.removeprefix("    def ").strip() for line in shared[1].splitlines()
                          if line.startswith("    def test_")}, shared_literal)
        shared_ids = shared_literal | {
            "test_process_ownership_" + family + "_through_both_real_fixture_callers"
            for family in ("async", "signals", "policies")
        }
        gates = {step.id: step for step in controller.catalog(paths, "linux", deadline=20.0)
                 if step.parser == "minitest"}
        self.assertEqual(set(gates), set(suites))
        for gate, (filename, expected_classes, count) in suites.items():
            with self.subTest(gate=gate):
                # Independent line-by-line source inventory, not the production
                # collector's regex/class-body splitting or its returned IDs.
                owner, classes, ids = None, set(), []
                for line in (ROOT / "tests/workflow" / filename).read_text().splitlines():
                    if line.startswith("class "):
                        owner = line.split()[1] if line.rstrip().endswith(" < Minitest::Test") else None
                        if owner is not None:
                            classes.add(owner)
                    elif line == "end":
                        owner = None
                    elif owner is not None and line.startswith("  def test_"):
                        name = line.removeprefix("  def ").strip()
                        self.assertRegex(name, r"^test_[A-Za-z0-9_]+$")
                        ids.append(owner + "#" + name)
                    elif owner is not None and line == "  include UploadProcessFixture::Contracts":
                        ids.extend(owner + "#" + name for name in shared_ids)
                if gate == "ruby-packaged-capture-source":
                    # Both classes inhabit the fixed file, but the literal source
                    # CLI selects only the common class; missing-helper mutations
                    # belong exclusively to the separately installed wheel gate.
                    self.assertEqual(classes, {"PackagedRubyCaptureTest", "InstalledRubyCaptureMissingHelperTest"})
                    classes = {owner for owner in classes if owner == "PackagedRubyCaptureTest"}
                    ids = [identifier for identifier in ids if identifier.partition("#")[0] in classes]
                expected = tuple(sorted(ids))
                self.assertEqual(classes, expected_classes)
                self.assertEqual(len(expected), count)
                self.assertEqual(len(set(expected)), count)
                self.assertEqual(controller.ruby_expected_ids(ROOT, gate), expected)
                self.assertEqual(gates[gate].expected_tests, count)

                def capture(completed):
                    text = "".join(identifier + " = 0.00 s = .\n" for identifier in completed)
                    text += f"\n{count} runs, {count * 3} assertions, 0 failures, 0 errors, 0 skips\n"
                    return SimpleNamespace(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                                           domain_finality=True, primary_error=None, cleanup_errors=(),
                                           stdout=text.encode("ascii"), stderr=b"", duration=0.01)

                parsed = controller.parse_capture(gates[gate], capture(reversed(expected)), paths, "linux", None)
                self.assertTrue(parsed.ok)
                self.assertEqual(sorted(parsed.details["completed"]), list(expected))
                wrong_method = expected[0].split("#")[0] + "#test_unknown_fixture_contract"
                wrong_class = "WrongFixtureSuite#" + expected[0].split("#")[1]
                mutations = [(wrong_method, *expected[1:]), (wrong_class, *expected[1:])]
                if gate == "ruby-packaged-capture-source":
                    mutations.append(("InstalledRubyCaptureMissingHelperTest#test_missing_installed_spawn_helper_refuses_fallback",
                                      *expected[1:]))
                if count > 1:
                    mutations.append((expected[1], *expected[1:]))  # Same count, duplicate ID.
                for mutated in mutations:
                    with self.assertRaisesRegex(controller.VerificationError, "MINITEST_COMPLETION_INVENTORY"):
                        controller.parse_capture(gates[gate], capture(mutated), paths, "linux", None)
        # QA-003 is a separate source patch with additional native obligations.
        # Its mere presence cannot silently inherit this smaller fixed matrix.
        with tempfile.TemporaryDirectory(prefix="mrk-ci-catalog-boundary-") as temporary:
            other_source = Path(temporary).resolve()
            sentinel = other_source / "src/mobile_release/local_signing.py"
            sentinel.parent.mkdir(parents=True)
            sentinel.write_bytes(b"raise AssertionError('data-only fixture must never be imported')\n")
            for platform in ("linux", "macos"):
                with self.subTest(unintegrated_source=platform), self.assertRaisesRegex(
                        controller.VerificationError, "LOCAL_SIGNING_MATRIX_REQUIRES_CATALOG_AMENDMENT"):
                    controller.catalog(dataclasses.replace(paths, source=other_source), platform, deadline=20.0)

    def test_final_report_preserves_upstream_status_and_publishes_finality_before_finishing(self):
        controller = controller_module()
        summary, runner_temp = Path("/fixture/step_summary_contract"), Path("/fixture")
        for initially_ok in (True, False):
            with self.subTest(initially_ok=initially_ok):
                events, published = [], []
                report = report_fixture(initially_ok)
                original_rows = copy.deepcopy(report["rows"])
                session = session_fixture(events)

                def publish(path, value, *, runner_temp: Path, deadline):
                    self.assertEqual((path, runner_temp, deadline), (summary, Path("/fixture"), 20.0))
                    events.append(("publish", deadline))
                    published.append(copy.deepcopy(value))

                with patch.object(controller, "publish_summary", publish), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=summary, runner_temp=runner_temp,
                                                        start=10.0, deadline=20.0)
                self.assertEqual(status, 0 if initially_ok else 1)
                self.assertIs(report["ok"], initially_ok)
                self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])
                self.assertEqual(report["rows"], original_rows)
                self.assertEqual(report["cleanup_errors"], [])
                self.assertTrue(published[0]["finality"])
                self.assertEqual(published[0]["persisted_capture_bytes"], 37)
                self.assertEqual(published[0]["seconds"], 2.0)
                self.assertIs(published[0]["ok"], initially_ok)
                if not initially_ok:
                    self.assertEqual(report["error"], "UPSTREAM_FIXTURE_FAILURE")
        for missing in ("session", "summary", "runner-temp"):
            with self.subTest(missing=missing):
                events = []
                report = report_fixture()
                session = None if missing == "session" else session_fixture(events)
                with patch.object(controller, "publish_summary") as publisher, \
                        patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=None if missing == "summary" else summary,
                                                        runner_temp=None if missing == "runner-temp" else runner_temp,
                                                        start=10.0, deadline=20.0)
                self.assertEqual(status, 1)
                self.assertFalse(report["ok"])
                publisher.assert_not_called()
                self.assertEqual(events, [] if session is None else [("close", True), ("finish",)])
                self.assertEqual(report["error"], "SUCCESS_WITHOUT_ORIGINAL_SESSION" if session is None
                                 else "NO_SAFE_SUMMARY_DESTINATION")

    def test_cleanup_publication_and_cancellation_failures_never_return_success_and_always_finish(self):
        controller = controller_module()
        cases = [(stage, exception) for stage in ("close", "publish", "finish")
                 for exception in (OSError, KeyboardInterrupt, SystemExit)]
        cases += [(stage, None) for stage in ("no-finality", "latched-failure", "cleanup-errors", "all-three")]
        for stage, exception in cases:
            for upstream_failed in (False, True):
                with self.subTest(stage=stage, exception=exception, upstream_failed=upstream_failed):
                    events, published = [], []
                    report = report_fixture(not upstream_failed)

                    def close_action(session):
                        if stage in {"close", "all-three"}:
                            raise (exception or OSError)("synthetic late close failure")
                        if stage == "no-finality":
                            session.domain_finality = False
                        if stage == "latched-failure":
                            session.failure = "EARLIER_SESSION_FAILURE"
                        if stage == "cleanup-errors":
                            session.cleanup_errors.append("SYNTHETIC_CLEANUP_FAILURE")

                    def finish_action(_session):
                        if stage in {"finish", "all-three"}:
                            raise (exception or OSError)("synthetic timer restoration failure")

                    def publish(_path, value, **kwargs):
                        events.append(("publish", kwargs["deadline"]))
                        published.append(copy.deepcopy(value))
                        if stage in {"publish", "all-three"}:
                            raise (exception or OSError)("synthetic publication failure")

                    session = session_fixture(events, close_action=close_action, finish_action=finish_action)
                    with patch.object(controller, "publish_summary", publish), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: 12.0)), redirect_stdout(io.StringIO()):
                        status = controller.finalize_report(report, session, summary=Path("/fixture/step_summary_contract"),
                                                            runner_temp=Path("/fixture"), start=10.0, deadline=20.0)
                    self.assertEqual(status, 1)
                    self.assertFalse(report["ok"])
                    self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])
                    self.assertEqual(report["persisted_capture_bytes"], 37)
                    if stage in {"close", "no-finality", "latched-failure", "cleanup-errors", "all-three"}:
                        self.assertFalse(published[0]["ok"])
                    if stage in {"close", "finish"}:
                        self.assertEqual(report["cleanup_errors"][0]["exception"], exception.__name__)
                    if stage == "all-three":
                        self.assertEqual(len(report["cleanup_errors"]), 2)
                    if upstream_failed:
                        self.assertEqual(report["error"], "UPSTREAM_FIXTURE_FAILURE")

    def test_original_deadline_covers_close_publication_finish_and_final_return(self):
        controller = controller_module()
        for phase in ("already-expired", "close", "publish", "finish", "final-return"):
            with self.subTest(phase=phase):
                events = []
                clock = SimpleNamespace(value=20.0 if phase == "already-expired" else 12.0)
                report = report_fixture()

                def now():
                    return 20.0 if phase == "final-return" and events and events[-1] == ("finish",) else clock.value

                def close_action(_session):
                    if phase == "close":
                        clock.value = 20.0

                def finish_action(_session):
                    if phase == "finish":
                        clock.value = 20.0

                def publish(_path, _report, **kwargs):
                    self.assertEqual(kwargs["deadline"], 20.0)
                    events.append(("publish", kwargs["deadline"]))
                    if phase == "publish":
                        clock.value = 20.0
                    # Deliberately return success-shaped output even at expiry:
                    # finalizer's own original-cutoff gate must still reject it.

                session = session_fixture(events, close_action=close_action, finish_action=finish_action)
                with patch.object(controller, "publish_summary", publish), \
                        patch.object(controller, "time", SimpleNamespace(monotonic=now)), redirect_stdout(io.StringIO()):
                    status = controller.finalize_report(report, session, summary=Path("/fixture/step_summary_contract"),
                                                        runner_temp=Path("/fixture"), start=10.0, deadline=20.0)
                self.assertEqual(status, 1)
                self.assertFalse(report["ok"])
                self.assertEqual(report["error"], "AGGREGATE_DEADLINE")
                self.assertEqual(events, [("close", True), ("publish", 20.0), ("finish",)])

    def test_summary_write_sync_close_and_print_aftereffects_are_bounded_by_original_deadline(self):
        controller = controller_module()
        with tempfile.TemporaryDirectory(prefix="mrk-ci-summary-") as temporary:
            root = Path(temporary).resolve()
            for phase in ("none", "write", "fsync", "descriptor-close", "print"):
                with self.subTest(late_aftereffect=phase):
                    summary = root / ("step_summary_" + phase)
                    summary.write_bytes(b"")
                    report, events, emitted, descriptors = report_fixture(), [], [], []
                    clock = SimpleNamespace(value=12.0)

                    def after_effect(name):
                        events.append((name,))
                        if phase == name:
                            clock.value = 20.0

                    def opened(path, flags):
                        self.assertEqual(path, summary)
                        self.assertEqual(flags, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
                        descriptor = os.open(path, flags)
                        descriptors.append(descriptor)
                        return descriptor

                    def write(descriptor, value):
                        self.assertEqual(descriptors, [descriptor])
                        count = os.write(descriptor, value)
                        after_effect("write")
                        return count

                    def sync(descriptor):
                        self.assertEqual(descriptors, [descriptor])
                        os.fsync(descriptor)
                        after_effect("fsync")

                    def close(descriptor):
                        self.assertEqual(descriptors, [descriptor])
                        os.close(descriptor)
                        after_effect("descriptor-close")

                    def printed(text, *, flush):
                        self.assertIs(flush, True)
                        emitted.append(text)
                        if text.startswith("MRK_CI_RESULT="):
                            after_effect("print")

                    facade = SimpleNamespace(open=opened, fstat=os.fstat, write=write, fsync=sync, close=close,
                                             O_WRONLY=os.O_WRONLY, O_APPEND=os.O_APPEND,
                                             O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
                    session = session_fixture(events)
                    with patch.object(controller, "os", facade), patch.object(controller, "print", printed, create=True), \
                            patch.object(controller, "time", SimpleNamespace(monotonic=lambda: clock.value)):
                        status = controller.finalize_report(report, session, summary=summary, runner_temp=root,
                                                            start=10.0, deadline=20.0)
                    self.assertEqual(status, 0 if phase == "none" else 1)
                    self.assertIs(report["ok"], phase == "none")
                    self.assertEqual(events[0], ("close", True))
                    self.assertEqual(events[-1], ("finish",))
                    self.assertEqual(events.count(("descriptor-close",)), 1)
                    self.assertEqual(len(descriptors), 1)
                    self.assertTrue(summary.read_bytes().startswith(b"## Mobile Release Kit isolated verification\n"))
                    self.assertEqual(any(line.startswith("MRK_CI_RESULT=") for line in emitted), phase in {"none", "print"})
                    if phase != "none":
                        self.assertEqual(report["error"], "AGGREGATE_DEADLINE")


if __name__ == "__main__":
    unittest.main()
