"""Inert Store-controller contracts, not native finality or platform evidence.

Every Session/capture/filesystem operation is an explicit data double. No
project/native subprocess, account, permission change or Store request is run.
The separate native gates alone provide actual source/wheel runtime evidence.
"""
from __future__ import annotations

from contextlib import contextmanager
import builtins
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from .test_ci_controller import native_capture_fixture
from .test_ci_sandbox import sandbox_module, session_double
from .test_ci_verification import ROOT, ci_module, controller_module, fixture_paths
from . import store_lane_native_fixture as native_fixture


class StoreLaneControllerTests(unittest.TestCase):
    def test_admitted_ruby_provider_uses_subject_relative_permissions_without_relaxing_product_custody(self):
        c = controller_module()
        paths = fixture_paths(c)
        ruby, prefix = paths.ruby, paths.ruby.parent.parent
        session = SimpleNamespace(uid=61001, gid=61001, admitted=True, ruby=ruby,
                                  tool_prefixes=(prefix,), ensure_idle=Mock())
        raw = b"fixed inert provider bytes"
        fields = dict(st_dev=5, st_ino=7, st_uid=1001, st_gid=1001, st_mode=stat.S_IFREG | 0o775,
                      st_nlink=1, st_size=len(raw), st_mtime_ns=11, st_ctime_ns=13)
        observed = SimpleNamespace(**fields)
        with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(Path, "resolve", autospec=True, side_effect=lambda path, **_k: path), \
                patch.object(Path, "lstat", return_value=observed) as inspect, \
                patch.object(c, "read_regular", return_value=raw) as read:
            result = c.store_native_ruby_binding(paths, session, deadline=1000.0)
            self.assertEqual((result["runtime_role"], result["prefix"], result["path"]), ("ruby", str(prefix), str(ruby)))
            self.assertEqual((result["uid"], result["gid"], result["mode"]), (1001, 1001, stat.S_IFREG | 0o775))
            self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
            read.assert_called_once_with(ruby, deadline=1000.0, maximum=64 * 1024**2)
            session.ensure_idle.assert_called_once_with(deadline=1000.0)
            for change in ({"st_uid": session.uid}, {"st_gid": session.gid}, {"st_mode": stat.S_IFREG | 0o777}):
                with self.subTest(provider=change):
                    inspect.return_value = SimpleNamespace(**{**fields, **change})
                    read.reset_mock()
                    with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_RUBY_PROVIDER_FILE"):
                        c.store_native_ruby_binding(paths, session, deadline=1000.0)
                    read.assert_not_called()
            inspect.return_value = observed
            for change in ({"admitted": False}, {"ruby": ruby.with_name("other-ruby")},
                           {"tool_prefixes": ()}, {"tool_prefixes": (prefix, prefix.parent)}):
                with self.subTest(role=change):
                    altered = SimpleNamespace(**{**vars(session), **change})
                    read.reset_mock()
                    inspect.reset_mock()
                    with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_RUBY_PROVIDER_ROLE"):
                        c.store_native_ruby_binding(paths, altered, deadline=1000.0)
                    read.assert_not_called()
                    inspect.assert_not_called()
            inspect.side_effect = [observed, SimpleNamespace(**{**fields, "st_ino": 8})]
            with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_RUBY_PROVIDER_CHANGED"):
                c.store_native_ruby_binding(paths, session, deadline=1000.0)
            inspect.side_effect = None
            # Even root-owned group-writable product files remain forbidden;
            # the provider-specific rule never changes fixture/product custody.
            inspect.return_value = SimpleNamespace(**{**fields, "st_uid": 0, "st_gid": 0})
            read.reset_mock()
            with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_FILE_BINDING"):
                c.store_native_file_binding(ruby, deadline=1000.0)
            read.assert_not_called()

    def test_exact_fifteen_fourteen_rows_are_separate_required_gates_not_default_discovery(self):
        checks, controller = ci_module("ci_checks"), controller_module()
        source = checks.store_lane_native_rows(ROOT, "source")
        wheel = checks.store_lane_native_rows(ROOT, "wheel")
        self.assertEqual((len(source), len(wheel)), (15, 14))
        self.assertEqual(source[1:], wheel)
        self.assertEqual(source[0][0], "ordinary-at-exit-control")
        self.assertEqual(len({identifier for _, identifier in source}), 7)
        self.assertEqual(len({subcase for subcase, _ in source}), 15)
        self.assertFalse(any(identifier.startswith(checks.STORE_NATIVE_PREFIX)
                             for identifier in checks.expected_python_ids(ROOT, "full")))
        for selection in ("wheel", "native"):
            self.assertNotIn("test_store_lane_native.py", checks.WHEEL_PATTERNS if selection == "wheel" else checks.NATIVE_PATTERNS)
        for platform in ("linux", "macos"):
            targeted = controller.catalog(fixture_paths(controller), platform, scope="store-lane", deadline=1000.0)
            self.assertEqual(tuple(step.id for step in targeted), controller.required_gate_ids(platform, "store-lane"))
            self.assertEqual(len(targeted), 22 if platform == "linux" else 23)
            for gate in controller.STORE_NATIVE_GATES:
                self.assertIn(gate, controller.required_gate_ids(platform))
                self.assertEqual(sum(step.id == gate for step in targeted), 1)
            self.assertFalse({"python-full", "python-wheel", "native-profile-source", "native-profile-wheel",
                              "local-signing-matrix", "jdk-signers", "actionlint"} & {step.id for step in targeted})
            with self.assertRaisesRegex(controller.VerificationError, "REQUIRED_GATE_INVENTORY"):
                controller.execute_pipeline(targeted, Mock(), platform=platform)  # Partial is never the platform aggregate.

    def _rig(self, platform="linux"):
        c, checks = controller_module(), ci_module("ci_checks")
        rig = SimpleNamespace(c=c, checks=checks, paths=fixture_paths(c), clock=10.0, runs=[], outputs=[], removals=[],
                              originals=[], fails_at=None, output_error_at=None, advance=1.0, failed=False, inner_bytes=11,
                              platform=platform, environments=[], capture_calls=[], original_snapshots=[],
                              failure_stderr=b"", failure_stdout=None)
        rig.boundary = session_double(sandbox_module(), "darwin" if platform == "macos" else "linux")
        rig.boundary.uid = rig.boundary.gid = 61001
        for name in ("source", "work", "inputs", "python", "ruby"):
            setattr(rig.boundary, name, getattr(rig.paths, name))
        rig.boundary.process_observer = None
        rig.boundary.tool_prefixes = (rig.paths.python.parent.parent, rig.paths.ruby.parent.parent, rig.paths.java_home)
        rig.state = c.StoreLaneNativeState()
        rig.abi = c.NativeABIState(phases={phase: tuple(native_capture_fixture() for _ in range(3))
                                         for phase in ("source", "wheel")})
        rig.binding = {"wheelSha256": None}
        rig.outside = {"fixtures": {name: {"path": str(rig.paths.source / name), "sha256": "a" * 64}
                                    for name in c.STORE_NATIVE_FIXTURES},
                       "ruby": {"sha256": "b" * 64}, "bundler": {"sha256": "c" * 64},
                       "python": {"sha256": "d" * 64}, "fastlane": {}}

        def idle(*, deadline):
            if rig.failed:
                raise c.VerificationError("FIXTURE_LATCHED_SESSION")
            c.check_clock(deadline)

        def run(argv, **options):
            index = len(rig.runs)
            is_binding = "binding" in argv
            phase = argv[3] if is_binding else argv[argv.index("--phase") + 1]
            directory = Path(argv[7] if is_binding else argv[argv.index("--case-directory") + 1])
            names = tuple(name for name, _ in native_fixture.case_inventory(phase))
            name = "binding-capture" if is_binding else f"case-{names.index(argv[argv.index('--subcase') + 1]) + 1:02d}"
            self.assertEqual(directory, rig.paths.work / "store-lane" / phase / name)
            def installed_input(*, deadline):
                self.assertEqual(phase, "wheel")
                self.assertEqual(deadline, options["absolute_deadline"])
            rig.boundary._validate_installed_bundle_input = Mock(side_effect=installed_input)
            environment = rig.boundary._environment(options["env"], deadline=options["absolute_deadline"])
            self.assertEqual(rig.boundary._validate_installed_bundle_input.call_count, int(phase == "wheel"))
            for key, leaf in (("HOME", "home"), ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")):
                self.assertEqual(environment[key], str(rig.paths.work / leaf))
            for key, leaf in (("GEM_SPEC_CACHE", "gem-cache"), ("BUNDLE_APP_CONFIG", "bundle-config"),
                              ("BUNDLE_USER_HOME", "bundle-home")):
                self.assertEqual(environment[key], str(directory / leaf))
            rig.environments.append(environment)
            rig.runs.append((tuple(argv), options))
            rig.clock += rig.advance
            failed = index == rig.fails_at
            stdout = c.store_native_wire(rig.binding) if is_binding else b"fixed synthetic bytes\n"
            value = native_capture_fixture(stdout=rig.failure_stdout if failed and rig.failure_stdout is not None else stdout,
                stderr=rig.failure_stderr if failed else b"",
                ok=not failed, returncode=1 if failed else 0, primary_error="command exited 1" if failed else None)
            rig.originals.append(value)
            rig.original_snapshots.append(dict(vars(value)))
            rig.session.persisted_bytes += sum(value.persisted)
            rig.failed = failed
            return value

        def outputs(directory, identity, session, *, deadline):
            session.ensure_idle(deadline=deadline)
            rig.outputs.append(directory)
            if len(rig.runs) - 1 == rig.output_error_at:
                raise c.VerificationError("FIXTURE_OUTPUT_FAILURE")
            session.persisted_bytes += 7
            return {"files": 1, "bytes": 7, "diagnostic_bytes": 7}

        rig.session = SimpleNamespace(uid=61001, gid=61001, persisted_bytes=0, ensure_idle=idle, run=run)
        rig.scan = outputs
        return rig

    def _gate(self, rig, phase="source"):
        c = rig.c
        _python, _prefix, modules, tooling = c.store_native_layout(rig.paths, phase)
        rig.binding = {"wheelSha256": None if phase == "source" else "e" * 64,
            "files": {name: {"path": str(tooling / name.removeprefix("fastlane/") if name.startswith("fastlane/")
                                       else modules / name.removeprefix("src/")), "sha256": "a" * 64}
                      for name in rig.checks.STORE_NATIVE_PRODUCTS}}
        clock = SimpleNamespace(monotonic=lambda: rig.clock)
        with patch.object(c, "time", clock), patch.object(rig.checks, "time", clock), \
                patch.object(c, "check_capacity"), patch.object(c, "require_retained_header"), \
                patch.object(c, "store_native_bindings", side_effect=lambda *a, **k: (rig.binding, rig.outside)), \
                patch.object(c, "store_native_directory", return_value=(5, 7, 0, 0, stat.S_IFDIR | 0o755)), \
                patch.object(c, "store_native_outputs", side_effect=rig.scan), \
                patch.object(c, "dispose_store_native_directory", side_effect=lambda path, *a, **k: rig.removals.append(path)), \
                patch.object(c, "create_file"), patch.object(c, "store_native_file_binding", return_value={"sha256": "f" * 64}), \
                patch.object(c, "parse_store_native_case", side_effect=lambda _result, _paths, _platform, _phase, subcase, identifier, *a, **k:
                              {"subcase": subcase, "test_id": identifier, "inner_observed_bytes": rig.inner_bytes}), \
                patch.object(c, "original_native_capture", wraps=c.original_native_capture) as capture, \
                patch.object(Path, "mkdir"), patch.object(c.os, "chmod"), patch.object(c.os, "chown"):
            result = c.perform_step(c.Step("store-lane-native-" + phase, kind="store-native", seconds=300),
                rig.paths, rig.session, rig.checks, {}, rig.platform, deadline=1000.0, native_abi=rig.abi, store_native=rig.state)
            rig.capture_calls.extend(capture.call_args_list)
            return result

    def test_each_row_keeps_one_original_and_one_absolute_phase_with_reusable_bound_source_control(self):
        for platform in ("linux", "macos"):
            with self.subTest(platform=platform):
                rig = self._rig(platform)
                with patch.object(rig.c, "native_failure_diagnostic") as diagnostic:
                    source = self._gate(rig)
                diagnostic.assert_not_called()
                self.assertTrue(source.ok, source.details)
                self.assertEqual(len(rig.runs), 16)  # Binding plus all15 source rows.
                self.assertEqual(len(rig.outputs), 16)
                self.assertEqual(len(rig.removals), 16)
                self.assertIs(rig.state.source_control, rig.originals[1])
                self.assertEqual(rig.state.phases["source"], tuple(rig.originals))
                self.assertTrue(all(row["conservative_accounted_bytes"] == 18 + sum(original.persisted)
                                    for row, original in zip(source.details["rows"], rig.originals[1:])))
                commands = rig.runs[1:]
                self.assertEqual({argv[argv.index("--deadline") + 1] for argv, _ in commands}, {"310.0"})
                self.assertEqual([argv[argv.index("--subcase") + 1] for argv, _ in commands],
                                 [case for case, _ in rig.checks.store_lane_native_rows(ROOT, "source")])
                for index, (argv, options) in enumerate(rig.runs):
                    self.assertEqual(options["profile"], "ordinary")
                    self.assertIs(options["dispose_retained_domain"], False)
                    self.assertEqual((options["seconds"], options["cpu_seconds"], options["output_limit"]), (20, 20, 65536))
                    self.assertEqual(options["absolute_deadline"], min(310.0, 30.0 + index))
                    if index:
                        self.assertEqual(argv[1:4], ("-I", "-S", "-B"))
                with patch.object(rig.c, "native_failure_diagnostic") as diagnostic:
                    wheel = self._gate(rig, "wheel")
                diagnostic.assert_not_called()
                self.assertTrue(wheel.ok, wheel.details)
                self.assertEqual(len(rig.runs), 31)
                self.assertEqual(len(rig.environments), 31)
                self.assertEqual(len(rig.state.phases["wheel"]), 15)
                self.assertFalse(any("ordinary-at-exit-control" in argv for argv, _ in rig.runs[16:]))
                for index in (0, 16):
                    argv, options = rig.runs[index]
                    self.assertIsNone(rig.capture_calls[index].kwargs["store_native_diagnostic"])
                    for key, leaf in (("HOME", "home"), ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")):
                        forbidden = {**options["env"], key: str(Path(argv[7]) / leaf)}
                        with self.assertRaisesRegex(sandbox_module().SessionError, "fixed clean-environment boundary"):
                            rig.boundary._environment(forbidden, deadline=options["absolute_deadline"])
                for phase, calls in (("source", rig.capture_calls[1:16]), ("wheel", rig.capture_calls[17:])):
                    modules = rig.c.store_native_layout(rig.paths, phase)[2]
                    expected_files = {str(modules / name.removeprefix("src/")): name
                                      for name in rig.checks.STORE_NATIVE_PRODUCTS if name.endswith(".py")}
                    expected_files.update({str(rig.paths.source / name): name
                                           for name in rig.c.STORE_NATIVE_FIXTURES if name.endswith(".py")})
                    for call, (subcase, identifier) in zip(calls, rig.checks.store_lane_native_rows(ROOT, phase)):
                        scope = call.kwargs["store_native_diagnostic"]
                        self.assertEqual((scope.phase, scope.subcase, scope.identifier), (phase, subcase, identifier))
                        self.assertEqual(dict(scope.filenames), expected_files)
                        with self.assertRaises(AttributeError):
                            scope.identifier = "foreign"
                        with self.assertRaises(TypeError):
                            scope.filenames["/private/foreign.py"] = "tests/foreign.py"
                # A later mutation of the test's binding dictionary cannot
                # rewrite the already-frozen per-original diagnostic scope.
                rig.binding["files"]["src/mobile_release/_command_process.py"]["path"] = "/private/foreign.py"
                self.assertEqual(dict(scope.filenames), expected_files)
        rig = self._rig()
        self.assertFalse(self._gate(rig, "wheel").ok)
        self.assertEqual(rig.runs, [])

    def test_capture_failure_retains_first_error_and_never_walks_unknown_or_runs_another_row(self):
        private = "PRIVATE_STORE_NATIVE_DIAGNOSTIC_CANARY"
        frame = lambda path, line: f'  File "{path}", line {line}, in {private}\n'.encode()
        faults = ("bound", "unbound", "foreign", "duplicate", "malformed", "private-field", "prerequisite",
                  "class-record", "stdout-marker", "ruby-binding", "parser-exception", "parser-interrupt",
                  "parser-expiry", "scan-exception", "scan-expiry")
        for phase in ("source", "wheel"):
            for fault in faults:
                with self.subTest(phase=phase, fault=fault):
                    rig = self._rig()
                    c = rig.c
                    if phase == "wheel":
                        self.assertTrue(self._gate(rig).ok)
                    before = len(rig.runs)
                    inventory = rig.checks.store_lane_native_rows(ROOT, phase)
                    index = next(index for index, (subcase, _) in enumerate(inventory) if subcase == "success0")
                    identifier = inventory[index][1]
                    rig.fails_at = before if fault == "ruby-binding" else before + index + 1
                    relative = "tests/workflow/test_store_lane_native.py"
                    fixture = "tests/workflow/store_lane_native_fixture.py"
                    product = "src/mobile_release/_command_process.py"
                    modules = c.store_native_layout(rig.paths, phase)[2]
                    opposite = c.store_native_layout(rig.paths, "wheel" if phase == "source" else "source")[2]
                    rejected = (frame(rig.paths.work / "source-build" / product, 71)
                                + frame(opposite / "mobile_release/_command_process.py", 72)
                                + frame("/private/" + private + "/" + relative, 73)
                                + frame(modules / "mobile_release/unbound.py", 74))
                    headers = (frame(rig.paths.source / relative, 201) + frame(rig.paths.source / fixture, 202)
                               + frame(modules / "mobile_release/_command_process.py", 203)) * 4
                    expected_locations = ([{"file": relative, "line": 201}, {"file": fixture, "line": 202},
                                           {"file": product, "line": 203}] * 4)[-8:]
                    callback = {"id": identifier, "outcome": "error", "category": "os-error", "errno": 2, "returncode": None}
                    diagnostic_phase = "tests"
                    if fault == "foreign":
                        callback["id"] = next(value for _, value in inventory if value != identifier)
                    elif fault == "private-field":
                        callback["message"] = private
                    elif fault == "prerequisite":
                        diagnostic_phase, callback["id"] = "prerequisite", "system-code"
                    elif fault == "class-record":
                        callback["id"] = "setUpClass (workflow.test_store_lane_native.StoreLaneNativeTests)"
                    diagnostic = {"schema": 1, "phase": diagnostic_phase, "records": [callback]}
                    marker = c.NATIVE_DIAGNOSTIC_PREFIX.encode() + c.store_native_wire(diagnostic)
                    if fault == "duplicate":
                        marker *= 2
                    elif fault == "malformed":
                        marker = c.NATIVE_DIAGNOSTIC_PREFIX.encode() + b"not-json\n"
                    elif fault == "stdout-marker":
                        rig.failure_stdout, marker = marker, b""
                    rig.failure_stderr = (rejected + (b"" if fault == "unbound" else headers)
                        + f"    private_source('{private}')\nFileNotFoundError: /private/{private}\n".encode() + marker)
                    native_parser, native_scan = c.native_failure_diagnostic, c._native_bound_failure_locations

                    def parse(text, expected, *, deadline):
                        if fault == "parser-exception":
                            raise RuntimeError(private)
                        if fault == "parser-interrupt":
                            raise KeyboardInterrupt(private)
                        if fault == "parser-expiry":
                            rig.clock = deadline
                        return native_parser(text, expected, deadline=deadline)

                    def scan(text, filenames, *, deadline):
                        if fault == "scan-exception":
                            raise ValueError(private)
                        if fault == "scan-expiry":
                            rig.clock = deadline
                        return native_scan(text, filenames, deadline=deadline)

                    with patch.object(c, "native_failure_diagnostic", side_effect=parse) as parsed, \
                            patch.object(c, "_native_bound_failure_locations", side_effect=scan) as projected, \
                            patch.object(c, "read_regular", side_effect=AssertionError(private)) as read:
                        result = self._gate(rig, phase)
                    read.assert_not_called()
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error, "COMMAND_EXIT_OR_FINALITY")
                    self.assertEqual(len(rig.runs), rig.fails_at + 1)
                    # The failed/latched domain never authorizes another scan,
                    # original, disposal, or a replacement deadline.
                    self.assertEqual(len(rig.outputs), rig.fails_at)
                    self.assertEqual(len(rig.removals), rig.fails_at)
                    self.assertIn("unavailable", result.details["surviving_accounting"])
                    failed, original = result.details["captures"][-1], rig.originals[-1]
                    self.assertEqual(failed["status"], "FAIL")
                    self.assertEqual(failed["capture"], c.capture_observations(original))
                    self.assertEqual(vars(original), rig.original_snapshots[-1])
                    with self.assertRaisesRegex(c.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        c.require_original_finality(original)
                    self.assertEqual(set(rig.state.phases), set() if phase == "source" else {"source"})
                    expected_status = (["UNEXECUTED"] * len(inventory) if fault == "ruby-binding" else
                                       ["PASS"] * index + ["FAIL"] + ["UNEXECUTED"] * (len(inventory) - index - 1))
                    self.assertEqual([row["status"] for row in result.details["rows"]], expected_status)
                    if fault == "ruby-binding":
                        parsed.assert_not_called()
                    else:
                        parsed.assert_called_once_with(rig.failure_stderr.decode("utf-8", "replace"), (identifier,),
                                                       deadline=rig.runs[-1][1]["absolute_deadline"])
                    if fault in {"bound", "unbound"}:
                        self.assertEqual(failed["native_diagnostic"], diagnostic)
                        projected.assert_called_once_with(rig.failure_stderr.decode("utf-8", "replace"),
                            rig.capture_calls[-1].kwargs["store_native_diagnostic"].filenames,
                            deadline=rig.runs[-1][1]["absolute_deadline"])
                        if fault == "bound":
                            self.assertEqual(failed["native_test_locations"], expected_locations)
                        else:
                            self.assertNotIn("native_test_locations", failed)
                    else:
                        self.assertNotIn("native_diagnostic", failed)
                        self.assertNotIn("native_test_locations", failed)
                        if not fault.startswith("scan-"):
                            projected.assert_not_called()
                    if fault.startswith(("parser-", "scan-")):
                        self.assertEqual(failed["store_native_diagnostic_error"],
                                         {"error": "STORE_NATIVE_DIAGNOSTIC_UNAVAILABLE"})
                    public = c.store_native_wire(result.details).decode()
                    for hidden in (private, str(rig.paths.source), str(modules), "/private/", "private_source"):
                        self.assertNotIn(hidden, public)
        rig = self._rig()
        rig.output_error_at = 1
        result = self._gate(rig)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "FIXTURE_OUTPUT_FAILURE")
        self.assertEqual(len(rig.runs), 2)
        self.assertEqual(len(rig.removals), 1)
        rig = self._rig()
        rig.inner_bytes = rig.c.STORE_NATIVE_CASE_BYTES
        result = self._gate(rig)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "STORE_NATIVE_CASE_OUTPUT_BOUND")
        self.assertEqual(len(rig.runs), 2)
        self.assertEqual(len(rig.removals), 1)  # The row cannot pass or dispose after the combined bound fails.
        rig = self._rig()
        rig.advance = 20.0
        result = self._gate(rig)
        self.assertFalse(result.ok)
        self.assertEqual(len(rig.runs), 1)
        self.assertEqual(rig.removals, [])

    def test_semantic_row_requires_original_finality_exact_callback_and_bound_marker_not_log_text(self):
        c, checks = controller_module(), ci_module("ci_checks")
        paths = fixture_paths(c)
        subcase, identifier = checks.store_lane_native_rows(ROOT, "source")[0]
        directory = Path("/fixture/work/store-lane/source/case-01")
        case = directory / "tmp/mrk-store-native-synthetic"
        binding, outside = {"source": "fixed"}, {"fixtures": {"tests/workflow/store_lane_native_fixture.rb": {"sha256": "a" * 64}}}
        def file(relative):
            return {"path": str(case / relative), "sha256": "a" * 64, "bytes": 17, "device": 5, "inode": 77,
                    "mode": stat.S_IFREG | 0o600, "uid": 61001, "gid": 61001}
        data = {"version": 1, "phase": "source", "subcase": subcase, "testId": identifier, "caseRoot": str(case),
                "productRetained": False, "persistedBytes": 42, "launcher": file("launcher/fastlane/run_lane.rb"),
                "request": file("request.json"), "bindingSha256": hashlib.sha256(c.store_native_wire(binding)).hexdigest(),
                "facts": {"ordinaryHookObserved": True}, "fixtureRemoved": True}
        stderr = f"{identifier.rsplit('.', 1)[1]} ({identifier}) ... ok\n\nRan 1 test in 0.01s\n\nOK\n".encode()
        def captured(value, **kwargs):
            return native_capture_fixture(b"bounded actual library log\nMRK_STORE_NATIVE_RESULT=" + c.store_native_wire(value), stderr, **kwargs)
        def parse(value):
            return c.parse_store_native_case(value, paths, "linux", "source", subcase, identifier, directory,
                                             binding, outside, owner=(61001, 61001, 5), deadline=1000.0)
        with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(Path, "lstat", side_effect=FileNotFoundError):
            self.assertEqual(parse(captured(data))["subcase"], subcase)
            mutations = [{**data, "version": True}, {**data, "version": 1.0}, {**data, "subcase": "success0"},
                         {**data, "testId": identifier + "_other"}, {**data, "bindingSha256": "b" * 64},
                         {**data, "persistedBytes": c.STORE_NATIVE_CASE_BYTES + 1}, {**data, "fixtureRemoved": False},
                         {**data, "launcher": {**data["launcher"], "uid": 0}},
                         {**data, "request": {**data["request"], "device": 6}}, {**data, "facts": {"ordinaryHookObserved": 1}}]
            for index, value in enumerate(mutations):
                with self.subTest(mutation=index), self.assertRaises(c.VerificationError):
                    parse(captured(value))
            for result in (native_capture_fixture(b"log only\n", stderr),
                           native_capture_fixture(captured(data).stdout + captured(data).stdout, stderr),
                           native_capture_fixture(captured(data).stdout, stderr.replace(b"... ok", b"... skipped"))):
                with self.assertRaises(c.VerificationError):
                    parse(result)
        with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(Path, "lstat", side_effect=AssertionError("no access before finality")) as read:
            with self.assertRaisesRegex(c.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                parse(captured(data, domain_finality=False))
            read.assert_not_called()

    def test_independent_survivor_accounting_counts_hardlinks_once_and_rejects_type_owner_and_bounds(self):
        c = controller_module()
        directory = Path("/fixture/work/store-lane/source/case-01")
        identity = (5, 7, 0, 0, stat.S_IFDIR | 0o755)
        root = SimpleNamespace(st_dev=5, st_ino=7, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
        def entry(name, inode=9, size=17, **changes):
            fields = dict(st_dev=5, st_ino=inode, st_uid=61001, st_gid=61001,
                          st_mode=stat.S_IFREG | 0o600, st_nlink=2, st_size=size)
            fields.update(changes)
            return SimpleNamespace(name=name, path=str(directory / name), stat=lambda **_k: SimpleNamespace(**fields))
        @contextmanager
        def scan(items):
            yield iter(items)
        def run(items, session):
            with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(Path, "lstat", return_value=root), patch.object(Path, "resolve", return_value=directory), \
                    patch.object(c.os, "scandir", side_effect=lambda _p: scan(items)):
                return c.store_native_outputs(directory, identity, session, deadline=1000.0)
        session = SimpleNamespace(uid=61001, gid=61001, persisted_bytes=123, ensure_idle=Mock())
        result = run([entry("terminal.part"), entry("terminal.json")], session)
        self.assertEqual((result["files"], result["bytes"], result["diagnostic_bytes"], session.persisted_bytes), (1, 17, 17, 140))
        session.ensure_idle.assert_called_once_with(deadline=1000.0)
        for altered in ([entry("link", st_mode=stat.S_IFLNK | 0o777)], [entry("foreign", st_uid=61002)],
                        [entry("other-device", st_dev=6)], [entry("loose", st_mode=stat.S_IFREG | 0o644)],
                         [entry("observation.json", size=65537)], [entry("oversize", size=1024**2 + 1)],
                         [entry("terminal.part", size=65537), entry("terminal.json", size=65537)],
                        [entry(f"file-{n}", inode=n + 10, size=1024**2, st_nlink=1) for n in range(9)]):
            with self.subTest(names=[row.name for row in altered]), self.assertRaises(c.VerificationError):
                run(altered, SimpleNamespace(uid=61001, gid=61001, persisted_bytes=0, ensure_idle=Mock()))
        blocked = SimpleNamespace(ensure_idle=Mock(side_effect=c.VerificationError("ORIGINAL_DOMAIN_UNKNOWN")))
        with patch.object(Path, "lstat", side_effect=AssertionError("unknown domain must not be read")) as read:
            with self.assertRaisesRegex(c.VerificationError, "ORIGINAL_DOMAIN_UNKNOWN"):
                c.store_native_outputs(directory, identity, blocked, deadline=1000.0)
            read.assert_not_called()

    def test_device_qualification_refuses_before_native_entry_and_disposal_requires_original_identity(self):
        c = controller_module()
        path = Path("/fixture/work/store-lane/source/case-01")
        root = SimpleNamespace(st_dev=5, st_ino=7, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
        probe = SimpleNamespace(st_dev=6, st_uid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        session = SimpleNamespace(uid=61001, gid=61001, ensure_idle=Mock())
        def observe(current):
            return probe if current.name == "same-device-probe" else root
        with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), patch.object(Path, "mkdir"), \
                patch.object(Path, "resolve", autospec=True, side_effect=lambda current, **k: current), \
                patch.object(Path, "lstat", autospec=True, side_effect=observe), \
                patch.object(c.os, "chmod"), patch.object(c.os, "chown"), patch.object(c, "create_file"), \
                patch.object(Path, "unlink") as remove:
            with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_SCRATCH_DEVICE"):
                c.store_native_directory(path, session, deadline=1000.0)
            remove.assert_not_called()  # Failed qualification keeps evidence; never relax device equality.
            probe.st_dev = 5
            self.assertEqual(c.store_native_directory(path, session, deadline=1000.0), (5, 7, 0, 0, root.st_mode))
            remove.assert_called_once_with()
        remover = Mock()
        remover.avoids_symlink_attacks = True
        with patch.object(c, "time", SimpleNamespace(monotonic=lambda: 10.0)), patch.object(c.os, "open", return_value=23), \
                patch.object(c.os, "stat", return_value=root), patch.object(c, "close_owned") as close, \
                patch.object(c.shutil, "rmtree", remover):
            with self.assertRaisesRegex(c.VerificationError, "STORE_NATIVE_DIRECTORY_CHANGED"):
                c.dispose_store_native_directory(path, (5, 8, 0, 0, root.st_mode), session, deadline=1000.0)
            remover.assert_not_called()
            close.assert_called_once_with(23)
        self._python_case_handoff_contracts()

    def _python_case_handoff_contracts(self):
        fixture = native_fixture
        source = Path("/fixture/session/source")
        work = source.parent / "work"
        ruby = Path("/fixture/tools/ruby")
        # Every fixed ordinal is checked; adversarial custody cases share the
        # first row in each phase rather than multiplying equivalent tests.
        faults = ("cached", "phase", "case-name", "relative-case", "source-link", "parent-link",
                  "root-owner", "root-mode", "root-device", "leaf-owner", "leaf-group", "leaf-mode",
                  "leaf-device", "leaf-type", "leaf-link", "cache-selector", "foreign-environment",
                  "foreign-tempdir", "bytes-tempdir", "tempdir-result")
        for phase in ("source", "wheel"):
            for ordinal, (subcase, _) in enumerate(fixture.case_inventory(phase), 1):
                for fault in ("valid", *(faults if ordinal == 1 else ())):
                    with self.subTest(case_handoff=(phase, ordinal, fault)):
                        directory = work / "store-lane" / phase / f"case-{ordinal:02d}"
                        prefix = source if phase == "source" else work / "wheel-venv"
                        modules = source / "src" if phase == "source" else prefix / "lib/python3.11/site-packages"
                        wheel = None if phase == "source" else work / "wheels/fixed.whl"
                        configuration = fixture.Configuration(phase, source, prefix, modules, ruby,
                            directory.parent / "binding.json", directory, 100.0, subcase, wheel,
                            None if phase == "source" else "a" * 64)
                        if fault == "phase":
                            configuration = replace(configuration, phase="unknown")
                        elif fault == "case-name":
                            configuration = replace(configuration, case_directory=directory.with_name("case-99"))
                        elif fault == "relative-case":
                            configuration = replace(configuration, case_directory=Path("case-01"))
                        nodes = {}
                        def node(path, *, uid=0, gid=0, mode=0o755, regular=False):
                            nodes[path] = SimpleNamespace(st_dev=5, st_uid=uid, st_gid=gid,
                                st_mode=(stat.S_IFREG if regular else stat.S_IFDIR) | mode, st_size=17)
                        for path in (source, prefix, modules, work, work / "store-lane", directory.parent, directory):
                            node(path)
                        for name in ("home", "tmp", "gem-cache", "bundle-config", "bundle-home"):
                            node(directory / name, uid=61001, gid=61001, mode=0o700)
                        node(ruby, mode=0o555, regular=True)
                        node(configuration.binding_file, uid=61001, gid=61001, mode=0o600, regular=True)
                        entry = source / "tests/workflow/store_lane_native_fixture.py"
                        node(entry, mode=0o444, regular=True)
                        if wheel is not None:
                            node(wheel, mode=0o444, regular=True)
                        changed = {"root-owner": (directory, "st_uid", 61001),
                            "root-mode": (directory, "st_mode", stat.S_IFDIR | 0o777),
                            "root-device": (directory, "st_dev", 6),
                            "leaf-owner": (directory / "tmp", "st_uid", 0),
                            "leaf-group": (directory / "tmp", "st_gid", 0),
                            "leaf-mode": (directory / "tmp", "st_mode", stat.S_IFDIR | 0o755),
                            "leaf-device": (directory / "tmp", "st_dev", 6),
                            "leaf-type": (directory / "tmp", "st_mode", stat.S_IFREG | 0o700)}
                        if fault in changed:
                            path, name, value = changed[fault]
                            setattr(nodes[path], name, value)
                        environment = {"HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
                            "TMP": str(work / "tmp"), "TEMP": str(work / "tmp"),
                            "GEM_SPEC_CACHE": str(directory / "gem-cache"),
                            "BUNDLE_APP_CONFIG": str(directory / "bundle-config"),
                            "BUNDLE_USER_HOME": str(directory / "bundle-home")}
                        if fault == "cache-selector":
                            environment["BUNDLE_USER_HOME"] = str(work / "bundle-home")
                        elif fault == "foreign-environment":
                            environment["HOME"] = "/unaccounted/home"
                        before = environment.copy()
                        scratch = str(directory / "tmp")
                        cached = scratch if fault == "cached" else "/foreign/tmp" if fault == "foreign-tempdir" else (
                            scratch.encode() if fault == "bytes-tempdir" else None)
                        def resolved(path, **_options):
                            self.assertIn(path, nodes, "unexpected fixture filesystem lookup")
                            return path.with_name("alias-target") if ((fault == "source-link" and path == source) or
                                (fault == "parent-link" and path == directory.parent)) else path
                        def observed(path, **_options):
                            self.assertIn(path, nodes, "unexpected fixture filesystem lookup")
                            return nodes[path]
                        flags = SimpleNamespace(**dict.fromkeys(("isolated", "ignore_environment", "no_user_site",
                            "no_site", "safe_path", "dont_write_bytecode"), 1))
                        with patch.object(fixture, "os", SimpleNamespace(environ=environment, geteuid=lambda: 61001,
                                getegid=lambda: 61001, access=lambda *_a: True, X_OK=os.X_OK)), \
                                patch.object(fixture, "sys", SimpleNamespace(implementation=SimpleNamespace(name="cpython"),
                                    version_info=(3, 11), flags=flags, path=["/stdlib-only"])), \
                                patch.object(fixture, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                                patch.object(fixture, "__file__", str(entry)), \
                                patch.object(Path, "resolve", autospec=True, side_effect=resolved), \
                                patch.object(Path, "stat", autospec=True, side_effect=observed), \
                                patch.object(Path, "is_symlink", autospec=True,
                                    side_effect=lambda path: fault == "leaf-link" and path == directory / "tmp"), \
                                patch.object(fixture.tempfile, "tempdir", cached), \
                                patch.object(fixture.tempfile, "_get_default_tempdir",
                                    side_effect=AssertionError("no ambient tempfile probe permitted")) as fallback, \
                                patch.object(fixture.tempfile, "gettempdir", wraps=fixture.tempfile.gettempdir) as temporary:
                            if fault == "tempdir-result":
                                temporary.return_value = "/foreign/tmp"
                            if fault not in {"valid", "cached"}:
                                with self.assertRaisesRegex(AssertionError, "Store native fixture:"):
                                    configuration.select_environment()
                                self.assertEqual(environment, before)
                                self.assertEqual(fixture.tempfile.tempdir, scratch if fault == "tempdir-result" else cached)
                            else:
                                configuration.select_environment()
                                self.assertEqual(fixture.tempfile.tempdir, scratch)
                                self.assertEqual({key: environment[key] for key in ("HOME", "TMPDIR", "TMP", "TEMP")},
                                    {"HOME": str(directory / "home"), "TMPDIR": scratch, "TMP": scratch, "TEMP": scratch})
                                configuration.validate()  # Repeated checks use explicit source/case, not the old HOME.
                                if ordinal == 1:
                                    environment.clear()
                                    environment.update(before)
                                    fixture.tempfile.tempdir = cached  # Restore only this patched synthetic fresh-process state.
                                    original_import = builtins.__import__
                                    stopped = RuntimeError("first project import reached after entry selection")
                                    def importing(name, *args, **kwargs):
                                        if name == "workflow":
                                            self.assertEqual(environment["HOME"], str(directory / "home"))
                                            self.assertEqual(fixture.tempfile.tempdir, scratch)
                                            raise stopped
                                        return original_import(name, *args, **kwargs)
                                    arguments = ["--phase", phase, "--source-root", str(source), "--prefix", str(prefix),
                                        "--module-root", str(modules), "--ruby", str(ruby), "--binding-file", str(configuration.binding_file),
                                        "--case-directory", str(directory), "--deadline", "100.0", "--subcase", subcase]
                                    if wheel is not None:
                                        arguments += ["--wheel", str(wheel), "--wheel-sha256", "a" * 64]
                                    with patch.object(builtins, "__import__", side_effect=importing):
                                        with self.assertRaises(RuntimeError) as caught:
                                            fixture.main(arguments)
                                    self.assertIs(caught.exception, stopped)
                            fallback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
