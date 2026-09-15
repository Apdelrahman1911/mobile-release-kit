"""Adversarial matrix data contracts and finite-entrypoint admission tests."""
from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import io
import json
import linecache
import os
import stat
import sys
import tempfile
import time
import traceback
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mobile_release

from . import local_signing_matrix_contract as contract
from . import local_signing_persistent_fixture as fixture
from . import local_signing_semantic_catalog as semantic_catalog
from . import local_signing_semantic_fixture as semantic_fixture
from . import run_local_signing_matrix as runner
from .workflow_harness import load_workflow


def event(number):
    return {"index": number, "operation": "write", "slot": "<ROOT>/session-<TOKEN>/state.pending",
            "origin": "mobile_release.local_signing:_write", "phase": "recovery", "occurrence": number,
            "details": {}, "succeeded": True}


class ObservedScan:
    """Count actual lazy filesystem reads and fail if the caller over-consumes."""
    def __init__(self, scan, limit, *, read_error=False, close_error=False):
        self.scan, self.limit = scan, limit
        self.read_error, self.close_error = read_error, close_error
        self.count, self.closed = 0, False

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if self.count >= self.limit:
            raise AssertionError("directory enumerated past its rejection bound")
        if self.read_error and self.count == 1:
            raise OSError("injected directory read failure")
        value = next(self.scan)
        self.count += 1
        return value

    def __exit__(self, *_):
        self.scan.close()
        self.closed = True
        if self.close_error:
            raise OSError("injected directory close failure")


class SemanticSelectorContractTests(unittest.TestCase):
    """Inert routing/finality contracts; these do NOT supply native evidence."""

    def test_closed_subset_preserves_semantics_and_global_not_context_filtered_occurrences(self):
        from collections import Counter
        self.assertEqual(Counter(case.kind for case in semantic_catalog.CASES.values()), {
            "seed": 42, "recovery": 50, "focused": 15, "command": 20, "healthy": 1, "native-prefix": 3})
        self.assertFalse(semantic_catalog.definition()["completeRequiredUnion"])
        self.assertEqual(len(semantic_catalog.SEEDS), 28)
        for number, occurrence in ((1, 3), (2, 4), (3, 5), (4, 5), (7, 6), (8, 6)):
            self.assertEqual(semantic_catalog.case(f"R/new/{number:02}").selector.occurrence, occurrence)
        for identifier in ("R/03", "R/20", "S/final-absent/none"):
            self.assertEqual(semantic_catalog.case(identifier).expected, "absent")
        seed = semantic_catalog.case("S/active-build-pending/none")
        self.assertEqual((seed.expected, seed.resolution, seed.selector.occurrence),
                         ("refused-unknown-resource", "recovered-with-conflict", 3))
        for identifier in ("C/caller/02", "R/new/02"):
            self.assertIs(dict(semantic_catalog.case(identifier).selector.context)["beforeGrant"], True)
        with self.assertRaisesRegex(AssertionError, "unknown semantic case"):
            semantic_catalog.case("R/extra-success")

    def test_direct_selector_ignores_global_index_but_rejects_route_and_live_context_drift(self):
        selector = semantic_catalog.case("R/new/02").selector
        observed = {"index": 91234, "operation": selector.operation, "slot": selector.slot,
                    "origin": selector.origin, "phase": selector.phase, "occurrence": selector.occurrence,
                    "details": {"destination": selector.destination}}
        self.assertTrue(selector.routes(observed))
        observed["index"] = 1
        self.assertTrue(selector.routes(observed))
        for field, value in (("origin", "model"), ("slot", selector.slot + "-other"),
                             ("phase", "setup"), ("occurrence", 1)):
            with self.subTest(field=field):
                changed = {**observed, field: value}
                self.assertFalse(selector.routes(changed))
        self.assertFalse(selector.routes({**observed, "details": {"destination": selector.destination + "-other"}}))
        context = dict(selector.context)
        selector.check_context(context)
        for field, value in (("beforeGrant", 1), ("operationKind", "observe"), ("operationPhase", "SETTLED")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                selector.check_context({**context, field: value})
        with self.assertRaises(AssertionError):
            selector.check_context({key: value for key, value in context.items() if key != "beforeGrant"})

    def test_matching_tuple_cannot_skip_a_wrong_context_or_succeed_when_cut_is_missing(self):
        with tempfile.TemporaryDirectory(prefix="mrk-semantic-selector-inert-") as temporary:
            root = Path(temporary)
            fixture.initialize(root)
            selector = semantic_catalog.case("C/caller/01").selector
            trace = semantic_fixture.SemanticTrace(root, "inert", selector)
            slot = root / "home/.mobile-release-signing" / ("session-" + "a" * 32) / "state.pending"
            wrong = {**dict(selector.context), "operationPhase": "SETTLED", "recoveryAttempt": False}
            with patch.object(trace, "observe_context", side_effect=AssertionError("wrong phase cannot select")), \
                    patch.object(trace, "cut", side_effect=AssertionError("must not cut")):
                trace.begin("replace", slot, selector.origin, {"destination": selector.destination})
            self.assertEqual(trace.occurrences[(selector.operation, selector.slot, selector.origin, "setup")], 1)
            self.assertIsNone(trace.selected_event)
            # Use the actual declared phase in a fresh inert trace. A matching
            # event is selected once; a later correct context cannot repair it.
            trace = semantic_fixture.SemanticTrace(root, "inert", selector)
            trace.phase = selector.phase
            with patch.object(trace, "observe_context", return_value=wrong), \
                    self.assertRaisesRegex(AssertionError, "semanticContextMismatch"):
                trace.begin("replace", slot, selector.origin, {"destination": selector.destination})
            with patch.object(trace, "observe_context", side_effect=AssertionError("must not retry context")):
                trace.begin("replace", slot, selector.origin, {"destination": selector.destination})
            with self.assertRaisesRegex(AssertionError, "selectedSemanticCutNotReached"):
                trace.result()

    def test_evidence_reader_rejects_linked_replaced_oversized_and_unknown_close_outputs(self):
        with tempfile.TemporaryDirectory(prefix="mrk-semantic-output-inert-") as temporary:
            root = Path(temporary)
            path = root / "step.json"
            fixture.write_json(path, {"synthetic": True})
            self.assertEqual(fixture.read_case_json(root, "step"), {"synthetic": True})
            os.link(path, root / "alias")
            with self.assertRaisesRegex(AssertionError, "metadata"):
                fixture.read_case_json(root, "step")
            (root / "alias").unlink()
            replacement = root / "replacement.json"
            fixture.write_json(replacement, {"synthetic": True})
            real_read, replaced = os.read, []
            def replace_after_read(descriptor, count):
                data = real_read(descriptor, count)
                if not replaced:
                    replacement.replace(path)
                    replaced.append(True)
                return data
            with patch.object(fixture.os, "read", side_effect=replace_after_read), \
                    self.assertRaisesRegex(AssertionError, "changed during read"):
                fixture.read_case_json(root, "step")
            real_close, closed = os.close, []
            def lost_close(descriptor):
                closed.append(descriptor)
                real_close(descriptor)  # Actual once-close; only its return is injected as lost.
                raise OSError("inert close return unavailable")
            with patch.object(fixture.os, "close", side_effect=lost_close), \
                    self.assertRaisesRegex(AssertionError, "original close is unknown"):
                fixture.read_case_json(root, "step")
            self.assertEqual(len(closed), 1)
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaises(AssertionError):
                fixture.read_case_json(root, "step")
            with self.assertRaisesRegex(AssertionError, "already exists"):
                semantic_fixture._new_step(root, "step")
            path.unlink()
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(AssertionError, "byte bound"):
                fixture.read_fixture_file(path, limit=4)

    def test_output_without_original_return_or_unknown_custody_cannot_discharge_debt(self):
        with tempfile.TemporaryDirectory(prefix="mrk-semantic-finality-inert-") as temporary:
            root = Path(temporary)
            fixture.initialize(root)
            identity = fixture._directory_identity(root)
            with patch.dict(fixture._CASE_CUSTODY, {str(root): identity}), \
                    patch.dict(fixture._CASE_RECOVERY_DEBT, {str(root): identity}):
                context = fixture.pin_case_context(root)
                # No actual worker is started: this is an output-only
                # counterexample, never a native/finality success simulation.
                with patch.object(fixture, "run_worker", return_value=None), \
                        self.assertRaisesRegex(AssertionError, "missing original case return"):
                    semantic_fixture.recovery_step(root, "no-return", token="a" * 32, manual="none",
                        expected="recovered", context=context, final=True)
                self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)
                error = OSError("inert original return unavailable")
                with patch.object(fixture, "run_worker", side_effect=error), self.assertRaises(OSError) as caught:
                    semantic_fixture.recovery_step(root, "lost-return", token="a" * 32, manual="none",
                        expected="recovered", context=context, final=True)
                self.assertIs(caught.exception, error)
                self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)
                fixture._CASE_CUSTODY[str(root)] = None
                from . import local_signing_case_owner as owner
                with patch.object(owner, "run_worker", side_effect=AssertionError("must not acquire")), \
                        self.assertRaisesRegex(AssertionError, "prior case custody remains unknown"):
                    semantic_fixture.recovery_step(root, "unknown", token="a" * 32, manual="none",
                        expected="recovered", context=context, final=True)
                self.assertEqual(fixture._CASE_RECOVERY_DEBT[str(root)], identity)

    def test_final_case_publication_rechecks_original_deadline_after_real_owned_removal(self):
        from . import local_signing_regression_fixture as regression_fixture
        with tempfile.TemporaryDirectory(prefix="mrk-semantic-final-cutoff-inert-") as temporary:
            parent = Path(temporary)
            clock = [0.0]
            real_remove = fixture.remove_case
            removed = []
            def inert_return(root, name, _task, **_unused):
                # Only model the trusted call's DATA return for this cutoff
                # unit contract. Never invoke its task/start a native worker or
                # accept these observations as platform execution evidence.
                fixture._CASE_CUSTODY[str(root)] = fixture._directory_identity(root)
                fixture.write_json(root / (name + ".json"), {"snapshot": {"nativeCalls": [None] * 50, "session": None}})
                return {"exit": 0, "originalAnchorWait": True, "originalWorkerWait": True,
                        "originalStatusEOF": True, "groupAbsentBeforeAnchorWait": True,
                        "deadlineTest": False, "runDeadlineExpired": False}
            def remove_at_cutoff(root):
                real_remove(root)  # Actual removal of this inert task-owned directory.
                removed.append(True)
                clock[0] = 1.0
            with patch.dict(fixture._CASE_CUSTODY), patch.dict(fixture._CASE_RECOVERY_DEBT), \
                    patch.object(fixture, "PHASE_DEADLINE", 1.0), \
                    patch.object(contract.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(fixture, "run_worker", side_effect=inert_return), \
                    patch.object(semantic_fixture, "assert_healthy_observation", return_value=None), \
                    patch.object(regression_fixture, "semantic_contributions", return_value=()), \
                    patch.object(fixture, "remove_case", side_effect=remove_at_cutoff), \
                    self.assertRaisesRegex(ValueError, "original matrix cutoff expired"):
                semantic_fixture.run_case(parent, "H/full-context")
            self.assertEqual(removed, [True])
            self.assertFalse((parent / "case").exists())

    def test_focused_manual_refusal_requires_observed_input_and_original_interruption(self):
        # Inert data-contract validation only: no terminal, signal, account or
        # original worker is acquired and this is not native branch evidence.
        def values(mode):
            event = {"index": 7, "operation": "manual/input", "slot": "tty", "origin": "owner",
                     "details": {"action": mode}}
            observation = {"eventIndex": 7, "action": mode}
            error = fixture.CredentialError("fictional refusal")
            if mode in {"wrong", "eof"}:
                event["succeeded"] = True
                observation["read"] = {"kind": mode, "characters": 6 if mode == "wrong" else 0}
            else:
                error = KeyboardInterrupt() if mode == "cancel" else fixture.OwnerResolutionRefused("fictional refusal")
            return SimpleNamespace(events=[event]), [observation], error
        fixture.assert_refusal_manual_evidence(SimpleNamespace(events=[]), [], "none",
                                               fixture.CredentialError("fictional refusal"))
        for mode in ("wrong", "eof", "cancel", "resolve"):
            with self.subTest(mode=mode):
                trace, observations, error = values(mode)
                fixture.assert_refusal_manual_evidence(trace, observations, mode, error)
                with self.assertRaisesRegex(AssertionError, "exactly once"):
                    fixture.assert_refusal_manual_evidence(trace, [], mode, error)
                observations[0]["eventIndex"] = 8
                with self.assertRaises(AssertionError):
                    fixture.assert_refusal_manual_evidence(trace, observations, mode, error)
                trace, observations, error = values(mode)
                if mode in {"wrong", "eof"}:
                    observations[0]["read"]["kind"] = "eof" if mode == "wrong" else "wrong"
                else:
                    trace.events[0]["succeeded"] = True
                with self.assertRaises(AssertionError):
                    fixture.assert_refusal_manual_evidence(trace, observations, mode, error)
                trace, observations, error = values(mode)
                wrong_error = KeyboardInterrupt() if mode in {"wrong", "eof", "resolve"} else fixture.CredentialError("not cancellation")
                with self.assertRaises(AssertionError):
                    fixture.assert_refusal_manual_evidence(trace, observations, mode, wrong_error)


class WorkloadContractTests(unittest.TestCase):
    """Closed routing and inert filesystem retention, never native evidence."""

    def test_finite_workloads_match_all_actual_profile_modes_without_admitting_unknowns(self):
        from collections import Counter
        from . import local_signing_workload as workload
        from unit import test_ios_profile_installation as profiles
        expected_roles = {"minimal-query-seed": 20, "persistent-original": 120, "automatic-recovery": 60,
                          "manual-recovery": 60, "focused-refusal": 60, "focused-owner": 60,
                          "bare-home-original": 60, "bare-home-recovery": 60,
                          "fresh-cli-recovery": 60, "account-native-flow": 120}
        self.assertEqual(dict(workload.WORKER_SECONDS), expected_roles)
        observed = []
        def boundary(_test, mode):
            observed.append(mode)
            return {"signalCount": 1, "cleanupAttempts": 1}
        # Only enumerate the real methods' finite calls with their sole native
        # boundary replaced before invocation. This runs no profile fixture.
        with patch.object(profiles.ProfileInstallationSignalTests, "run_boundary", new=boundary), \
                patch.object(profiles, "run_owned", side_effect=AssertionError("inert routing cannot launch")):
            for name in (
                "test_real_pending_signals_during_native_open_fstat_fdopen_and_close_are_owned",
                "test_original_unmocked_open_and_initial_fstat_interruptions_cannot_leak_files_or_descriptors",
                "test_actual_caller_handoff_and_repeated_cleanup_signals_do_not_rely_on_generator_gc",
                "test_successful_native_mutation_is_registered_before_deferred_cancellation",
                "test_first_signal_at_cleanup_entry_and_before_exit_dispatch_cannot_skip_ownership",
                "test_handler_restoration_and_partial_installation_cannot_swallow_or_abandon_cancellation",
                "test_late_setup_and_actual_materialized_body_cancellation_never_execute_following_build_code",
                "test_cleanup_failure_is_not_masked_by_deferred_cancellation_and_remaining_cleanup_runs",
            ):
                getattr(profiles.ProfileInstallationSignalTests(name), name)()
        self.assertEqual(len(observed), 50)
        self.assertEqual(set(observed), set(workload.PROFILE_SIGNAL_SECONDS))
        self.assertEqual(len(set(observed)), len(observed))
        self.assertEqual(Counter(workload.profile_signal_timeout(mode) for mode in observed), {15: 17, 60: 8, 120: 25})
        for callback, unknown in ((workload.worker_timeout, "unbounded"),
                                  (workload.profile_signal_timeout, "standalone-unreviewed"),
                                  (workload.recovery_timeout, "retry"), (workload.worker_timeout, 20)):
            with self.assertRaisesRegex(AssertionError, "unknown signing"):
                callback(unknown)
        with self.assertRaises(TypeError):
            workload.WORKER_SECONDS["persistent-original"] = 999

    def test_profile_signal_actual_launcher_transports_only_its_selected_temporary_parent(self):
        from . import local_signing_workload as workload
        from unit import test_ios_profile_installation as profiles
        selected = str(Path.cwd() / "inert-selected-profile-parent")
        ambient = str(Path.cwd() / "inert-ambient-profile-parent")
        original_cache, observed = tempfile.tempdir, []
        stopped = RuntimeError("inert request recorder; never launch or return a native result")

        def record(command, **options):
            observed.append((command, options))
            raise stopped

        # Invoke the actual caller, not its former whole-method mock. The sole
        # command boundary stops before any process, receipt or fixture exists.
        with patch.object(tempfile, "tempdir", selected), \
                patch.object(tempfile, "gettempdir", wraps=tempfile.gettempdir) as selection, \
                patch.object(tempfile, "_get_default_tempdir", side_effect=AssertionError("no default probe")), \
                patch.dict(os.environ, {"TMPDIR": ambient, "TMP": ambient, "TEMP": ambient,
                                        "MRK_INERT_UNRELATED_ENV": "must-not-be-forwarded"}), \
                patch.object(profiles, "run_owned", side_effect=record):
            for mode in workload.PROFILE_SIGNAL_SECONDS:
                with self.subTest(mode=mode), self.assertRaises(RuntimeError) as caught:
                    profiles.ProfileInstallationSignalTests().run_boundary(mode)
                self.assertIs(caught.exception, stopped)
                self.assertEqual(selection.call_count, len(observed))
                self.assertEqual(tempfile.tempdir, selected)
                command, options = observed[-1]
                self.assertEqual(command, [sys.executable, "-I", "-S", "-B",
                    str(Path(profiles.__file__).parents[1] / "workflow/profile_installation_fixture.py"),
                    str(Path(mobile_release.__file__).resolve().parent.parent), mode, selected])
                self.assertEqual(options, {"timeout": workload.profile_signal_timeout(mode), "capture": True,
                    "output_limit": 64 * 1024, "environ": {
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C",
                        "TMPDIR": selected, "TMP": selected, "TEMP": selected}})
            self.assertEqual(len(observed), 50)
        self.assertIs(tempfile.tempdir, original_cache)

    def test_profile_signal_bootstrap_pins_exact_parent_before_imports_or_work(self):
        path = Path(__file__).with_name("profile_installation_fixture.py")
        tree = ast.parse(path.read_text(), str(path))
        bootstrap, entry = [node for node in tree.body if isinstance(node, ast.If)]
        first_product_import = next(index for index, node in enumerate(tree.body)
                                    if isinstance(node, ast.ImportFrom) and node.module == "mobile_release")
        self.assertLess(tree.body.index(bootstrap), first_product_import)
        cache_writes = lambda node: [child for child in ast.walk(node) if isinstance(child, ast.Attribute)
            and isinstance(child.ctx, ast.Store) and isinstance(child.value, ast.Name)
            and (child.value.id, child.attr) == ("tempfile", "tempdir")]
        self.assertEqual(cache_writes(tree), cache_writes(bootstrap))
        code = compile(ast.Module(body=[bootstrap, entry], type_ignores=[]), str(path), "exec")
        calls, stopped = [], RuntimeError("inert fixture body stop")

        def stop(mode, parent):
            calls.append((mode, parent))
            self.assertEqual(tempfile.tempdir, str(parent))
            # A real default stdlib allocation stands in for the materialized
            # path's tempfile consumer; no product body or native owner runs.
            with tempfile.TemporaryDirectory(prefix="mrk-inert-nested-") as nested:
                self.assertEqual(Path(nested).parent, parent)
            raise stopped

        def namespace(name, arguments, environment):
            return {"__name__": name, "ROOT": path.parents[2], "Path": Path, "tempfile": tempfile,
                    "sys": SimpleNamespace(argv=list(arguments), path=[]),
                    "os": SimpleNamespace(environ=environment), "run_case": stop, "json": json}

        # Only the original two main guards are executed. Their real body is
        # replaced before dispatch; no product imports, signals or waits occur.
        with tempfile.TemporaryDirectory(prefix="mrk-inert-profile-bootstrap-") as temporary:
            parent = Path(temporary) / "selected"
            parent.mkdir(mode=0o700)
            selected = str(parent)
            environment = {key: selected for key in ("TMPDIR", "TMP", "TEMP")}
            arguments = [str(path), "inert-selected-package", "material-body:TERM", selected]
            with patch.object(tempfile, "tempdir", "inert-unselected-cache"), \
                    patch.object(tempfile, "_get_default_tempdir", side_effect=AssertionError("no fallback probe")):
                with self.assertRaises(RuntimeError) as caught:
                    exec(code, namespace("__main__", arguments, environment))
                self.assertIs(caught.exception, stopped)
                self.assertEqual(calls, [("material-body:TERM", parent)])
                self.assertFalse(list(parent.iterdir()))

            invalid = [(arguments[:-1], environment), (arguments + ["extra"], environment),
                       (arguments[:-1] + ["relative-parent"], {key: "relative-parent" for key in environment})]
            for key in environment:
                invalid.extend(((arguments, {**environment, key: "foreign-parent"}),
                                (arguments, {name: value for name, value in environment.items() if name != key})))
            for arguments, environment in invalid:
                calls.clear()
                with self.subTest(arguments=arguments, environment=environment), \
                        patch.object(tempfile, "tempdir", "inert-unselected-cache"):
                    with self.assertRaises((AssertionError, ValueError)):
                        exec(code, namespace("__main__", arguments, environment))
                    self.assertEqual(tempfile.tempdir, "inert-unselected-cache")
                    self.assertFalse(calls)
            calls.clear()
            with patch.object(tempfile, "tempdir", "inert-import-cache"):
                imported = namespace("workflow.profile_installation_fixture", [], {})
                exec(code, imported)
                self.assertEqual(tempfile.tempdir, "inert-import-cache")
                self.assertEqual(imported["sys"].argv, [])
                self.assertFalse(calls)

    def test_profile_signal_explicit_case_parent_retains_all_unsuccessful_inert_cases(self):
        from contextlib import contextmanager
        import shutil
        path = Path(__file__).with_name("profile_installation_fixture.py")
        tree = ast.parse(path.read_text(), str(path))
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "completed_case_directory")
        original_case = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_case")
        context = next(node for node in original_case.body if isinstance(node, ast.With)).items[0].context_expr
        namespace = {"contextmanager": contextmanager, "Path": Path, "tempfile": tempfile, "stat": stat, "shutil": shutil}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(path), "exec"), namespace)
        context_code = compile(ast.Expression(body=context), str(path), "eval")

        def case_directory(parent):
            # Execute the real call expression and helper, not a copied owner.
            return eval(context_code, {**namespace, "parent": parent})

        # This outer directory holds inert files only. Its later deletion never
        # represents native recovery or disposal of an uncertain command owner.
        with tempfile.TemporaryDirectory(prefix="mrk-inert-profile-cases-") as temporary:
            parent, ambient = Path(temporary) / "selected", Path(temporary) / "ambient"
            parent.mkdir(mode=0o700)
            ambient.mkdir(mode=0o700)
            with patch.object(tempfile, "tempdir", str(ambient)), \
                    patch.object(tempfile, "_get_default_tempdir", side_effect=AssertionError("no default probe")):
                with patch.object(tempfile, "mkdtemp", wraps=tempfile.mkdtemp) as allocation:
                    with case_directory(parent) as successful:
                        self.assertEqual(successful.parent, parent)
                        self.assertEqual(stat.S_IMODE(successful.lstat().st_mode), 0o700)
                    allocation.assert_called_once_with(prefix="mrk-profile-signal-", dir=parent)
                self.assertFalse(successful.exists())

                original = RuntimeError("inert body failure")
                with self.assertRaises(RuntimeError) as caught:
                    with case_directory(parent) as failed:
                        (failed / "evidence").write_bytes(b"inert retained evidence")
                        raise original
                self.assertIs(caught.exception, original)
                self.assertEqual((failed / "evidence").read_bytes(), b"inert retained evidence")

                with self.assertRaises(AssertionError):
                    with case_directory(parent) as replaced:
                        retained = replaced.with_name(replaced.name + "-original")
                        replaced.rename(retained)
                        replaced.mkdir(mode=0o700)
                        (replaced / "evidence").write_bytes(b"inert replacement")
                self.assertTrue(retained.is_dir())
                self.assertEqual((replaced / "evidence").read_bytes(), b"inert replacement")

                missing = parent / "missing-parent"
                with self.assertRaises(FileNotFoundError):
                    with case_directory(missing):
                        self.fail("missing selected parent entered the fixture body")
                self.assertFalse(missing.exists())
                refused = OSError("inert selected-parent allocation refusal")
                with patch.object(tempfile, "mkdtemp", side_effect=refused) as allocation:
                    with self.assertRaises(OSError) as caught:
                        with case_directory(parent):
                            self.fail("failed allocation entered the fixture body")
                    allocation.assert_called_once_with(prefix="mrk-profile-signal-", dir=parent)
                self.assertIs(caught.exception, refused)
                self.assertFalse(list(ambient.iterdir()))

    def test_adapter_methods_keep_fixed_ids_and_route_only_the_two_canonical_cases(self):
        path = Path(__file__).parents[1] / "unit/test_local_signing_persistent.py"
        tree = ast.parse(path.read_text())
        declared = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PersistentSigningTests")
        methods = {node.name: node for node in declared.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(len(contract.ADAPTER_TEST_IDS), 5)
        for identifier in contract.ADAPTER_TEST_IDS[:4]:
            self.assertIn(identifier.rsplit(".", 1)[1], methods)
        for name, identifier in (
            ("test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery", "C/fence/04"),
            ("test_genuine_model_inventory_active_build_pending_contrast", "S/active-build-pending/none"),
        ):
            calls = [node for node in ast.walk(methods[name]) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
            routes = [node for node in calls if node.func.attr == "semantic_adapter"]
            self.assertEqual(len(routes), 1)
            self.assertEqual(ast.literal_eval(routes[0].args[0]), identifier)
            self.assertFalse({node.func.attr for node in calls} & {"original_inventory", "inventory_original", "recover_final", "seed_case"})
        self.assertEqual(contract.ADAPTER_PROGRESS_CASES[-2:], ("semantic-main", "semantic-resolution"))

    def test_post_semantic_assertion_failure_retains_its_actual_inert_parent_evidence(self):
        from unit.test_local_signing_persistent import PersistentSigningTests
        with tempfile.TemporaryDirectory(prefix="mrk-adapter-retention-inert-") as temporary, \
                patch.dict(fixture._CASE_CUSTODY, {}, clear=True), patch.dict(fixture._CASE_RECOVERY_DEBT, {}, clear=True):
            test = PersistentSigningTests("test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery")
            test.root = Path(temporary) / "adapter"
            test.root.mkdir(mode=0o700)
            test._root_identity = fixture._directory_identity(test.root)
            test._semantic_adapter_complete = False  # Post-result assertions never completed.
            fixture.write_json(test.root / "preserved.json", {"inert": True})
            with self.assertRaisesRegex(AssertionError, "adapter assertions incomplete"):
                test.tearDown()
            self.assertEqual(fixture.read_case_json(test.root, "preserved"), {"inert": True})
            self.assertEqual(fixture._directory_identity(test.root), test._root_identity)
            # Only this test's outer private TemporaryDirectory removes these
            # inert files. No native work/custody receipt was ever produced.


class MatrixContractTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"kind": "github", "repository": "example/mobile-release-kit", "commit": "1" * 40,
                      "runId": "1234", "attempt": 3, "job": "test-signing-matrix", "os": "ubuntu-24.04"}
        self.package, self.definitions = contract.digest("production"), contract.digest("test definitions")
        self.catalog = contract.layered_catalog()
        self.expected = {system: list(self.catalog.expected_ids(system)) for system in contract.OPERATING_SYSTEMS}
        self.original = {"events": [event(number) for number in range(1, 129)], "lines": ["production:1"]}
        self.recovery = {"groups": {}}
        self.legacy_cases = fixture.matrix_cases(self.original, self.recovery)
        self.legacy_expected = list(self.legacy_cases)

    def candidates(self):
        result = []
        for operating_system in contract.OPERATING_SYSTEMS:
            expected = self.expected[operating_system]
            catalog_sha = contract.digest(self.catalog.definition(operating_system))
            for shard in range(contract.SHARDS):
                scope = {**self.scope, "os": operating_system, "attempt": 1}
                selected = list(self.catalog.shard_ids(operating_system, shard))
                run = {"executedCaseIds": selected, "catalogSha256": catalog_sha,
                       "packageSha256": self.package, "definitionsSha256": self.definitions,
                       "resultsSha256": contract.digest((operating_system, shard)),
                       "coverage": self.catalog.coverage(operating_system, selected),
                       "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}
                proof = {"schemaVersion": 2, "scope": scope, "shard": shard, "expectedCaseIds": expected[:],
                         "expectedSha256": contract.digest(expected), "catalogSha256": catalog_sha,
                         "source": copy.deepcopy(run), "wheel": copy.deepcopy(run)}
                result.append((contract.artifact_name(scope, shard), proof))
        return result

    def reduce(self, candidates):
        return contract.reconcile(candidates, self.scope, self.package, self.definitions)

    @staticmethod
    def inert_clean_snapshot():
        return {"session": None, "controls": {}, "fences": {}, "native": {}, "ownedRemaining": {},
                "nativeDirectory": False, "preferences": {"default": "fictional", "search": ["fictional"]}}

    @classmethod
    def inert_recovery(cls, token, expected="recovered", manual="none"):
        after = cls.inert_clean_snapshot()
        refused = expected == "refused-unknown-resource"
        if refused:
            after["session"] = token
        return {"sessionToken": token, "expectedStatus": expected,
                "before": {"session": token}, "after": after, "snapshot": copy.deepcopy(after),
                "unknown": {"inert-unproven-file": {}} if refused else {},
                "result": None if refused else {"status": expected, "session": token},
                "refused": "inert unknown resource" if refused else None, "idleAndRenewedAdmission": not refused,
                "events": [] if manual == "none" else [{"index": 1, "operation": "manual/input", "origin": "owner",
                    "slot": "tty", "phase": "recovery", "details": {"action": manual}, "succeeded": True}]}

    @staticmethod
    def inert_cut(selector, token):
        return {"sessionToken": token, "selector": selector.record(), "edge": selector.edge,
                "context": dict(selector.context), "event": {
                    **{key: getattr(selector, key) for key in ("operation", "slot", "origin", "phase", "occurrence")},
                    "index": 91234, "details": {"destination": selector.destination}}}

    def inert_semantic_row(self, name, steps, negatives=()):
        """Self-consistent parser DATA only, never an original execution receipt."""
        item = next(item for item in self.catalog.cases_for(self.scope["os"]) if item.name == name)
        stem = "semantic-" + contract.digest(name)
        filename = stem + "-complete.json"
        parts = list(self.catalog.regression_parts(item, self.scope["os"]))
        complete = {"schema": "mrk-signing-semantic-case-v1", "case": json.loads(item.specification), "steps": steps,
                    "negativeEvidence": [stem + "-" + suffix + ".json" for suffix, _step in negatives]}
        evidence = {filename: complete, **{stem + "-" + suffix + ".json": copy.deepcopy(step) for suffix, step in negatives}}
        if parts:
            evidence[stem + "-regression.json"] = {"schema": "mrk-signing-semantic-contribution-v1", "semantic": name,
                "contributions": parts, "evidenceSha256": contract.digest(complete)}
        return {"schemaVersion": 2, "caseId": item.identifier, "kind": "semantic", "name": name,
            "observation": {"caseId": name, "status": "semantic-subset-case", "evidence": filename,
                "caseRemoved": True, "originalWorkersSettled": True, "regressionContributions": parts},
            "evidence": evidence, "regressionParts": parts}

    @staticmethod
    def refresh_inert_semantic_digests(row):
        complete = row["evidence"][row["observation"]["evidence"]]
        for filename in complete["negativeEvidence"]:
            if filename in row["evidence"]:
                for step in complete["steps"]:
                    if step["name"] == row["evidence"][filename]["name"]:
                        row["evidence"][filename] = copy.deepcopy(step)
        for filename, value in row["evidence"].items():
            if filename.endswith("-regression.json"):
                value["evidenceSha256"] = contract.digest(complete)

    def test_legacy_algorithm_ids_stay_stable_without_becoming_active_catalog_authority(self):
        shuffled = copy.deepcopy(self.original)
        shuffled["events"].reverse()
        for index, item in enumerate(shuffled["events"], 9000):
            item["index"] = index
        other = fixture.matrix_cases(shuffled, self.recovery)
        self.assertEqual(list(other), self.legacy_expected)
        self.assertEqual(fixture.matrix_inventory_digest(self.legacy_cases, self.original, self.recovery),
                         fixture.matrix_inventory_digest(other, shuffled, self.recovery))
        union = set()
        for shard in range(contract.SHARDS):
            selected = {case for case in self.legacy_expected if contract.shard_for(case) == shard}
            self.assertTrue(selected)
            self.assertFalse(union.intersection(selected))
            union.update(selected)
        self.assertEqual(union, set(self.legacy_expected))
        for expected in self.expected.values():
            self.assertFalse(union.intersection(expected))
        changed = copy.deepcopy(self.original)
        changed["events"][0]["succeeded"] = False
        changed["events"][0]["error"] = "OSError"
        changed["events"][0]["details"]["flags"] = 256
        changed_cases = fixture.matrix_cases(changed, self.recovery)
        self.assertEqual(list(changed_cases), self.legacy_expected)
        self.assertNotEqual(fixture.matrix_inventory_digest(changed_cases, changed, self.recovery),
                            fixture.matrix_inventory_digest(self.legacy_cases, self.original, self.recovery))

    def test_complete_two_os_source_wheel_union_accepts_older_successful_cells_after_partial_rerun(self):
        candidates = self.candidates()
        rerun = copy.deepcopy(candidates[0][1])
        rerun["scope"]["attempt"] = 3
        candidates.append((contract.artifact_name(rerun["scope"], rerun["shard"]), rerun))
        result = self.reduce(iter(candidates))  # Stream downloaded proofs, including older attempts.
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["producingAttempts"]["ubuntu-24.04/0"], 3)
        self.assertEqual(result["producingAttempts"]["macos-26/0"], 1)
        for operating_system in contract.OPERATING_SYSTEMS:
            for mode in ("source", "wheel"):
                row = result["operatingSystems"][operating_system][mode]
                self.assertEqual(row["cases"], len(self.expected[operating_system]))
                self.assertEqual(row["coverage"], self.catalog.coverage(operating_system, self.expected[operating_system]))
                obligations = self.catalog.REGRESSION.obligations(operating_system)
                self.assertEqual(row["originalRegressionMethods"], len(obligations))
                self.assertEqual(row["originalRegressionParts"], sum(map(len, obligations.values())))

    def test_source_authority_rejects_a_self_consistent_producer_omission_at_the_first_proof(self):
        candidates = self.candidates()
        name, proof = candidates[0]
        missing = proof["source"]["executedCaseIds"][0]
        proof["expectedCaseIds"].remove(missing)
        proof["expectedSha256"] = contract.digest(proof["expectedCaseIds"])
        for mode in ("source", "wheel"):
            proof[mode]["executedCaseIds"].remove(missing)
            proof[mode]["coverage"] = self.catalog.coverage(proof["scope"]["os"], proof[mode]["executedCaseIds"])
        # Even internally consistent producer IDs/digests/coverage cannot
        # replace the independently reconstructed source authority. Unlike v1,
        # rejection does not depend on finding a disagreeing second cell.
        with self.assertRaisesRegex(ValueError, "expected cases differ from source catalog"):
            contract.validate_proof(proof, name, self.scope, self.package, self.definitions)
        with self.assertRaisesRegex(ValueError, "expected cases differ from source catalog"):
            self.reduce(candidates)

    def test_missing_duplicate_extra_wrong_scope_and_invalid_later_proofs_never_fall_back(self):
        for change in ("missing", "duplicate", "wrong-name", "repository", "commit", "runId", "job", "future-attempt",
                       "package", "definitions", "catalog", "proof-catalog", "coverage-kinds", "coverage-parts",
                       "omitted-source", "omitted-wheel", "duplicate-ID", "extra-ID", "wrong-shard", "empty",
                       "legacy-version", "legacy-inventory", "bool-version", "bool-attempt", "bool-shard", "unknown-field",
                       "cleanup", "paths"):
            with self.subTest(change=change):
                candidates = self.candidates()
                name, proof = candidates[0]
                if change == "missing": candidates.pop()
                elif change == "duplicate": candidates.append(copy.deepcopy(candidates[0]))
                elif change == "wrong-name": candidates[0] = (name + "-other", proof)
                elif change in ("repository", "commit", "runId", "job"): proof["scope"][change] = "wrong"
                elif change == "future-attempt": proof["scope"]["attempt"] = 4
                elif change in ("package", "definitions", "catalog"):
                    key = {"package": "packageSha256", "definitions": "definitionsSha256", "catalog": "catalogSha256"}[change]
                    proof["source"][key] = "f" * 64
                elif change == "proof-catalog": proof["catalogSha256"] = "f" * 64
                elif change == "coverage-kinds": proof["source"]["coverage"]["kinds"]["semantic"] += 1
                elif change == "coverage-parts": proof["wheel"]["coverage"]["regressionParts"].append("G/unknown")
                elif change.startswith("omitted-"): proof[change.removeprefix("omitted-")]["executedCaseIds"].pop()
                elif change == "duplicate-ID": proof["source"]["executedCaseIds"].append(proof["source"]["executedCaseIds"][0])
                elif change == "extra-ID": proof["wheel"]["executedCaseIds"] = sorted([*proof["wheel"]["executedCaseIds"], "f" * 64])
                elif change == "wrong-shard": proof["shard"] = 1
                elif change == "empty": proof["expectedCaseIds"] = []
                elif change == "legacy-version": proof["schemaVersion"] = 1
                elif change == "legacy-inventory": proof["source"]["inventorySha256"] = proof["source"].pop("catalogSha256")
                elif change == "bool-version": proof["schemaVersion"] = True
                elif change == "bool-attempt": proof["scope"]["attempt"] = True
                elif change == "bool-shard": proof["shard"] = False
                elif change == "unknown-field": proof["forcePass"] = True
                elif change == "cleanup": proof["source"]["allExactChildrenReapedAndGroupsAbsent"] = False
                elif change == "paths": proof["wheel"]["allCasePathsRemoved"] = False
                with self.assertRaises(ValueError): self.reduce(candidates)
        for invalid_attempt in (1, 3):
            with self.subTest(invalid_attempt=invalid_attempt):
                candidates = self.candidates()
                valid = candidates.pop(0)[1]
                invalid = copy.deepcopy(valid)
                valid["scope"]["attempt"] = 4 - invalid_attempt
                invalid["scope"]["attempt"] = invalid_attempt
                invalid["source"]["executedCaseIds"].pop()
                # Every candidate is checked, including a later-listed older
                # invalid attempt when a valid newer attempt is available.
                candidates.insert(0, (contract.artifact_name(valid["scope"], 0), valid))
                candidates.append((contract.artifact_name(invalid["scope"], 0), invalid))
                with self.assertRaisesRegex(ValueError, "omitted"):
                    self.reduce(candidates)

    def test_bounded_strict_json_and_unmerged_artifact_identity_are_required(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-proof-") as directory:
            root = Path(directory)
            name, proof = self.candidates()[0]
            artifact = root / name
            artifact.mkdir()
            path = artifact / "proof.json"
            for content in (b'{"scope":{},"scope":{}}', b'{"number":NaN}', b'{"incomplete":', b'\xff'):
                path.write_bytes(content)
                with self.assertRaises((ValueError, UnicodeError)): contract.read_proof(path)
            path.write_bytes(b" " * (contract.MAX_PROOF_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size bound"): contract.read_proof(path)
            path.write_bytes(contract.canonical(proof))
            self.assertEqual(list(contract.proof_paths(root)), [(name, path)])
            self.assertEqual(contract.read_proof(path), proof)
            (artifact / "extra.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "extra files"): list(contract.proof_paths(root))
            (artifact / "extra.json").unlink()
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "regular"): contract.read_proof(path)
        with self.assertRaisesRegex(ValueError, "missing"): self.reduce([])

    def test_proof_directory_scan_is_actually_bounded_before_excess_entries_are_consumed(self):
        real_scandir = os.scandir
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-scanning-") as temporary:
            for count in (0, contract.MAX_PROOFS, contract.MAX_PROOFS + 7):
                with self.subTest(count=count):
                    root = Path(temporary) / str(count)
                    root.mkdir()
                    for index in range(count):
                        artifact = root / f"local-signing-matrix-proof-macos-26-0-attempt-{index + 1}"
                        artifact.mkdir()
                        (artifact / "proof.json").write_text("{}")
                    scans = []

                    def scan(path):
                        observed = ObservedScan(real_scandir(path), contract.MAX_PROOFS + 1 if path == root else 2)
                        scans.append(observed)
                        return observed

                    with patch.object(contract.os, "scandir", side_effect=scan), patch.object(
                        os, "listdir", side_effect=AssertionError("eager listdir is not a bounded scan")
                    ):
                        if count == contract.MAX_PROOFS:
                            paths = list(contract.proof_paths(root))
                            self.assertEqual(len(paths), count)
                            self.assertEqual(paths, sorted(paths))
                        else:
                            with self.assertRaisesRegex(ValueError, "missing or excessive"):
                                list(contract.proof_paths(root))
                    self.assertEqual(scans[0].count, min(count, contract.MAX_PROOFS + 1))
                    self.assertTrue(all(scan.closed for scan in scans))
                    self.assertEqual(len(scans), 1 + count if count == contract.MAX_PROOFS else 1)
                    for observed in scans:
                        with self.assertRaises(StopIteration): next(observed.scan)

            root = Path(temporary) / "inner"
            root.mkdir()
            artifact = root / "local-signing-matrix-proof-macos-26-0-attempt-1"
            artifact.mkdir()
            for name in ["proof.json", *[f"extra-{index}" for index in range(7)]]:
                (artifact / name).write_text("{}")
            scans = []
            with patch.object(contract.os, "scandir", side_effect=scan), patch.object(
                os, "listdir", side_effect=AssertionError("eager listdir is not a bounded scan")
            ), self.assertRaisesRegex(ValueError, "extra files"):
                list(contract.proof_paths(root))
            self.assertEqual([observed.count for observed in scans], [1, 2])
            self.assertTrue(all(observed.closed for observed in scans))

    def test_proof_scanner_errors_close_actual_handles_and_cannot_accept_truncated_entries(self):
        real_scandir = os.scandir
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-scan-errors-") as temporary:
            root = Path(temporary)
            artifact = root / "local-signing-matrix-proof-macos-26-0-attempt-1"
            artifact.mkdir()
            (artifact / "proof.json").write_text("{}")
            for level in (root, artifact):
                for error in ("read", "close"):
                    with self.subTest(level=level.name, error=error):
                        scans = []

                        def scan(path):
                            observed = ObservedScan(real_scandir(path), contract.MAX_PROOFS + 1 if path == root else 2,
                                                    read_error=path == level and error == "read",
                                                    close_error=path == level and error == "close")
                            scans.append(observed)
                            return observed

                        with patch.object(contract.os, "scandir", side_effect=scan), self.assertRaisesRegex(
                            OSError, f"directory {error} failure"
                        ):
                            list(contract.proof_paths(root))
                        self.assertTrue(all(observed.closed for observed in scans))
                        for observed in scans:
                            with self.assertRaises(StopIteration): next(observed.scan)

    def test_actual_typed_observation_not_requested_id_is_the_execution_authority(self):
        # Synthetic parser fixtures only: these rows do not demonstrate an
        # original TestCase, native worker, cleanup or platform execution.
        operating_system = self.scope["os"]
        items = [item for item in self.catalog.cases_for(operating_system) if item.kind == "regression"][:2]
        self.assertEqual(len(items), 2)
        def record(item):
            specification = json.loads(item.specification)
            filename = "regression-" + contract.digest(item.name) + ".json"
            return {"schemaVersion": 2, "caseId": item.identifier, "kind": item.kind, "name": item.name,
                    "observation": {"caseId": item.name, "status": "regression-case", "evidence": filename,
                                    "caseRemoved": True, "originalWorkersSettled": True},
                    "evidence": {filename: {"schema": "mrk-signing-regression-case-v1", "case": specification,
                        "originalTestcaseCompleted": True, "typedVariant": specification["helper"] != "whole",
                        "testsRun": 1, "setupBodyTeardownCleanupsReturned": True,
                        "originalWorkersSettled": True, "caseRemoved": True}},
                    "regressionParts": [item.name]}
        records = [record(item) for item in items]
        expected = [item.identifier for item in items]
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-actual-") as directory:
            root = Path(directory)
            def write(values):
                with gzip.open(root / "results.jsonl.gz", "wb") as stream:
                    for value in values: stream.write(contract.canonical(value) + b"\n")
            write(records)
            self.assertRegex(runner.validate_actual_results(root, expected, operating_system=operating_system),
                             r"^[0-9a-f]{64}$")
            for variant in ("wrong-kind", "wrong-name", "wrong-observation", "wrong-descriptor", "wrong-variant",
                            "missing-evidence", "extra-evidence", "missing-contribution", "unreturned-testcase",
                            "unsettled-worker", "retained-path", "legacy-row", "bool-version", "extra-field",
                            "duplicate", "missing", "reordered"):
                with self.subTest(variant=variant):
                    values = copy.deepcopy(records)
                    bad = values[0]
                    payload = bad["evidence"][bad["observation"]["evidence"]]
                    if variant == "wrong-kind": bad["kind"] = "primitive"
                    elif variant == "wrong-name": bad["name"] = items[1].name
                    elif variant == "wrong-observation": bad["observation"]["caseId"] = items[1].name
                    elif variant == "wrong-descriptor": payload["case"]["helper"] = "unknown"
                    elif variant == "wrong-variant": payload["typedVariant"] = not payload["typedVariant"]
                    elif variant == "missing-evidence": bad["evidence"].clear()
                    elif variant == "extra-evidence": bad["evidence"]["unrecognized.json"] = {}
                    elif variant == "missing-contribution": bad["regressionParts"] = []
                    elif variant == "unreturned-testcase": payload["setupBodyTeardownCleanupsReturned"] = False
                    elif variant == "unsettled-worker": bad["observation"]["originalWorkersSettled"] = False
                    elif variant == "retained-path": payload["caseRemoved"] = False
                    elif variant == "legacy-row": values[0] = {"caseId": bad["caseId"], "seed": "original",
                        "outcome": {"automatic": "recovered", "manual": None},
                        "results": {"original-cut": {"event": event(1), "edge": "before"}, "final-automatic": {}}}
                    elif variant == "bool-version": bad["schemaVersion"] = True
                    elif variant == "extra-field": bad["forcePass"] = True
                    elif variant == "duplicate": values[1] = copy.deepcopy(bad)
                    elif variant == "missing": values.pop()
                    elif variant == "reordered": values.reverse()
                    write(values)
                    with self.assertRaises(ValueError):
                        runner.validate_actual_results(root, expected, operating_system=operating_system)

        # Preserve the old wrong-reached-cut counterexample in the active v2
        # semantic shape. These are inert parser DATA, not native receipts.
        item = next(item for item in self.catalog.cases_for(operating_system) if item.name == "C/caller/02")
        specification = json.loads(item.specification)
        token = "a" * 32
        filename = "semantic-" + contract.digest(item.name) + "-complete.json"
        original = {"exit": 0, "originalAnchorWait": True, "originalWorkerWait": True, "originalStatusEOF": True,
                    "groupAbsentBeforeAnchorWait": True, "deadlineTest": False, "runDeadlineExpired": False}
        cut = self.inert_cut(self.catalog.SEMANTIC.case(item.name).selector, token)
        semantic = self.inert_semantic_row(item.name, [
            {"name": "seed", "original": {**original, "exit": 73}, "observation": cut},
            {"name": "semantic-main", "original": original, "manual": "none", "expected": specification["expected"],
             "observation": self.inert_recovery(token, specification["expected"])}])
        self.assertEqual(contract.validate_layered_record(semantic, operating_system), item.identifier)
        reindexed = copy.deepcopy(semantic)
        reindexed["evidence"][filename]["steps"][0]["observation"]["event"]["index"] = 1
        self.assertEqual(contract.validate_layered_record(reindexed, operating_system), item.identifier)
        for variant in ("actual-occurrence", "actual-destination", "actual-edge", "actual-context-type", "missing-context",
                        "missing-recovery", "unreturned-original", "actual-outcome", "actual-session", "actual-refusal",
                        "actual-idle", "retained-resource"):
            with self.subTest(semantic_variant=variant):
                changed = copy.deepcopy(semantic)
                steps = changed["evidence"][filename]["steps"]
                reached = steps[0]["observation"]
                if variant == "actual-occurrence": reached["event"]["occurrence"] += 1
                elif variant == "actual-destination": reached["event"]["details"]["destination"] += "-other"
                elif variant == "actual-edge": reached["edge"] = "before"
                elif variant == "actual-context-type": reached["context"]["beforeGrant"] = 1
                elif variant == "missing-context": reached.pop("context")
                elif variant == "missing-recovery": steps.pop()
                elif variant == "unreturned-original": steps[-1]["original"]["originalWorkerWait"] = False
                elif variant == "actual-outcome": steps[-1]["observation"]["result"]["status"] = "absent"
                elif variant == "actual-session": steps[-1]["observation"]["result"]["session"] = "b" * 32
                elif variant == "actual-refusal": steps[-1]["observation"]["refused"] = "not recovered"
                elif variant == "actual-idle": steps[-1]["observation"]["idleAndRenewedAdmission"] = False
                elif variant == "retained-resource": steps[-1]["observation"]["after"]["ownedRemaining"] = {"inert": {}}
                with self.assertRaises(ValueError):
                    contract.validate_layered_record(changed, operating_system)

        # Reuse the existing pure H data fixture rather than simulate another
        # native flow. Rehash alias DATA after mutations so a digest mismatch
        # cannot mask acceptance of an incomplete actual observation.
        from .test_local_signing_observation import ObservationContractTests
        healthy = ObservationContractTests.inert_healthy_data(Path("/fictional-inert-root"))
        healthy["snapshot"].update(self.inert_clean_snapshot())
        healthy["snapshot"]["preferences"] = copy.deepcopy(healthy["snapshot"]["original"])
        healthy_row = self.inert_semantic_row("H/full-context", [
            {"name": "healthy", "original": original, "observation": healthy}])
        self.assertEqual(contract.validate_layered_record(healthy_row, operating_system), healthy_row["caseId"])
        for variant in ("missing-H", "missing-checkpoint", "failed-effect", "retained-H", "early-terminal"):
            with self.subTest(healthy_variant=variant):
                changed = copy.deepcopy(healthy_row)
                step = changed["evidence"][changed["observation"]["evidence"]]["steps"][0]
                value = step["observation"]
                if variant == "missing-H": step["observation"] = {}
                elif variant == "missing-checkpoint": value["healthyContexts"]["checkpoints"].pop()
                elif variant == "failed-effect":
                    value["events"][value["healthyContexts"]["effects"][0]["eventIndex"] - 1]["succeeded"] = False
                elif variant == "retained-H": value["snapshot"]["ownedRemaining"] = {"inert-retained": {}}
                elif variant == "early-terminal": value["events"][-1]["index"] = 450
                self.refresh_inert_semantic_digests(changed)
                with self.assertRaises(ValueError): contract.validate_layered_record(changed, operating_system)

        def recovery_step(name, expected, manual="none"):
            return {"name": name, "original": original, "manual": manual, "expected": expected,
                    "observation": self.inert_recovery(token, expected, manual)}

        for prefix_name in ("database", "lock", "transaction-stage"):
            source = self.catalog.SEMANTIC
            declared = source.case("N/native-prefix/" + prefix_name)
            cut = self.inert_cut(declared.selector, token)
            payload = source.NATIVE_PREFIX_CONTENT[prefix_name]
            size = len(payload) // 2
            facts = {"device": 1, "inode": 2, "mode": 0o600, "size": size,
                     "sha256": hashlib.sha256(payload[:size]).hexdigest()}
            filename = declared.selector.operation.removeprefix("native-effect/write/")
            names = ["default-keychain", "list-keychains", "create-keychain"]
            if prefix_name == "transaction-stage": names.append("set-keychain-settings")
            cut["context"]["recoveryAttempt"] = False
            cut["originalCommand"] = {"command": names[-1], "ordinal": len(names),
                                      "keychain": source.KEYCHAIN + "/" + source.DB_NAME, "revisionBefore": 0}
            cut["physicalWrite"] = {"name": filename, "bytes": size, "intendedBytes": len(payload),
                "sha256": facts["sha256"], "intendedSha256": hashlib.sha256(payload).hexdigest(),
                "facts": facts, "properPrefix": True, "revisionAtCut": int(prefix_name == "transaction-stage")}
            cut["snapshot"] = {"session": token, "native": {
                source.KEYCHAIN.removeprefix("<ROOT>/").replace("<TOKEN>", token) + "/" + filename: copy.deepcopy(facts)},
                "nativeCalls": [{"command": name, "mutation": number >= 2, "recovery": False}
                                for number, name in enumerate(names)]}
            main = recovery_step("semantic-main", source.REFUSED)
            native_row = self.inert_semantic_row(declared.identifier, [
                {"name": "seed", "original": {**original, "exit": 73}, "observation": cut}, main,
                recovery_step("semantic-resolution", declared.resolution, "resolve")], [("negative", main)])
            self.assertEqual(contract.validate_layered_record(native_row, operating_system), native_row["caseId"])
        for variant in ("missing-prefix", "empty-prefix", "changed-prefix", "changed-inode", "wrong-command", "false-refusal-idle"):
            with self.subTest(native_variant=variant):
                changed = copy.deepcopy(native_row)  # Last positive is the distinct transaction-stage case.
                steps = changed["evidence"][changed["observation"]["evidence"]]["steps"]
                cut = steps[0]["observation"]
                if variant == "missing-prefix": cut.pop("physicalWrite")
                elif variant == "empty-prefix": cut["physicalWrite"]["bytes"] = 0
                elif variant == "changed-prefix": cut["physicalWrite"]["sha256"] = "f" * 64
                elif variant == "changed-inode": cut["physicalWrite"]["facts"]["inode"] += 1
                elif variant == "wrong-command": cut["originalCommand"]["ordinal"] = 3
                elif variant == "false-refusal-idle": steps[1]["observation"]["idleAndRenewedAdmission"] = True
                self.refresh_inert_semantic_digests(changed)
                with self.assertRaises(ValueError): contract.validate_layered_record(changed, operating_system)

        refusals = []
        for mode in ("none", "resolve"):
            refusal_event = {"index": 1, "operation": "manual/input", "origin": "owner", "slot": "tty", "details": {"action": mode}}
            refusals.append({"name": "focused-" + mode, "original": original, "manual": mode, "observation": {
                "before": {"session": token, "preferences": {"default": "fictional", "search": []}},
                "after": {"session": token, "preferences": {"default": "fictional", "search": []}},
                "error": "inert expected refusal", "caughtType": "CredentialError" if mode == "none" else "OwnerResolutionRefused",
                "events": [] if mode == "none" else [refusal_event],
                "inputObservations": [] if mode == "none" else [{"eventIndex": 1, "action": mode}],
                "resourcesPreserved": True, "freshAdmission": "pending"}})
        action = "fixture/foreign-native-db"
        owner_value = {"manualFixtureAction": True, "idleAndRenewedAdmission": True,
            "result": {"status": "recovered-with-conflict", "session": token}, "after": self.inert_clean_snapshot(),
            "preferences": self.inert_clean_snapshot()["preferences"],
            "events": [{"index": 1, "operation": "manual/input", "origin": "owner", "slot": "tty",
                        "details": {"action": action}, "succeeded": True}],
            "inputObservations": [{"eventIndex": 1, "action": action, "read": {"kind": "recheck", "characters": 41}}]}
        focused_row = self.inert_semantic_row("F/07", [
            {"name": "seed", "original": {**original, "exit": 73},
             "observation": self.inert_cut(self.catalog.SEMANTIC.SEEDS["active-after-build"], token)}, *refusals,
            {"name": "focused-fixture-owner", "original": original, "observation": owner_value}],
            [("negative-none", refusals[0]), ("negative-resolve", refusals[1])])
        self.assertEqual(contract.validate_layered_record(focused_row, operating_system), focused_row["caseId"])
        for variant in ("seed-only", "missing-owner", "owner-idle", "owner-outcome", "unpreserved", "missing-negative"):
            with self.subTest(focused_variant=variant):
                changed = copy.deepcopy(focused_row)
                complete = changed["evidence"][changed["observation"]["evidence"]]
                steps = complete["steps"]
                if variant == "seed-only": del steps[1:]
                elif variant == "missing-owner": steps.pop()
                elif variant == "owner-idle": steps[-1]["observation"]["idleAndRenewedAdmission"] = False
                elif variant == "owner-outcome": steps[-1]["observation"]["result"]["status"] = "recovered"
                elif variant == "unpreserved": steps[1]["observation"]["resourcesPreserved"] = False
                elif variant == "missing-negative": changed["evidence"].pop(complete["negativeEvidence"][0])
                self.refresh_inert_semantic_digests(changed)
                with self.assertRaises(ValueError): contract.validate_layered_record(changed, operating_system)

        primitive_rows = {}
        for family in ("writer-failures", "reader-failures", "remover-failures"):
            rows = []
            for variant in self.catalog.PRIMITIVE_FAILURES[family]:
                operation = ("write" if variant in {"short-write", "zero-write", "oversized-write", "partial-write-error"}
                             else "fsync" if "sync-" in variant else "unlink" if variant.startswith("unlink-")
                             else "read" if variant in {"read-before", "read-after", "reader-name-changed"} else "close")
                fault = {"variant": variant, "effectCompleted": not variant.endswith("-before")
                         and variant not in {"zero-write", "oversized-write"}, "event": {
                    "index": 1, "operation": operation, "slot": "<ROOT>/home/inert", "origin": "mobile_release.local_signing:_write",
                    "phase": "component", "occurrence": 1, "details": {}}}
                generations = {}
                if variant in {"short-write", "partial-write-error"}: fault.update(written=1, prefixHex="7b")
                if variant in {"stage-replaced", "target-replaced", "reader-name-changed"}:
                    fault["replacement"] = {"device": 1, "inode": 3, "mode": 0o600, "size": 1,
                                            "sha256": hashlib.sha256(b"x").hexdigest()}
                    generations["1:3"] = {"fixtureReplacement": variant}
                error = (None if variant == "short-write" else "ProcessCleanupError" if variant == "close-after"
                         else "ProcessError" if variant == "reader-close-after"
                         else "OSError" if variant.endswith(("-before", "-after")) or variant == "partial-write-error"
                         else "FileExistsError" if variant.startswith("pending-") else "CredentialError")
                rows.append({"variant": variant, "originalError": error,
                    "journalFailed": family != "reader-failures" and variant != "short-write",
                    "faults": [] if variant.startswith(("pending-", "immutable-")) else [fault],
                    "initial": {"<ROOT>/home": [1, 2]}, "retainedIdentities": {"<ROOT>/home": [1, 2]}, "generations": generations,
                    "physical": {"<ROOT>/home": {"type": stat.S_IFDIR, "mode": 0o700, "links": 1,
                                                 "initialAliases": ["<ROOT>/home"]}}, "nativeCommands": 0})
            item = next(item for item in self.catalog.cases_for(operating_system) if item.name == "A/" + family)
            row = {"schemaVersion": 2, "caseId": item.identifier, "kind": "primitive", "name": item.name,
                "observation": {"component": family, "actualFailureCases": len(rows), "resultsSha256": contract.digest(rows),
                    "nativeCommands": 0, "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True},
                "evidence": {"component-evidence.json": rows}, "regressionParts": []}
            self.assertEqual(contract.validate_layered_record(row, operating_system), item.identifier)
            primitive_rows[family] = row
        # The writer retains its concrete close error; the reader deliberately
        # projects the shared guard into a ProcessError. Neither is an alias for
        # the other, a generic IO error, or a missing failure observation.
        for family, variant, wrong in (
                ("writer-failures", "close-after", ("ProcessError", "OSError", None)),
                ("reader-failures", "reader-close-after", ("ProcessCleanupError", "OSError", None))):
            for error in wrong:
                with self.subTest(close_variant=variant, wrong_error=error):
                    changed = copy.deepcopy(primitive_rows[family])
                    rows = changed["evidence"]["component-evidence.json"]
                    next(row for row in rows if row["variant"] == variant)["originalError"] = error
                    changed["observation"]["resultsSha256"] = contract.digest(rows)
                    with self.assertRaises(ValueError):
                        contract.validate_layered_record(changed, operating_system)
        for variant in ("missing-outcome", "short-latched", "writer-unlatched", "reader-latched", "remover-success",
                        "missing-fault", "repeated-fault", "wrong-effect", "missing-physical"):
            with self.subTest(primitive_variant=variant):
                family = "reader-failures" if variant == "reader-latched" else "remover-failures" if variant == "remover-success" else "writer-failures"
                changed = copy.deepcopy(primitive_rows[family])
                rows = changed["evidence"]["component-evidence.json"]
                if variant == "missing-outcome": rows[0].pop("originalError")
                elif variant in {"short-latched", "reader-latched"}: rows[0]["journalFailed"] = True
                elif variant == "writer-unlatched": rows[1]["journalFailed"] = False
                elif variant == "remover-success": rows[0]["originalError"] = None
                elif variant == "missing-fault": rows[0]["faults"].clear()
                elif variant == "repeated-fault": rows[0]["faults"] *= 2
                elif variant == "wrong-effect": rows[0]["faults"][0]["effectCompleted"] = False
                elif variant == "missing-physical": rows[0].pop("physical")
                changed["observation"]["resultsSha256"] = contract.digest(rows)
                with self.assertRaises(ValueError): contract.validate_layered_record(changed, operating_system)

    def test_original_c_prefix_reducer_requires_actual_positive_bytes_and_exact_read_inode(self):
        observation = {"nonce": "1" * 32, "commandSequence": 1, "ordinal": 4, "operation": "PENDING_WRITE",
            "edge": "PARTIAL", "outcome": "OK", "written": 2, "total": 8, "syncFlags": 0,
            "creationIdentity": [1, 2, 1000, 1000, stat.S_IFREG | 0o600, 1], "operandHex": b"test".hex(),
            "originalWorker": True, "actualReadHex": b"te".hex(),
            "originalFileState": [1, 2, stat.S_IFREG | 0o600, 1, 1000, 1000, 2, 17, 19],
            "finalAbsentBeforeAndAfter": True, "originalReadClosed": True}
        def validate(value):
            return contract.validate_original_c_prefix(value)
        self.assertIsNone(validate(observation))
        changes = ({"written": 0, "actualReadHex": ""}, {"written": -1}, {"written": True}, {"total": 9.0},
                   {"total": 4097}, {"operandHex": "not-hex!"}, {"actualReadHex": "ffff"}, {"syncFlags": True},
                   {"nonce": "x" * 32}, {"commandSequence": True}, {"ordinal": 0}, {"outcome": "PENDING"},
                   {"originalReadClosed": 1}, {"extra": True}, {"creationIdentity": [1, 3, 1000, 1000, stat.S_IFREG | 0o600, 1]},
                   {"originalFileState": [1, 2, stat.S_IFREG | 0o600, True, 1000, 1000, 2, 17, 19]},
                   {"originalFileState": [1, 2, stat.S_IFREG | 0o600, 1, 1000, 1000, 3, 17, 19]})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate({**observation, **change})
        absent = dict(observation)
        absent.pop("originalFileState")
        with self.assertRaises(ValueError):
            validate(absent)

    def test_ci_scope_and_invalid_selection_do_not_silently_become_local_or_partial_success(self):
        metadata = {key: value for key, value in self.scope.items() if key != "os"}
        self.assertEqual(contract.scope_from_metadata(metadata, "ubuntu-24.04", producer=True), self.scope)
        for field in metadata:
            missing = dict(metadata)
            missing.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.scope_from_metadata(missing, "ubuntu-24.04", producer=True)
        for changes in ({"attempt": True}, {"job": "test"}, {"kind": "local"}, {"runId": None},
                        {"commit": "1" * 39}, {"unlisted": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.scope_from_metadata({**metadata, **changes}, "ubuntu-24.04", producer=True)
        reduced = contract.scope_from_metadata({**metadata, "job": "test"}, "ubuntu-24.04", producer=False)
        self.assertEqual(reduced, self.scope)
        with redirect_stderr(io.StringIO()):
            for arguments in (("--shard", "-1"), ("--shard", "48"), ("--shard", "true"),
                              ("--shard", "1", "--all"), ("--phase", "other"),
                              ("--phase", "source", "--reduce", "/data")):
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    runner.main([*arguments, "--output", "/unreached", "--os", "ubuntu-24.04"])

    def test_ci_requires_fixed_full_matrix_both_imports_and_mandatory_unmerged_proofs(self):
        workflow = load_workflow(runner.ROOT / ".github/workflows/ci.yml")
        job, aggregate = workflow["jobs"]["test-signing-matrix"], workflow["jobs"]["test"]
        self.assertEqual(job["name"], "test-signing-matrix (${{ matrix.os }}, ${{ matrix.shard }})")
        self.assertEqual(tuple(job["strategy"]["matrix"]), ("shard", "os", "include"))
        self.assertEqual(job["strategy"]["matrix"], {"os": list(contract.OPERATING_SYSTEMS), "shard":
            "${{ fromJSON(github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-matrix-canary' && '[0]' || '[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47]') }}",
            "include": "${{ fromJSON(github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-matrix-canary' && '[{\"os\":\"ubuntu-24.04\",\"shard\":20},{\"os\":\"ubuntu-24.04\",\"shard\":28},{\"os\":\"macos-26\",\"shard\":1},{\"os\":\"macos-26\",\"shard\":12},{\"os\":\"macos-26\",\"shard\":37}]' || '[]') }}"})
        self.assertEqual(job["strategy"]["max-parallel"], 20)
        self.assertIs(job["strategy"]["fail-fast"], False)
        self.assertEqual(job["timeout-minutes"], 60)
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("env", job)
        self.assertNotIn("environment", job)
        self.assertNotIn("outputs", job)
        self.assertEqual(job["if"], "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target == 'full' || inputs.verification_target == 'signing-matrix-canary') }}")
        self.assertNotIn("continue-on-error", job)
        commands = [step["run"] for step in job["steps"] if "run" in step]
        self.assertEqual(len(commands), 3)  # Hosted guard, Linux provider preparation, fixed controller.
        owner = next(command for command in commands if "verify_ci.py" in command)
        self.assertIn("sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin PYTHONSAFEPATH=1", owner)
        self.assertIn("--scope signing-matrix", owner)
        for metadata in ("--repository", "--commit", "--run-id", "--run-attempt", "--job", "--shard"):
            self.assertIn(metadata, owner)
        for command in commands:
            self.assertNotIn("run_local_signing_matrix.py", command)
            self.assertNotIn("pip wheel", command)
            self.assertNotIn("Popen", command)
        self.assertEqual(aggregate["needs"], ["test-linux", "test-native-profiles", "test-signing-matrix"])
        self.assertIn('"$MATRIX_RESULT" == success', aggregate["steps"][0]["run"])
        uploads = [step for step in job["steps"] if "local-signing-matrix-proof-" in step.get("with", {}).get("name", "")]
        self.assertEqual(len(uploads), 1)
        self.assertNotIn("if", uploads[0])
        self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error")
        self.assertIn("${{ github.run_attempt }}", uploads[0]["with"]["name"])
        self.assertNotIn("overwrite", uploads[0]["with"])
        downloads = [step for step in aggregate["steps"] if "actions/download-artifact@" in step.get("uses", "")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["with"], {"pattern": "local-signing-matrix-proof-*", "path": "${{ runner.temp }}/signing-matrix-proofs",
                                               "merge-multiple": False, "digest-mismatch": "error"})
        reducers = [step for step in aggregate["steps"] if "--reduce" in step.get("run", "")]
        self.assertEqual(len(reducers), 1)
        self.assertNotIn("--local-reduction", reducers[0]["run"])
        for step in aggregate["steps"]:
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)


class MatrixPhaseAdmissionTests(unittest.TestCase):
    """No process, fixture dispatch or production import in these recorders."""

    def test_explicit_ci_and_local_routes_require_complete_disjoint_metadata(self):
        valid = SimpleNamespace(local=False, repository="example/mobile-release-kit", commit="1" * 40,
                                run_id="1234", run_attempt=1, job="test-signing-matrix")
        for key in ("repository", "commit", "run_id", "run_attempt", "job"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "complete explicit"):
                runner.explicit_metadata(SimpleNamespace(**{**vars(valid), key: None}))
        with self.assertRaisesRegex(ValueError, "partial CI"):
            runner.explicit_metadata(SimpleNamespace(**{**vars(valid), "local": True}))
        local = SimpleNamespace(local=True, repository=None, commit=None, run_id=None, run_attempt=None, job=None)
        self.assertEqual(runner.explicit_metadata(local), {"kind": "local", "repository": None,
                         "commit": None, "runId": None, "attempt": 1, "job": "local"})

    def test_phase_rejects_runtime_deadline_and_root_changes_before_import_or_creation(self):
        flags = SimpleNamespace(**{name: 1 for name in ("isolated", "ignore_environment", "no_user_site",
                                                       "no_site", "safe_path", "dont_write_bytecode")})
        args = SimpleNamespace(deadline=20.0, phase="source", package_root=Path("/not-the-fixed-package"),
                               output=Path("/not-created"), shard=0, local_reduction=False)
        with patch.object(runner, "sys", SimpleNamespace(flags=flags)), \
                patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaisesRegex(ValueError, "fixed phase roots"):
                runner.phase(args, {})
            for cutoff in (None, 9.0, 10.0, 431.0, float("nan"), float("inf")):
                with self.subTest(cutoff=cutoff), self.assertRaisesRegex(ValueError, "original phase deadline"):
                    runner.phase(SimpleNamespace(**{**vars(args), "deadline": cutoff}), {})
            flags.no_site = 0
            with self.assertRaisesRegex(ValueError, "isolated no-site"):
                runner.phase(args, {})

    def test_definitions_bind_every_controller_and_provider_file_not_only_python_helpers(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-definitions-") as temporary:
            root = Path(temporary)
            for directory in (root / "tests", root / ".github/scripts", root / ".github/workflows"):
                directory.mkdir(parents=True)
            for number in range(10):
                (root / "tests" / f"test_{number}.py").write_text("# inert definition\n")
            (root / ".github/workflows/ci.yml").write_text("# inert workflow\n")
            (root / "pyproject.toml").write_text("# inert packaging\n")
            helper = root / ".github/scripts/verifier-data.txt"
            helper.write_text("fixed admitted provider data\n")
            first = contract.definitions_manifest(root)
            self.assertIn(".github/scripts/verifier-data.txt", first)
            helper.write_text("changed provider data\n")
            self.assertNotEqual(contract.digest(first), contract.digest(contract.definitions_manifest(root)))
            helper.unlink()
            helper.symlink_to(root / "pyproject.toml")
            with self.assertRaisesRegex(ValueError, "invalid test definition"):
                contract.definitions_manifest(root)
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 20.0)), \
                    self.assertRaisesRegex(ValueError, "cutoff expired"):
                contract.package_manifest(root, deadline=20.0)

    def test_create_only_record_cannot_overwrite_prior_proof_or_follow_a_link(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-write-") as temporary:
            root = Path(temporary)
            path = root / "proof.json"
            runner.write_record(path, {"diagnostic": True})
            content = path.read_bytes()
            with self.assertRaises(FileExistsError): runner.write_record(path, {"replaced": True})
            self.assertEqual(path.read_bytes(), content)
            linked = root / "linked.json"
            linked.symlink_to(path)
            with self.assertRaises(FileExistsError): runner.write_record(linked, {"replaced": True})
            self.assertEqual(path.read_bytes(), content)


class SigningAdapterAdmissionTests(unittest.TestCase):
    """Closed-scope DATA checks; no test method, subprocess or native dispatch."""

    def metadata(self):
        return {"kind": "github", "repository": "example/mobile-release-kit", "commit": "1" * 40,
                "runId": "1234", "attempt": 1, "job": "test-signing-adapter"}

    def test_literal_inventory_and_metadata_never_expand_the_matrix_reducer(self):
        self.assertEqual(contract.adapter_test_ids(runner.ROOT), contract.ADAPTER_TEST_IDS)
        expected = tuple("unit.test_local_signing_persistent.PersistentSigningTests." + name for name in (
            "test_one_real_model_command_bridge_finishes_before_success",
            "test_actual_case_wait_eof_barrier_crash_and_deadline_settle_before_return",
            "test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery",
            "test_genuine_model_inventory_active_build_pending_contrast",
        )) + ("workflow.test_command_account_lifecycle.CommandAccountLifecycleTests."
              "test_prepared_no_target_original_fence_and_same_lease_cleanup",)
        self.assertEqual(contract.ADAPTER_TEST_IDS, expected)
        self.assertEqual(len(set(contract.ADAPTER_TEST_IDS)), 5)
        self.assertEqual(contract.ADAPTER_TEST_FILES, {
            **dict.fromkeys(expected[:4], "tests/unit/test_local_signing_persistent.py"),
            expected[4]: "tests/workflow/test_command_account_lifecycle.py",
        })
        # The additional literal method must be defined in its own exact class
        # and file, not merely named in the old four-method source module.
        account_path = runner.ROOT / "tests/workflow/test_command_account_lifecycle.py"
        original_read = Path.read_bytes
        method = expected[4].rsplit(".", 1)[1]
        member = "    def " + method + "(self):\n        pass\n"
        for content in ("class Other:\n" + member, "class CommandAccountLifecycleTests:\n    pass\n",
                        "class CommandAccountLifecycleTests:\n" + member * 2,
                        ("class CommandAccountLifecycleTests:\n" + member) * 2):
            def changed(path, content=content):
                return content.encode() if path == account_path else original_read(path)
            with patch.object(Path, "read_bytes", new=changed), self.assertRaises(ValueError):
                contract.adapter_test_ids(runner.ROOT)
        value = self.metadata()
        scope = contract.adapter_scope_from_metadata(value, "ubuntu-24.04")
        self.assertEqual(scope["schema"], "mrk-signing-adapter-scope-v1")
        for changes in ({"job": "test-signing-matrix"}, {"kind": "local"}, {"attempt": True},
                        {"runId": None}, {"repository": None}, {"commit": "wrong"}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.adapter_scope_from_metadata({**value, **changes}, "ubuntu-24.04")
        for producer in (False, True):
            with self.assertRaises(ValueError):
                contract.scope_from_metadata(value, "ubuntu-24.04", producer=producer)

    def test_adapter_cli_rejects_shard_reducer_local_and_incomplete_scope_before_dispatch(self):
        base = ["--adapter-phase", "source", "--output", "/not-created", "--os", "ubuntu-24.04",
                "--repository", "example/mobile-release-kit", "--commit", "1" * 40,
                "--run-id", "1234", "--run-attempt", "1", "--job", "test-signing-adapter"]
        with patch.object(runner, "adapter_phase") as dispatch, \
                patch.object(runner, "operating_system", return_value="ubuntu-24.04"), redirect_stderr(io.StringIO()):
            for extra in (["--shard", "0"], ["--reduce", "/other"], ["--local"], ["--local-reduction"]):
                with self.subTest(extra=extra), self.assertRaises((ValueError, SystemExit)):
                    runner.main(base + extra)
            with self.assertRaises(ValueError):
                runner.main(base[:-2])  # Missing job never implies local.
            dispatch.assert_not_called()

    def test_adapter_deadline_runtime_and_fixed_roots_precede_product_loading(self):
        flags = SimpleNamespace(**{name: 1 for name in ("isolated", "ignore_environment", "no_user_site",
                                                       "no_site", "safe_path", "dont_write_bytecode")})
        args = SimpleNamespace(deadline=20.0, adapter_phase="source", package_root=Path("/not-the-fixed-package"),
                               output=Path("/not-created"))
        with patch.object(runner, "sys", SimpleNamespace(flags=flags)), \
                patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaisesRegex(ValueError, "fixed adapter roots"):
                runner.adapter_phase(args, {})
            for cutoff in (None, True, 10.0, 431.0, float("nan")):
                with self.subTest(cutoff=cutoff), self.assertRaisesRegex(ValueError, "original adapter deadline"):
                    runner.adapter_phase(SimpleNamespace(**{**vars(args), "deadline": cutoff}), {})
            flags.no_site = 0
            with self.assertRaisesRegex(ValueError, "isolated no-site"):
                runner.adapter_phase(args, {})

    def test_actual_origin_roles_require_existing_exact_files_without_importing_unused_modules(self):
        original_import = __import__

        def no_production_import(name, *args, **kwargs):
            if name == "mobile_release" or name.startswith("mobile_release."):
                raise AssertionError("origin inspection must not import production modules")
            # pathlib may import a standard-library path helper on Python 3.12+.
            return original_import(name, *args, **kwargs)

        parent_names = {"mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
                        "mobile_release._native_process"}
        self.assertEqual(contract.ADAPTER_ORIGIN_MODULES, {
            "parent": parent_names, "commandWorker": parent_names | {"mobile_release._command_process"}})
        relative = {name: "__init__.py" if name == "mobile_release" else name.split(".")[-1] + ".py"
                    for name in parent_names | {"mobile_release._command_process"}}
        with tempfile.TemporaryDirectory(prefix="mrk-adapter-origins-inert-") as temporary:
            root = Path(temporary).resolve()
            packages = (root / "source/mobile_release", root / "wheel/lib/python3.11/site-packages/mobile_release")
            for package in packages:
                package.mkdir(parents=True)
                for name in (*relative.values(), "optional.py", ".py"):
                    (package / name).write_text("# Inert origin metadata, never imported.\n")
            for package, other in (packages, tuple(reversed(packages))):
                modules = {name: SimpleNamespace(__file__=str(package / path)) for name, path in relative.items()}
                parent = {name: module for name, module in modules.items() if name in parent_names}
                with self.subTest(package=package.name), patch.object(contract, "sys", SimpleNamespace(modules=parent)), \
                        patch("builtins.__import__", side_effect=no_production_import):
                    actual = contract.actual_adapter_origins(package, "parent")
                    self.assertEqual(set(actual), parent_names)
                    with self.assertRaisesRegex(ValueError, "loaded modules missing"):
                        contract.actual_adapter_origins(package, "commandWorker")
                with patch.object(contract, "sys", SimpleNamespace(modules=modules)):
                    self.assertEqual(contract.actual_adapter_origins(package, "commandWorker"), relative)
                    self.assertEqual(contract.actual_adapter_origins(package, "parent"), relative)
                missing = dict(modules)
                missing.pop("mobile_release._native_process")
                wrong = (
                    missing,
                    {**modules, "mobile_release": SimpleNamespace(__file__=str(package / ".py"))},
                    {**modules, "mobile_release.local_signing": SimpleNamespace(__file__=str(package / "owned_process.py"))},
                    {**modules, "mobile_release._command_process": SimpleNamespace(__file__=str(other / "_command_process.py"))},
                    {**modules, "mobile_release.optional": SimpleNamespace(__file__=str(other / "optional.py"))},
                    {**modules, "mobile_release.optional": SimpleNamespace(__file__=str(package / "missing.py"))},
                    {**modules, "mobile_release.optional": SimpleNamespace()},
                )
                for snapshot in wrong:
                    with patch.object(contract, "sys", SimpleNamespace(modules=snapshot)), \
                            self.assertRaises((ValueError, OSError)):
                        contract.actual_adapter_origins(package, "commandWorker")
                with patch.object(contract, "sys", SimpleNamespace(modules=modules)), \
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 20.0)), \
                        self.assertRaisesRegex(ValueError, "cutoff"):
                    contract.actual_adapter_origins(package, "commandWorker", deadline=20.0)

    def test_actual_result_accepts_only_fresh_first_worker_origins_before_success(self):
        origins = {name: "__init__.py" if name == "mobile_release" else name.split(".")[-1] + ".py"
                   for name in ("mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
                                "mobile_release._native_process", "mobile_release._command_process")}
        for mode in ("good", "missing", "malformed", "foreign", "already-supplied", "failed", "stopped", "wrong-provider"):
            with self.subTest(mode=mode):
                identifier = contract.ADAPTER_TEST_IDS[1 if mode == "wrong-provider" else 0]
                test = SimpleNamespace(id=lambda: identifier, _adapter_command_worker_origins=dict(origins))
                result = runner.SigningAdapterResult("source", 20.0, ())
                with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                    result.startTest(test)
                    previous = None
                    candidate = test
                    if mode == "missing": test._adapter_command_worker_origins = None
                    if mode == "malformed": test._adapter_command_worker_origins.pop("mobile_release._command_process")
                    if mode == "foreign": candidate = SimpleNamespace(id=test.id, _adapter_command_worker_origins=dict(origins))
                    if mode == "already-supplied":
                        previous = result.command_worker_origins = dict(origins)
                    if mode == "failed": result.failed = True
                    if mode == "stopped": result.stop()
                    first = result.first_failure = ("original", "failure") if mode in {"failed", "stopped"} else None
                    if mode == "good":
                        result.addSuccess(candidate)
                        test._adapter_command_worker_origins.clear()
                        self.assertEqual(result.command_worker_origins, origins)
                        self.assertEqual(result.succeeded, [identifier])
                        with self.assertRaises(ValueError): result.addSuccess(candidate)
                    else:
                        with self.assertRaises(ValueError): result.addSuccess(candidate)
                        self.assertEqual(result.succeeded, [])
                        self.assertIs(result.command_worker_origins, previous)
                    self.assertIs(result.first_failure, first)
                    result.stopTest(test)


class SigningAdapterDiagnosticTests(unittest.TestCase):
    """Actual exception/callback projection, with no native or child dispatch."""

    def context_and_task(self, *, foreign=False):
        trusted = "/fixed/source/tests/unit/test_local_signing_persistent.py"
        filename = "/PRIVATE/other/tests/unit/test_local_signing_persistent.py" if foreign else trusted
        namespace = {}
        exec(compile("def fail():\n    raise ValueError('PRIVATE_MESSAGE /PRIVATE/case/path')\n", filename, "exec"), namespace)
        context = ("source", contract.ADAPTER_TEST_IDS[0], ((trusted, "tests/unit/test_local_signing_persistent.py"),))
        return context, namespace["fail"]

    def test_progress_contract_is_finite_failure_only_and_dropped_before_prior_details(self):
        context, task = self.context_and_task()
        try:
            task()
        except ValueError as first:
            try:
                task()
            except ValueError as second:
                second.__cause__ = first
                error = sys.exc_info()
        progress = {"case": "query", "owner": {"stage": "run-owned", "command": 4, "elapsedMs": 321,
                    "completed": 3, "totalMs": 222, "maxMs": 111},
                    "service": {"stage": "EOF", "command": 4, "elapsedMs": 320}}
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            project = lambda value: contract.adapter_failure_record(context, "unittest", "error", error,
                                                                     deadline=20.0, progress=value)
            self.assertEqual(project(progress)["progress"], progress)
            unavailable = {"case": "query", "owner": None, "service": None}
            self.assertEqual(project(unavailable)["progress"], unavailable)
            invalid = (["PRIVATE"], {**progress, "case": "/PRIVATE/case"}, {**progress, "pid": 123},
                       {**progress, "owner": None}, {**progress, "service": {**progress["service"], "command": 3}},
                       {**progress, "service": {**progress["service"], "stage": "PRIVATE"}})
            for bad in invalid:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    project(bad)
            for fields in ({"command": True}, {"elapsedMs": 1.0}, {"completed": 5}, {"totalMs": -1},
                           {"maxMs": 223}, {"elapsedMs": 1 << 31}, {"stage": "PRIVATE"}, {"argv": "PRIVATE"}):
                with self.subTest(fields=fields), self.assertRaises(ValueError):
                    project({**progress, "owner": {**progress["owner"], **fields}})
            for layer, outcome in (("worker", "error"), ("unittest", "skip"), ("unittest", "unexpected-success")):
                with self.subTest(layer=layer, outcome=outcome), self.assertRaises(ValueError):
                    contract.adapter_failure_record(context, layer, outcome, error, deadline=20.0, progress=progress)
            # Real2048-byte limit: two long prebound root/related locations fit
            # without the new page data. Progress must go before either one.
            long_public = "src/mobile_release/" + "nested/" * 110 + "module.py"
            context = (*context[:2], ((context[2][0][0], long_public),))
            original = project(None)
            self.assertIn("related", original)
            self.assertLessEqual(len(contract.ADAPTER_FAILURE_PREFIX) + len(contract.canonical(original)) + 1, 2048)
            self.assertEqual(project(progress), original)

    def test_projector_uses_only_exact_precomputed_frames_and_never_private_text_or_source_reads(self):
        for foreign in (False, True):
            context, task = self.context_and_task(foreign=foreign)
            try:
                task()
            except ValueError:
                error = sys.exc_info()
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic path resolution")), \
                    patch.object(Path, "stat", side_effect=AssertionError("no diagnostic filesystem read")), \
                    patch.object(traceback, "extract_tb", side_effect=AssertionError("no formatted traceback")), \
                    patch.object(linecache, "getline", side_effect=AssertionError("no diagnostic source read")):
                record = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0)
            self.assertEqual(record["category"], "value-error")
            self.assertEqual(record["locations"], [] if foreign else [
                {"file": "tests/unit/test_local_signing_persistent.py", "line": 2}])
            self.assertNotIn("PRIVATE", contract.canonical(record).decode())

    def test_target_stderr_projection_is_bounded_private_and_dropped_before_existing_observations(self):
        context, task = self.context_and_task()
        actual, public = context[2][0]
        header = "Traceback (most recent call last):\n"
        frame = lambda number: f'  File "{actual}", line {number}, in PRIVATE_function\n'
        raw = header + frame(1) + "    PRIVATE source code\n" + frame(2) + frame(3) + "ValueError: PRIVATE message\n"
        with patch.object(Path, "resolve", side_effect=AssertionError("no target diagnostic resolution")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("no target diagnostic read")), \
                patch.object(linecache, "getline", side_effect=AssertionError("no source lines")), \
                patch.object(contract, "_adapter_locations", side_effect=AssertionError("no extra actual traceback walk")):
            observed = contract.adapter_target_result(context, 1, raw)
            self.assertEqual(observed, (1, "traceback-frames", ((public, 2), (public, 3))))
            self.assertNotIn("PRIVATE", str(observed))
            self.assertEqual(contract.adapter_target_result(context, -128, ""), (-128, "empty", ()))
            self.assertEqual(contract.adapter_target_result(context, 255, ""), (255, "empty", ()))
            prefix = header + frame(7)
            byte_boundary = prefix + "x" * (8192 - len(prefix.encode("utf-8")))
            lines_boundary = prefix + "PRIVATE ignored line\n" * 62
            for content in (byte_boundary, lines_boundary):
                self.assertEqual(contract.adapter_target_result(context, 1, content)[1:],
                                 ("traceback-frames", ((public, 7),)))
            invalid = (None, b"", raw.encode(), byte_boundary + "x", lines_boundary + "extra\n",
                       prefix + "\u00e9" * 4096, prefix + "\ud800", "PRIVATE prefix\n" + raw,
                       header + '  File "/PRIVATE/other.py", line 1, in private\n',
                       header + frame("01"), header + frame("1000000"), header + frame("1.0"),
                       header + frame("True"), header + frame(1).replace("PRIVATE_function", "x" * 257))
            for content in invalid:
                self.assertEqual(contract.adapter_target_result(context, 1, content), (1, "unavailable", ()))
            for status in (True, 1.0, -129, 256, None):
                with self.assertRaises(ValueError):
                    contract.adapter_target_result(context, status, raw)
        try:
            task()
        except ValueError:
            error = sys.exc_info()
        # A long but prebound public module path cannot crowd out the existing
        # root/related observation or raise the established 2048-byte envelope.
        long_public = "src/mobile_release/" + "nested/" * 130 + "module.py"
        context = (*context[:2], (*context[2], ("/fixed/target.py", long_public)))
        large_target = (1, "traceback-frames", ((long_public, 1), (long_public, 2)))
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            original = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0)
            reduced = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0,
                                                       target_result=large_target)
        self.assertEqual(reduced, original)
        self.assertLessEqual(len(contract.ADAPTER_FAILURE_PREFIX) + len(contract.canonical(reduced)) + 1, 2048)

    def test_target_observer_requires_original_prearmed_pid_context_thread_and_absorbing_claim(self):
        owner = runner.case_owner
        context, _task = self.context_and_task()
        original_projection = owner.adapter_target_result
        thread = object()
        result = owner.CompletedProcess(["PRIVATE argv"], 1, "PRIVATE stdout", "")
        class Lookalike(owner.CompletedProcess):
            pass
        for mode in ("observed", "projection-error", "bad-status", "busy", "foreign-pid", "foreign-thread", "foreign-context", "lookalike"):
            with self.subTest(mode=mode):
                calls = []
                slot = {"context": context, "pid": 7, "thread": thread, "lock": owner.threading.Lock(),
                        "claimed": False, "first": None, "reserved": 16, "target_claimed": False, "target": None}
                current = (context[0], context[1], context[2]) if mode == "foreign-context" else context
                selected = (Lookalike(["PRIVATE"], 1, "", "") if mode == "lookalike" else
                            owner.CompletedProcess(["PRIVATE"], True, "", "") if mode == "bad-status" else result)
                def project(scope, status, stderr):
                    self.assertTrue(slot["target_claimed"])
                    calls.append((scope, status, stderr))
                    value = original_projection(scope, status, stderr)
                    if mode == "projection-error":
                        raise ValueError("PRIVATE optional diagnostic failure")
                    return value
                if mode == "busy":
                    slot["lock"].acquire()
                try:
                    with patch.multiple(owner, _ADAPTER_WORKER_DIAGNOSTIC=slot, ADAPTER_DIAGNOSTIC_CONTEXT=current,
                                        os=SimpleNamespace(getpid=lambda: 8 if mode == "foreign-pid" else 7),
                                        adapter_target_result=project), \
                            patch.object(owner.threading, "current_thread", return_value=object() if mode == "foreign-thread" else thread):
                        owner.observe_adapter_target_result(selected)
                        owner.observe_adapter_target_result(selected)
                finally:
                    if mode == "busy":
                        slot["lock"].release()
                claimed = mode in {"observed", "projection-error", "bad-status"}
                self.assertEqual(len(calls), int(claimed))
                self.assertEqual(slot["target_claimed"], claimed)
                self.assertEqual(slot["target"], (1, "empty", ()) if mode == "observed" else None)
                self.assertFalse(slot["claimed"])
                self.assertEqual(slot["reserved"], 16)
        with patch.object(owner, "_ADAPTER_WORKER_DIAGNOSTIC", None):
            owner.observe_adapter_target_result(object())  # Disabled means no inspection or dynamic slot allocation.

    def test_suppressed_cyclic_links_use_builtin_data_and_share_the_original_frame_budget(self):
        class PrivateError(Exception):
            def __getattribute__(self, name):
                raise AssertionError("exception attributes must not be consulted")
            def __str__(self):
                raise AssertionError("exception text must not be formatted")
        context, _task = self.context_and_task()
        namespace = {"PrivateError": PrivateError}
        source = ("def deep(n):\n"
                  "    if n: return deep(n - 1)\n"
                  "    raise ValueError('PRIVATE deeply nested error')\n"
                  "def fail(n):\n"
                  "    try: deep(n)\n"
                  "    except ValueError:\n"
                  "        raise PrivateError('PRIVATE suppressed error') from None\n")
        exec(compile(source, context[2][0][0], "exec"), namespace)
        for depth in (1, 100):
            try:
                namespace["fail"](depth)
            except PrivateError:
                error = sys.exc_info()
            original = BaseException.__dict__["__context__"].__get__(error[1], BaseException)
            # Real built-in cyclic links, not a custom graph supplied to the projector.
            original.__cause__ = error[1]
            visited = []
            locations = contract._adapter_locations
            def counted(frame, source_map, budget, maximum):
                before = budget[0]
                result = locations(frame, source_map, budget, maximum)
                visited.append(before - budget[0])
                return result
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(contract, "_adapter_locations", new=counted), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("no source reads")), \
                    patch.object(linecache, "getline", side_effect=AssertionError("no source lines")):
                first = contract.adapter_command_first(context, original)
                record = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0,
                                                          command_first=first, command_reserved=16)
            self.assertEqual(record["category"], "exception")
            self.assertEqual([row["via"] for row in record["related"]], [["command-first"], ["context"]])
            self.assertLessEqual(sum(visited), 64)
            if depth == 100:
                self.assertEqual(sum(visited), 64)
            self.assertTrue(all(len(row["locations"]) <= 2 for row in record["related"]))
            self.assertLessEqual(len(contract.ADAPTER_FAILURE_PREFIX) + len(contract.canonical(record)) + 1, 2048)
            self.assertNotIn("PRIVATE", contract.canonical(record).decode())
        # Even a long real exception chain contributes no more than three links.
        chain = [ValueError() for _ in range(12)]
        for left, right in zip(chain, chain[1:]):
            left.__context__ = right
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            record = contract.adapter_failure_record(context, "worker", "error", (ValueError, chain[0], None), deadline=20.0)
        self.assertEqual([row["via"] for row in record["related"]], [["context"] * count for count in (1, 2, 3)])

    def test_original_command_recorder_runs_once_first_and_diagnostic_claim_is_absorbing(self):
        owner = runner.case_owner
        context, task = self.context_and_task()
        try:
            task()
        except ValueError as caught:
            first_error = caught
        for mode in ("observed", "projection-error", "original-error", "busy", "foreign-pid", "other-role"):
            with self.subTest(mode=mode):
                calls, projections = [], []
                first = OSError("PRIVATE original recorder failure")
                slot = {"pid": 7, "context": context, "lock": owner.threading.Lock(), "claimed": False, "first": None}
                command = SimpleNamespace(pid=8 if mode == "foreign-pid" else 7,
                                          role="C" if mode == "other-role" else "O", primary=None)
                def actual(instance, error, **kwargs):
                    calls.append((instance, error, kwargs))
                    if mode == "original-error":
                        raise first
                    if instance.primary is None:
                        instance.primary = error
                    return "actual-result"
                def project(scope, error):
                    self.assertTrue(slot["claimed"])
                    self.assertIs(command.primary, error)
                    projections.append((scope, error))
                    value = contract.adapter_command_first(scope, error)
                    if mode == "projection-error":
                        raise RuntimeError("PRIVATE diagnostic failure")
                    return value
                if mode == "busy":
                    slot["lock"].acquire()
                try:
                    with patch.multiple(owner, _ADAPTER_WORKER_DIAGNOSTIC=slot,
                                        os=SimpleNamespace(getpid=lambda: 7), adapter_command_first=project):
                        recorded = owner.adapter_command_recorder(actual)
                        if mode == "original-error":
                            with self.assertRaises(OSError) as caught:
                                recorded(command, first_error, unknown=True)
                            self.assertIs(caught.exception, first)
                        else:
                            self.assertEqual(recorded(command, first_error, unknown=True), "actual-result")
                            self.assertEqual(recorded(command, first_error, unknown=False), "actual-result")
                            self.assertEqual(recorded(command, TypeError("PRIVATE later error")), "actual-result")
                finally:
                    if mode == "busy":
                        slot["lock"].release()
                self.assertEqual(calls[0], (command, first_error, {"unknown": True}))
                self.assertEqual(len(calls), 1 if mode == "original-error" else 3)
                self.assertEqual(len(projections), int(mode in {"observed", "projection-error"}))
                self.assertEqual(slot["claimed"], mode in {"observed", "projection-error"})
                self.assertEqual(slot["first"] is not None, mode == "observed")
        with patch.object(owner, "_ADAPTER_WORKER_DIAGNOSTIC", None):
            self.assertIs(owner.adapter_command_recorder(actual), actual)

    def test_worker_reserved_budget_survives_missing_inflight_and_failed_command_projection(self):
        owner = runner.case_owner
        context, _task = self.context_and_task()
        namespace = {}
        exec(compile("def deep(n):\n    if n: return deep(n - 1)\n    raise ValueError('PRIVATE')\n",
                     context[2][0][0], "exec"), namespace)
        try:
            namespace["deep"](100)
        except ValueError:
            error = sys.exc_info()
        for mode in ("inflight", "failed", "later"):
            with self.subTest(mode=mode):
                visits, records = [], []
                slot = {"context": context, "pid": 7, "lock": owner.threading.Lock(),
                        "claimed": False, "first": None, "reserved": 16}
                command = SimpleNamespace(pid=7, role="O", primary=None)
                locations = contract._adapter_locations
                def counted(frame, source_map, budget, maximum):
                    before = budget[0]
                    result = locations(frame, source_map, budget, maximum)
                    visits.append(before - budget[0])
                    return result
                def root_record():
                    self.assertIsNone(slot["first"])
                    records.append(contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0,
                        command_first=slot["first"], command_reserved=slot["reserved"]))
                def actual(instance, caught):
                    instance.primary = caught
                def project(scope, caught):
                    value = contract.adapter_command_first(scope, caught)  # Consumes 16 real frames BEFORE failure.
                    if mode == "inflight":
                        root_record()  # Same scalar boundary as a concurrent worker failure; no test thread.
                    if mode == "failed":
                        raise RuntimeError("PRIVATE after partial diagnostic work")
                    return value
                with patch.multiple(owner, _ADAPTER_WORKER_DIAGNOSTIC=slot,
                                    os=SimpleNamespace(getpid=lambda: 7), adapter_command_first=project), \
                        patch.object(contract, "_adapter_locations", new=counted), \
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                    recorded = owner.adapter_command_recorder(actual)
                    if mode == "later":
                        root_record()  # Unclaimed is not permission to spend the reserved 16 again.
                    recorded(command, error[1])
                    if mode == "failed":
                        root_record()
                self.assertEqual(sum(visits), 64)
                self.assertEqual(len(records), 1)
                self.assertNotIn("related", records[0])

    def test_case_failure_scalars_use_original_terminal_observations_without_new_waits_or_reads(self):
        owner = runner.case_owner
        context, _task = self.context_and_task()
        for terminal in (b"EXPIRED -9\n", b"SETTLED 91\n", None):
            with self.subTest(terminal=terminal):
                events, records = [], iter((b"ARMED 42\n", terminal, b""))
                original = ValueError("PRIVATE missing terminal")
                class Wait:
                    pid, status, unknown, retired = 41, None, False, False
                    def fork(self):
                        events.append("original-fork")
                        return self.pid
                    def wait(self):
                        events.append("original-wait")
                        self.retired, self.status = True, 0
                        return self.status
                handles = SimpleNamespace(errors=[], pipe=lambda _name: None, get=lambda _name: 10,
                                          close=lambda _name: None, close_except=lambda: None)
                def receive(_descriptor, data, _deadline):
                    record = next(records)
                    if record is None:
                        raise original
                    data.extend(record)
                    return bool(record)
                def converted(status):
                    events.append(("existing-conversion", status))
                    return 0
                native = SimpleNamespace(getpid=lambda: 7, getpgrp=lambda: 8,
                    waitstatus_to_exitcode=converted, killpg=lambda *_: events.append("original-group-stop"))
                with patch.multiple(owner, os=native, OriginalWait=Wait, Handles=lambda: handles,
                                    receive=receive, send=lambda *_: None, absent=lambda *_args, **_kwargs: True,
                                    time=SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda _seconds: None),
                                    threading=SimpleNamespace(active_count=lambda: 1),
                                    ADAPTER_DIAGNOSTIC_CONTEXT=context, ADAPTER_CASE_FAILURE=None), \
                        patch.object(Path, "read_bytes", side_effect=AssertionError("no post-failure reads")):
                    with self.assertRaises((AssertionError, ValueError)) as caught:
                        owner.run_worker(Path("/not-created"), "inert", lambda: None, write_json=lambda *_: None)
                    case = owner.adapter_case_failure(context)
                    self.assertIsNone(owner.adapter_case_failure((context[0], context[1], context[2])))
                self.assertEqual(events.count("original-wait"), 1)
                if terminal is None:
                    self.assertIs(caught.exception, original)
                    self.assertEqual(case, (0, None, None, False, None))
                    self.assertNotIn(("existing-conversion", 0), events)
                else:
                    self.assertEqual(case, (0, -9 if terminal.startswith(b"EXPIRED") else 91, 0, True,
                                            terminal.startswith(b"EXPIRED")))
                    self.assertEqual(events.count(("existing-conversion", 0)), 1)

    def test_trace_filter_preserves_production_inventory_across_nonproduction_callbacks_and_generator_resumes(self):
        production = {"__name__": "mobile_release.local_signing"}
        helper = {"__name__": "inert_helper"}
        exec(compile("def leaf(value):\n    return value + 1\n"
                     "def produce(helper):\n    for value in range(3):\n        yield from helper(value, leaf)\n"
                     "def entry(helper):\n    return list(produce(helper))\n", "<inert-production>", "exec"), production)
        exec(compile("def helper(value, callback):\n    yield callback(value)\n    yield callback(value + 10)\n"
                     "def invoke(entry):\n    return entry(helper)\n", "<inert-helper>", "exec"), helper)
        old_lines, old_nonproduction, new_nonproduction = set(), [], []
        def old(frame, event, _arg):
            module = frame.f_globals.get("__name__")
            if event == "line":
                if module in fixture.PRODUCTION:
                    old_lines.add(module + ":" + frame.f_code.co_name + ":" + str(frame.f_lineno))
                elif module == "inert_helper":
                    old_nonproduction.append(frame.f_lineno)
            return old
        previous = sys.gettrace()
        try:
            sys.settrace(old)
            expected = helper["invoke"](production["entry"])
        finally:
            sys.settrace(previous)
        trace = object.__new__(fixture.Trace)
        trace.lines, trace.inventory = set(), True
        actual = fixture.Trace._trace_lines
        def observed(self, frame, event, arg):
            if event == "line" and frame.f_globals.get("__name__") == "inert_helper":
                new_nonproduction.append(frame.f_lineno)
            return actual(self, frame, event, arg)
        with patch.object(fixture.Trace, "_trace_lines", new=observed), \
                patch.object(runner.case_owner, "ADAPTER_DIAGNOSTIC_CONTEXT", None):
            with trace.installed():
                value = helper["invoke"](production["entry"])
        self.assertEqual(value, expected)
        self.assertIs(sys.gettrace(), previous)
        self.assertTrue(old_lines and old_nonproduction)
        self.assertFalse(new_nonproduction)
        self.assertEqual(trace.lines, old_lines)

    def test_actual_result_first_subtest_failure_survives_teardown_skip_and_diagnostic_write_failure(self):
        context, task = self.context_and_task()
        try:
            task()
        except ValueError:
            error = sys.exc_info()
        for broken in (False, True):
            stream = io.StringIO()
            sink = SimpleNamespace(write=lambda _text: (_ for _ in ()).throw(OSError("PRIVATE writer error"))) if broken else stream
            test = unittest.FunctionTestCase(lambda: None)
            test.id = lambda: context[1]
            result = runner.SigningAdapterResult(context[0], 20.0, context[2])
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), redirect_stderr(sink):
                result.startTest(test)
                self.assertIs(runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT, result.context)
                runner.case_owner.ADAPTER_CASE_FAILURE = (result.context, (0, None, None, False, None))
                result.addSubTest(test, test, error)
                first = result.first_failure
                result.addError(test, error)  # A later teardown failure must not replace it.
                result.addSkip(test, "PRIVATE skip reason")
                result.stopTest(test)
            self.assertIs(result.first_failure, first)
            self.assertEqual(first, (context[1], "error"))
            self.assertTrue(result.failed and result.shouldStop)
            self.assertFalse(result.wasSuccessful())
            self.assertIsNone(runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT)
            if broken:
                self.assertEqual(stream.getvalue(), "")
            else:
                lines = stream.getvalue().splitlines()
                self.assertEqual(len(lines), 1)
                record = json.loads(lines[0].removeprefix(contract.ADAPTER_FAILURE_PREFIX))
                self.assertEqual((record["testId"], record["layer"], record["outcome"]), (context[1], "unittest", "error"))
                self.assertEqual(record["case"], {"expectedExit": 0, "workerExit": None, "anchorExit": None,
                                                  "terminalParsed": False, "anchorExpired": None})
                self.assertNotIn("PRIVATE", lines[0])

    def test_worker_observation_is_disabled_by_default_and_writer_failure_keeps_exit_and_private_evidence(self):
        owner = runner.case_owner
        context, task = self.context_and_task()
        class Exited(BaseException):
            pass
        for mode in ("disabled", "enabled", "writer-error", "late-failure", "slot-interrupted", "success"):
            with self.subTest(mode=mode):
                calls, output = [], io.StringIO()
                sink = SimpleNamespace(write=lambda _text: (_ for _ in ()).throw(OSError("PRIVATE writer error"))) \
                    if mode == "writer-error" else output
                handles = SimpleNamespace(errors=[], close_except=lambda *_: calls.append("close-all"),
                    close=lambda name: calls.append(("close", name)), get=lambda _name: 123)
                native = SimpleNamespace(getpid=lambda: 9, getppid=lambda: 7, getpgrp=lambda: 8,
                    _exit=lambda code: (_ for _ in ()).throw(Exited(code)))
                def failed_task():
                    calls.append("task")
                    if mode == "success":
                        return "inert result"
                    try:
                        task()
                    except BaseException as primary:
                        owner.observe_adapter_target_result(owner.CompletedProcess(["PRIVATE target"], 1, "PRIVATE output", ""))
                        raise primary
                def receive(_fd, buffer, _deadline):
                    buffer.extend(b"RUN\n")
                    return True
                with patch.multiple(owner, os=native, receive=receive, send=lambda *_: None,
                                    remaining=lambda cutoff: calls.append(("task-endpoint", cutoff)) or 1,
                                    CASE_DEADLINE=None, _ADAPTER_WORKER_DIAGNOSTIC=None,
                                    threading=SimpleNamespace(Lock=lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
                                        if mode == "slot-interrupted" else owner.threading,
                                    adapter_progress=lambda stage: calls.append(("progress", stage)),
                                    ADAPTER_DIAGNOSTIC_CONTEXT=None if mode == "disabled" else context), \
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 21.0 if mode == "late-failure" else 10.0)), \
                        redirect_stderr(sink), \
                        self.assertRaises(Exited) as caught:
                    owner._worker(handles, 7, 8, Path("/not-created"), "synthetic", failed_task, 20.0,
                        lambda path, _value: calls.append(("private-write", path.name)), hard=25.0)
                self.assertEqual(caught.exception.args, (0 if mode == "success" else owner.WORKER_ERROR,))
                filename = "synthetic.json" if mode == "success" else "synthetic-error.json"
                self.assertEqual(calls.count(("private-write", filename)), 1)
                self.assertEqual(calls.count("task"), int(mode != "slot-interrupted"))
                self.assertTrue(all(call[1] == 20.0 for call in calls if type(call) is tuple and call[0] == "task-endpoint"))
                stages = [call[1] for call in calls if type(call) is tuple and call[0] == "progress"]
                self.assertEqual(stages, [] if mode == "slot-interrupted" else
                                 ["task-entered", "task-returned", "result-write-returned"] if mode == "success" else ["task-entered"])
                self.assertEqual(calls[-1], "close-all")
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertEqual(output.getvalue().count(contract.ADAPTER_FAILURE_PREFIX),
                                 int(mode in {"enabled", "late-failure", "slot-interrupted"}))
                if mode == "enabled":
                    record = json.loads(output.getvalue().removeprefix(contract.ADAPTER_FAILURE_PREFIX))
                    self.assertEqual(record["targetResult"], {"returncode": 1, "stderrKind": "empty", "locations": []})


class SigningAdapterPhaseDiagnosticTests(unittest.TestCase):
    """Optional phase observations only; no real worker, file or suite dispatch."""

    def context_and_task(self):
        actual = ("/fixed/runner.py", "/fixed/contract.py")
        context = ("source", 20.0, tuple(zip(actual, contract.ADAPTER_PHASE_FAILURE_FILES)))
        namespace = {}
        exec(compile("def fail():\n    raise ValueError('PRIVATE phase message')\n", actual[0], "exec"), namespace)
        return context, namespace["fail"]

    def test_phase_projection_uses_true_prebound_frames_and_fixed_visit_and_output_bounds(self):
        context, task = self.context_and_task()
        try:
            task()
        except ValueError:
            error = sys.exc_info()
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic resolution")), \
                patch.object(Path, "stat", side_effect=AssertionError("no diagnostic stat")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("no diagnostic read")), \
                patch.object(traceback, "extract_tb", side_effect=AssertionError("no formatted traceback")), \
                patch.object(linecache, "getline", side_effect=AssertionError("no source reads")):
            for stage in contract.ADAPTER_PHASE_FAILURE_STAGES:
                output = io.StringIO()
                with redirect_stderr(output):
                    record = contract.emit_adapter_phase_failure(context, stage, error)
                self.assertEqual(record["locations"], [{"file": contract.ADAPTER_PHASE_FAILURE_FILES[0], "line": 2}])
                self.assertEqual(record["category"], "value-error")
                self.assertEqual(set(record), {"schema", "phase", "stage", "category", "locations"})
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertLessEqual(len(output.getvalue().encode("ascii")), 2048)
            for invalid, stage, actual_error in (
                    (("foreign", *context[1:]), "suite", error),
                    (("source", True, context[2]), "suite", error),
                    (("source", None, context[2]), "suite", error),
                    (("source", float("nan"), context[2]), "suite", error),
                    (("source", 20.0, ((context[2][0][0], "/PRIVATE/file"), context[2][1])), "suite", error),
                    (context, "suite-extra", error), (context, True, error),
                    (context, "suite", (TypeError, error[1], error[2])),
                    (context, "suite", (error[0], error[1], None))):
                output = io.StringIO()
                with redirect_stderr(output):
                    self.assertIsNone(contract.emit_adapter_phase_failure(invalid, stage, actual_error))
                self.assertEqual(output.getvalue(), "")

            # More than64 actual foreign frames precede the one allowed frame.
            # A projector scanning beyond its raw-frame budget would expose it.
            namespace = {}
            exec(compile("def descend(depth, task):\n    return descend(depth - 1, task) if depth else task()\n",
                         "/PRIVATE/foreign.py", "exec"), namespace)
            try:
                namespace["descend"](70, task)
            except ValueError:
                deep_error = sys.exc_info()
            self.assertEqual(contract.adapter_phase_failure_record(context, "suite", deep_error)["locations"], [])
            # Repeated allowed frames still publish at most four locations.
            namespace = {}
            exec(compile("def descend(depth):\n    if depth: return descend(depth - 1)\n    raise ValueError('PRIVATE')\n",
                         context[2][0][0], "exec"), namespace)
            try:
                namespace["descend"](8)
            except ValueError:
                repeated_error = sys.exc_info()
            self.assertEqual(len(contract.adapter_phase_failure_record(context, "suite", repeated_error)["locations"]), 4)

        output = io.StringIO()
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 20.0)), redirect_stderr(output):
            self.assertIsNone(contract.emit_adapter_phase_failure(context, "suite", error))
        self.assertEqual(output.getvalue(), "")

    def test_actual_adapter_emits_separate_parent_and_command_worker_origins_through_publication(self):
        from . import profile_process_fixture as profile_fixture
        flags = SimpleNamespace(**{name: 1 for name in (
            "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")})
        parent = {name: "__init__.py" if name == "mobile_release" else name.split(".")[-1] + ".py"
                  for name in ("mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
                               "mobile_release._native_process")}
        worker = {**parent, "mobile_release._command_process": "_command_process.py"}
        methods = {}
        for identifier, filename in contract.ADAPTER_TEST_FILES.items():
            namespace = {}
            exec(compile("def method(self):\n    raise AssertionError('inert emitter must not execute native tests')\n",
                         str(runner.ROOT / filename), "exec"), namespace)
            methods[identifier] = namespace["method"]

        class SelectedTest:
            _testMethodName = "method"

            def __init__(self, identifier):
                self.identifier = identifier
                selected = contract.ADAPTER_TEST_IDS[0] if defect == "wrong-fifth-origin" else identifier
                self.method = methods[selected].__get__(self, type(self))
                self._adapter_command_worker_origins = (
                    dict(worker) if identifier == contract.ADAPTER_TEST_IDS[0] and defect != "missing-worker" else None)

            def id(self):
                return self.identifier

        class Single:
            def __init__(self, identifier):
                self.test = SelectedTest(identifier)

            def __iter__(self):
                return iter((self.test,))

            def countTestCases(self):
                return 1

        def run(suites, result):
            for suite in suites:
                test = suite.test
                result.startTest(test)
                result.addSuccess(test)  # Inert unittest/worker observation, not an executed native case.
                result.stopTest(test)

        model = sys.modules[fixture.PersistentSigningModel.__module__]
        for phase, defect in (("source", None), ("wheel", None), ("source", "parent-escape"),
                              ("source", "missing-worker"), ("source", "wrong-fifth-origin"),
                              ("source", "retained-workspace")):
            with self.subTest(phase=phase, defect=defect):
                package = runner.ROOT.parent / ("work/source-build/src/mobile_release" if phase == "source" else
                                               "work/wheel-venv/lib/python3.11/site-packages/mobile_release")
                output_path = runner.ROOT.parent / "work/signing-adapter" / phase
                modules = {name: SimpleNamespace(__file__=str(package / relative)) for name, relative in parent.items()}
                if defect == "parent-escape": modules["mobile_release.optional"] = SimpleNamespace(__file__="/foreign/optional.py")
                output, errors = io.StringIO(), io.StringIO()
                temporary = SimpleNamespace(tempdir="original-tempdir")
                local_sys = SimpleNamespace(flags=flags, path=list(sys.path), modules=modules)
                fake_unittest = SimpleNamespace(TestLoader=lambda: SimpleNamespace(errors=[], loadTestsFromName=Single),
                    TestSuite=lambda suites: SimpleNamespace(run=lambda result: run(suites, result)))
                args = SimpleNamespace(deadline=20.0, adapter_phase=phase, output=output_path, package_root=package)
                scope = contract.adapter_scope_from_metadata({"kind": "github", "repository": "example/mobile-release-kit",
                    "commit": "1" * 40, "runId": "1234", "attempt": 1, "job": "test-signing-adapter"}, "ubuntu-24.04")
                with ExitStack() as stack:
                    for manager in (
                        patch.object(runner, "sys", local_sys),
                        patch.object(contract, "sys", SimpleNamespace(modules=modules, stderr=errors)),
                        patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)),
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)),
                        patch.object(runner, "tempfile", temporary), patch.object(runner, "unittest", fake_unittest),
                        patch.object(contract, "adapter_test_ids", return_value=contract.ADAPTER_TEST_IDS),
                        patch.object(runner, "adapter_source_map", return_value=()),
                        patch.object(fixture.signing, "__file__", str(package / "local_signing.py")),
                        patch.object(fixture, "PHASE_DEADLINE", None),
                        patch.object(fixture, "_CASE_CUSTODY", {}), patch.object(fixture, "_CASE_RECOVERY_DEBT", {}),
                        patch.object(model, "_RETAINED_MODEL_LIFETIMES", ()),
                        patch.object(profile_fixture, "assert_fixture_idle"),
                        patch.object(profile_fixture, "_RETAINED_WORKSPACES", [object()] if defect == "retained-workspace" else []),
                        patch.object(runner.case_owner, "ADAPTER_DIAGNOSTIC_CONTEXT", None),
                        patch.object(Path, "resolve", new=lambda path, **_kw: path),
                        patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False),
                        patch.object(Path, "is_dir", return_value=True), patch.object(Path, "is_file", return_value=True),
                        patch.object(Path, "mkdir", return_value=None), patch.object(Path, "iterdir", return_value=iter(())),
                        redirect_stdout(output), redirect_stderr(errors),
                    ):
                        stack.enter_context(manager)
                    if defect:
                        with self.assertRaises(ValueError): runner.adapter_phase(args, scope)
                    else:
                        self.assertEqual(runner.adapter_phase(args, scope), 0)
                    self.assertEqual(temporary.tempdir, "original-tempdir")
                    self.assertIsNone(runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT)
                if defect:
                    self.assertEqual(output.getvalue(), "")
                else:
                    record = json.loads(output.getvalue().removeprefix("MRK_SIGNING_ADAPTER_PHASE="))
                    contract.validate_adapter_record(record, scope, phase, package)
                    self.assertEqual(record["schema"], "mrk-signing-adapter-phase-v2")
                    self.assertEqual(record["origins"], {"parent": parent, "commandWorker": worker})
                    self.assertEqual(record["successfulIds"], list(contract.ADAPTER_TEST_IDS))
                    self.assertEqual(errors.getvalue(), "")

    def test_actual_adapter_wrapper_preserves_setup_and_post_suite_failures_after_finally(self):
        flags = SimpleNamespace(**{name: 1 for name in (
            "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")})
        package = runner.ROOT.parent / "work/source-build/src/mobile_release"
        output_path = runner.ROOT.parent / "work/signing-adapter/source"
        methods = {}
        for identifier, filename in contract.ADAPTER_TEST_FILES.items():
            namespace = {}
            exec(compile("def method(self):\n    pass\n", str(runner.ROOT / filename), "exec"), namespace)
            methods[identifier] = namespace["method"]

        class SelectedTest:
            _testMethodName = "method"

            def __init__(self, identifier):
                self.identifier = identifier
                self.method = methods[identifier].__get__(self, type(self))

            def id(self):
                return self.identifier

        class Single:
            def __init__(self, identifier):
                self.test = SelectedTest(identifier)

            def __iter__(self):
                return iter((self.test,))

            def countTestCases(self):
                return 1

        model = sys.modules[fixture.PersistentSigningModel.__module__]
        actual_emitter = contract.emit_adapter_phase_failure
        original_deadline = fixture.PHASE_DEADLINE
        for stage in ("admission", "postconditions"):
            for emitter_raises in (False, True):
                with self.subTest(stage=stage, emitter_raises=emitter_raises):
                    events, observed, output = [], [], io.StringIO()
                    temporary = SimpleNamespace(tempdir="original-tempdir")
                    local_sys = SimpleNamespace(flags=flags, path=list(sys.path), modules=sys.modules)
                    fake_unittest = SimpleNamespace(
                        TestLoader=lambda: SimpleNamespace(errors=[], loadTestsFromName=Single),
                        TestSuite=lambda _tests: SimpleNamespace(run=lambda _result: events.append("suite-returned")),
                    )
                    args = SimpleNamespace(deadline=20.0, adapter_phase="source", output=output_path,
                                           package_root=Path("/not-fixed") if stage == "admission" else package)

                    def emit(context, actual_stage, error):
                        observed.append((context, actual_stage, error[1], temporary.tempdir,
                                         runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT))
                        events.append("diagnostic")
                        if emitter_raises:
                            raise KeyboardInterrupt("PRIVATE optional emission failure")
                        return actual_emitter(context, actual_stage, error)

                    with ExitStack() as stack:
                        for manager in (
                            patch.object(runner, "sys", local_sys),
                            patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)),
                            patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)),
                            patch.object(runner, "tempfile", temporary), patch.object(runner, "unittest", fake_unittest),
                            patch.object(contract, "adapter_test_ids", return_value=contract.ADAPTER_TEST_IDS),
                            patch.object(runner, "adapter_source_map", return_value=(("/fixed/runner.py", contract.ADAPTER_FAILURE_TEST_FILES[0]),)),
                            patch.object(fixture.signing, "__file__", str(package / "local_signing.py")),
                            patch.object(fixture, "PHASE_DEADLINE", original_deadline),
                            patch.object(fixture, "_CASE_CUSTODY", {}), patch.object(fixture, "_CASE_RECOVERY_DEBT", {}),
                            patch.object(model, "_RETAINED_MODEL_LIFETIMES", (object(),)),
                            patch.object(runner.case_owner, "ADAPTER_DIAGNOSTIC_CONTEXT", object()),
                            patch.object(Path, "resolve", new=lambda path, **_kw: path),
                            patch.object(Path, "exists", return_value=False), patch.object(Path, "is_symlink", return_value=False),
                            patch.object(Path, "mkdir", new=lambda path, **_kw: events.append("mkdir")),
                            patch.object(Path, "iterdir", side_effect=AssertionError("retained model short-circuits output IO")),
                            patch.object(contract, "emit_adapter_phase_failure", side_effect=emit), redirect_stderr(output),
                        ):
                            stack.enter_context(manager)
                        with self.assertRaisesRegex(ValueError, "fixed adapter roots" if stage == "admission" else "adapter failed or retained") as caught:
                            runner.adapter_phase(args, {})
                    self.assertIs(fixture.PHASE_DEADLINE, original_deadline)
                    self.assertEqual(len(observed), 1)
                    self.assertEqual(observed[0][1], stage)
                    self.assertIs(observed[0][2], caught.exception)
                    self.assertEqual(observed[0][3], "original-tempdir")
                    if stage == "postconditions":
                        self.assertIsNone(observed[0][4])
                    self.assertEqual(events, ["diagnostic"] if stage == "admission" else ["mkdir", "suite-returned", "diagnostic"])
                    if emitter_raises:
                        self.assertEqual(output.getvalue(), "")
                    else:
                        record = json.loads(output.getvalue().removeprefix(contract.ADAPTER_PHASE_FAILURE_PREFIX))
                        self.assertEqual(record["stage"], stage)
                        self.assertTrue(record["locations"])
                    self.assertNotIn("PRIVATE", output.getvalue())


class RegressionIsolationContractTests(unittest.TestCase):
    """Real unittest lifecycle plus inert owner seams, never native receipts."""

    def exercise(self, mode):
        from . import local_signing_regression_fixture as regression
        descriptor = next(item for item in regression.catalog.cases_for("ubuntu-24.04") if item.kind == "execution")
        flags = SimpleNamespace(**{name: 1 for name in (
            "isolated", "ignore_environment", "no_user_site", "no_site", "safe_path", "dont_write_bytecode")})
        events, clock, in_worker = [], [10.0], [False]
        actual_read, actual_write, actual_remove = fixture.read_case_json, fixture.write_json, fixture.remove_case
        outer = self

        class OriginalCase(unittest.TestCase):
            def setUp(self):
                events.append("setup")
                self.addCleanup(self.original_cleanup)

            def original_cleanup(self):
                events.append("cleanup")
                if mode == "cleanup-failed":
                    raise OSError("inert original cleanup failure")

            def runTest(self):
                events.append("body")
                self.assertTrue(in_worker[0])
                scratch = Path(tempfile.tempdir)
                self.assertEqual(scratch.name, "scratch")
                self.assertTrue((scratch.parent / "last-worker.json").is_file())
                if mode == "test-failed":
                    self.fail("inert original body failure")
                elif mode == "outside-debt":
                    fixture._CASE_RECOVERY_DEBT[str(scratch.parents[2] / "outside")] = ("retained",)
                elif mode == "outside-case":
                    fixture._CASE_CUSTODY[str(scratch.parents[2] / "outside")] = None
                elif mode == "replaced-map":
                    fixture._CASE_CUSTODY = dict(fixture._CASE_CUSTODY)
                elif mode == "scratch-retained":
                    (scratch / "retained.txt").write_text("synthetic unit evidence")

            def tearDown(self):
                events.append("teardown")

        def construct(actual):
            outer.assertTrue(in_worker[0], "G construction escaped the original task closure")
            outer.assertIs(actual, descriptor)
            events.append("construct")
            return OriginalCase()

        def checked(root, context):
            outer.assertEqual(fixture._directory_identity(root), context)
            contract.before_deadline(fixture.PHASE_DEADLINE)
            if mode == "source-drift" and "cleanup" in events:
                raise AssertionError("inert changed source binding")

        def owned(root, name, task, **options):
            events.append("owner-enter")
            outer.assertEqual((name, options), ("regression", {"timeout": 10.0}))
            fixture._CASE_CUSTODY[str(root)] = None
            actual_write(root / "last-worker.json", {"diagnosticOnly": True})
            if mode == "owner-error":
                raise OSError("inert original owner failure")
            in_worker[0] = True
            try:
                observed = task()  # Deliberately inert, synchronous original task seam only.
            finally:
                in_worker[0] = False
            if mode == "bad-evidence":
                observed["testsRun"] = True  # Equal to1 is not the exact typed lifecycle record.
            actual_write(root / (name + ".json"), observed)
            fixture._CASE_CUSTODY[str(root)] = fixture._directory_identity(root)
            events.append("owner-return")
            return None if mode == "missing-return" else {
                "exit": 0, "originalAnchorWait": True, "originalWorkerWait": True,
                "originalStatusEOF": mode != "owner-unknown", "groupAbsentBeforeAnchorWait": True,
                "deadlineTest": False, "runDeadlineExpired": False}

        def read(root, name):
            outer.assertIn("owner-return", events)
            events.append("read")
            return actual_read(root, name)

        def preserve(path, value):
            outer.assertIn("read", events)
            events.append("preserve")
            return actual_write(path, value)

        def remove(root):
            outer.assertIn("preserve", events)
            outer.assertTrue((root.parent / ("regression-" + fixture.digest(descriptor.identifier) + ".json")).is_file())
            events.append("remove")
            if mode == "remove-failed":
                raise OSError("inert removal failure")
            actual_remove(root)
            if mode == "cutoff-after-remove":
                clock[0] = 20.0

        with tempfile.TemporaryDirectory(prefix="mrk-g-isolation-inert-") as temporary:
            parent = Path(temporary).resolve() / "case"
            parent.mkdir(mode=0o700)
            previous = tempfile.tempdir
            with patch.object(fixture, "_CASE_CUSTODY", {}), patch.object(fixture, "_CASE_RECOVERY_DEBT", {}), \
                    patch.object(fixture, "PHASE_DEADLINE", 20.0), \
                    patch.object(fixture, "pin_case_context", side_effect=fixture._directory_identity), \
                    patch.object(fixture, "check_case_context", side_effect=checked), \
                    patch.object(fixture, "run_worker", side_effect=owned), \
                    patch.object(fixture, "read_case_json", side_effect=read), \
                    patch.object(fixture, "write_json", side_effect=preserve), \
                    patch.object(fixture, "remove_case", side_effect=remove), \
                    patch.object(regression, "_runtime_case", side_effect=construct), \
                    patch.object(regression.catalog, "case", return_value=descriptor), \
                    patch.object(regression, "sys", SimpleNamespace(platform="linux", flags=flags)), \
                    patch.object(regression, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                    patch.object(contract, "time", SimpleNamespace(monotonic=lambda: clock[0])):
                if mode == "success":
                    result = regression.run_case(parent, descriptor.identifier)
                    self.assertEqual(result["caseId"], descriptor.identifier)
                    self.assertEqual(events, ["owner-enter", "construct", "setup", "body", "teardown", "cleanup",
                                              "owner-return", "read", "preserve", "remove"])
                    self.assertFalse((parent / "original-g").exists())
                    self.assertEqual(fixture._CASE_CUSTODY, {})
                    self.assertEqual(fixture._CASE_RECOVERY_DEBT, {})
                else:
                    with self.assertRaises((AssertionError, OSError, ValueError)):
                        regression.run_case(parent, descriptor.identifier)
                    self.assertEqual((parent / "original-g").exists(), mode != "cutoff-after-remove")
                    if mode not in {"remove-failed", "cutoff-after-remove"}:
                        self.assertNotIn("remove", events)
                        self.assertNotIn("preserve", events)
                    else:
                        self.assertEqual(events[-2:], ["preserve", "remove"])
                    if mode == "owner-error":
                        self.assertNotIn("construct", events)
                    if mode in {"missing-return", "owner-unknown"}:
                        self.assertNotIn("read", events)
                self.assertEqual(tempfile.tempdir, previous)
                self.assertFalse(in_worker[0])
            # Only inert task-owned bytes exist here; TemporaryDirectory safely
            # disposes them after all retained-evidence assertions. No workers.

    def test_original_g_construction_and_complete_lifecycle_precede_original_return_and_removal(self):
        self.exercise("success")

    def test_original_failure_unknown_outside_debt_source_and_cleanup_errors_withhold_rows(self):
        for mode in ("test-failed", "cleanup-failed", "outside-debt", "outside-case", "replaced-map",
                     "scratch-retained", "owner-error", "owner-unknown", "missing-return", "bad-evidence",
                     "source-drift", "remove-failed", "cutoff-after-remove"):
            with self.subTest(mode=mode):
                self.exercise(mode)

    def test_layered_g_owner_cost_is_added_without_changing_original_ids_or_commands(self):
        catalog = contract.layered_catalog()
        for operating_system in catalog.OPERATING_SYSTEMS:
            for item in catalog.cases_for(operating_system):
                if item.kind == "regression":
                    original = catalog.REGRESSION.case(item.name)
                    self.assertEqual(json.loads(item.specification), original.record())
                    self.assertEqual(item.estimated_commands, original.estimated_commands)
                    self.assertEqual(item.owned_workers, original.owned_workers + 1)
                    self.assertEqual(item.scheduling_units, original.scheduling_units + 4)
            groups, _weights = catalog.assignment(operating_system)
            self.assertEqual(sorted(value for group in groups for value in group), list(catalog.expected_ids(operating_system)))
            self.assertTrue(all(tuple(sorted(group)) == group for group in groups))


if __name__ == "__main__":
    unittest.main()
