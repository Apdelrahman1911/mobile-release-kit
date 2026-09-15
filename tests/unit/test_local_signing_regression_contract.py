"""Inert G coverage/lifecycle contracts; no native/process owner is acquired."""
from __future__ import annotations

import ast
import copy
import json
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from unit import local_signing_workspace as workspace
from workflow import local_signing_regression_catalog as catalog
from workflow.local_signing_regression_fixture import RegressionResult, run_case, semantic_contributions, _bound_method
from workflow.local_signing_workload import PROFILE_SIGNAL_SECONDS


class RegressionCatalogTests(unittest.TestCase):
    def test_actual_helper_identity_source_and_decorator_cannot_be_substituted(self):
        class Original:
            def helper(self):
                return "inert original helper"
        expected = Path(__file__).resolve()
        self.assertIs(_bound_method(Original, "helper", expected), Original.helper)
        with patch.object(Original, "helper", lambda self: None):
            with self.assertRaisesRegex(AssertionError, "function identity changed"):
                _bound_method(Original, "helper", expected)
        with self.assertRaisesRegex(AssertionError, "defining source changed"):
            _bound_method(Original, "helper", expected.parent / "foreign.py")
        for flag in ("__unittest_skip__", "__unittest_expecting_failure__"):
            with self.subTest(flag=flag), patch.object(Original.helper, flag, True, create=True):
                with self.assertRaises(AssertionError):
                    _bound_method(Original, "helper", expected)

    def test_exact_original_obligations_fixed_variants_platforms_and_source_ids(self):
        root = Path(__file__).resolve().parents[1]
        for platform, execution_count, method_count in (("ubuntu-24.04", 160, 84), ("macos-26", 170, 86)):
            selected = catalog.cases_for(platform)
            executions = [value for value in selected if value.kind == "execution"]
            contributions = [value for value in selected if value.kind == "semantic-contribution"]
            self.assertEqual((len(executions), len(contributions)), (execution_count, 18))
            obligations = catalog.obligations(platform)
            self.assertEqual(len(obligations), method_count)
            self.assertEqual(tuple(obligations), catalog.delegated_methods(platform))
            self.assertEqual(sorted(identifier for ids in obligations.values() for identifier in ids),
                             sorted(value.identifier for value in selected))
            self.assertTrue(all(value.scheduling_units > 0 and value.planning_basis for value in executions))
            self.assertTrue(all(value.scheduling_units == 0 for value in contributions))
            for value in selected:
                self.assertEqual(json.loads(json.dumps(value.record())), value.record())
            for original in obligations:
                module, cls_name, method = original.rsplit(".", 2)
                tree = ast.parse((root / (module.replace(".", "/") + ".py")).read_text())
                cls, = (value for value in tree.body if isinstance(value, ast.ClassDef) and value.name == cls_name)
                self.assertEqual(sum(isinstance(value, ast.FunctionDef) and value.name == method for value in cls.body), 1)
        linux = set(catalog.delegated_methods("ubuntu-24.04"))
        darwin = set(catalog.delegated_methods("macos-26"))
        self.assertEqual(darwin - linux, {"unit.test_local_signing_composition.SigningCompositionTests." + method
                                        for method in catalog.METHODS["unit.test_local_signing_composition.SigningCompositionTests"]})
        self.assertEqual(catalog.SIGNAL_MODES, set(PROFILE_SIGNAL_SECONDS))
        modes = [mode for values in catalog.SIGNAL_METHOD_VARIANTS.values() for mode in values]
        self.assertEqual((len(modes), len(set(modes))), (50, 50))

    def test_aliases_are_exact_contributions_not_independent_execution_or_whole_method_success(self):
        expected = {"C/fence/04", "S/active-build-pending/none", "H/full-context", *(f"F/{number:02}" for number in range(1, 16))}
        aliases = [value for value in catalog.CASES.values() if value.kind == "semantic-contribution"]
        self.assertEqual({value.semantic for value in aliases}, expected)
        self.assertEqual(len(aliases), 18)
        self.assertEqual(sorted(len(values) for method, values in catalog.obligations("ubuntu-24.04").items()
                                if ".PersistentSigningTests." in method), [1, 1, 16])
        for value in aliases:
            self.assertEqual(catalog.semantic_contributions(value.semantic), (value.identifier,))
            with self.assertRaisesRegex(AssertionError, "cannot start"):
                run_case(Path("/nonexistent-inert-contract"), value.identifier)
        with self.assertRaisesRegex(AssertionError, "unknown original"):
            catalog.case("G/unregistered")

    def test_canonical_contribution_requires_original_specialized_predicates(self):
        from workflow import local_signing_semantic_catalog as semantic
        def original(value, *, expected=0):
            self.assertEqual(value, {"inertOriginal": expected})
        fake = SimpleNamespace(assert_original_return=original, CRASH=73,
                               signing=SimpleNamespace(DB_NAME="signing.keychain-db"), digest=lambda _value: "inert")
        def step(name, observation, **values):
            return {"name": name, "original": {"inertOriginal": 73 if name == "seed" else 0},
                    "observation": observation, **values}
        def evidence(identifier, steps, negative=()):
            return {"schema": "mrk-signing-semantic-case-v1", "case": semantic.case(identifier).record(),
                    "steps": steps, "negativeEvidence": list(negative)}
        c = evidence("C/fence/04", [step("seed", {"edge": "partial", "originalCFenceObservation": {
            "originalWorker": True, "originalReadClosed": True, "written": 1, "total": 2,
            "actualReadHex": "01", "operandHex": "0102"}}), step("semantic-main", {
                "result": {"status": "recovered"}, "idleAndRenewedAdmission": True}, manual="none", expected="recovered")])
        negative = step("semantic-main", {"refused": "inert-refusal", "idleAndRenewedAdmission": False},
                        manual="none", expected="refused-unknown-resource")
        s = evidence("S/active-build-pending/none", [step("seed", {
            "selector": {"occurrence": 3}, "physicalWrite": {"properPrefix": True},
            "snapshot": {"controls": {"state.json": {"value": {"inflight": {"phase": "ARMED"},
                "native": {"signing.keychain-db": "old"}}}}},
            "context": {"liveState": {"inflight": {"phase": "SETTLED"}, "native": {"signing.keychain-db": "new"}}}}),
            negative, step("semantic-resolution", {"result": {"status": "recovered-with-conflict"},
                "idleAndRenewedAdmission": True}, manual="resolve", expected="recovered-with-conflict")], ["semantic-inert-negative.json"])
        fake.read_case_json = lambda _parent, _name: negative
        operations = ("buffer.write", "buffer.flush", "buffer.close", "link", "native/build", "native/import",
                      "native-effect/replace/signing.keychain-db", "command-fence/PENDING_WRITE", "command-fence/DATA_FSYNC",
                      "command-fence/FINAL_LINK", "command-fence/DIRECTORY_FSYNC")
        h = evidence("H/full-context", [step("healthy", {"events": [{"operation": value} for value in operations],
                     "snapshot": {"preferences": {"inert": True}, "original": {"inert": True}, "ownedRemaining": {}}})])
        samples = [
            ("C/fence/04", c, lambda value: value["steps"][0]["observation"]["originalCFenceObservation"].update(actualReadHex="02")),
            ("S/active-build-pending/none", s, lambda value: value["steps"][0]["observation"]["context"]["liveState"]["native"].update({"signing.keychain-db": "old"})),
            ("H/full-context", h, lambda value: value["steps"][0]["observation"]["events"].pop()),
        ]
        for identifier, observation, name, values, mutation in (
            ("F/01", {"result": {"status": "recovered-with-conflict"}}, "focused-main", {},
             lambda value: value["steps"][1]["observation"]["result"].update(status="recovered")),
            ("F/05", {"freshAdmission": "pending", "resourcesPreserved": True}, "focused-refusal", {},
             lambda value: value["steps"][1]["observation"].update(resourcesPreserved=False)),
            ("F/14", {"refused": None, "result": {"status": "recovered"}}, "focused-main", {"manual": "none", "expected": "recovered"},
             lambda value: value["steps"][1]["observation"].update(refused="inert-refusal")),
            ("F/15", {"refused": "inert-refusal"}, "focused-refusal", {"manual": "none", "expected": "refused-unknown-resource"},
             lambda value: value["steps"][1]["observation"].update(refused=None)),
        ):
            samples.append((identifier, evidence(identifier, [step("seed", {}), step(name, observation, **values)]), mutation))
        foreign = {"freshAdmission": "pending", "resourcesPreserved": True, "before": {"preferences": ["inert"]},
                   "after": {"preferences": ["inert"]}}
        samples.append(("F/07", evidence("F/07", [step("seed", {}), step("focused-none", copy.deepcopy(foreign)),
                         step("focused-resolve", copy.deepcopy(foreign))]),
                        lambda value: value["steps"][2]["observation"]["after"].update(preferences=["changed"])))
        package = sys.modules["workflow"]
        with patch.object(package, "local_signing_persistent_fixture", fake, create=True):
            for identifier, value, mutate in samples:
                with self.subTest(identifier=identifier):
                    self.assertEqual(semantic_contributions(Path("/inert-no-io"), identifier, value), catalog.semantic_contributions(identifier))
                    changed = copy.deepcopy(value)
                    mutate(changed)
                    with self.assertRaises(AssertionError):
                        semantic_contributions(Path("/inert-no-io"), identifier, changed)


class NativeWorkspaceTests(unittest.TestCase):
    @contextmanager
    def original_case(self, stage=None, *, result=None, default=False):
        events = []

        class Result(unittest.TestResult):
            def __init__(self):
                super().__init__()
                self.failfast = True
                self.hooks = []
            def startTestRun(self):
                self.hooks.append("start")
            def stopTestRun(self):
                self.hooks.append("stop")

        supplied = result or Result()

        class Original(workspace.NativeCaseWorkspaceMixin, unittest.TestCase):
            def defaultTestResult(self):
                return supplied
            def setUp(self):
                self.root = self.native_case_directory(prefix="inert-G-")
                (self.root / "evidence").write_bytes(b"inert fixture; no native owner")
                self.addCleanup(lambda: events.append("independent-cleanup"))
                if stage == "cleanup":
                    self.addCleanup(lambda: (_ for _ in ()).throw(OSError("inert close failure")))
                if stage == "setup":
                    raise ValueError("inert setup failure")
            def runTest(self):
                events.append("body")
                if stage == "body":
                    self.fail("inert body failure")
                if stage == "subtest":
                    for number in range(2):
                        with self.subTest(number=number):
                            events.append("variant-" + str(number))
                            self.fail("inert subtest failure")
                if stage == "skip":
                    self.skipTest("current inert skip")
                if stage == "subtest-skip":
                    with self.subTest(skipping=True):
                        self.skipTest("current inert subtest skip")
                if stage == "early-cleanups":
                    self.doCleanups()
                if stage == "mode-drift":
                    self.root.chmod(0o755)
                if stage == "replaced-root":
                    self.root.rename(self.root.with_name(self.root.name + "-retained"))
                    self.root.mkdir(mode=0o700)
                    (self.root / "foreign").write_bytes(b"not the original root")
                if stage == "result-replaced":
                    supplied.skipped = list(supplied.skipped)
                if stage == "later-cleanup":
                    self._cleanups.insert(0, (lambda: events.append("unexpected-later-cleanup"), (), {}))
            def tearDown(self):
                events.append("teardown")
                if stage == "teardown":
                    raise OSError("inert teardown failure")
                super().tearDown()

        # Only inert test-owned files are disposed by this outer test. No model,
        # command/case worker, profile resource or process API is ever acquired.
        with tempfile.TemporaryDirectory(prefix="mrk-inert-G-contract-") as directory:
            with patch.object(tempfile, "tempdir", directory):
                case = Original()
                returned = case.run() if default else case.run(supplied)
            self.assertIs(returned, supplied)
            yield case, supplied, events

    def test_success_keeps_original_lifecycle_result_hooks_and_prior_allowed_skips(self):
        with self.original_case(default=True) as (case, result, events):
            self.assertEqual(result.hooks, ["start", "stop"])
            self.assertTrue(result.wasSuccessful())
            self.assertFalse(case.root.exists())
            self.assertEqual(events, ["body", "teardown", "independent-cleanup"])
        prior = unittest.TestResult()
        prior.skipped.append((unittest.FunctionTestCase(lambda: None), "earlier permitted macOS-only skip"))
        with self.original_case(result=prior) as (case, result, events):
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(len(result.skipped), 1)
            self.assertFalse(case.root.exists())

    def test_every_failed_lifecycle_retains_root_and_runs_independent_cleanup(self):
        for stage in ("setup", "body", "subtest", "teardown", "cleanup", "skip", "subtest-skip", "early-cleanups"):
            with self.subTest(stage=stage), self.original_case(stage) as (case, result, events):
                self.assertFalse(result.wasSuccessful())
                self.assertTrue((case.root / "evidence").is_file())
                self.assertEqual(events.count("independent-cleanup"), 1)
                if stage == "subtest":
                    self.assertIn("variant-0", events)
                    self.assertNotIn("variant-1", events)
                if stage == "setup":
                    self.assertNotIn("teardown", events)

    def test_original_identity_result_and_last_callback_are_required_for_removal(self):
        for stage in ("mode-drift", "replaced-root", "result-replaced", "later-cleanup"):
            with self.subTest(stage=stage), self.original_case(stage) as (case, result, events):
                self.assertFalse(result.wasSuccessful())
                self.assertTrue(case.root.exists())
                self.assertEqual(events.count("independent-cleanup"), 1)
                if stage == "replaced-root":
                    self.assertEqual((case.root / "foreign").read_bytes(), b"not the original root")
                    self.assertTrue((case.root.with_name(case.root.name + "-retained") / "evidence").is_file())

    def test_unsettled_ledger_expired_deadline_and_removal_failure_cannot_be_success(self):
        for name in ("assert_native_cases_idle", "_before_bound_deadline"):
            with self.subTest(gate=name), patch.object(workspace, name, side_effect=AssertionError("inert closed gate")):
                with self.original_case() as (case, result, events):
                    self.assertFalse(result.wasSuccessful())
                    self.assertTrue((case.root / "evidence").is_file())
        real = workspace.shutil.rmtree
        attempts = []
        def failed(path, *args, **kwargs):
            if Path(path).name.startswith("inert-G-"):
                attempts.append(path)
                raise OSError("inert removal failure")
            return real(path, *args, **kwargs)
        with patch.object(workspace.shutil, "rmtree", side_effect=failed):
            with self.original_case() as (case, result, events):
                self.assertFalse(result.wasSuccessful())
                self.assertTrue((case.root / "evidence").is_file())
        self.assertEqual(len(attempts), 1)
        with patch.dict(sys.modules, {"unit.local_signing_persistent": SimpleNamespace(_RETAINED_MODEL_LIFETIMES=[object()])}):
            with self.assertRaisesRegex(AssertionError, "custody is retained"):
                workspace.assert_native_cases_idle()


class RegressionResultTests(unittest.TestCase):
    def test_failure_latches_before_optional_result_reporting_and_forbids_success(self):
        case = unittest.FunctionTestCase(lambda: None)
        for outcome in ("error", "failure", "skip", "expected-failure", "unexpected-success", "subtest"):
            with self.subTest(outcome=outcome):
                result = RegressionResult(case, deadline=time.monotonic() + 60)
                result.startTest(case)
                try:
                    raise AssertionError("inert failure")
                except AssertionError:
                    error = sys.exc_info()
                if outcome == "error": result.addError(case, error)
                elif outcome == "failure": result.addFailure(case, error)
                elif outcome == "skip": result.addSkip(case, "inert")
                elif outcome == "expected-failure": result.addExpectedFailure(case, error)
                elif outcome == "unexpected-success": result.addUnexpectedSuccess(case)
                else: result.addSubTest(case, case, error)
                self.assertTrue(result.regression_failed and result.shouldStop and result.failfast)
                first = result.first_failure
                result.reject("later-cleanup")
                self.assertEqual(result.first_failure, first)
                with self.assertRaisesRegex(AssertionError, "failed G"):
                    result.addSuccess(case)
                result.stopTest(case)
                self.assertEqual((result.started, result.stopped, result.succeeded), (1, 1, 0))
        result = RegressionResult(case, deadline=time.monotonic() + 60)
        with patch.object(unittest.TestResult, "addError", side_effect=OSError("inert optional reporting failure")):
            with self.assertRaises(OSError):
                result.addError(case, error)
        self.assertTrue(result.regression_failed and result.shouldStop)
