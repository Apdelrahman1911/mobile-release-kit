from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.errors import StoreOperationError, ValidationError
from mobile_release.provenance import (
    validate_create_retry_inventory,
    validate_receipt_chain,
    validate_receipt_raw_binding,
)
from mobile_release.stores import _require_fastlane_bundle, _runtime_environment

from unit.apple_contract_helpers import apple_samples, wrap_apple_contracts

try:
    import jsonschema
except ImportError:  # an explicit optional-test limitation, never a full-gate pass
    jsonschema = None


ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "candidate", "candidate-retry", "external", "external-retry", "external-available", "production",
    "production-retry", "production-receipt-recovery", "production-screenshot-retry",
    "production-automatic-appinfo-retry",
}


class _RuntimeAdmissionTrace:
    """Observe the existing five calls, without changing their execution."""

    _OUTPUTS = ("3.3.12", "4.0.16", None,
                "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")

    def __init__(self, run):
        self._run = run
        self.rows = [None] * 5
        self.attempted = 0
        self.overflow = False

    def __call__(self, *args, **kwargs):
        index = self.attempted
        if index < 5:
            self.attempted += 1
            self.rows[index] = ("unconfirmed", False, None, None, None)
        else:
            self.overflow = True
        try:
            result = self._run(*args, **kwargs)
        except subprocess.TimeoutExpired:
            if index < 5:
                self.rows[index] = ("timeout", False, None, None, None)
            raise
        except OSError:
            if index < 5:
                self.rows[index] = ("os-error", False, None, None, None)
            raise
        if index < 5:
            row = ("unclassified", True, None, None, None)
            # Do not coerce malformed results, invoke user-defined field methods,
            # or replace the original return with an observation error.
            if type(result) is subprocess.CompletedProcess:
                fields = vars(result)
                if type(fields) is dict and len(fields) <= 4 and all(type(name) is str for name in fields):
                    status, stdout, stderr = (fields.get(name) for name in ("returncode", "stdout", "stderr"))
                    if type(status) is int and type(stdout) is str and type(stderr) is str:
                        expected = self._OUTPUTS[index]
                        matches = None if index == 2 else (stdout.strip() if index < 2 else stdout) == expected
                        row = ("returned", True, status == 0, matches, stderr == "")
            self.rows[index] = row
        return result


def _fail_required_runtime_admission(case, trace):
    """Fixed source locations, never raw child text; this cannot return PASS."""
    if (type(trace) is not _RuntimeAdmissionTrace or type(trace.rows) is not list or len(trace.rows) != 5
            or type(trace.attempted) is not int or not 0 <= trace.attempted <= 5
            or type(trace.overflow) is not bool):
        case.fail("Runtime admission observation shape differs")
    if trace.overflow:
        case.fail("Runtime admission exceeded the five observed stages")
    for index, row in enumerate(trace.rows):
        if index >= trace.attempted:
            valid = row is None
        else:
            valid = (type(row) is tuple and len(row) == 5 and type(row[0]) is str
                     and row[0] in {"returned", "timeout", "os-error", "unconfirmed", "unclassified"}
                     and type(row[1]) is bool and all(value is None or type(value) is bool for value in row[2:]))
            if valid:
                if row[0] == "returned":
                    valid = (row[1] is True and type(row[2]) is bool and type(row[4]) is bool
                             and (row[3] is None if index == 2 else type(row[3]) is bool))
                else:
                    valid = row[1:] == (row[0] == "unclassified", None, None, None)
        if not valid:
            case.fail("Runtime admission observation shape differs")
    if trace.attempted == 0:
        case.fail("Runtime admission rejected before any invocation")
    category, returned, status_zero, output_matches, stderr_empty = trace.rows[trace.attempted - 1]
    if category == "unclassified":
        case.fail("Runtime admission returned an unclassified result")
    # Literal branches intentionally give each phase/predicate a distinct line
    # in the existing filtered traceback. No new diagnostic protocol is needed.
    if trace.attempted == 1:
        if category == "timeout":
            case.fail("Ruby version admission timed out")
        if category == "os-error":
            case.fail("Ruby version admission launch failed")
        case.assertTrue(returned, "Ruby version admission return is unconfirmed")
        case.assertTrue(status_zero, "Ruby version admission exited nonzero")
        case.assertTrue(output_matches, "Ruby version admission output differs")
    elif trace.attempted == 2:
        if category == "timeout":
            case.fail("Bundler version admission timed out")
        if category == "os-error":
            case.fail("Bundler version admission launch failed")
        case.assertTrue(returned, "Bundler version admission return is unconfirmed")
        case.assertTrue(status_zero, "Bundler version admission exited nonzero")
        case.assertTrue(output_matches, "Bundler version admission output differs")
    elif trace.attempted == 3:
        if category == "timeout":
            case.fail("Bundle check admission timed out")
        if category == "os-error":
            case.fail("Bundle check admission launch failed")
        case.assertTrue(returned, "Bundle check admission return is unconfirmed")
        case.assertTrue(status_zero, "Bundle check admission exited nonzero")
    elif trace.attempted == 4:
        if category == "timeout":
            case.fail("Default runtime admission timed out")
        if category == "os-error":
            case.fail("Default runtime admission launch failed")
        case.assertTrue(returned, "Default runtime admission return is unconfirmed")
        case.assertTrue(status_zero, "Default runtime admission exited nonzero")
        case.assertTrue(output_matches, "Default runtime admission output differs")
        case.assertTrue(stderr_empty, "Default runtime admission stderr is nonempty")
    else:
        if category == "timeout":
            case.fail("Bundled runtime admission timed out")
        if category == "os-error":
            case.fail("Bundled runtime admission launch failed")
        case.assertTrue(returned, "Bundled runtime admission return is unconfirmed")
        case.assertTrue(status_zero, "Bundled runtime admission exited nonzero")
        case.assertTrue(output_matches, "Bundled runtime admission output differs")
        case.assertTrue(stderr_empty, "Bundled runtime admission stderr is nonempty")
    case.fail("Runtime admission rejected without an identified predicate")


class AppleContractTests(unittest.TestCase):
    """Cross the real Ruby JSON boundary, not a reimplementation of its states.

    The lane exporter uses the pinned SDK and synthetic HTTP transport. Python
    supplies only the additional repository/artifact envelopes absent from those
    deliberately minimal lane fixtures. This does not claim Store authentication,
    Apple-signed artifact validation, or live service compatibility.
    """

    def validate_samples(self, samples: dict, root: Path) -> dict:
        self.assertEqual(set(samples), CASES)
        config, documents = wrap_apple_contracts(root, samples=samples)
        schemas = {
            kind: json.loads((ROOT / "schemas" / name).read_text())
            for kind, name in {
                "intent": "store-operation-intent.schema.json",
                "receipt": "receipt.schema.json", "candidate": "candidate.schema.json",
            }.items()
        }
        if jsonschema is None and os.environ.get("MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS") == "1":
            self.fail("the required Ruby/Python/schema contract gate requires jsonschema")
        for name, value in documents.items():
            with self.subTest(case=name), patch.dict(os.environ, {}, clear=True):
                receipt, intent, candidate = value["receipt"], value["intent"], value["candidate"]
                stage = receipt["stage"]
                validate_receipt_raw_binding(receipt, store_receipt=value["raw"], operation_intent=intent, candidate_manifest=candidate)
                validate_receipt_chain(
                    candidate_manifest=candidate,
                    candidate_receipt=receipt if stage == "candidate" else documents["candidate"]["receipt"],
                    external_receipt=receipt if stage == "external-testing" else documents["external-available"]["receipt"] if stage == "production-submit" else None,
                    production_receipt=receipt if stage == "production-submit" else None,
                    candidate_intent=intent if stage == "candidate" else documents["candidate"]["intent"],
                    external_intent=intent if stage == "external-testing" else documents["external-available"]["intent"] if stage == "production-submit" else None,
                    production_intent=intent if stage == "production-submit" else None,
                    platform="ios", config=config,
                )
                if jsonschema is not None:
                    for kind, schema in schemas.items():
                        jsonschema.Draft202012Validator(schema).validate(value[kind])
                original_raw = samples[name]["receipt"]
                self.assertEqual(original_raw["schemaVersion"], 3)
                # The envelope helper must not rewrite observed state to fit the
                # Python consumer. Only synthetic outer intent hashes change.
                for field in set(original_raw) - {"operationIntentSha256", "createRetry"}:
                    self.assertEqual(value["raw"][field], original_raw[field], field)
                self.assertEqual(receipt["readback"]["state"], original_raw["state"])
                self.assertEqual(receipt["readback"]["observedAt"], original_raw["observedAt"])
                if stage == "external-testing":
                    external = intent["storePrecondition"]["snapshot"]["external"]
                    before = {item["locale"]: item for item in external["localizations"]}
                    target = {item["locale"]: item["whatsNew"] for item in external["targetLocalizations"]}
                    self.assertEqual(before["ja"]["id"], "locale-unconfigured")
                    self.assertEqual(target["ja"], "  Unconfigured 日本語 <keep> 🧪\n\n")
                    self.assertEqual(target["ja"], before["ja"]["whatsNew"])
                    self.assertEqual(set(target), {"en-US", "fr-FR", "de-DE", "ja"})
                    for locale in config.section("metadata")["iosLocales"]:
                        self.assertEqual(target[locale], "Test the fictional workflow")
                if stage == "production-submit":
                    self.assertIs(receipt["destination"]["automaticRelease"], False)
        self.assertEqual(documents["production-receipt-recovery"]["receipt"]["outcome"], "reconciled")
        self.assertEqual(documents["candidate-retry"]["receipt"]["outcome"], "operator-authorized-retry")
        self.assertEqual(documents["external-retry"]["receipt"]["outcome"], "operator-authorized-create-retry")
        self.assertEqual(documents["external"]["receipt"]["readback"]["state"], "submitted-for-review")
        self.assertEqual(documents["external-available"]["receipt"]["readback"]["state"], "available-to-testers")
        with self.assertRaisesRegex(ValidationError, "available-to-testers"):
            validate_receipt_chain(
                candidate_manifest=documents["candidate"]["candidate"],
                candidate_receipt=documents["candidate"]["receipt"],
                external_receipt=documents["external"]["receipt"],
                candidate_intent=documents["candidate"]["intent"],
                external_intent=documents["external"]["intent"],
                platform="ios", config=config, require_production_eligible_external=True,
            )
        return documents

    def test_checked_in_actual_lane_samples_validate_python_and_schema_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.validate_samples(apple_samples(), Path(temporary))

    def test_real_lane_export_is_deterministic_and_matches_checked_in_contract(self) -> None:
        required = os.environ.get("MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS") == "1"

        def unavailable(reason: str) -> None:
            if required:
                self.fail(reason)
            self.skipTest(reason)

        if not shutil.which("ruby") or not shutil.which("bundle"):
            unavailable("Ruby 3.3.12, Fiddle 1.1.2 and the locked Fastlane bundle are unavailable")
        # Never pass Store/signing/GitHub credentials, user-controlled preload
        # flags or caller Gemfiles into the credential-free simulation.
        names = {"PATH", "HOME", "GEM_HOME", "GEM_PATH", "BUNDLE_PATH", "LANG", "LC_ALL", "TMPDIR"}
        env = _runtime_environment({name: os.environ[name] for name in names if os.environ.get(name)})
        env.update({
            "BUNDLE_GEMFILE": str(ROOT / "Gemfile"), "BUNDLE_FROZEN": "true",
            "FASTLANE_SKIP_UPDATE_CHECK": "true", "FASTLANE_OPT_OUT_USAGE": "true",
        })
        trace = _RuntimeAdmissionTrace(subprocess.run)
        try:
            # Admission and export must use the same narrow bundle context;
            # ambient deployment/without settings cannot select another bundle.
            with patch.dict(os.environ, env, clear=True), patch("mobile_release.stores.subprocess.run", new=trace):
                _require_fastlane_bundle(ROOT)
        except StoreOperationError as error:
            if required:
                _fail_required_runtime_admission(self, trace)
            unavailable(str(error))
        with tempfile.TemporaryDirectory(prefix="mrk-apple-contract-") as temporary:
            root = Path(temporary)
            outputs = [root / f"export-{index}.json" for index in range(2)]
            for output in outputs:
                completed = subprocess.run(
                    ["bundle", "exec", "ruby", "tests/workflow/export_apple_contract_fixtures.rb", str(output)],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertTrue(output.is_file(), "the exporter exited without producing its contract")
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            generated = json.loads(outputs[0].read_text())
            self.assertEqual(generated["format"], "mrk-synthetic-apple-contract-v1")
            self.assertEqual(generated["cases"], apple_samples(), "regenerate and review the actual lane fixture after contract changes")
            self.validate_samples(generated["cases"], root / "python-consumer")

    def test_retry_graph_rejects_wrong_targets_parents_and_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, documents = wrap_apple_contracts(Path(temporary))
        checked = 0
        for case, value in documents.items():
            if "createRetry" not in value["raw"]:
                continue
            original = value["raw"]["createRetry"]["inventory"]
            intent = value["intent"]
            validate_create_retry_inventory(original, operation_intent=intent)
            for index, node in enumerate(original["creates"]):
                mutations = [lambda item: item.update(targetSha256="f" * 64)]
                parent = node["parent"]
                if parent["mode"] == "present" and parent["resourceType"] in {"apps", "builds", "appInfos"}:
                    mutations.append(lambda item: item["parent"].update(id="unrelated-parent"))
                elif parent["mode"] == "missing":
                    mutations.append(lambda item: item["parent"].update(logicalKeySha256="e" * 64))
                elif parent["mode"] == "automatic":
                    mutations.append(lambda item: item["parent"].update(referenceSha256="e" * 64))
                if node["dependencies"]:
                    mutations.append(lambda item: item.update(dependencies=[]))
                else:
                    mutations.append(lambda item: item.update(dependencies=[item["logicalKeySha256"]]))
                for mutate in mutations:
                    changed = copy.deepcopy(original)
                    mutate(changed["creates"][index])
                    with self.subTest(case=case, resource=node["resourceType"]), self.assertRaises(ValidationError):
                        validate_create_retry_inventory(changed, operation_intent=intent)
                    checked += 1
        self.assertGreater(checked, 70)


class RuntimeAdmissionAttributionTests(unittest.TestCase):
    """Inert admission observations; neither test may acquire a subprocess."""

    def test_trace_forwards_original_admission_without_extra_calls(self):
        tooling = Path("/fictional/pinned-contract")
        marker = "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"
        outputs = ("\n3.3.12 \n", " 4.0.16\n", "unconstrained bundle output", marker, marker)
        replies = [subprocess.CompletedProcess([], 0, stdout=value, stderr="benign warning" if index < 3 else "")
                   for index, value in enumerate(outputs)]
        calls, incoming = [], []

        def deny(*_args, **_kwargs):
            raise AssertionError("unexpected process or temporary export")

        def original(*args, **kwargs):
            previous_args, previous_kwargs, previous_environment = incoming[-1]
            self.assertEqual(len(args), 1)
            self.assertIs(args[0], previous_args[0])
            self.assertEqual(set(kwargs), set(previous_kwargs))
            for name in kwargs:
                self.assertIs(kwargs[name], previous_kwargs[name])
            self.assertEqual(kwargs["env"], previous_environment)
            self.assertEqual(set(kwargs), {"cwd", "env", "text", "stdout", "stderr", "timeout", "check"})
            self.assertEqual({name: value for name, value in kwargs.items() if name != "env"}, {
                "cwd": tooling, "text": True, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                "timeout": 60, "check": False,
            })
            if calls:
                self.assertIs(kwargs["env"], calls[0][1])
            self.assertLess(len(calls), 5)
            calls.append((list(args[0]), kwargs["env"]))
            return replies[len(calls) - 1]

        trace = _RuntimeAdmissionTrace(original)

        def forwarded(*args, **kwargs):
            previous_argv = list(args[0])
            incoming.append((args, kwargs, dict(kwargs["env"])))
            result = trace(*args, **kwargs)
            self.assertIs(result, replies[len(calls) - 1])
            self.assertEqual(args[0], previous_argv)
            self.assertEqual(kwargs["env"], incoming[-1][2])
            return result

        original_run = subprocess.run
        with patch.dict(os.environ, {"PATH": "/fictional/bin", "BUNDLE_PATH": "/fictional/bundle"}, clear=True), \
                patch.object(shutil, "which", return_value="/fictional/ruby"), \
                patch.object(subprocess, "Popen", side_effect=deny) as popen, \
                patch.object(tempfile, "TemporaryDirectory", side_effect=deny) as temporary, \
                patch.object(subprocess, "run", new=forwarded):
            _require_fastlane_bundle(tooling)
        self.assertIs(subprocess.run, original_run)
        popen.assert_not_called()
        temporary.assert_not_called()
        primitive = str(tooling / "fastlane/native_process_spawn.rb")
        probe = 'require ARGV.fetch(0); MobileReleaseKit::NativeProcessSpawn.admit_runtime!; STDOUT.write("' + marker + '")'
        self.assertEqual([argv for argv, _environment in calls], [
            ["ruby", "-e", "print RUBY_VERSION"], ["bundle", "--version"], ["bundle", "check"],
            ["ruby", "--disable=rubyopt,gems,did_you_mean,error_highlight,syntax_suggest,rjit,yjit",
             "--external-encoding=UTF-8", "--internal-encoding=UTF-8", "-e", probe, "--", primitive],
            ["bundle", "exec", "ruby", "-e", probe, "--", primitive],
        ])
        self.assertEqual((trace.attempted, trace.overflow), (5, False))
        self.assertEqual(trace.rows, [("returned", True, True, True, False), ("returned", True, True, True, False),
                                     ("returned", True, True, None, False), ("returned", True, True, True, True),
                                     ("returned", True, True, True, True)])

    def test_required_failure_attribution_is_private_and_optional_mode_unchanged(self):
        private = "synthetic-private-runtime-data"
        marker = "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"
        outputs = ("3.3.12", "4.0.16", "", marker, marker)

        def deny(*_args, **_kwargs):
            raise AssertionError("unexpected process or temporary export")

        def rejection(trace, expected):
            try:
                _fail_required_runtime_admission(self, trace)
            except AssertionError as error:
                self.assertIn(expected, str(error))
                self.assertNotIn(private, str(error))
                frame, locations = error.__traceback__, []
                while frame is not None:
                    if frame.tb_frame.f_code is _fail_required_runtime_admission.__code__:
                        locations.append(frame.tb_lineno)
                    frame = frame.tb_next
                self.assertEqual(len(locations), 1)
                return locations[0]
            self.fail("required admission rejection returned successfully")

        def exercise(failed, bad):
            calls, observed_exceptions = [], []

            def original(*args, **kwargs):
                index = len(calls)
                calls.append(index)
                self.assertLessEqual(index, failed)
                if index == failed:
                    if isinstance(bad, BaseException):
                        raise bad
                    return bad
                return subprocess.CompletedProcess(args[0], 0, stdout=outputs[index], stderr="")

            trace = _RuntimeAdmissionTrace(original)

            def forwarded(*args, **kwargs):
                try:
                    result = trace(*args, **kwargs)
                except BaseException as error:
                    self.assertIs(error, bad)
                    observed_exceptions.append(True)
                    raise
                if len(calls) == failed + 1:
                    self.assertIs(result, bad)
                return result

            original_run = subprocess.run
            with patch.dict(os.environ, {"PATH": "/fictional/bin"}, clear=True), \
                    patch.object(shutil, "which", return_value="/fictional/ruby"), \
                    patch.object(subprocess, "Popen", side_effect=deny) as popen, \
                    patch.object(tempfile, "TemporaryDirectory", side_effect=deny) as temporary, \
                    patch.object(subprocess, "run", new=forwarded):
                try:
                    _require_fastlane_bundle(Path("/fictional/pinned-contract"))
                except BaseException as error:
                    caught = error
                else:
                    self.fail("original runtime admission unexpectedly accepted the failure")
            self.assertIs(subprocess.run, original_run)
            self.assertEqual(calls, list(range(failed + 1)))
            self.assertEqual(observed_exceptions, [True] if isinstance(bad, BaseException) else [])
            self.assertNotIn(private, repr(trace.rows))
            popen.assert_not_called()
            temporary.assert_not_called()
            return trace, caught

        cases = (
            (0, subprocess.CompletedProcess([], 0, stdout=private, stderr=""), "Ruby version admission output differs"),
            (1, subprocess.CompletedProcess([], 0, stdout=private, stderr=""), "Bundler version admission output differs"),
            (2, subprocess.CompletedProcess([], 1, stdout=private, stderr=private), "Bundle check admission exited nonzero"),
            (3, subprocess.TimeoutExpired(private, 60, output=private, stderr=private), "Default runtime admission timed out"),
            (3, subprocess.CompletedProcess([], 0, stdout=private, stderr=""), "Default runtime admission output differs"),
            (4, OSError(private), "Bundled runtime admission launch failed"),
            (4, subprocess.CompletedProcess([], 1, stdout=marker, stderr=""), "Bundled runtime admission exited nonzero"),
            (4, subprocess.CompletedProcess([], 0, stdout=private, stderr=""), "Bundled runtime admission output differs"),
            (4, subprocess.CompletedProcess([], 0, stdout=marker, stderr=private), "Bundled runtime admission stderr is nonempty"),
        )
        locations = []
        for failed, bad, expected in cases:
            with self.subTest(stage=failed, predicate=expected):
                trace, error = exercise(failed, bad)
                self.assertIs(type(error), StoreOperationError)
                locations.append(rejection(trace, expected))
        self.assertEqual(len(set(locations)), len(cases))
        for error in (KeyboardInterrupt(private), SystemExit(private), RuntimeError(private)):
            trace, caught = exercise(0, error)
            self.assertIs(caught, error)
            rejection(trace, "Ruby version admission return is unconfirmed")

        class Opaque:
            def forbidden(self, *_args, **_kwargs):
                raise AssertionError("observer coerced a malformed value")
            __bool__ = __str__ = __repr__ = __eq__ = strip = forbidden

        class OpaqueFields(dict):
            get = Opaque.forbidden

        class NonordinaryResult(subprocess.CompletedProcess):
            __getattribute__ = Opaque.forbidden

        opaque = Opaque()
        fields_result = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        fields_result.__dict__ = OpaqueFields(vars(fields_result))
        malformed = (opaque, subprocess.CompletedProcess([], opaque, stdout="", stderr=""),
                     subprocess.CompletedProcess([], 0, stdout=opaque, stderr=""),
                     subprocess.CompletedProcess([], 0, stdout="", stderr=opaque), fields_result,
                     NonordinaryResult([], 0, stdout="", stderr=""))
        for result in malformed:
            trace = _RuntimeAdmissionTrace(lambda: result)
            self.assertIs(trace(), result)
            self.assertEqual(trace.rows[0], ("unclassified", True, None, None, None))
            rejection(trace, "Runtime admission returned an unclassified result")
        trace = _RuntimeAdmissionTrace(deny)
        rejection(trace, "Runtime admission rejected before any invocation")
        trace.rows[0] = (private,)
        rejection(trace, "Runtime admission observation shape differs")
        calls = []

        def successful():
            index = len(calls)
            calls.append(index)
            return subprocess.CompletedProcess([], 0, stdout=outputs[min(index, 4)], stderr="")

        trace = _RuntimeAdmissionTrace(successful)
        for _ in range(5):
            trace()
        rejection(trace, "Runtime admission rejected without an identified predicate")
        for _ in range(2):
            trace()
        self.assertEqual((len(calls), trace.attempted, len(trace.rows), trace.overflow), (7, 5, 5, True))
        rejection(trace, "Runtime admission exceeded the five observed stages")

        # Exercise the real test method, including restoration before its fixed
        # required failure or its unchanged optional skip. No export may begin.
        for required, missing in ((False, False), (True, False), (True, True)):
            case = AppleContractTests("test_real_lane_export_is_deterministic_and_matches_checked_in_contract")
            ambient = {"PATH": "/fictional/bin", "MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS": "1" if required else "0"}
            calls, reports = [], []

            def original(*_args, **_kwargs):
                calls.append(True)
                self.assertEqual(len(calls), 1)
                raise OSError(private)

            original_report = case.fail if required else case.skipTest

            def report(message):
                self.assertIs(subprocess.run, original)
                self.assertTrue(dict(os.environ) == ambient, "admission environment was not restored")
                self.assertNotIn(private, message)
                reports.append(message)
                original_report(message)

            original_run = subprocess.run
            with patch.dict(os.environ, ambient, clear=True), \
                    patch.object(shutil, "which", side_effect=["/fictional/ruby", "/fictional/bundle", None]
                                 if missing else lambda *_args, **_kwargs: "/fictional/tool"), \
                    patch.object(subprocess, "Popen", side_effect=deny) as popen, \
                    patch.object(tempfile, "TemporaryDirectory", side_effect=deny) as temporary, \
                    patch.object(subprocess, "run", new=original), \
                    patch.object(case, "fail" if required else "skipTest", new=report):
                with self.assertRaises(AssertionError if required else unittest.SkipTest) as raised:
                    case.test_real_lane_export_is_deterministic_and_matches_checked_in_contract()
            self.assertIs(subprocess.run, original_run)
            self.assertEqual(len(calls), 0 if missing else 1)
            self.assertEqual(len(reports), 1)
            if required:
                self.assertEqual(str(raised.exception), "Runtime admission rejected before any invocation" if missing
                                 else "Ruby version admission launch failed")
            else:
                self.assertEqual(str(raised.exception), "Pinned Store tooling requires Ruby 3.3.12. Select that exact version before running "
                                 "online preflight or a Store lane.")
            popen.assert_not_called()
            temporary.assert_not_called()


if __name__ == "__main__":
    unittest.main()
