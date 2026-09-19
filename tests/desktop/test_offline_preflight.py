"""Inert saved-preflight regressions, NOT native/host/runtime qualification.

Only existing fixed seams are patched. No project, descriptor, subprocess,
signal handler, account, network service or new execution harness is acquired.
The original types below are constructed as DATA; closure flags in predicate
tests are not evidence of any real operation. Execution needs separate review.
"""
from __future__ import annotations

import copy
import hashlib
import json
import stat
import subprocess
import types
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_preflight_control as control
from mobile_release import _desktop_preflight_protocol as wire
from mobile_release import desktop_preflight as service
from mobile_release import preflight, credentials, discovery
from mobile_release._desktop_preflight_budget import OfflinePreflightBudget, PreflightBudgetError, _Iterator
from mobile_release.api import _snapshot
from mobile_release.build_inputs import InvocationCustody
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config import ReleaseConfig, _iter_text_lines, parse_key_value_text
from mobile_release.reporting import Finding, Report, Status


def saved_data():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.inert.preflight", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [["inert-project-check", "PRIVATE_ARG"]], "androidArtifact": [], "iosArtifact": []},
    }


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def fingerprint(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def request_data(raw=None):
    raw = encoded(saved_data()) if raw is None else raw
    return {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "inert-project", "draftRevision": 2, "baselineGeneration": 3,
            "savedConfig": fingerprint(raw), "platform": "android", "operation": "offline-preflight"},
        "native": {"profile": "linux-gnu-x86_64", "projectRoot": "/inert/project", "cwd": "/inert/runtime",
            "rootIdentity": {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}}}


def terminal(req, report=None):
    return {"schemaVersion": 1, "context": req.context, "outcome": "complete", "reason": "none",
        "result": wire.project_result(Report("inert") if report is None else report, req.context["savedConfig"]),
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": False,
            "commands": 0, "profileCalls": 0, "inputClosed": True, "handlersRestored": True,
            "invocationClosed": True, "stopObserved": "none"}}


@contextmanager
def inert_source():
    guard = DefaultCancellation(wire.ProtocolError, "inert original owner")
    source = control.PreflightInput(100)
    source.acquired = True  # Predicate DATA only: never acquire stdin.
    source.active = source.request_returned = True
    guard._install_preflight_source(source)
    with patch.object(source, "poll", return_value=None):
        yield guard, source


class PreflightProtocolTests(unittest.TestCase):
    def test_private_request_has_exact_context_and_no_renderer_input_surface(self):
        value = request_data()
        parsed = wire.parse_request(encoded(value))
        self.assertEqual(parsed.context, value["context"])
        self.assertEqual(parsed.native, value["native"])
        for field in ("draft", "argv", "environment", "root", "runtime"):
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded({**value, field: "PRIVATE"}))
        for raw in (encoded(value).replace(b'"protocol":', b'"protocol":"duplicate","protocol":', 1),
                    encoded(value) + b"\n", b" " * (wire.REQUEST_LIMIT + 1), b"\xef\xbb\xbf" + encoded(value)):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(raw)
        for field, bad in (("draftRevision", True), ("baselineGeneration", 2**32 - 1), ("platform", "ios")):
            other = copy.deepcopy(value)
            other["context"][field] = bad
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(other))

    def test_all_nine_statuses_complete_negative_and_redaction(self):
        report = Report("PRIVATE_COMMAND", context={"path": "PRIVATE_PATH"})
        for index in range(137):
            report.add(f"project-check.preflight.{index}" if index < 32 else "PRIVATE_CODE", list(Status)[index % 9],
                       "PRIVATE_MESSAGE", details={"stdout": "PRIVATE_OUTPUT"}, remediation="PRIVATE_REMEDIATION")
        with patch.object(Report, "as_dict", side_effect=AssertionError("raw report serialization")):
            result = wire.project_result(report, request_data()["context"]["savedConfig"])
        self.assertFalse(report.ok)
        self.assertEqual(result["summary"]["total"], 137)
        self.assertEqual((result["summary"]["shown"], result["summary"]["omitted"]), (128, 9))
        self.assertEqual(set(result["summary"]["counts"]), set(wire.STATUSES))
        self.assertNotIn("PRIVATE_", json.dumps(result))
        self.assertEqual(result["findings"][31]["projectCheckIndex"], 31)
        self.assertEqual(result["findings"][32]["check"], "other-core-finding")
        req = wire.parse_request(encoded(request_data()))
        value = terminal(req, report)
        wire.validate_terminal(value, req)  # Completion is not Report.ok.
        wire.response(req, "terminal", value)
        for mutate in (
            lambda r: r["summary"].update(omitted=0),
            lambda r: r["findings"][0].update(projectCheckIndex=32),
            lambda r: r["findings"][0].pop("projectCheckIndex"),
            lambda r: r["findings"][0].update(message="PRIVATE_MESSAGE"),
        ):
            invalid = copy.deepcopy(result)
            mutate(invalid)
            with self.assertRaises(wire.ProtocolError):
                wire.validate_result(invalid)

    def test_unknown_and_complete_require_original_closed_lifetime(self):
        req = wire.parse_request(encoded(request_data()))
        for field in ("complete", "contained", "inputClosed", "handlersRestored", "invocationClosed"):
            value = terminal(req)
            value["lifetime"][field] = False
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, req)
            value.update(outcome="unknown", reason="cleanup-unknown", result=None)
            wire.validate_terminal(value, req)
        value = terminal(req)
        value.update(outcome="unknown", reason="cleanup-unknown", result=None)
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, req)  # Unknown cannot claim settled DATA.
        value.update(outcome="cancelled", reason="cancelled")
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, req)
        value["lifetime"]["stopObserved"] = "cancelled"
        wire.validate_terminal(value, req)

    def test_snapshot_fingerprint_is_exact_and_uncertain_root_clears_it(self):
        raw = encoded(saved_data())
        config = None
        for text in (raw.decode(), json.dumps(saved_data(), indent=2)):
            inventory = _snapshot._Inventory()
            with patch.object(_snapshot, "_read_file", return_value=text):
                config = _snapshot._config(7, "mobile-release.json", inventory)
            self.assertEqual(config["content"], fingerprint(text.encode()))
        self.assertIsNotNone(config)
        expected = copy.deepcopy(config["content"])
        for settled in (False, True):
            inventory = _snapshot._Inventory(root_settled=settled)
            result = _snapshot._assemble_snapshot("/inert/project", "inert", inventory, copy.deepcopy(config))
            self.assertEqual(result["config"]["content"], expected if settled else None)


class PreflightBudgetTests(unittest.TestCase):
    def test_limits_are_charged_before_attempt_and_failure_is_absorbing(self):
        for counter, maximum, action in (
            ("files", 512, lambda b: b.file_admission(b.root / "leaf", 1)),
            ("paths", 4096, lambda b: b.path(b.root / "leaf")),
            ("reads", 64 * 1024 * 1024, lambda b: b.read_request(1)),
            ("capture", 8 * 1024 * 1024, lambda b: b.capture(1)),
            ("nodes", 65_536, lambda b: b.list()),
        ):
            with self.subTest(counter=counter), inert_source() as (guard, source):
                budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
                budget.counters[counter] = maximum
                with self.assertRaises(PreflightBudgetError):
                    action(budget)
                self.assertIsNotNone(source.first_failure)
                with self.assertRaises(PreflightBudgetError):
                    budget.charge("other", 0, 1)

    def test_next_including_eof_is_precharged_and_iterators_are_not_acquired_after_cap(self):
        with inert_source() as (guard, source):
            budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
            iterator = _Iterator(budget)
            iterator.value, iterator.state = iter(()), "open"
            budget.counters["advances"] = 49_999
            with self.assertRaises(StopIteration):
                next(iterator)
            self.assertEqual(budget.counters["advances"], 50_000)
            with self.assertRaises(PreflightBudgetError):
                next(iterator)
        with inert_source() as (guard, source):
            budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
            budget.counters["iterators"] = 4096
            with patch("os.scandir", side_effect=AssertionError("new iterator")) as opened:
                with self.assertRaises(PreflightBudgetError):
                    with budget.entries(7):
                        self.fail("cap must precede acquisition")
                opened.assert_not_called()

    def test_directory_depth_allows_one_file_leaf_but_no_extra_directory(self):
        with inert_source() as (guard, source):
            budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
            directory = "/".join(["d"] * 32)
            budget.relative(budget.root / directory / "leaf")
            reader = types.SimpleNamespace(inventory=types.SimpleNamespace(budget=budget), root=7)
            with self.assertRaises(PreflightBudgetError):
                _snapshot._NamedTextReads.directory(reader, directory + "/extra-directory")

    def test_retention_precedes_insertion_and_streaming_policy_is_unchanged(self):
        with inert_source() as (guard, source):
            budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
            values = budget.list()
            with self.assertRaises(PreflightBudgetError):
                values.append("x" * (16 * 1024 + 1))
            self.assertEqual(values, [])
        text = "A=1\r\nB=2\v# ignored\fC=3\x1cD=4\x85E=5\u2028F=6\u2029"
        self.assertEqual(list(_iter_text_lines(text)), text.splitlines())
        with inert_source() as (guard, source):
            budget = OfflinePreflightBudget(Path("/inert/project"), guard, source)
            self.assertEqual(parse_key_value_text(text, budget=budget), parse_key_value_text(text))
            inputs = dict(projects=["app.xcodeproj"], workspaces=[], scheme_names=["App", "App"], generated_sources=[],
                          texts=["PRODUCT_BUNDLE_IDENTIFIER = $(BASE).app", "BASE = org.first\nBASE = org.second"])
            self.assertEqual(discovery.parse_ios_sources(**inputs, budget=budget), discovery.parse_ios_sources(**inputs))

    def test_remaining_timeout_floors_and_first_failure_does_not_renew(self):
        with inert_source() as (guard, source):
            with patch.object(control.time, "monotonic", return_value=source.work_end - 1.9):
                self.assertEqual(source.remaining_timeout(1800), 1)
            with patch.object(control.time, "monotonic", return_value=source.work_end - 0.9):
                with self.assertRaises(KeyboardInterrupt):
                    source.remaining_timeout(1800)
                first = source.first_failure
            with patch.object(control.time, "monotonic", return_value=source.work_end + 500):
                source.stop("cancelled")
            self.assertEqual(source.first_failure, first)
            self.assertEqual(source.stop_reason, "timed-out")

    def test_first_exception_is_observed_before_original_cleanup(self):
        with inert_source() as (guard, source):
            observed = []
            scope = CleanupScope(guard, lambda: observed.append(source.first_failure), owns_cancellation=False, first_primary=True)
            with patch.object(control.time, "monotonic", return_value=101):
                with self.assertRaisesRegex(ValueError, "primary"):
                    with scope:
                        raise ValueError("primary")
            self.assertEqual(observed, [101])


class PreflightServiceTests(unittest.TestCase):
    def test_saved_refusals_precede_policy_and_never_accept_a_draft(self):
        good = encoded(saved_data())
        disabled = saved_data()
        disabled["android"] = {"enabled": False}
        ios_only = copy.deepcopy(disabled)
        ios_only["ios"] = {"enabled": True, "bundleId": "org.inert.preflight", "identityStatus": "unverified"}
        ios_only["metadata"]["iosLocales"] = ["en-US"]
        sensitive = saved_data()
        sensitive["projectChecks"]["preflight"] = [["inert", "password=abcdefgh"]]
        for raw, expected, compared in (
            (None, "saved-config-missing", good), (good + b" ", "saved-config-changed", good),
            (b"{", "saved-config-invalid", b"{"),
            (encoded(disabled), "saved-config-invalid", encoded(disabled)),
            (encoded(ios_only), "platform-disabled", encoded(ios_only)),
            (encoded(sensitive), "saved-config-sensitive", encoded(sensitive)),
        ):
            with self.subTest(reason=expected), inert_source() as (guard, source):
                req = wire.parse_request(encoded(request_data(compared)))
                run = service.OfflinePreflightRun(req, guard, source)
                with patch.object(run.budget, "read", return_value=raw), \
                     patch.object(service, "_preflight", side_effect=AssertionError("policy after refusal")) as policy:
                    with self.assertRaises(service._Refused) as refused:
                        run._saved()
                    self.assertEqual(refused.exception.reason, expected)
                    policy.assert_not_called()

    def test_fixed_saved_selection_uses_shared_policy_and_same_original_invocation(self):
        raw = encoded(saved_data())
        req = wire.parse_request(encoded(request_data(raw)))
        with inert_source() as (guard, source), ExitStack() as patches:
            run = service.OfflinePreflightRun(req, guard, source)
            owners = []

            @contextmanager
            def custody(root, *, mode, cancellation):
                self.assertEqual((root, mode), (Path("/inert/project"), "build"))
                self.assertIs(cancellation, guard)
                original = InvocationCustody(root, mode, guard)  # Construction only.
                owners.append(original)
                with patch.object(original, "require") as required, \
                     patch.object(original, "project", return_value=nullcontext()), \
                     patch.object(original, "_offline_preflight_root", return_value=(7, req.native["rootIdentity"])):
                    yield original
                    self.assertTrue(required.called)
                    for call in required.call_args_list:
                        self.assertIs(call.kwargs["cancellation"], guard)

            self.assertIs(service._preflight, preflight._preflight)
            patches.enter_context(patch.object(service, "invocation_custody", custody))
            patches.enter_context(patch.object(service.sys, "platform", "linux"))
            patches.enter_context(patch.object(service.os, "getcwd", return_value="/inert/runtime"))
            patches.enter_context(patch.object(run.budget, "read", return_value=raw))
            patches.enter_context(patch.object(preflight, "doctor", side_effect=lambda config, *args, **kwargs: Report("inert", budget=config._preflight_budget)))
            patches.enter_context(patch.object(preflight, "metadata_findings", return_value=[]))
            patches.enter_context(patch.object(ReleaseConfig, "release_version", return_value=types.SimpleNamespace(name="1.2.3", build=7)))
            command = patches.enter_context(patch.object(preflight, "run_owned", return_value=subprocess.CompletedProcess([], 1)))
            policy = patches.enter_context(patch.object(service, "_preflight", wraps=preflight._preflight))
            for name in ("run_android_build", "run_ios_build", "effective_identity_findings", "local_signing_lease",
                         "materialize_build_inputs", "validate_signing_material", "online_preflight_findings",
                         "validate_aab", "validate_ipa", "validate_xcarchive", "inspect_ios_artifact_set"):
                patches.enter_context(patch.object(preflight, name, side_effect=AssertionError("forbidden capability")))
            patches.enter_context(patch.object(credentials, "load_credentials_file", side_effect=AssertionError("credentials file")))
            patches.enter_context(patch.object(credentials, "credential_values_from_environment", side_effect=AssertionError("environment credentials")))
            run.run()
            self.assertEqual(len(owners), 1)
            self.assertIs(run.budget.invocation, owners[0])
            self.assertEqual(policy.call_args.kwargs, {"mode": "offline", "platforms": ("android",), "run_builds": False,
                "artifacts": None, "credentials_file": None, "credentials_from_env": False, "require_tools": False,
                "signing_lease": None, "invocation": owners[0]})
            self.assertEqual(command.call_args.args[0], ["inert-project-check", "PRIVATE_ARG"])
            self.assertIs(command.call_args.kwargs["cancellation"], guard)
            self.assertFalse(command.call_args.kwargs["capture"])
            self.assertIsNone(command.call_args.kwargs["execution_scope"])
            self.assertIsNone(source.first_failure)  # Complete nonzero is policy FAIL, not F.
            self.assertFalse(run.report.ok)

    def test_cleared_project_pointer_is_not_original_closure(self):
        guard = DefaultCancellation(wire.ProtocolError, "inert original owner")
        owner = InvocationCustody(Path("/inert/project"), "build", guard)
        owner.claimed = owner._cleanup_complete = True
        owner.project_started = True
        owner.project_owner = None
        self.assertFalse(owner._offline_preflight_closed(guard))

