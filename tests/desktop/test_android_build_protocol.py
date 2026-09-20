"""Inert Android protocol regressions; source only until separate admission.

All IDs, observations, lifetime flags and stream counters below are invented
predicate DATA. They prove no file custody, process execution, cleanup, native
finality or qualification. No project/file/process/native owner is acquired.
"""
from __future__ import annotations

import copy
import json
import stat
import unittest
from unittest.mock import patch

from mobile_release import _desktop_android_build_protocol as wire
from mobile_release.reporting import Finding, Report, Status


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"


def request_data():
    identity = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o700, "uid": 123, "gid": 123}
    return {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
            "context": {"projectId": "inert-android", "draftRevision": 2, "baselineGeneration": 3,
                        "savedConfig": {"bytes": 512, "sha256": "c" * 64},
                        "savedVersion": {"source": "release/version.properties", "bytes": 41,
                                         "sha256": "d" * 64, "name": "1.2.3", "build": 42},
                        "platform": "android", "operation": "android-build-inspect"},
            "native": {"profile": "linux-gnu-x86_64", "projectRoot": "/PRIVATE_PROJECT", "cwd": "/PRIVATE_CWD",
                       "rootIdentity": dict(identity), "toolchain": {"schemaVersion": 1,
                       "profile": wire.TOOLCHAIN_PROFILE, "root": "/PRIVATE_TOOLCHAIN", "rootIdentity": dict(identity),
                       "inventorySha256": "e" * 64}}}


def selection():
    return {"module": ":app", "variant": "release", "applicationId": "org.example.app", "task": ":app:bundleRelease"}


def report(rows=None):
    value = Report("PRIVATE_COMMAND", context={"path": "/PRIVATE_CONTEXT", "password": "PRIVATE_SECRET"})
    rows = [("android.aab.structure", Status.PASS), ("android.aab.manifest", Status.PASS),
            ("android.aab.signer", Status.SKIP)] if rows is None else rows
    for code, status in rows:
        value.add(code, status, "PRIVATE_MESSAGE", category="PRIVATE_CATEGORY",
                  details={"stdout": "PRIVATE_OUTPUT", "argv": ["PRIVATE_ARG"]}, remediation="PRIVATE_REMEDIATION")
    return value


def artifact():
    return wire.project_artifact({"logicalName": "android-aab", "platform": "android", "kind": "aab",
                                  "fileName": "app-release.aab", "size": 1024, "sha256": "f" * 64,
                                  "architectures": ["arm64-v8a"]}, unknown_abi=False)


def complete(request, findings=None):
    activity = wire.project_activity(report() if findings is None else findings, stage="disposing-work",
                                     selection=selection(), command={"outcome": "exited", "exitCode": 0})
    result = wire.project_result(activity, artifact(), used_config=request.context["savedConfig"],
                                 used_version=request.context["savedVersion"], toolchain_profile=wire.TOOLCHAIN_PROFILE)
    return {"schemaVersion": 1, "context": copy.deepcopy(request.context), "outcome": "complete", "reason": "none",
            "activity": activity, "disposition": {"work": "removed", "artifacts": "retained-local-result"}, "result": result,
            "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
                         "commands": 2, "profileCalls": 0, "inputClosed": True, "handlersRestored": True,
                         "invocationClosed": True, "artifactsClosed": True, "toolsClosed": True,
                         "namespaceClosed": True, "stopObserved": "none"}}


def command_failure(request, code=7):
    value = complete(request)
    value.update(outcome="failed", reason="command-failed", result=None)
    value["activity"] = wire.project_activity(None, stage="disposing-work", selection=selection(),
                                             command={"outcome": "exited", "exitCode": code})
    value["disposition"]["artifacts"] = "not-created"
    value["lifetime"]["commands"] = 1
    return value


class AndroidBuildProtocolTests(unittest.TestCase):
    def setUp(self):
        self.request = wire.parse_request(encoded(request_data()))

    def test_closed_request_domains_cannot_authorize_offline_argv_or_signing(self):
        data = request_data()
        self.assertEqual(self.request.context, data["context"])
        self.assertEqual(self.request.native, data["native"])
        for location, field in (((), "argv"), (("context",), "root"), (("context",), "module"),
                                (("context",), "signed"), (("native",), "environment"),
                                (("native", "toolchain"), "roles"), (("native", "toolchain"), "qualified")):
            other = copy.deepcopy(data)
            target = other
            for key in location:
                target = target[key]
            target[field] = "PRIVATE_VALUE"
            with self.subTest(location=location, field=field), self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(other))
        for field, bad in (("protocol", "mrk-offline-preflight/1"), ("operationId", "../PRIVATE")):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded({**data, field: bad}))
        for parent, field, bad in (("context", "operation", "offline-preflight"), ("context", "platform", "ios"),
                                    ("native", "profile", "macos-arm64"), ("native", "profile", "linux-gnu-aarch64")):
            other = copy.deepcopy(data)
            other[parent][field] = bad
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(encoded(other))

    def test_raw_duplicate_encoding_numeric_and_structural_limits_fail_closed(self):
        raw = encoded(request_data())
        bad_values = [raw.replace(b'"sha256":', b'"sha256":"duplicate","sha256":', 1),
                      b"\xef\xbb\xbf" + raw, raw + b"\n", raw[:-1], b" " * (wire.REQUEST_LIMIT + 1),
                      raw.replace(b'"draftRevision":2', b'"draftRevision":NaN'),
                      raw.replace(b'"draftRevision":2', b'"draftRevision":Infinity'),
                      raw.replace(b'"draftRevision":2', b'"draftRevision":2.0'),
                      raw.replace(b'"draftRevision":2', b'"draftRevision":9007199254740992'),
                      raw.replace(b'"projectId":"inert-android"', b'"projectId":"\\ud800"')]
        nested = 0
        for _ in range(20):
            nested = [nested]
        for extra in (nested, [0] * 8200, "x" * 4097):
            bad_values.append(encoded({**request_data(), "extra": extra}))
        for raw in bad_values:
            with self.subTest(size=len(raw)), self.assertRaises(wire.ProtocolError) as rejected:
                wire.parse_request(raw)
            self.assertEqual(str(rejected.exception), "Invalid saved Android build protocol")

    def test_prepare_is_bounded_saved_pair_data_not_release_policy_or_native_authority(self):
        value = {key: item for key, item in self.request.context.items() if key not in {"platform", "operation"}}
        self.assertEqual(wire.parse_prepare(encoded(value).rstrip(b"\n")), value)
        other = copy.deepcopy(value)
        other["savedVersion"]["name"] = "not-a-marketing-version"
        # The original core selection must still run its shared release policy.
        self.assertEqual(wire.prepare(other)["savedVersion"]["name"], "not-a-marketing-version")
        for field, bad in (("draftRevision", True), ("baselineGeneration", 2**32 - 1)):
            with self.assertRaises(wire.ProtocolError):
                wire.prepare({**value, field: bad})
        for path in ("/PRIVATE_VERSION", "../version.properties", ".mobile-release/private/version", "release/credentials/version"):
            other = copy.deepcopy(value)
            other["savedVersion"]["source"] = path
            with self.assertRaises(wire.ProtocolError):
                wire.prepare(other)
        other = copy.deepcopy(value)
        other["savedVersion"]["bytes"] = wire.MAX_VERSION_BYTES + 1
        with self.assertRaises(wire.ProtocolError):
            wire.prepare(other)
        with self.assertRaises(wire.ProtocolError):
            wire.prepare({**value, "native": request_data()["native"]})

    def test_terminal_binds_both_byte_pairs_source_and_displayed_name_build(self):
        base = complete(self.request)
        wire.validate_terminal(base, self.request)
        for parent, field, different in (("usedConfig", "bytes", 513), ("usedConfig", "sha256", "a" * 64),
                ("usedVersion", "bytes", 42), ("usedVersion", "sha256", "a" * 64),
                ("usedVersion", "source", "release/another.properties"), ("usedVersion", "name", "1.2.4"),
                ("usedVersion", "build", 43)):
            value = copy.deepcopy(base)
            value["result"][parent][field] = different
            with self.subTest(parent=parent, field=field), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        value = copy.deepcopy(base)
        value["activity"]["selection"]["task"] = ":other:bundleRelease"
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)  # Standalone result and activity cannot disagree.

    def test_projection_never_reads_or_relays_private_reports_native_paths_or_logs(self):
        findings = report()
        for status in Status:
            findings.add("PRIVATE_CODE", status, "PRIVATE_" * 4096, details={"password": "PRIVATE_PASSWORD"})
        with patch.object(Report, "as_dict", side_effect=AssertionError("raw report serialization")), \
                patch.object(Finding, "as_dict", side_effect=AssertionError("raw finding serialization")):
            value = complete(self.request, findings)
            raw = wire.response(self.request, "terminal", value, sequence=1)
        self.assertNotIn(b"PRIVATE_", raw)
        self.assertNotIn(b"rootIdentity", raw)
        self.assertNotIn(b"inventorySha256", raw)
        self.assertEqual(set(value["activity"]["summary"]["counts"]), set(wire.STATUSES))
        self.assertEqual(value["result"]["assurances"]["sourceBinding"], "not-established")
        self.assertEqual(value["result"]["assurances"]["releaseReadiness"], "not-assessed")
        self.assertIn("may have signed", wire.SIGNER_MESSAGE)

    def test_known_command_failure_and_unknown_outcome_are_not_interchangeable(self):
        for code in (7, -9):
            wire.validate_terminal(command_failure(self.request, code), self.request)
        value = command_failure(self.request)
        value["activity"]["command"] = {"outcome": "unknown", "exitCode": None}
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)
        value["reason"] = "command-incomplete"
        wire.validate_terminal(value, self.request)  # Settled cleanup can coexist with no usable return code.
        value.update(outcome="unknown", reason="cleanup-unknown")
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)  # Unknown command status alone is not unknown cleanup.
        value["lifetime"]["inputClosed"] = False
        wire.validate_terminal(value, self.request)
        self.assertIn("Possible causes", wire.reason_guidance("command-failed"))
        self.assertIn("no exit code", wire.reason_guidance("command-incomplete"))
        self.assertIn("further execution stays blocked", wire.reason_guidance("cleanup-unknown"))
        with self.assertRaises(wire.ProtocolError):
            wire.project_activity(report(), stage="disposing-work", selection=selection(),
                                  command={"outcome": "exited", "exitCode": 7})

    def test_no_effect_refusal_and_original_cleanup_uncertainty_remain_distinct(self):
        value = command_failure(self.request)
        value.update(outcome="refused", reason="module-required")
        value["activity"] = wire.project_activity(None, stage="accepted", selection=None,
                                                 command={"outcome": "not-dispatched", "exitCode": None})
        value["lifetime"].update(commands=0, commandDispatched=False)
        value["disposition"] = {"work": "not-created", "artifacts": "not-created"}
        wire.validate_terminal(value, self.request)
        value["lifetime"]["invocationClosed"] = False
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)
        value.update(outcome="unknown", reason="cleanup-unknown")
        wire.validate_terminal(value, self.request)

    def test_negative_reason_cannot_invent_capture_or_deny_a_known_return(self):
        for code in (0, 7, -9):
            value = command_failure(self.request, code)
            value["reason"] = "command-incomplete"
            with self.subTest(code=code), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        for reason in ("artifact-missing", "artifact-ambiguous", "artifact-unsafe", "artifact-changed"):
            value = command_failure(self.request, 0)
            value["reason"] = reason
            wire.validate_terminal(value, self.request)  # Genuine post-zero capture failure DATA.
            value["activity"]["command"]["exitCode"] = 7
            with self.subTest(reason=reason), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
            value.update(outcome="refused")
            value["activity"] = wire.project_activity(None, stage="accepted", selection=None,
                                                      command={"outcome": "not-dispatched", "exitCode": None})
            value["lifetime"].update(commands=0, commandDispatched=False)
            value["disposition"] = {"work": "not-created", "artifacts": "not-created"}
            with self.subTest(noBuild=reason), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)

    def test_stop_reason_needs_observed_stop_without_rewriting_earlier_primary(self):
        for reason, expected in (("cancelled", "cancelled"), ("context-changed", "cancelled"),
                                 ("document-lost", "cancelled"), ("shutdown", "cancelled"),
                                 ("timed-out", "timed-out")):
            value = command_failure(self.request)
            value["reason"] = reason
            with self.subTest(reason=reason), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
            value["lifetime"]["stopObserved"] = expected
            wire.validate_terminal(value, self.request)
        value = command_failure(self.request)
        value["lifetime"]["stopObserved"] = "cancelled"
        value["disposition"]["work"] = "retained-work"
        wire.validate_terminal(value, self.request)  # First known failure remains primary.

    def test_every_original_close_and_ledger_fact_vetoes_complete(self):
        for field, bad in (("complete", False), ("fatal", True), ("contained", False), ("inputClosed", False),
                ("handlersRestored", False), ("invocationClosed", False), ("artifactsClosed", False),
                ("toolsClosed", False), ("namespaceClosed", False)):
            value = complete(self.request)
            value["lifetime"][field] = bad
            with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
            value.update(outcome="unknown", reason="cleanup-unknown", result=None)
            value["disposition"]["artifacts"] = "retained-incomplete"
            wire.validate_terminal(value, self.request)
        for field, bad in (("profileCalls", 1), ("commands", 3), ("commands", True), ("inputClosed", 1)):
            value = complete(self.request)
            value["lifetime"][field] = bad
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        value = complete(self.request)
        value["lifetime"]["commands"] = 1
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)  # Native-checked requires both original command records.

    def test_late_stop_or_unknown_disposition_cannot_leave_success_artifacts(self):
        for stop in ("cancelled", "timed-out"):
            value = complete(self.request)
            value["lifetime"]["stopObserved"] = stop
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
            value.update(outcome=stop, reason=stop, result=None)
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
            value["disposition"]["artifacts"] = "retained-incomplete"
            wire.validate_terminal(value, self.request)
        value = complete(self.request)
        value["disposition"]["work"] = "unknown"
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)
        value.update(outcome="unknown", reason="cleanup-unknown", result=None)
        value["disposition"]["artifacts"] = "retained-incomplete"
        wire.validate_terminal(value, self.request)

    def test_known_retained_work_is_failed_not_clean_and_not_an_unknown_close(self):
        value = complete(self.request)
        value.update(outcome="failed", reason="work-retained", result=None)
        value["disposition"] = {"work": "retained-work", "artifacts": "retained-incomplete"}
        wire.validate_terminal(value, self.request)
        value.update(outcome="unknown", reason="cleanup-unknown")
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)
        value["lifetime"]["namespaceClosed"] = False
        wire.validate_terminal(value, self.request)

    def test_failed_inspection_can_complete_without_native_or_release_approval(self):
        rows = [("android.aab.structure", Status.FAIL)]
        value = complete(self.request, report(rows))
        value["lifetime"]["commands"] = 1
        wire.validate_terminal(value, self.request)
        self.assertEqual(value["result"]["assurances"]["structure"], "failed")
        self.assertEqual(value["result"]["assurances"]["nativeManifest"], "not-checked")
        for suffix in ([("android.aab.manifest", Status.SKIP)],
                       [("android.aab.manifest", Status.PASS), ("android.aab.package", Status.FAIL)],
                       [("android.aab.manifest", Status.PASS), ("android.aab.manifest", Status.PASS)]):
            value = complete(self.request, report([("android.aab.structure", Status.PASS), *suffix]))
            wire.validate_terminal(value, self.request)
            self.assertEqual(value["result"]["assurances"]["applicationVersion"], "not-established")
        findings = report([("android.aab.structure", Status.PASS), ("android.build.process-lifetime", Status.FAIL)])
        with self.assertRaises(wire.ProtocolError):
            complete(self.request, findings)  # Lifecycle failure is not ordinary failed inspection completion.

    def test_no_native_signer_freshness_or_optional_artifact_claim_can_be_injected(self):
        base = complete(self.request)
        for field, forged in (("signer", "approved"), ("toolkitSigning", "unsigned"), ("storeOperation", "impossible"),
                               ("sourceBinding", "verified"), ("releaseReadiness", "ready")):
            value = copy.deepcopy(base)
            value["result"]["assurances"][field] = forged
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        for field, bad in (("fileName", "/PRIVATE_PATH.aab"), ("logicalName", "android-mapping"),
                           ("freshness", "new-location"), ("architectures", ["PRIVATE_ARCHIVE_PATH"]),
                           ("size", wire.MAX_AAB_BYTES + 1)):
            value = copy.deepcopy(base)
            value["result"]["artifacts"][0][field] = bad
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        value = copy.deepcopy(base)
        value["result"]["artifacts"].append(artifact())
        with self.assertRaises(wire.ProtocolError):
            wire.validate_terminal(value, self.request)
        for location in ((), ("lifetime",), ("result",)):
            value = copy.deepcopy(base)
            target = value
            for key in location:
                target = target[key]
            target["nativeFinality"] = True
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(value, self.request)
        with self.assertRaises(wire.ProtocolError):
            complete(self.request, report([("android.aab.signer", Status.PASS)]))

    def test_finding_limit_is_refusal_not_truncation_that_hides_failed_inspection(self):
        findings = report()
        while len(findings.findings) < wire.MAX_FINDINGS:
            findings.add("PRIVATE_CODE", Status.PASS, "PRIVATE_TEXT")
        value = complete(self.request, findings)
        wire.validate_terminal(value, self.request)
        self.assertEqual(value["result"]["summary"]["omitted"], 0)
        self.assertEqual(value["result"]["summary"]["total"], wire.MAX_FINDINGS)
        findings.add("android.aab.package", Status.FAIL, "PRIVATE_WRONG_ID")
        with self.assertRaises(wire.ProtocolError):
            complete(self.request, findings)

    def test_stream_is_contiguous_monotone_single_terminal_and_nonreflective(self):
        stream = wire.AndroidBuildFrames(self.request)
        frames = [stream.response("accepted", {"schemaVersion": 1, "context": self.request.context})]
        for stage in wire.STAGES:
            frames.append(stream.response("progress", {"schemaVersion": 1, "stage": stage}))
        frames.append(stream.response("terminal", complete(self.request)))
        self.assertEqual([json.loads(frame)["sequence"] for frame in frames], list(range(len(frames))))
        self.assertLessEqual(len(frames), wire.MAX_FRAMES)
        self.assertLessEqual(sum(map(len, frames)), wire.RESPONSE_LIMIT)
        self.assertNotIn(b"PRIVATE_", b"".join(frames))
        with self.assertRaises(wire.ProtocolError):
            stream.response("terminal", complete(self.request))

    def test_failed_stream_step_or_changed_request_cannot_be_replayed_or_rearmed(self):
        stream = wire.AndroidBuildFrames(self.request)
        stream.response("accepted", {"schemaVersion": 1, "context": self.request.context})
        stream.response("progress", {"schemaVersion": 1, "stage": "building"})
        with self.assertRaises(wire.ProtocolError):
            stream.response("progress", {"schemaVersion": 1, "stage": "inputs-bound"})
        with self.assertRaises(wire.ProtocolError):
            stream.response("terminal", complete(self.request))
        stream = wire.AndroidBuildFrames(self.request)
        stream.response("accepted", {"schemaVersion": 1, "context": self.request.context})
        self.request.context["savedVersion"]["build"] += 1
        with self.assertRaises(wire.ProtocolError):
            stream.response("progress", {"schemaVersion": 1, "stage": "inputs-bound"})

    def test_progress_and_aggregate_budget_veto_late_positive_data(self):
        stream = wire.AndroidBuildFrames(self.request)
        stream.response("accepted", {"schemaVersion": 1, "context": self.request.context})
        stream.response("progress", {"schemaVersion": 1, "stage": "disposing-work"})
        value = command_failure(self.request)
        value["activity"]["stage"] = "building"
        with self.assertRaises(wire.ProtocolError):
            stream.response("terminal", value)
        stream = wire.AndroidBuildFrames(self.request)
        stream.response("accepted", {"schemaVersion": 1, "context": self.request.context})
        stream._bytes = wire.RESPONSE_LIMIT - 1  # Charged-count predicate only, never transport evidence.
        with self.assertRaises(wire.ProtocolError):
            stream.response("progress", {"schemaVersion": 1, "stage": "building"})
        with self.assertRaises(wire.ProtocolError):
            stream.response("terminal", complete(self.request))
        with self.assertRaises(wire.ProtocolError):
            wire.AndroidBuildFrames(self.request).response("terminal", complete(self.request))
