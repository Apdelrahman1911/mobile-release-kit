"""Four focused variable DATA groups; all HTTP replies are explicit inert DATA.

No credential/native/process/network/source IO is performed. These fake reader
returns cannot establish transport, assignment, consent or original finality.
"""
from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import github_setup_remote as old
from mobile_release import github_setup_variables as variables
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
from mobile_release.config import ReleaseConfig

NOW = "2026-10-09T12:00:00Z"
LATER = "2026-10-09T12:00:01Z"
VALUES = {
    "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release.key-1",
    "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER": "projects/123/locations/global/workloadIdentityPools/release/providers/github",
    "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT": "release-bot@example-project.iam.gserviceaccount.com",
    "MOBILE_RELEASE_ASC_KEY_ID": "A1B2C3D4E5",
    "MOBILE_RELEASE_ASC_ISSUER_ID": "12345678-1234-5678-abcd-123456789abc",
}
ALIAS = "MOBILE_RELEASE_ANDROID_KEY_ALIAS"


def selection(name=ALIAS, *, mode="create", stage="candidate"):
    return {"kind": "environment_variable", "mode": mode, "stage": stage, "requirement": name,
            "source": {"recordId": "a" * 32, "recordRevision": 3, "contextRevision": 9}}


def target(name=ALIAS, *, mode="create", stage="candidate"):
    return variables.VariableTarget.parse({"projectBinding": "b" * 64, "repository": "Owner/Repo",
        "accountId": "11", "repositoryId": "22", "selection": selection(name, mode=mode, stage=stage)})


def action(name=ALIAS, *, mode="create", stage="candidate", prepared=None):
    selected = target(name, mode=mode, stage=stage)
    return variables.VariableAction.parse({"kind": "prepare" if prepared is None else "apply",
        "target": selected.value(), "prepared": prepared})


def configuration():
    return {"savedConfig": {"bytes": 100, "sha256": "c" * 64},
            "canonicalConfig": {"bytes": 120, "sha256": "d" * 64}}


def policy_config(*, android=True, ios=True):
    # Constructed configuration is DATA, not saved-file/native admission.
    return ReleaseConfig(Path("/inert/config.json"), Path("/inert"), {
        "android": {"enabled": android}, "ios": {"enabled": ios},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"}})


def repo():
    return {"id": 22, "full_name": "Owner/Repo", "default_branch": "main",
            "visibility": "private", "archived": False, "permissions": {"admin": True}}


def reply(body=None, status=200, *, failure="none", control=None):
    return ReadResult({"status": status, "body": body, "failure": failure},
                      _control() if control is None else control)


class DataReader:
    """Uses the production schedule, but supplies no network/settlement evidence."""
    def __init__(self, request, *, desired=None, before=None, overrides=None):
        self.request = request
        self.schedule = variables.VariableSchedule(request)
        self.desired = VALUES[request.target.selection.requirement] if desired is None else desired
        self.before = ("OLD-VALUE-NOT-DISPLAYED" if request.target.selection.mode == "replace" else None) if before is None else before
        self.overrides = overrides or {}
        self.calls = []
        self.requests = []

    def read(self, step, reference=None):
        self.requests.append(self.schedule.claim(step, reference))
        self.calls.append(step)
        if step in self.overrides:
            value = self.overrides[step]
            if isinstance(value, BaseException):
                raise value
            return value
        selected = self.request.target.selection
        if step == "account":
            return reply({"id": 11, "login": "fixture"})
        if step.startswith("repository-"):
            return reply(repo())
        if step.startswith("environment-"):
            return reply({"id": 33, "name": selected.environment, "protection_rules": [{"unrelated": "preserved"}]})
        if step == "write":
            return reply({} if selected.mode == "create" else None, 201 if selected.mode == "create" else 204)
        value = self.desired if step == "variable-after" else self.before
        if value is None:
            return reply(None, 404)
        return reply({"name": selected.requirement, "value": value, "created_at": NOW,
                      "updated_at": LATER if step == "variable-after" else NOW})


def run_data(request, reader=None, *, desired=None, config=None):
    value = VALUES[request.target.selection.requirement] if desired is None else desired
    reader = DataReader(request, desired=value) if reader is None else reader
    binding = configuration() if config is None else config
    result = variables.execute_variable(request, reader, value=value, configuration=binding, observed_at=NOW)
    encoded = variables.encode_variable_result(request, result, desired_value=value, configuration=binding)
    assert json.loads(encoded) == result
    return result, reader


def prepared_action(name=ALIAS, *, mode="create", stage="candidate"):
    initial = action(name, mode=mode, stage=stage)
    result, _ = run_data(initial)
    return action(name, mode=mode, stage=stage, prepared=result["prepared"])


class VariableSetupTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((old, "_make_live_reader"), (socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(obj, name, side_effect=AssertionError("No live factory in variable DATA tests"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_closed_five_mapping_policy_and_actual_serialized_bounds(self):
        self.assertEqual(set(VALUES), {row[0] for row in variables.VARIABLE_FIELDS})
        self.assertEqual(len(variables.VARIABLE_FIELDS), 5)
        self.assertEqual(target().selection.mapping, ("android-keystore", "keyAlias", "android"))
        for name, valid in VALUES.items():
            selected = target(name).selection
            variables.require_variable(policy_config(), selected, purpose="full")
            self.assertEqual(variables._desired(name, valid), valid)
            with self.assertRaises(variables.VariableRefused):
                variables.require_variable(policy_config(android=False, ios=False), selected, purpose="full")
            for invalid in ("", " ", valid + "\n", valid + "\0", "é", "x" * 4097, True):
                reader = DataReader(action(name))
                with self.subTest(name=name, invalid=repr(invalid)[:20]), self.assertRaises(ValueError):
                    variables.execute_variable(action(name), reader, value=invalid, configuration=configuration(), observed_at=NOW)
                self.assertEqual(reader.calls, [])
        with self.assertRaises(variables.VariableRefused):
            variables.require_variable(policy_config(), target(stage="production").selection, purpose="full")
        with self.assertRaises(variables.VariableRefused):
            variables.require_variable(policy_config(), target().selection, purpose="store")
        with self.assertRaises(variables.VariableRefused):
            variables.require_variable(policy_config(), target("MOBILE_RELEASE_ASC_KEY_ID").selection, purpose="signing")
        for field, bad in (("kind", "environment_secret"), ("mode", "upsert"), ("stage", "arbitrary"),
                           ("requirement", "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION"),
                           ("requirement", "MOBILE_RELEASE_ANDROID_KEY_PASSWORD"), ("requirement", "alias")):
            row = selection();row[field] = bad
            with self.assertRaises(ValueError):variables.VariableSelection.parse(row)
        for source in ([], {"recordId": "A" * 32, "recordRevision": 1, "contextRevision": 1},
                       {"recordId": "a" * 32, "recordRevision": True, "contextRevision": 1},
                       {"recordId": "a" * 32, "recordRevision": 2**32, "contextRevision": 1}):
            row = selection();row["source"] = source
            with self.assertRaises(ValueError):variables.VariableSelection.parse(row)
        row = selection();row["plaintext"] = "never a renderer argument"
        with self.assertRaises(ValueError):variables.VariableSelection.parse(row)
        for identifier in (True, 22, "0", str(2**63), "01"):
            row = target().value();row["repositoryId"] = identifier
            with self.assertRaises(ValueError):variables.VariableTarget.parse(row)
        largest = "projects/1/locations/global/workloadIdentityPools/" + "p" * (4096 - len("projects/1/locations/global/workloadIdentityPools//providers/g")) + "/providers/g"
        self.assertEqual(len(largest), 4096)
        request = action("MOBILE_RELEASE_GOOGLE_WIF_PROVIDER")
        result, _ = run_data(request, desired=largest)
        raw = variables._bounded(result["prepared"], variables.MAX_PREPARED_BYTES)
        self.assertEqual(variables._bounded(result["prepared"], len(raw)), raw)
        with self.assertRaises(ValueError):variables._bounded(result["prepared"], len(raw) - 1)
        # Same encoder accounts actual escaped bytes, not character counts.
        escaped = {"text": "\n" * 10}; encoded = variables._bounded(escaped, 32)
        self.assertEqual(len(encoded), 31)
        with self.assertRaises(ValueError):variables._bounded(escaped, len(encoded) - 1)
        self.assertEqual(result["prepared"]["after"]["value"]["text"], largest)
        self.assertNotIn(largest, repr(variables.VariablePrepared.parse(result["prepared"])))
        bad = copy.deepcopy(result["prepared"]);bad["after"]["value"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):variables.VariablePrepared.parse(bad)
        for stamp in ("2026-02-30T00:00:00Z", "2026-10-09T12:00:00+00:00"):
            bad = copy.deepcopy(result["prepared"]);bad["observedAt"] = stamp
            with self.assertRaises(ValueError):variables.VariablePrepared.parse(bad)
        # Future normalization never adds secret raw value or relaxed fields.
        bad = copy.deepcopy(result["prepared"]);bad["before"]["value"] = {"text": "old"}
        with self.assertRaises(ValueError):variables.VariablePrepared.parse(bad)

    def test_fixed_six_eight_schedule_and_closed_prepared_result_codec(self):
        for mode in ("create", "replace"):
            start = action(mode=mode)
            proposal, reader = run_data(start)
            self.assertEqual(reader.calls, list(reader.schedule.expected))
            self.assertEqual(len(reader.calls), 6)
            self.assertTrue(all(r.method == "GET" and r.body is None for r in reader.requests))
            request = action(mode=mode, prepared=proposal["prepared"])
            result, reader = run_data(request)
            self.assertEqual(len(reader.calls), 8)
            self.assertEqual(result["effect"], "readback-confirmed")
            write = reader.requests[4]
            suffix = "/environments/mobile-candidate/variables"
            self.assertEqual(write.method, "POST" if mode == "create" else "PATCH")
            self.assertEqual(write.path, "/repos/Owner/Repo" + suffix + ("" if mode == "create" else "/" + ALIAS))
            expected = {"value": VALUES[ALIAS]}
            if mode == "create":expected["name"] = ALIAS
            self.assertEqual(json.loads(write.body), expected)
            with self.assertRaises(ValueError):reader.schedule.claim("repository-after")
            for wrong in ("write", "variable-before", "list", "delete"):
                schedule = variables.VariableSchedule(start)
                with self.assertRaises(ValueError):schedule.claim(wrong)
                self.assertEqual(schedule.steps, [])
            schedule = variables.VariableSchedule(start);schedule.claim("account")
            with self.assertRaises(ValueError):schedule.claim("account")
            self.assertEqual(schedule.steps, ["account"])
            with self.assertRaises(ValueError):variables.VariableSchedule(start).claim("account", "arbitrary")
            self.assertEqual(variables.VariableAction.parse(request.value()), request)
            self.assertEqual(proposal["prepared"]["confirmation"], variables.CONFIRMATION)
            for key, badvalue in (("effect", "accepted-not-value-verified"), ("schemaVersion", True),
                                  ("writeClaimed", False), ("observed", None)):
                bad = copy.deepcopy(result);bad[key] = badvalue
                with self.assertRaises(ValueError):variables.encode_variable_result(request, bad, desired_value=VALUES[ALIAS], configuration=configuration())
            bad = copy.deepcopy(proposal);bad["prepared"]["after"]["value"]["text"] = "different"
            bad["prepared"]["after"]["value"].update(bytes=9, sha256=hashlib.sha256(b"different").hexdigest())
            with self.assertRaises(ValueError):variables.encode_variable_result(start, bad, desired_value=VALUES[ALIAS], configuration=configuration())
            bad = copy.deepcopy(proposal);bad["prepared"]["configuration"]["savedConfig"]["sha256"] = "f" * 64
            with self.assertRaises(ValueError):variables.encode_variable_result(start, bad, desired_value=VALUES[ALIAS], configuration=configuration())
            bad = request.value();bad["target"]["selection"] = list(bad["target"]["selection"].values())
            with self.assertRaises(ValueError):variables.VariableAction.parse(bad)
        # Current legacy route remains closed; no Initial/GO/live activation.
        with self.assertRaises(ValueError):old.Selection.parse(selection())
        self.assertEqual(old.Schedule(old.Action.parse({"kind": "prepare", "target": {
            "projectBinding": "b" * 64, "repository": "Owner/Repo", "accountId": "11", "repositoryId": "22",
            "selection": {"kind": "actions_enabled", "enabled": True}}, "prepared": None})).claim("account").path, "/user")

        # The real isolated runtime codecs reuse the actual old Initial
        # envelope class. This is DATA only, not a native request admission.
        from mobile_release import github_setup_variable_runtime as runtime
        for name in VALUES:
            for mode in ("create", "replace"):
                for pure in (action(name, mode=mode), prepared_action(name, mode=mode)):
                    source = {"root": "/inert/registered", "rootIdentity": {"device": "1", "inode": "2",
                        "mode": 0o40700, "uid": 501, "gid": 20}, "draft": configuration()["canonicalConfig"],
                        "platform": pure.target.selection.mapping[2], "purpose": "full",
                        "material": runtime._fingerprint(VALUES[name])}
                    selected = runtime.VariableRuntimeAction.parse({**pure.value(), "source": source})
                    initial = old.Initial("e" * 32, selected, "f" * 64)
                    frame = {"protocol": old.PROTOCOL, "id": initial.id,
                        "go": {"requestSha256": initial.digest, "token": "opaque-token", "value": VALUES[name]}}
                    encode = lambda row: old._canonical(row) + b"\n"
                    self.assertEqual(runtime.parse_variable_go(encode(frame), initial), ("opaque-token", VALUES[name]))
                    result, _ = run_data(pure)
                    projected = json.loads(runtime.encode_runtime_result(initial, result,
                        desired_value=VALUES[name], configuration=configuration()))
                    self.assertEqual(projected, {"protocol": old.PROTOCOL, "id": initial.id, "result": result})
                    for change in (lambda x: x.update(id="d" * 32),
                                   lambda x: x["go"].update(requestSha256="d" * 64),
                                   lambda x: x["go"].update(token=" "),
                                   lambda x: x["go"].update(token="x" * 4097),
                                   lambda x: x["go"].update(value=VALUES[name] + "x"),
                                   lambda x: x["go"].update(extra=True),
                                   lambda x: x.update(go=list(x["go"].values()))):
                        wrong = copy.deepcopy(frame);change(wrong)
                        with self.assertRaises(ValueError): runtime.parse_variable_go(encode(wrong), initial)
                    wrong = copy.deepcopy(frame);wrong["go"]["token"] = '"' * 4096
                    self.assertGreater(len(encode(wrong)), old.MAX_GO_BYTES)
                    with self.assertRaises(ValueError): runtime.parse_variable_go(encode(wrong), initial)
                    for key in ("rootIdentity", "draft", "material"):
                        badsource = copy.deepcopy(source);badsource[key] = list(badsource[key].values())
                        with self.assertRaises(ValueError):
                            runtime.VariableRuntimeAction.parse({**pure.value(), "source": badsource})
                    badsource = copy.deepcopy(source);badsource["material"]["sha256"] = "0" * 64
                    if pure.kind == "apply":
                        with self.assertRaises(ValueError): runtime.VariableRuntimeAction.parse({**pure.value(), "source": badsource})
        self.assertEqual(runtime.WIRE_WORK_BYTES, 663554)

    def test_all_five_create_replace_and_fresh_context_refusals(self):
        for name in VALUES:
            for mode in ("create", "replace"):
                request = prepared_action(name, mode=mode)
                result, reader = run_data(request)
                self.assertEqual(result["reason"], "none")
                self.assertEqual(result["observed"]["value"]["sha256"], hashlib.sha256(VALUES[name].encode()).hexdigest())
                self.assertNotIn("text", result["observed"]["value"])
                self.assertEqual(len(reader.calls), 8)
        start = action(mode="replace")
        nochange, reader = run_data(start, DataReader(start, before=VALUES[ALIAS]))
        self.assertEqual((nochange["reason"], nochange["prepared"], len(reader.calls)), ("no-change", None, 6))
        forged = copy.deepcopy(nochange);forged["observed"]["value"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):variables.encode_variable_result(start, forged, desired_value=VALUES[ALIAS], configuration=configuration())
        create = action();exists, reader = run_data(create, DataReader(create, before="previous-value"))
        self.assertEqual((exists["reason"], len(reader.calls)), ("variable-exists", 4))
        missing, reader = run_data(start, DataReader(start, overrides={"variable-before": reply(None, 404)}))
        self.assertEqual((missing["reason"], len(reader.calls)), ("variable-missing", 4))
        request = prepared_action(mode="replace")
        for step, data in (("account", {"id": 12, "login": "other"}),
                           ("repository-before", {**repo(), "id": 23}),
                           ("environment-before", {"id": 34, "name": "mobile-candidate"}),
                           ("variable-before", {"name": ALIAS, "value": "OLD-VALUE-NOT-DISPLAYED", "created_at": NOW, "updated_at": LATER})):
            result, reader = run_data(request, DataReader(request, overrides={step: reply(data)}))
            self.assertNotEqual(result["reason"], "none")
            self.assertFalse(result["writeClaimed"])
            self.assertNotIn("write", reader.calls)
        for changed in ("new-current-alias", VALUES[ALIAS] + "-new"):
            reader = DataReader(request)
            with self.assertRaisesRegex(variables.VariableRefused, "fixed nonsecret"):
                variables.execute_variable(request, reader, value=changed, configuration=configuration(), observed_at=NOW)
            self.assertEqual(reader.calls, [])
        config = configuration();config["savedConfig"]["sha256"] = "e" * 64
        reader = DataReader(request)
        with self.assertRaises(variables.VariableRefused):
            variables.execute_variable(request, reader, value=VALUES[ALIAS], configuration=config, observed_at=NOW)
        self.assertEqual(reader.calls, [])
        for raw in ("", "é" * (variables.MAX_REMOTE_VALUE_BYTES // 2)):
            before, reader = run_data(start, DataReader(start, before=raw))
            self.assertEqual(before["reason"], "none")
            self.assertEqual(before["prepared"]["before"]["value"]["bytes"], len(raw.encode()))
            self.assertNotIn(raw if raw else "\"text\":\"\"", json.dumps(before["prepared"]["before"], ensure_ascii=False))
        invalid, _ = run_data(start, DataReader(start, before="é" * (variables.MAX_REMOTE_VALUE_BYTES // 2 + 1)))
        self.assertEqual(invalid["reason"], "response-invalid")

    def test_each_returned_failure_preserves_prefix_write_uncertainty_and_no_retry(self):
        for mode in ("create", "replace"):
            for request in (action(mode=mode), prepared_action(mode=mode)):
                steps = variables.VariableSchedule(request).expected
                for index, step in enumerate(steps):
                    failures = (ReadFailure("network-unavailable"), reply(None, 403),
                                reply(None, None, failure="tls-failed"), reply([], 200),
                                reply(None, 429, control=_control("rate-limited", 2)))
                    for fault in failures:
                        result, reader = run_data(request, DataReader(request, overrides={step: fault}))
                        self.assertEqual(reader.calls, list(steps[:index + 1]))
                        self.assertNotEqual(result["reason"], "none")
                        claimed = request.kind == "apply" and index >= 4
                        acknowledged = request.kind == "apply" and index > 4
                        self.assertEqual(result["writeClaimed"], claimed)
                        self.assertEqual(result["writeAcknowledged"], acknowledged)
                        self.assertEqual(result["effect"], "unknown" if claimed else "not-started")
                        self.assertIsNone(result["prepared"])
                        self.assertIsNone(result["observed"])
                        if fault is failures[-1]:
                            self.assertEqual((result["reason"], result["control"]["cooldownSeconds"]), ("rate-limited", 2))
                reader = DataReader(request, overrides={"account": RuntimeError("original-close-unknown")})
                with self.assertRaisesRegex(RuntimeError, "original-close-unknown"):
                    variables.execute_variable(request, reader, value=VALUES[ALIAS], configuration=configuration(), observed_at=NOW)
                self.assertEqual(reader.calls, ["account"])
                from mobile_release.github_setup_secret_inputs import SecretConfigurationError
                for step in steps:
                    error = SecretConfigurationError("configuration-changed")
                    reader = DataReader(request, overrides={step: error})
                    with self.assertRaises(SecretConfigurationError) as caught:
                        variables.execute_variable(request, reader, value=VALUES[ALIAS], configuration=configuration(), observed_at=NOW)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(reader.calls, list(steps[:steps.index(step)+1]))
            request = prepared_action(mode=mode)
            badwrites = ((reply(None, 201),) if mode == "replace" else ()) + (
                reply({"unexpected": 1}, 201), reply({}, 204), reply({}, 200))
            if mode == "create":
                for empty in (None, {}):
                    accepted, admitted = run_data(request, DataReader(request, overrides={"write": reply(empty, 201)}))
                    self.assertEqual((accepted["reason"], accepted["effect"], accepted["writeAcknowledged"], len(admitted.calls)),
                                     ("none", "readback-confirmed", True, 8))
            for fault in badwrites:
                result, reader = run_data(request, DataReader(request, overrides={"write": fault}))
                self.assertEqual((result["reason"], result["effect"], result["writeClaimed"], result["writeAcknowledged"]),
                                 ("response-invalid", "unknown", True, False))
                self.assertEqual(reader.calls[-1], "write")
            for step, fault in (("variable-after", reply(None, 404)),
                                ("variable-after", reply({"name": ALIAS, "value": "wrong", "created_at": NOW, "updated_at": LATER})),
                                ("environment-after", reply({"id": 34, "name": "mobile-candidate"})),
                                ("repository-after", reply({**repo(), "archived": True}))):
                result, _ = run_data(request, DataReader(request, overrides={step: fault}))
                self.assertEqual(result["effect"], "unknown")
                self.assertTrue(result["writeAcknowledged"])
                self.assertIsNone(result["observed"])

        # A real ConfigV2 error cannot lose original close-unknown merely
        # because its first finite reason matches a DATA refusal. Reader flags
        # below are explicitly inert observations, not transport settlement.
        from mobile_release import github_setup_variable_runtime as runtime
        from mobile_release.github_setup_secret_inputs import SecretConfigurationError
        from types import SimpleNamespace
        request = prepared_action()
        source = {"root": "/inert/registered", "rootIdentity": {"device": "1", "inode": "2",
            "mode": 0o40700, "uid": 501, "gid": 20}, "draft": configuration()["canonicalConfig"],
            "platform": "android", "purpose": "full", "material": runtime._fingerprint(VALUES[ALIAS])}
        initial = old.Initial("e" * 32, runtime.VariableRuntimeAction.parse({**request.value(), "source": source}), "f" * 64)
        for claimed, acknowledged in ((False, False), (True, False), (True, True)):
            reader = SimpleNamespace(write_claimed=claimed, write_acknowledged=acknowledged)
            error = SecretConfigurationError("configuration-changed")
            row = runtime._configuration_failure(request, error, _control(), reader=reader, prior=None)
            self.assertEqual((row["reason"], row["effect"], row["writeClaimed"], row["writeAcknowledged"]),
                             ("configuration-changed", "unknown" if claimed else "not-started", claimed, acknowledged))
            self.assertEqual(json.loads(runtime.encode_runtime_result(initial, row,
                desired_value=VALUES[ALIAS], configuration=None))["result"], row)
            prior = {**row, "reason": "rate-limited", "control": _control("rate-limited", 2)}
            retained = runtime._configuration_failure(request, error, prior["control"], reader=reader, prior=prior)
            self.assertEqual((retained["reason"], retained["control"]), ("rate-limited", prior["control"]))
            for changed in ({**row, "observed": {}}, {**row, "prepared": {}},
                            {**row, "reason": "unknown-free-text"}, {**row, "schemaVersion": True}):
                with self.assertRaises(ValueError): runtime.encode_runtime_result(initial, changed,
                    desired_value=VALUES[ALIAS], configuration=None)
            error._cleanup_unknown = True  # Explicit injected private custody fact.
            with self.assertRaises(SecretConfigurationError) as caught:
                runtime._configuration_failure(request, error, _control(), reader=reader, prior=prior)
            self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()
