"""Inert preflight policy: no HTTP/TLS, process, credential or native evidence."""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from mobile_release import github_preflight as policy
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control

TIME = "2026-09-26T16:00:00Z"
SOURCE = "a" * 40
RUN = 18446744073709551615
PRIVATE = "INERT_NOT_A_CREDENTIAL"


def target() -> policy.Target:
    return policy.Target.parse({"projectBinding": "b" * 64, "repository": "owner/app", "accountId": "11",
                                "repositoryId": "22", "branch": "release/ui", "toolingRepository": policy.TOOLING_REPOSITORY,
                                "toolingSha": "c" * 40, "platform": "android", "marker": "d" * 32})


def prepared() -> policy.Prepared:
    selected = target()
    return policy.Prepared(selected, SOURCE, "33", hashlib.sha256(policy.canonical_caller(selected)).hexdigest(), TIME)


def repository() -> dict:
    return {"id": 22, "full_name": "owner/app", "default_branch": "main", "visibility": "private",
            "archived": False, "permissions": {"pull": True}, "ignored": PRIVATE}


def run() -> dict:
    return {"id": RUN, "run_attempt": 1, "workflow_id": 33, "path": policy.WORKFLOW_PATH,
            "name": policy.WORKFLOW_NAME, "head_sha": SOURCE, "head_branch": "release/ui", "event": "workflow_dispatch",
            "display_title": policy.display_title(target().marker), "repository": {"id": 22, "full_name": "owner/app"},
            "head_repository": {"id": 22, "full_name": "owner/app"}, "actor": {"id": 11}, "triggering_actor": {"id": 11},
            "status": "queued", "conclusion": None, "html_url": f"https://github.com/owner/app/actions/runs/{RUN}",
            "ignored": PRIVATE}


def job() -> dict:
    return {"id": 55, "run_id": RUN, "run_attempt": 1, "head_sha": SOURCE, "name": "preflight / validate-platform",
            "status": "queued", "conclusion": None, "ignored": PRIVATE}


def bodies() -> dict:
    raw = policy.canonical_caller(target())
    return {"account": {"id": 11, "login": "owner", "ignored": PRIVATE}, "repository-before": repository(),
            "branch": {"ref": "refs/heads/release/ui", "object": {"type": "commit", "sha": SOURCE}},
            "workflow": {"id": 33, "path": policy.WORKFLOW_PATH, "state": "active", "name": policy.WORKFLOW_NAME},
            "caller": {"type": "file", "path": policy.WORKFLOW_PATH, "encoding": "base64", "size": len(raw),
                       "content": base64.b64encode(raw).decode(),
                       "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()},
            "repository-after": repository(),
            "dispatch": {"workflow_run_id": RUN, "run_url": f"https://api.github.com/repos/owner/app/actions/runs/{RUN}",
                         "html_url": f"https://github.com/owner/app/actions/runs/{RUN}"},
            "attempt": run(), "runs": {"total_count": 1, "workflow_runs": [run()]},
            "jobs": {"total_count": 1, "jobs": [job()]}}


class Reader:
    def __init__(self, action: policy.Action, values: dict) -> None:
        self.schedule = policy.Schedule(action)
        self.values = values
        self.calls: list[policy.HttpRequest] = []

    def read(self, step: str, reference: str | None = None) -> ReadResult:
        self.calls.append(self.schedule.claim(step, reference))
        value = self.values[step]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, ReadResult):
            return value
        return ReadResult({"status": 200, "body": value, "failure": "none"}, _control())


def execute(kind: str, values: dict | None = None) -> tuple[dict, Reader]:
    action = policy.Action.parse({"kind": kind, "target": target().value(),
                                  "prepared": None if kind == "prepare" else prepared().value(),
                                  "runId": str(RUN) if kind == "track" else None})
    reader = Reader(action, bodies() if values is None else values)
    result = policy.execute(action, reader, observed_at=TIME)
    assert PRIVATE not in json.dumps(result)
    return result, reader


class GitHubPreflightPolicyTests(unittest.TestCase):
    def test_prepare_is_exact_six_gets_and_immutable_caller(self):
        result, reader = execute("prepare")
        self.assertEqual(result["reason"], "none")
        self.assertEqual(policy.Prepared.parse(result["prepared"]), prepared())
        self.assertEqual(reader.schedule.steps, ["account", "repository-before", "branch", "workflow", "caller", "repository-after"])
        self.assertEqual([call.method for call in reader.calls], ["GET"] * 6)
        self.assertIn("/git/ref/heads/release%2Fui", reader.calls[2].path)
        self.assertTrue(reader.calls[4].path.endswith("?ref=" + SOURCE))
        self.assertEqual(result["effect"], "none")
        self.assertIsNone(result["run"])

    def test_caller_source_and_identity_fail_before_any_dispatch(self):
        for step, changes, expected in (
            ("caller", {"content": base64.b64encode(b"different caller").decode()}, "caller-mismatch"),
            ("workflow", {"path": ".github/workflows/mobile-candidate.yml"}, "workflow-unavailable"),
            ("branch", {"ref": "refs/tags/release/ui"}, "source-changed"),
            ("repository-after", {"id": 23}, "target-changed"),
            ("account", {"id": 12}, "target-changed"),
        ):
            with self.subTest(step=step):
                values = bodies(); values[step].update(changes)
                result, reader = execute("prepare", values)
                self.assertEqual(result["reason"], expected)
                self.assertIsNone(result["prepared"])
                self.assertTrue(all(call.method == "GET" for call in reader.calls))

    def test_dispatch_is_one_post_and_returned_id_is_not_workflow_success(self):
        result, reader = execute("dispatch")
        self.assertEqual([call.method for call in reader.calls], ["GET"] * 4 + ["POST"])
        self.assertEqual(reader.calls[-1].path, "/repos/owner/app/actions/workflows/33/dispatches")
        body = json.loads(reader.calls[-1].body)
        self.assertEqual(body, {"ref": "release/ui", "return_run_details": True, "inputs": {
            "platform": "android", "desktop_request": "d" * 32,
            "desktop_source_sha": SOURCE, "desktop_expected_ref": "refs/heads/release/ui"}})
        self.assertEqual((result["effect"], result["runId"], result["run"]), ("accepted", str(RUN), None))
        with self.assertRaises(ValueError):
            reader.read("dispatch")

    def test_changed_branch_during_consent_is_not_sent(self):
        values = bodies(); values["branch"]["object"]["sha"] = "f" * 40
        result, reader = execute("dispatch", values)
        self.assertEqual((result["reason"], result["effect"]), ("source-changed", "not-sent"))
        self.assertNotIn("POST", [call.method for call in reader.calls])

    def test_lost_response_204_and_invalid_run_url_never_retry_or_claim_no_effect(self):
        for value in (ReadFailure("network-unavailable"),
                      ReadResult({"status": 204, "body": None, "failure": "none"}, _control("response-invalid")),
                      {**bodies()["dispatch"], "html_url": "https://unrelated.invalid/"}):
            with self.subTest(value=type(value).__name__):
                values = bodies(); values["dispatch"] = value
                result, reader = execute("dispatch", values)
                self.assertEqual(result["effect"], "potentially-applied")
                self.assertIsNone(result["runId"])
                self.assertEqual(sum(call.method == "POST" for call in reader.calls), 1)

    def test_upstream_ids_remain_integers_and_javascript_receives_strings(self):
        for wrong in (str(RUN), True, float(RUN), RUN + 1, 0):
            values = bodies(); values["dispatch"]["workflow_run_id"] = wrong
            result, _ = execute("dispatch", values)
            self.assertEqual(result["reason"], "response-invalid")
            self.assertEqual(result["effect"], "potentially-applied")
        result, _ = execute("track")
        self.assertEqual(result["run"]["id"], str(RUN))
        self.assertEqual(result["run"]["jobs"][0]["id"], "55")

    def test_reconciliation_requires_actor_triggering_actor_and_entire_title(self):
        for changes in ({"actor": {"id": 12}}, {"triggering_actor": {"id": 12}},
                        {"display_title": policy.display_title(target().marker) + " extra"},
                        {"display_title": target().marker}, {"run_attempt": 2},
                        {"path": ".github/workflows/mobile-candidate.yml"}, {"head_sha": "0" * 40},
                        {"head_repository": {"id": 23, "full_name": "owner/fork"}}):
            values = bodies(); values["runs"]["workflow_runs"][0].update(changes)
            result, reader = execute("reconcile", values)
            self.assertNotEqual(result["reason"], "none")
            self.assertIsNone(result["runId"])
            self.assertEqual(len(reader.calls), 3)

    def test_no_match_duplicate_or_partial_roster_stays_unresolved(self):
        rosters = ({"total_count": 0, "workflow_runs": []},
                   {"total_count": 2, "workflow_runs": [run()]},
                   {"total_count": 101, "workflow_runs": [run()]},
                   {"total_count": 2, "workflow_runs": [run(), run()]})
        for roster in rosters:
            values = bodies(); values["runs"] = roster
            result, reader = execute("reconcile", values)
            self.assertIn(result["reason"], {"unresolved-run", "ambiguous-run"})
            self.assertEqual(len(reader.calls), 3)
            self.assertIsNone(result["runId"])

    def test_unique_match_is_followed_by_exact_attempt_and_job_identity(self):
        result, reader = execute("reconcile")
        self.assertEqual(result["reason"], "none")
        self.assertEqual(len(reader.calls), 6)
        self.assertTrue(reader.calls[3].path.endswith(f"/actions/runs/{RUN}/attempts/1"))
        self.assertEqual(result["run"]["assurance"], "github-workflow-observation-not-release-evidence")
        self.assertEqual(result["run"]["jobs"][0]["kind"], "input-guard")
        for field, value in (("run_attempt", 2), ("run_id", 99), ("head_sha", "e" * 40),
                             ("name", "unknown Store job")):
            values = bodies(); values["jobs"]["jobs"][0][field] = value
            result, _ = execute("track", values)
            self.assertNotEqual(result["reason"], "none")
            self.assertIsNone(result["run"])

    def test_terminal_workflow_and_job_states_are_not_mixed(self):
        values = bodies(); values["attempt"].update(status="completed", conclusion="failure")
        values["jobs"]["jobs"][0].update(status="completed", conclusion="failure")
        result, _ = execute("track", values)
        self.assertEqual(result["run"]["conclusion"], "failure")
        values["attempt"]["conclusion"] = None
        result, _ = execute("track", values)
        self.assertEqual(result["reason"], "response-invalid")
        self.assertIsNone(result["run"])

    def test_success_requires_observed_guard_and_requested_platform_jobs(self):
        values = bodies(); values["attempt"].update(status="completed", conclusion="success")
        guard = {**job(), "status": "completed", "conclusion": "success"}
        android = {**guard, "id": 56, "name": "preflight / android"}
        for rows in ([], [guard], [guard, {**android, "conclusion": "skipped"}],
                     [guard, {**android, "status": "queued", "conclusion": None}]):
            values["jobs"] = {"total_count": len(rows), "jobs": rows}
            result, _ = execute("track", values)
            self.assertEqual(result["reason"], "jobs-incomplete")
            self.assertIsNone(result["run"])
        values["jobs"] = {"total_count": 2, "jobs": [guard, android]}
        result, _ = execute("track", values)
        self.assertEqual(result["reason"], "none")
        self.assertEqual(result["run"]["assurance"], "github-workflow-observation-not-release-evidence")

    def test_native_action_shapes_branch_grammar_and_schedule_are_closed(self):
        good = policy.Action("dispatch", target(), prepared()).value()
        for key, value in (("token", PRIVATE), ("url", "https://other.invalid/"), ("retry", True)):
            with self.assertRaises(ValueError):
                policy.Action.parse({**good, key: value})
        for ref in ("refs/heads/main", "refs/tags/main", "../main", "a//b", "a.lock", "a/.b", "-a", "a?x=1", "a\nmain"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                policy.branch(ref)
        changed = copy.deepcopy(good); changed["prepared"]["sourceSha"] = "z" * 40
        with self.assertRaises(ValueError):
            policy.Action.parse(changed)
        schedule = policy.Schedule(policy.Action.parse(good))
        with self.assertRaises(ValueError):
            schedule.claim("dispatch")

    def test_cooldown_and_fatal_account_refusal_stop_dependent_requests(self):
        values = bodies()
        values["account"] = ReadResult({"status": 429, "body": None, "failure": "none"}, _control("rate-limited", 60))
        result, reader = execute("prepare", values)
        self.assertEqual(result["control"]["cooldownSeconds"], 60)
        self.assertEqual(result["reason"], "rate-limited")
        self.assertEqual(len(reader.calls), 1)

    def test_canonical_template_and_early_guard_preserve_legacy_and_nonpublishing_scope(self):
        root = Path(__file__).resolve().parents[2]
        template = (root / "templates/workflows/mobile-preflight.yml").read_bytes()
        self.assertEqual(policy.canonical_caller(target()), template.replace(b"__MOBILE_RELEASE_KIT_SHA__", b"c" * 40)
                         .replace(b"__MOBILE_RELEASE_KIT_REPOSITORY__", policy.TOOLING_REPOSITORY.encode()))
        workflow = (root / ".github/workflows/reusable-preflight.yml").read_text()
        guard = workflow.split("  validate-platform:", 1)[1].split("  android:", 1)[0]
        for name in ("MOBILE_RELEASE_DESKTOP_REQUEST", "MOBILE_RELEASE_DESKTOP_SOURCE_SHA", "MOBILE_RELEASE_DESKTOP_EXPECTED_REF"):
            self.assertIn(name, guard)
        self.assertIn('if [[ -n "$MOBILE_RELEASE_DESKTOP_REQUEST$MOBILE_RELEASE_DESKTOP_SOURCE_SHA$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" ]]', guard)
        self.assertIn('[[ "$MOBILE_RELEASE_DESKTOP_SOURCE_SHA" == "$MOBILE_RELEASE_CALLER_SHA" ]]', guard)
        self.assertIn('[[ "$MOBILE_RELEASE_DESKTOP_EXPECTED_REF" == "$MOBILE_RELEASE_CALLER_REF" ]]', guard)
        self.assertEqual(workflow.count("    needs: validate-platform"), 2)
        self.assertNotIn("secrets:", template.decode())
        # Static check only, not TLS/native qualification. The original public
        # connection wrapper still claims only its five existing GETs.
        transport = ast.parse((root / "src/mobile_release/_github_connection_transport.py").read_text())
        live = next(node for node in transport.body if isinstance(node, ast.FunctionDef) and node.name == "_make_live_reader")
        calls = [node for node in ast.walk(live) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exchange"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0].value, "GET")


if __name__ == "__main__":
    unittest.main()
