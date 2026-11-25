"""Inert metadata fixtures. No real HTTP, auth/config, process or native owner."""
from __future__ import annotations

import copy
import json
import unittest

from mobile_release import github_activity as p
from mobile_release import _github_activity_transport as transport
from mobile_release import _github_connection_transport as common
from mobile_release import _desktop_github_activity as worker
from mobile_release.github_preflight import HttpRequest

NOW = "2026-10-20T12:00:00Z"
SHA, OTHER = "a" * 40, "b" * 40
TARGET = p.Target("f" * 64, "example/application", "7", "9")
BASE = "/repos/example/application"
REPO = {"id": 9, "full_name": TARGET.repository}


def pull(**changes):
    value = {"id": 31, "number": 3, "title": "Example change", "state": "open", "draft": False,
             "head": {"sha": SHA, "ref": "feature/example", "repo": REPO},
             "base": {"sha": OTHER, "ref": "main", "repo": REPO}, "updated_at": NOW, "changed_files": 1,
             "body": "EXAMPLE_PRIVATE_PR_BODY", "html_url": "https://invalid.example/provider-link"}
    value.update(changes)
    return copy.deepcopy(value)


def run(**changes):
    value = {"id": 40, "run_attempt": 2, "name": "Example checks", "status": "completed", "conclusion": "success",
             "head_sha": SHA, "head_branch": "feature/example", "event": "push", "created_at": NOW, "updated_at": NOW,
             "repository": REPO, "head_repository": REPO, "logs_url": "https://invalid.example/logs", "head_commit": {"message": "PRIVATE_EXAMPLE"}}
    value.update(changes)
    return copy.deepcopy(value)


def response(body, *, status=200, reason="none", delay=None):
    return common.ReadResult({"status": status, "body": copy.deepcopy(body), "failure": "none"}, common._control(reason, delay))


def identity():
    return [("/user", response({"id": 7, "login": "example", "email": "private-example@invalid.example"})),
            (BASE, response(REPO))]


class Script:
    def __init__(self, selected, rows):
        self.selected = selected
        self.rows = list(rows)
        self.paths = []

    def __call__(self, request):
        # Exercise the actual closed profile/role/path boundary, not a generic
        # fake endpoint accepting whatever the tested producer invents.
        role = transport.request_role(TARGET, self.selected, request)
        common._request_limits(common._ExchangeProfile.ACTIVITY, role, request.method, request.path)
        expected, result = self.rows.pop(0)
        if request.path != expected or request.body is not None:
            raise AssertionError((request.path, expected))
        self.paths.append(request.path)
        return result


def pr_script(*, first=None, last=None, files=None, reviews=None, statuses=None, checks=None):
    selected = {"kind": "pull-request", "number": "3"}
    first = first or pull()
    row = {"filename": "app/src/main.kt", "status": "modified", "additions": 2, "deletions": 1,
           "patch": "EXAMPLE_PRIVATE_PATCH", "raw_url": "https://invalid.example/source"}
    review = {"id": 50, "user": {"login": "example-reviewer", "email": "PRIVATE_EXAMPLE"}, "state": "APPROVED",
              "commit_id": OTHER, "submitted_at": NOW, "body": "EXAMPLE_PRIVATE_REVIEW"}
    return Script(selected, identity() + [
        (BASE + "/pulls/3", response(first)),
        (BASE + "/pulls/3/files?per_page=30&page=1", files or response([row])),
        (BASE + "/pulls/3/reviews?per_page=30&page=1", reviews or response([review])),
        (BASE + "/commits/" + SHA + "/status?per_page=30&page=1", statuses or response({"sha": SHA, "total_count": 0, "statuses": []})),
        (BASE + "/commits/" + SHA + "/check-runs?per_page=30&page=1", checks or response({"total_count": 0, "check_runs": []})),
        (BASE + "/pulls/3", response(last or first))])


def observed(script):
    return p.observe(TARGET, script.selected, script, observed_at=NOW)


class ActivityTests(unittest.TestCase):
    def test_pr_eight_gets_exact_head_and_metadata_only(self):
        script = pr_script()
        result = observed(script)
        self.assertEqual(result["reason"], "none")
        self.assertEqual(len(script.paths), 8)
        self.assertEqual(script.rows, [])
        data = result["data"]
        self.assertTrue(data["headChecked"])
        self.assertEqual(data["reviews"]["coverage"], "windowed")
        self.assertNotEqual(data["reviews"]["rows"][0]["commitSha"], data["pullRequest"]["headSha"])
        for key in ("checkRuns", "commitStatuses"):
            self.assertEqual(data[key]["rows"], [])
            self.assertNotIn("passed", data[key])
        wire = p.canonical(result).decode()
        for hidden in ("PRIVATE", "invalid.example", '"patch"', '"body"', '"html_url"', '"logs_url"', '"email"'):
            self.assertNotIn(hidden, wire)

    def test_permissions_are_unavailable_not_empty_complete(self):
        result = observed(pr_script(files=response(None, status=403, reason="forbidden"),
                                    checks=response(None, status=404, reason="not-found-or-inaccessible")))
        self.assertEqual(result["reason"], "none")
        for key in ("changedFiles", "checkRuns"):
            self.assertEqual(result["data"][key]["state"], "unavailable")
            self.assertEqual(result["data"][key]["coverage"], "unknown")
            self.assertIsNone(result["data"][key]["total"])

    def test_moving_head_or_changed_file_total_drops_entire_result(self):
        for last in (pull(head={"sha": OTHER, "ref": "feature/example", "repo": REPO}), pull(changed_files=2)):
            with self.subTest(last=last["changed_files"]):
                r = observed(pr_script(last=last))
                self.assertEqual(r["reason"], "selection-changed")
                self.assertIsNone(r["data"])
                self.assertEqual(r["control"]["reason"], "none")  # Not an account failure.

    def test_wrong_status_sha_or_check_head_refused(self):
        wrong = {"id": 80, "name": "Checks", "status": "completed", "conclusion": "neutral", "head_sha": OTHER}
        for kwargs in ({"statuses": response({"sha": OTHER, "total_count": 0, "statuses": []})},
                       {"checks": response({"total_count": 1, "check_runs": [wrong]})}):
            r = observed(pr_script(**kwargs))
            self.assertEqual(r["reason"], "selection-changed")
            self.assertIsNone(r["data"])

    def test_foreign_account_repository_and_non_numeric_ids(self):
        for path, body, reason in (("/user", {"id": 8}, "target-changed"),
                                  (BASE, {"id": 10, "full_name": TARGET.repository}, "target-changed"),
                                  ("/user", {"id": "7"}, "response-invalid")):
            rows = identity()
            rows[0 if path == "/user" else 1] = (path, response(body))
            r = observed(Script({"kind": "overview", "branch": None}, rows))
            self.assertEqual(r["reason"], reason)
            self.assertEqual(r["control"]["reason"], reason)
            self.assertIsNone(r["data"])

    def test_windowed_overview_and_explicit_branch_recheck(self):
        selected = {"kind": "overview", "branch": "feature/example"}
        ref = BASE + "/git/ref/heads/feature%2Fexample"
        refbody = {"ref": "refs/heads/feature/example", "object": {"type": "commit", "sha": SHA}}
        rows = identity() + [(ref, response(refbody)),
            (BASE + "/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1&head=example%3Afeature%2Fexample", response([pull()])),
            (BASE + "/actions/runs?per_page=30&page=1&branch=feature%2Fexample", response({"total_count": 2, "workflow_runs": [run()]})),
            (ref, response(refbody)), (BASE, response(REPO))]
        script = Script(selected, rows)
        result = observed(script)
        self.assertEqual(result["reason"], "none")
        self.assertEqual(len(script.paths), 7)
        self.assertEqual(result["data"]["workflowRuns"]["coverage"], "windowed")
        rows[-2] = (ref, response({"ref": refbody["ref"], "object": {"type": "commit", "sha": OTHER}}))
        self.assertEqual(observed(Script(selected, rows))["reason"], "selection-changed")
        rows[-2] = (ref, response(refbody))
        rows[4] = (rows[4][0], response({"total_count": 1, "workflow_runs": [run(head_repository={"id": 19, "full_name": "example-fork/application"})]}))
        self.assertEqual(observed(Script(selected, rows))["reason"], "selection-changed")

    def test_empty_overview_still_rechecks_repository_id_and_limit_is_not_bad_account(self):
        selected = {"kind": "overview", "branch": None}
        rows = identity() + [(BASE + "/pulls?state=open&sort=updated&direction=desc&per_page=30&page=1", response([])),
            (BASE + "/actions/runs?per_page=30&page=1", response({"total_count": 0, "workflow_runs": []})),
            (BASE, response({"id": 10, "full_name": TARGET.repository}))]
        r = observed(Script(selected, rows))
        self.assertEqual(r["reason"], "target-changed")
        self.assertIsNone(r["data"])
        r = observed(pr_script(first=pull(title="a" * 513)))
        self.assertEqual(r["reason"], "response-limit")
        self.assertEqual(r["control"]["reason"], "none")

    def test_run_attempt_and_jobs_bound_to_exact_run_sha(self):
        selected = {"kind": "workflow-run", "runId": "40", "attempt": 2}
        path = BASE + "/actions/runs/40/attempts/2"
        job = {"id": 60, "name": "Build", "status": "completed", "conclusion": "skipped",
               "run_id": 40, "run_attempt": 2, "head_sha": SHA, "steps": [{"name": "EXAMPLE_PRIVATE_STEP"}]}
        rows = identity() + [(path, response(run())), (path + "/jobs?per_page=30&page=1", response({"total_count": 1, "jobs": [job]})), (path, response(run()))]
        r = observed(Script(selected, rows))
        self.assertEqual(r["reason"], "none")
        self.assertEqual(r["data"]["jobs"]["rows"][0]["conclusion"], "skipped")
        self.assertNotIn("steps", p.canonical(r).decode())
        for changed in (dict(job, run_id=41), dict(job, run_attempt=3), dict(job, head_sha=OTHER)):
            bad = rows[:]; bad[3] = (path + "/jobs?per_page=30&page=1", response({"total_count": 1, "jobs": [changed]}))
            self.assertEqual(observed(Script(selected, bad))["reason"], "selection-changed")
        rows[-1] = (path, response(run(run_attempt=3)))
        self.assertEqual(observed(Script(selected, rows))["reason"], "selection-changed")

    def test_row_limit_duplicates_and_malformed_total_refuse_not_partial(self):
        review = {"id": 50, "user": None, "state": "COMMENTED", "commit_id": SHA, "submitted_at": NOW}
        cases = [(pr_script(reviews=response([review] * 31)), "response-limit"),
                 (pr_script(reviews=response([review] * 2)), "response-invalid"),
                 (pr_script(checks=response({"total_count": True, "check_runs": []})), "response-invalid")]
        for script, reason in cases:
            r = observed(script)
            self.assertEqual(r["reason"], reason)
            self.assertIsNone(r["data"])

    def test_rate_limit_preserves_original_control_and_stops_schedule(self):
        script = pr_script(files=response(None, status=403, reason="rate-limited", delay=12))
        r = observed(script)
        self.assertEqual(r["reason"], "rate-limited")
        self.assertEqual(r["control"]["cooldownSeconds"], 12)
        self.assertEqual(len(script.paths), 4)
        self.assertIsNone(r["data"])

    def test_post_read_failure_keeps_already_observed_control(self):
        def failed(_request):
            failed.control = common._control("rate-limited", 15)
            raise common.ReadFailure("network-unavailable")
        r = p.observe(TARGET, {"kind": "overview", "branch": None}, failed, observed_at=NOW)
        self.assertEqual(r["reason"], "network-unavailable")
        self.assertEqual(r["control"], common._control("rate-limited", 15))
        self.assertIsNone(r["data"])

    def test_unknown_upstream_shape_has_fixed_error_not_raw_text(self):
        r = observed(pr_script(first=pull(title="bad\u202etitle")))
        self.assertEqual(r["reason"], "response-invalid")
        self.assertIsNone(r["data"])
        self.assertNotIn("title", p.canonical(r).decode())

    def test_closed_selection_and_original_ready_go(self):
        selected = {"kind": "overview", "branch": None}
        raw = p.canonical({"protocol": p.PROTOCOL, "id": "github-activity-1", "action": {"target": TARGET.value(), "selection": selected}}) + b"\n"
        original = worker.parse_initial(raw)
        self.assertEqual(json.loads(worker.ready_frame(original))["ready"]["requestSha256"], original.digest)
        go = {"protocol": p.PROTOCOL, "id": original.id, "go": {"requestSha256": original.digest, "token": "synthetic-fixture-only"}}
        self.assertEqual(worker.parse_go(p.canonical(go) + b"\n", original), "synthetic-fixture-only")
        go["go"]["requestSha256"] = "0" * 64
        with self.assertRaises(ValueError): worker.parse_go(p.canonical(go) + b"\n", original)
        duplicate = raw.replace(b'"id":"github-activity-1"', b'"id":"other","id":"github-activity-1"')
        with self.assertRaises(ValueError): worker.parse_initial(duplicate)
        for bad in ({"kind": "rerun", "runId": "40", "attempt": 2}, {"kind": "overview", "branch": "../main"},
                    {"kind": "workflow-run", "runId": "40", "attempt": True}, dict(selected, token="not-allowed")):
            with self.assertRaises(ValueError): p.selection(bad)

    def test_fixed_endpoint_profile_refuses_generic_access(self):
        role = common._ResponseRole.ACTIVITY_OBJECT
        for method, path in (("POST", BASE + "/actions/runs/40/rerun-failed-jobs"), ("GET", "https://api.github.com/user"),
                             ("GET", BASE + "/actions/runs/40/logs"), ("GET", BASE + "/actions/runs?per_page=100&page=1"),
                             ("GET", BASE + "/git/ref/heads/%2e%2e"), ("GET", BASE + "/contents/private")):
            with self.assertRaises(ValueError): common._request_limits(common._ExchangeProfile.ACTIVITY, role, method, path)
        with self.assertRaises(ValueError): common._request_limits(common._ExchangeProfile.STANDARD, role, "GET", "/user")
        with self.assertRaises(ValueError): transport.request_role(TARGET, {"kind": "pull-request", "number": "3"}, HttpRequest("GET", BASE + "/pulls/4", None))

    def test_shared_original_budget_eight_requests_and_single_sixty_seconds(self):
        now = [10.0]
        budget = common._Budget(10.0, monotonic=lambda: now[0], _profile=common._ExchangeProfile.ACTIVITY)
        for _ in range(8): budget.claim_request()
        with self.assertRaises(common.ReadFailure): budget.claim_request()
        self.assertEqual(budget.end, 70.0)
        self.assertEqual(budget.body_total_limit, 2 * 1024 * 1024)
        now[0] = 70.0
        with self.assertRaises(common.ReadFailure): budget.remaining()
        self.assertEqual(budget.end, 70.0)


if __name__ == "__main__":
    unittest.main()
