"""Finite runner-policy DATA regressions; not native/API/finality evidence.

All exchanges below are in-memory tables. No live factory, filesystem asset,
credential service, child, process-control API or GitHub request runs here.
"""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from mobile_release import github_runner_prerequisite as runner
from mobile_release._desktop_github_engine import ProtocolError, parse_request as old_parse
from mobile_release._github_connection_transport import (
    ReadFailure, ReadResult, _Budget, _CloseFailure, _control,
    _ExchangeProfile, _ResponseRole, _request_limits,
)

TIME = "2026-09-28T12:00:00Z"
REQUEST = runner.RunnerRequest("runner-1", "owner/app", "11", "22", "INERT_TOKEN")
PRIVATE = "INERT_RUNNER_NAME_NEVER_PUBLIC"


def success(body):
    return ReadResult({"status": 200, "body": body, "failure": "none"}, _control())


def inventory(rows):
    return {"total_count": len(rows), "runners": rows}


def machine(identity=101, labels=("self-hosted",), **extra):
    return {"id": identity, "name": PRIVATE, "os": "linux", "status": "offline", "busy": True,
            "ephemeral": True, "labels": [{"id": index + 1, "name": label, "type": "custom"}
                                           for index, label in enumerate(labels)], **extra}


def observations(*, organization=False, groups=0, local=None):
    repository = {"id": 22, "full_name": "owner/app", "owner": {"id": 33, "login": "owner",
                  "type": "Organization" if organization else "User"},
                  "archived": False, "permissions": {"admin": True}}
    rows = {
        "user-before": success({"id": 11, "login": "owner"}),
        "repository-before": success(deepcopy(repository)),
        "repository-runners": success(inventory([] if local is None else local)),
    }
    if organization:
        rows["organization-groups"] = success({"total_count": groups, "runner_groups": [
            {"id": index + 40, "inherited": index % 2 == 0, "name": PRIVATE} for index in range(groups)]})
        for index in range(groups):
            rows["group-runners-" + str(index)] = success(inventory([machine(200 + index)]))
    rows.update({"repository-after": success(deepcopy(repository)),
                 "user-after": success({"id": 11, "login": "owner"})})
    return rows


class Reader:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def read(self, step):
        self.calls.append(step)
        result = self.rows[step]
        if isinstance(result, Exception):
            raise result
        return result


class Exchange:
    def __init__(self, rows):
        self.rows, self.calls = iter(rows.values()), []

    def __call__(self, method, path, body, *, _role):
        self.calls.append((method, path, body, _role))
        result = next(self.rows)
        if isinstance(result, Exception):
            raise result
        return result


def observe(rows, *, fixed=False):
    exchange = Exchange(rows) if fixed else None
    reader = runner._FixedReader(REQUEST, exchange) if fixed else Reader(rows)
    outcome = runner.observe(REQUEST, reader, observed_at=TIME)
    encoded = runner.encode_response(REQUEST.id, outcome)
    return reader, outcome, encoded, exchange


def frame():
    return {"protocol": runner.PROTOCOL, "id": REQUEST.id, "params": {
        "repository": REQUEST.repository, "expectedAccountId": "11",
        "expectedRepositoryId": "22", "token": "INERT_TOKEN"}}


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


class GitHubRunnerPrerequisiteTests(unittest.TestCase):
    def test_private_request_is_closed_pinned_and_not_admitted_by_old_protocols(self):
        original = frame()
        self.assertEqual(runner.parse_request(wire(original)), REQUEST)
        with self.assertRaises(ProtocolError):
            old_parse(wire(original))
        for name, value in [("expectedAccountId", None), ("expectedRepositoryId", None),
                            ("expectedAccountId", True), ("expectedRepositoryId", "00"),
                            ("expectedRepositoryId", "18446744073709551616"),
                            ("token", "bad token"), ("repository", "owner/app/extra"),
                            ("labels", ["linux"]), ("url", "https://example.invalid"),
                            ("token", "x" * 4097)]:
            changed = deepcopy(original); changed["params"][name] = value
            with self.subTest(name=name), self.assertRaises(ProtocolError):
                runner.parse_request(wire(changed))
        for protocol in ("mrk-github-readonly/1", "mrk-github-device/1", "mrk-github-input-metadata/1",
                         "mrk-github-input-group/1"):
            changed = deepcopy(original); changed["protocol"] = protocol
            with self.subTest(protocol=protocol), self.assertRaises(ProtocolError):
                runner.parse_request(wire(changed))
        raw = wire(original)
        for malformed in (raw[:-1], raw + b"\n", b" " + raw, raw.replace(b'"id":', b'"id":"second","id":'),
                          raw.replace(b'"token":"INERT_TOKEN"', b'"token":"\\ud800"')):
            with self.assertRaises(ProtocolError):
                runner.parse_request(malformed)

    def test_exact_personal_and_all_org_group_schedules_have_no_filter_or_replay(self):
        for organization, count in [(False, 0), *[(True, i) for i in range(9)]]:
            rows = observations(organization=organization, groups=count)
            reader, outcome, _, exchange = observe(rows, fixed=True)
            self.assertEqual(outcome["reason"], "none")
            self.assertEqual(outcome["networkCleanup"], "confirmed")
            paths = ["/user", "/repos/owner/app", "/repos/owner/app/actions/runners?per_page=100&page=1"]
            if organization:
                paths += ["/orgs/owner/actions/runner-groups?per_page=100&page=1"]
                paths += [f"/orgs/owner/actions/runner-groups/{40+i}/runners?per_page=100&page=1" for i in range(count)]
            paths += ["/repos/owner/app", "/user"]
            self.assertEqual(exchange.calls, [("GET", path, None, _ResponseRole.RUNNER_PREREQUISITE) for path in paths])
            self.assertEqual(len(exchange.calls), 6 + count if organization else 5)
            with self.assertRaises(ValueError):
                reader.read("user-after")
            self.assertNotIn("visible_to_repository", " ".join(paths))

    def test_unobserved_group_cannot_start_and_failed_call_is_not_retryable(self):
        exchange = Exchange(observations(organization=True, groups=1))
        reader = runner._FixedReader(REQUEST, exchange)
        with self.assertRaises(ValueError):
            reader.read("group-runners-0")
        self.assertEqual(exchange.calls, [])
        for response in (ReadResult({"status": 401, "body": {}, "failure": "none"}, _control("unauthorized")),
                         ReadResult({"status": 200, "body": {}, "failure": "none"}, []),
                         ReadFailure("network-unavailable")):
            reader = runner._FixedReader(REQUEST, Exchange({"user-before": response}))
            try:
                reader.read("user-before")
            except ReadFailure:
                pass
            with self.assertRaises(ValueError):
                reader.read("repository-before")
            with self.assertRaises(ValueError):
                reader.read("user-before")

    def test_runner_role_rejects_other_profiles_and_noncanonical_routes(self):
        role, profile = _ResponseRole.RUNNER_PREREQUISITE, _ExchangeProfile.RUNNER_PREREQUISITE
        for other in _ExchangeProfile:
            if other is not profile:
                with self.subTest(profile=other), self.assertRaises(ValueError):
                    _request_limits(other, role, "GET", "/user")
        for method, path, selected_role in [
            ("PUT", "/repos/owner/app/actions/runners?per_page=100&page=1", role),
            ("POST", "/orgs/owner/actions/runner-groups", role),
            ("GET", "/repos/owner/app/actions/runners?per_page=100&page=2", role),
            ("GET", "/orgs/owner/actions/runner-groups?visible_to_repository=app&per_page=100&page=1", role),
            ("GET", "/orgs/owner/actions/runner-groups/0/runners?per_page=100&page=1", role),
            ("GET", "/orgs/owner/actions/runner-groups/999999999999999999999/runners?per_page=100&page=1", role),
            ("GET", "/repos/owner/app/actions/permissions", role),
            ("GET", "/user", _ResponseRole.STANDARD),
        ]:
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                _request_limits(profile, selected_role, method, path)
        with patch.object(runner, "_make_live_exchange", return_value=Exchange(observations())) as factory:
            reader = runner._make_live_reader(REQUEST, started=1.0, runtime_dir="/inert/runtime")
            self.assertIsInstance(reader, runner._FixedReader)
            factory.assert_called_once_with("INERT_TOKEN", started=1.0, runtime_dir="/inert/runtime",
                                            api_version="2026-03-10", _profile=profile)

    def test_complete_hundred_per_list_and_nine_inventories_are_supported(self):
        rows = observations(organization=True, groups=8, local=[machine(i + 1) for i in range(100)])
        for index in range(8):
            rows["group-runners-" + str(index)] = success(inventory([machine(101 + index * 100 + j) for j in range(100)]))
        reader, outcome, encoded, _ = observe(rows)
        self.assertEqual(len(reader.calls), 14)
        self.assertEqual(outcome["reason"], "none")
        self.assertEqual(len(outcome["facts"]["repositoryRunners"]), 100)
        self.assertEqual(sum(len(g["runners"]) for g in outcome["facts"]["groups"]), 800)
        self.assertLessEqual(len(encoded), runner.RESPONSE_LIMIT)
        self.assertNotIn(PRIVATE.encode(), encoded)
        self.assertNotIn(b"INERT_TOKEN", encoded)
        self.assertNotIn(b'"status"', encoded)
        self.assertTrue(all(row.observation["body"] == {} for row in rows.values()))

    def test_all_group_superset_including_inherited_offline_busy_and_unicode_collisions(self):
        for label in ("ubuntu-24.04", "UBUNTU-24.04", "macos-26", "MacOS-26", "macoſ-26"):
            for organization in (False, True):
                rows = observations(organization=organization, groups=1 if organization else 0)
                step = "group-runners-0" if organization else "repository-runners"
                rows[step] = success(inventory([machine(labels=(label,))]))
                reader, outcome, encoded, _ = observe(rows)
                self.assertEqual(outcome["reason"], "runner-collision")
                self.assertEqual(reader.calls[-1], step)
                self.assertIsNone(outcome["facts"])
                self.assertEqual(rows[step].observation["body"], {})
                self.assertNotIn(PRIVATE.encode(), encoded)
        # This is an all-group conservative check, not an empty-filter inference.
        rows = observations(organization=True, groups=1)
        rows["organization-groups"].observation["body"]["runner_groups"][0]["visibility"] = "selected"
        rows["group-runners-0"] = success(inventory([machine(labels=("macos-26",))]))
        self.assertEqual(observe(rows)[1]["reason"], "runner-collision")

    def test_groups_are_complete_bounded_unique_and_require_inherited_boolean(self):
        variants = [
            {"total_count": 9, "runner_groups": []},
            {"total_count": True, "runner_groups": []},
            {"total_count": 1, "runner_groups": []},
            {"total_count": 2, "runner_groups": [{"id": 40, "inherited": False}] * 2},
            {"total_count": 1, "runner_groups": [{"id": "40", "inherited": False}]},
            {"total_count": 1, "runner_groups": [{"id": 40}]},
            {"total_count": 1, "runner_groups": [{"id": 40, "inherited": 1}]},
        ]
        for body in variants:
            rows = observations(organization=True, groups=1)
            rows["organization-groups"] = success(deepcopy(body))
            reader, outcome, _, _ = observe(rows, fixed=True)
            self.assertIsNone(outcome["facts"])
            self.assertIn(outcome["reason"], {"response-invalid", "response-limit"})
            self.assertEqual(reader.claimed, 4)

    def test_runner_counts_identity_and_labels_are_closed_and_bounded(self):
        broken = [
            {"total_count": 101, "runners": []}, {"total_count": True, "runners": []},
            {"total_count": 1, "runners": []}, inventory([machine(), machine()]),
            inventory([machine(identity=True)]), inventory([machine(identity=0)]),
            inventory([machine(identity=2**64)]), inventory([machine(labels=("same", "SAME"))]),
            inventory([machine(labels=("",))]), inventory([machine(labels=("x" * 257,))]),
            inventory([machine(labels=("bad\x00label",))]), inventory([machine(labels=tuple(str(i) for i in range(65)))]),
            inventory([{**machine(), "labels": [{"id": 1, "name": "a", "type": "unknown"}]}]),
        ]
        for body in broken:
            rows = observations(); rows["repository-runners"] = success(body)
            reader, outcome, _, _ = observe(rows)
            self.assertEqual(reader.calls[-1], "repository-runners")
            self.assertIn(outcome["reason"], {"response-invalid", "response-limit"})
            self.assertIsNone(outcome["facts"])
        rows = observations(organization=True, groups=1, local=[machine(200)])
        reader, outcome, _, _ = observe(rows)
        self.assertEqual(reader.calls[-1], "group-runners-0")
        self.assertEqual(outcome["reason"], "response-invalid")

    def test_user_repo_owner_and_admin_brackets_are_required(self):
        for step, target, key, value in [
            ("user-before", "body", "id", 12), ("user-after", "body", "id", 12),
            ("repository-before", "body", "id", 23), ("repository-after", "body", "id", 23),
            ("repository-after", "owner", "id", 34), ("repository-after", "owner", "type", "Organization"),
            ("repository-before", "owner", "type", "Enterprise"),
            ("repository-before", "owner", "login", "another"),
            ("repository-before", "body", "full_name", "owner/another"),
            ("repository-before", "body", "archived", True),
            ("repository-before", "permissions", "admin", False),
            ("repository-after", "permissions", "admin", False),
        ]:
            rows = observations(); body = rows[step].observation["body"]
            (body if target == "body" else body[target])[key] = value
            reader, outcome, _, _ = observe(rows)
            self.assertEqual(reader.calls[-1], step)
            self.assertIsNone(outcome["facts"])
            self.assertNotEqual(outcome["reason"], "none")

    def test_denied_inherited_inventory_and_authenticated_cooldown_are_not_empty_coverage(self):
        for step in ("repository-runners", "organization-groups", "group-runners-0"):
            for status, reason, delay in [(401, "unauthorized", None), (403, "forbidden", None),
                                          (404, "not-found-or-inaccessible", None), (429, "rate-limited", 7)]:
                rows = observations(organization=True, groups=1)
                rows[step] = ReadResult({"status": status, "body": {}, "failure": "none"}, _control(reason, delay))
                reader, outcome, _, _ = observe(rows)
                self.assertEqual(reader.calls[-1], step)
                self.assertEqual(outcome["reason"], reason)
                self.assertEqual(outcome["control"]["cooldownSeconds"], delay)
                self.assertEqual(outcome["networkCleanup"], "confirmed")
                self.assertIsNone(outcome["facts"])

    def test_invalid_data_and_close_failure_do_not_create_success_or_cleanup(self):
        for invalid in [ReadResult({"status": 200, "body": {}, "failure": "none"}, []),
                        ReadResult({"status": True, "body": {}, "failure": "none"}, _control()),
                        ReadResult({"status": 200, "body": [], "failure": "none"}, _control()),
                        ReadResult({"status": 200, "body": {}, "failure": "none", "extra": True}, _control()),
                        ReadResult({"status": 200, "body": {}, "failure": "none"}, {**_control(), "extra": True})]:
            rows = observations(); rows["user-before"] = invalid
            _, outcome, _, _ = observe(rows, fixed=True)
            self.assertEqual(outcome["reason"], "response-invalid")
            self.assertIsNone(outcome["facts"])
        for error in [_CloseFailure("inert close failure"), ReadFailure("network-unavailable")]:
            rows = observations(); rows["repository-runners"] = error
            reader, outcome, _, _ = observe(rows)
            self.assertEqual(reader.calls[-1], "repository-runners")
            self.assertEqual(outcome["networkCleanup"], "unknown")
            self.assertIsNone(outcome["facts"])

    def test_body_aggregate_complexity_and_result_limits_stop_without_next_read(self):
        rows = observations(); rows["repository-runners"].observation["body"]["unused"] = "x" * (256 * 1024)
        reader, outcome, _, _ = observe(rows)
        self.assertEqual(reader.calls[-1], "repository-runners")
        self.assertEqual(outcome["reason"], "response-limit")
        rows = observations()
        for result in rows.values():
            result.observation["body"]["unused"] = "x" * (220 * 1024)
        reader, outcome, _, _ = observe(rows)
        self.assertEqual(reader.calls[-1], "user-after")
        self.assertEqual(outcome["reason"], "response-limit")
        rows = observations(); rows["repository-runners"].observation["body"]["unused"] = list(range(20001))
        self.assertEqual(observe(rows)[1]["reason"], "response-limit")
        # Valid per-response inventories may still overflow the closed result.
        rows = observations(organization=True, groups=8)
        for index in range(8):
            rows["group-runners-" + str(index)] = success(inventory([
                machine(1000 + index * 100 + i, labels=("x" * 255, "y" * 255)) for i in range(100)]))
        _, outcome, encoded, _ = observe(rows)
        self.assertEqual(outcome["reason"], "response-limit")
        self.assertIsNone(outcome["facts"])
        self.assertLess(len(encoded), 1024)

    def test_original_ten_second_budget_and_smaller_total_are_not_renewed(self):
        now = [5.0]
        budget = _Budget(5.0, monotonic=lambda: now[0], _profile=_ExchangeProfile.RUNNER_PREREQUISITE)
        self.assertEqual(budget.body_total_limit, 1024 * 1024)
        self.assertEqual(budget.remaining(), 10.0)
        now[0] = 14.0
        self.assertEqual(budget.remaining(), 1.0)
        now[0] = 15.0
        with self.assertRaises(ReadFailure):
            budget.remaining()
        self.assertEqual(budget.end, 15.0)

    def test_closed_normalized_result_refuses_raw_or_unchecked_facts(self):
        _, outcome, _, _ = observe(observations(local=[machine()]))
        mutations = [
            lambda value: value.update(extra=True),
            lambda value: value["facts"].update(token="INERT_TOKEN"),
            lambda value: value["facts"]["repositoryRunners"][0].update(name=PRIVATE),
            lambda value: value["facts"]["repositoryRunners"][0].update(labels=["macos-26"]),
            lambda value: value["facts"]["repositoryRunners"][0].update(labels=["UPPERCASE"]),
            lambda value: value["facts"]["repositoryRunners"][0].update(labels=["same", "same"]),
            lambda value: value["facts"].update(observedAt="2026-02-30T12:00:00Z"),
            lambda value: value.update(networkCleanup="unknown"),
            lambda value: value.update(control=_control("unauthorized")),
            lambda value: value.update(reason="runner-collision"),
        ]
        for mutate in mutations:
            value = deepcopy(outcome); mutate(value)
            with self.assertRaises(ValueError):
                runner.encode_response(REQUEST.id, value)
