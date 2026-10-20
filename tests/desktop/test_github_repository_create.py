"""Closed repository policy/frames on inert data; no filesystem, HTTP or native owner."""
from __future__ import annotations

import copy
import json
import time
import unittest
from unittest.mock import patch

from mobile_release import github_repository_create as p
from mobile_release import _desktop_github_repository_create as runtime
from mobile_release._github_repository_create_journal import Journal
from mobile_release._github_repository_create_transport import validate_endpoint, validate_body, request_role
from mobile_release._github_connection_transport import (
    ReadFailure, ReadResult, _Budget, _ExchangeProfile as Profile, _ResponseRole as Role,
    _Head, _control, _header_control, _request_limits,
)

PRIVATE = "INERT_PROVIDER_BODY_MUST_NOT_ESCAPE"


def target(**changes):
    value = {"projectBinding": "a" * 64, "repository": "sample-user/sample-app", "accountId": "11",
             "accountLogin": "sample-user", "ownerKind": "user", "visibility": "private", "marker": "b" * 32}
    value.update(changes)
    return p.Target.parse(value)


def prepared(t=None):
    t = t or target()
    return p.Prepared.parse(p.Prepared(t, "11" if t.owner_kind == "user" else "22",
                                      "self" if t.owner_kind == "user" else "active-member").value())


def upstream(t=None, repo_id=33):
    t = t or target()
    return {"id": repo_id, "full_name": t.repository, "private": t.visibility == "private", "visibility": t.visibility,
            "fork": False, "archived": False, "owner": {"id": 11 if t.owner_kind == "user" else 22,
                "login": t.owner, "type": "User" if t.owner_kind == "user" else "Organization"}, "ignored_private_body": PRIVATE}


def identity(t=None):
    t = t or target()
    rows = [("GET", "/user", 200, {"id": 11, "login": t.account_login, "type": "User", "email": PRIVATE})]
    if t.owner_kind == "organization":
        rows += [("GET", "/orgs/" + t.owner, 200, {"id": 22, "login": t.owner}),
                 ("GET", "/user/memberships/orgs/" + t.owner, 200, {"state": "active", "role": "member",
                    "user": {"id": 11, "login": t.account_login}, "organization": {"id": 22, "login": t.owner}})]
    return rows


class Exchange:
    def __init__(self, rows, events=None):
        self.rows = list(rows)
        self.events = [] if events is None else events
        self.calls = []

    def __call__(self, request):
        expected = self.rows.pop(0)
        assert (request.method, request.path) == expected[:2], (request.method, request.path, expected[:2])
        self.calls.append(request)
        self.events.append(request.method + " " + request.path)
        if isinstance(expected[2], Exception):
            raise expected[2]
        return ReadResult({"status": expected[2], "body": copy.deepcopy(expected[3]), "failure": "none"}, _control())


class MemoryJournal(Journal):
    """Exercise the actual record grammar/fence only, not custody or disposal."""
    def __init__(self, events=None):
        super().__init__("/inert-task-home", end=0)
        self.files = {}
        self.events = [] if events is None else events

    def _post(self):
        pass

    def _names(self):
        return set(self.files)

    def _read(self, name):
        return self.files[name]

    def _create(self, name, raw):
        assert name not in self.files
        self.events.append(name.split(".")[1])
        self.files[name] = raw


def creation_exchange(t=None, *, post=None, readback=None, events=None):
    t = t or target()
    rows = identity(t) + [("GET", "/repos/" + t.repository, 404, None),
                          ("POST", t.endpoint(), 201 if post is None else post, upstream(t) if post is None else None)]
    if post is None:
        rows += [("GET", "/repos/" + t.repository, 200, upstream(t) if readback is None else readback)]
    return Exchange(rows, events)


def initial(kind, t=None, original=None):
    t = t or target()
    raw = p.canonical({"protocol": p.PROTOCOL, "id": "repository-create-1", "action": {"kind": kind, "target": t.value(),
        "home": None if kind == "prepare" else "/inert-task-home", "preparedSha256": p.digest(original) if original else None}}) + b"\n"
    return runtime.parse_initial(raw), raw


class RepositoryCreateTests(unittest.TestCase):
    def test_target_is_exact_coordinate_and_private_public_confirmation_not_permission(self):
        for name in ("sample-user/sample-app", "org/_sample.app"):
            self.assertEqual(p.coordinate(name), name)
        for name in ("https://github.com/a/b", "a/b/c", "a/..", "a/%2f", "a/b?private=false", "a/b\n", "a/b.git", "-a/b", "a--b/c"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.coordinate(name)
        with self.assertRaises(ValueError):
            target(token=PRIVATE)
        with self.assertRaises(ValueError):
            target(accountLogin="another-account")
        self.assertEqual(target().body(), {"name": "sample-app", "private": True, "auto_init": False})
        public = prepared(target(visibility="public"))
        self.assertIn("Anyone can see", public.value()["confirmation"])
        self.assertEqual(public.value()["creationPermission"], "not-proven")
        self.assertNotIn(PRIVATE, json.dumps(public.value()))

    def test_prepare_user_and_organization_are_read_only_and_404_not_absence_proof(self):
        for t in (target(), target(repository="sample-org/sample-app", ownerKind="organization")):
            exchange = Exchange(identity(t) + [("GET", "/repos/" + t.repository, 404, None)])
            review, control = p.prepare(t, exchange)
            self.assertEqual(review, prepared(t))
            self.assertEqual(control, _control())
            self.assertEqual(review.value()["repositoryObservation"], "not-found-or-inaccessible")
            self.assertTrue(all(r.method == "GET" and r.body is None for r in exchange.calls))
            self.assertNotIn(PRIVATE, json.dumps(review.value()))

    def test_changed_account_owner_or_inactive_membership_never_reaches_post(self):
        t = target(repository="sample-org/sample-app", ownerKind="organization")
        for index, field, value in ((0, "id", 99), (1, "id", 99), (2, "state", "pending")):
            rows = identity(t)
            rows[index][3][field] = value
            exchange = Exchange(rows)
            result = p.create(prepared(t), exchange, MemoryJournal())
            self.assertEqual(result["effect"], "not-sent")
            self.assertIn(result["reason"], {"target-changed", "membership-unconfirmed"})
            self.assertFalse(any(r.method == "POST" for r in exchange.calls))

    def test_existing_name_is_not_overwritten_or_adopted(self):
        exchange = Exchange(identity() + [("GET", "/repos/" + target().repository, 200, upstream())])
        result = p.create(prepared(), exchange, MemoryJournal())
        self.assertEqual((result["effect"], result["reason"]), ("not-sent", "repository-exists"))
        self.assertIsNone(result["observed"])

    def test_one_post_is_between_durable_claim_and_original_id_readback(self):
        events = []
        journal = MemoryJournal(events)
        exchange = creation_exchange(events=events)
        result = p.create(prepared(), exchange, journal)
        self.assertEqual(result["effect"], "created-observed")
        self.assertEqual(result["acknowledged"], result["observed"])
        self.assertEqual(events, ["GET /user", "GET /repos/sample-user/sample-app", "intent", "claim",
                                  "POST /user/repos", "receipt", "GET /repos/sample-user/sample-app"])
        self.assertEqual(json.loads(exchange.calls[2].body), {"name": "sample-app", "private": True, "auto_init": False})
        self.assertEqual(len([r for r in exchange.calls if r.method == "POST"]), 1)
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(PRIVATE.encode(), b"".join(journal.files.values()))

    def test_lost_post_reply_and_permission_refusal_do_not_authorize_resend(self):
        for failure in (ReadFailure("network-unavailable"), 422, 409):
            journal = MemoryJournal()
            exchange = creation_exchange(post=failure)
            result = p.create(prepared(), exchange, journal)
            self.assertEqual(result["effect"], "potentially-applied")
            self.assertTrue(result["claimed"])
            self.assertIsNone(result["acknowledged"])
            self.assertEqual(len([r for r in exchange.calls if r.method == "POST"]), 1)
            self.assertEqual(journal.pending(target())[0]["claimed"], True)
            with self.assertRaises(p.Refused):
                journal.create_intent(prepared(target(marker="c" * 32)).value())

    def test_receipt_failure_or_changed_readback_never_reports_created(self):
        class FailedReceipt(MemoryJournal):
            def record(self, value):
                raise p.Refused("journal-unavailable")
        result = p.create(prepared(), creation_exchange(), FailedReceipt())
        self.assertEqual((result["effect"], result["acknowledged"]), ("potentially-applied", None))
        result = p.create(prepared(), creation_exchange(readback=upstream(repo_id=44)), MemoryJournal())
        self.assertEqual((result["effect"], result["reason"]), ("potentially-applied", "target-changed"))
        self.assertEqual(result["acknowledged"]["id"], "33")
        self.assertIsNone(result["observed"])

    def test_reconcile_unattributed_404_and_immutable_receipt_are_get_only(self):
        journal = MemoryJournal()
        p.create(prepared(), creation_exchange(post=ReadFailure("network-unavailable")), journal)
        record = journal.pending(target())[0]
        for body, expected in ((None, "unresolved"), (upstream(), "found-unattributed")):
            exchange = Exchange(identity() + [("GET", "/repos/" + target().repository, 404 if body is None else 200, body)])
            result = p.reconcile(record, exchange)
            self.assertEqual(result["effect"], expected)
            self.assertTrue(all(r.method == "GET" for r in exchange.calls))
        record["acknowledged"] = {"id": "33", "fullName": target().repository, "ownerId": "11", "visibility": "private", "url": "https://github.com/" + target().repository}
        for repo_id, expected in ((33, "created-observed"), (44, "unresolved")):
            result = p.reconcile(record, Exchange(identity() + [("GET", "/repos/" + target().repository, 200, upstream(repo_id=repo_id))]))
            self.assertEqual(result["effect"], expected)
            self.assertEqual(result["acknowledged"]["id"], "33")

    def test_record_reopen_fences_new_marker_and_cross_project_same_owner_name(self):
        old = MemoryJournal()
        p.create(prepared(), creation_exchange(), old)
        loaded = MemoryJournal()
        loaded.files = dict(old.files)
        loaded._load()
        self.assertEqual(loaded.pending(target()), old.pending(target()))
        for t in (target(marker="c" * 32), target(marker="d" * 32, projectBinding="e" * 64, repository="sample-user/SAMPLE-app")):
            with self.assertRaises(p.Refused) as refusal:
                loaded.create_intent(prepared(t).value())
            self.assertEqual(refusal.exception.reason, "previous-attempt")
        self.assertEqual(loaded.files, old.files)
        self.assertIsNone(loaded.selected)

    def test_orphan_duplicate_foreign_receipt_or_inventory_drift_is_refused_not_repaired(self):
        original = MemoryJournal()
        p.create(prepared(), creation_exchange(), original)
        for mutation in (lambda files: files.pop("b" * 32 + ".intent.json"),
                         lambda files: files.__setitem__("b" * 32 + ".claim.json", b'{"phase":"create","phase":"create"}\n'),
                         lambda files: files.__setitem__("unknown.json", b"{}\n"),
                         lambda files: files.__setitem__("b" * 32 + ".receipt.json", p.canonical({"intentSha256": "f" * 64, "repository": {}}) + b"\n")):
            journal = MemoryJournal()
            journal.files = dict(original.files)
            mutation(journal.files)
            before = dict(journal.files)
            with self.assertRaises((ValueError, KeyError)):
                journal._load()
            self.assertEqual(journal.files, before)

    def test_closed_transport_roles_cannot_borrow_other_profile_or_endpoint_body(self):
        self.assertEqual(_request_limits(Profile.REPOSITORY_CREATE, Role.REPOSITORY_CREATE_ACCOUNT, "GET", "/user"), (256 * 1024, 256))
        for role, method, path in ((Role.STANDARD, "GET", "/user"), (Role.REPOSITORY_CREATE_ACCOUNT, "POST", "/user"),
             (Role.REPOSITORY_CREATE_OWNER, "GET", "/orgs/sample-org/repos"), (Role.REPOSITORY_CREATE_LOOKUP, "DELETE", "/repos/a/b"),
             (Role.REPOSITORY_CREATE_WRITE, "POST", "/repos/a/b"), (Role.REPOSITORY_CREATE_WRITE, "POST", "/user/repos?auto_init=true")):
            with self.assertRaises(ValueError):
                validate_endpoint(role, method, path)
        with self.assertRaises(ValueError):
            _request_limits(Profile.SETUP, Role.REPOSITORY_CREATE_WRITE, "POST", "/user/repos")
        for body in (b'{"name":"app","private":true,"auto_init":true}', b'{"name":"app","private":true,"auto_init":false,"token":"INERT"}',
                     b'{"name":"app","name":"app","private":true,"auto_init":false}'):
            with self.assertRaises(ValueError):
                validate_body(Role.REPOSITORY_CREATE_WRITE, body)
        with self.assertRaises(ValueError):
            request_role(target(), p.HttpRequest("POST", "/orgs/sample-org/repos", p.canonical(target().body())))

    def test_original_budget_and_201_404_handling_are_limited_to_new_closed_roles(self):
        budget = _Budget(10, monotonic=lambda: 11, wall=lambda: 0, _profile=Profile.REPOSITORY_CREATE)
        self.assertEqual(budget.end, 70)
        for _ in range(8):
            budget.claim_request()
        with self.assertRaises(ReadFailure):
            budget.claim_request()
        for status, role in ((201, Role.REPOSITORY_CREATE_WRITE), (404, Role.REPOSITORY_CREATE_LOOKUP), (422, Role.REPOSITORY_CREATE_WRITE)):
            self.assertEqual(_header_control(_Head(status, 11, {}), budget, _role=role)["reason"], "none")
        self.assertEqual(_header_control(_Head(201, 11, {}), budget, _role=Role.REPOSITORY_CREATE_ACCOUNT)["reason"], "response-invalid")
        hint = _header_control(_Head(429, 11, {"retry-after": ["7"]}), budget, _role=Role.REPOSITORY_CREATE_WRITE)
        self.assertEqual((hint["reason"], hint["cooldownSeconds"]), ("rate-limited", 7))
        self.assertEqual(budget.requests, 8)

    def test_frames_bind_original_prepare_and_cannot_accept_invented_success_or_duplicates(self):
        retained = prepared()
        request, raw = initial("create", original=retained)
        go = {"protocol": p.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest, "token": "inert-session-input", "prepared": retained.value()}}
        token, selected = runtime.parse_go(p.canonical(go) + b"\n", request)
        self.assertEqual(selected, retained)
        self.assertEqual(token, "inert-session-input")
        wrong = copy.deepcopy(go)
        wrong["go"]["prepared"]["target"]["visibility"] = "public"
        with self.assertRaises(ValueError):
            runtime.parse_go(p.canonical(wrong) + b"\n", request)
        with self.assertRaises(ValueError):
            runtime.parse_initial(raw.replace(b'"kind":"create"', b'"kind":"create","kind":"create"'))
        result = {"schemaVersion": 1, "kind": "create", "reason": "none", "prepared": None, "pending": None,
                  "creation": p.create(retained, creation_exchange(), MemoryJournal()), "control": _control()}
        encoded = runtime.encode_result(request, result, retained)
        self.assertNotIn(PRIVATE.encode(), encoded)
        for mutate in (lambda r: r["creation"].__setitem__("acknowledged", None), lambda r: r["creation"].__setitem__("claimed", False),
                       lambda r: r["creation"]["observed"].__setitem__("id", "44"), lambda r: r.__setitem__("creation", None)):
            bad = copy.deepcopy(result)
            mutate(bad)
            with self.assertRaises(ValueError):
                runtime.encode_result(request, bad, retained)

    def test_pending_runtime_uses_no_exchange_and_does_not_grant_loaded_records_write_authority(self):
        request, _ = initial("pending")
        class InertJournal(MemoryJournal):
            def __init__(self, home, *, end):
                super().__init__()
            def open(self):
                pass
            def close(self):
                pass
        with patch.object(runtime, "Journal", InertJournal), patch.object(runtime, "make_exchange", side_effect=AssertionError("No exchange for pending")):
            result = runtime.execute(request, None, None, started=time.monotonic(), runtime_dir="/inert-runtime")
        self.assertEqual((result["reason"], result["pending"]), ("none", []))
        runtime.encode_result(request, result)
        self.assertIsNone(result["creation"])


if __name__ == "__main__":
    unittest.main()
