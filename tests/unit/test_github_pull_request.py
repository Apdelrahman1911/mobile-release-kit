"""Inert DATA/fake HTTP only. No socket, home/config, process or native owner."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from mobile_release import github_pull_request as p
from mobile_release import _desktop_github_pull_request as wire
from mobile_release import _github_pull_request_transport as transport
from mobile_release._github_pull_request_journal import Journal
from mobile_release._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, ReadFailure, ReadResult, _control, _role_limits
from mobile_release.github_preflight import HttpRequest


def draft(**changes):
    return p.Draft.parse({"base": "main", "head": "feature/login", "title": "Review login screen", "body": "What changed\nUser-approved description", **changes})


def target(**changes):
    d = draft()
    value = {"scope": {"projectBinding": "a" * 64, "repository": "owner/app", "accountId": "11", "repositoryId": "22"},
             "intent": {"base": d.base, "head": d.head, "marker": "b" * 32, "titleSha256": p.sha_text(d.title), "bodySha256": p.sha_text(d.body)}}
    value.update(changes)
    return p.Target.parse(value)


def repo(): return {"id": 22, "full_name": "owner/app", "archived": False, "disabled": False, "permissions": {"push": True}}
def ref(side):
    return {"ref": "refs/heads/" + ("main" if side == "base" else "feature/login"),
            "object": {"type": "commit", "sha": ("c" if side == "base" else "d") * 40}}
def compare():
    return {"base_commit": {"sha": "c" * 40}, "status": "ahead", "ahead_by": 2, "behind_by": 0, "total_commits": 2,
            "files": [{"filename": "screen/login.swift", "status": "modified", "patch": "PRIVATE source not projected"}]}
def pull():
    r = {"id": 44, "number": 3, "title": draft().title, "body": draft().post_body(target())["body"], "state": "open", "draft": True}
    for side in ("base", "head"):
        r[side] = {"repo": repo(), "sha": ref(side)["object"]["sha"], "ref": draft().value()[side]}
    return r


class Exchange:
    def __init__(self, change=None): self.calls = []; self.change = change
    def __call__(self, request):
        self.calls.append(request); path = request.path; status = 201 if request.method == "POST" else 200
        if path == "/user": body = {"id": 11, "type": "User"}
        elif path == "/repos/owner/app": body = repo()
        elif "/git/ref/" in path: body = ref("base" if path.endswith("main") else "head")
        elif "/compare/" in path: body = compare()
        elif "/pulls?" in path: body = []
        else: body = pull()
        if self.change: status, body = self.change(request, len(self.calls), status, body)
        return ReadResult({"status": status, "body": body, "failure": "none"}, _control())


class MemoryJournal(Journal):
    """The REAL journal state machine; only byte storage replaced with inert map."""
    def __init__(self, files=None):
        super().__init__("/inert-task-home", end=60)
        self.files = {} if files is None else files
    def _names(self): return set(self.files)
    def _read(self, name): return self.files[name]
    def _create(self, name, data):
        if name in self.files: raise OSError("inert exclusive create")
        self.files[name] = data
    def _post(self): pass


def prepared(): return p.prepare(target(), draft(), Exchange())[0]


class DraftPullRequestTests(unittest.TestCase):
    def test_review_is_nine_gets_private_window_and_no_permission_or_source_claim(self):
        exchange = Exchange(); review, _ = p.prepare(target(), draft(), exchange)
        self.assertEqual(len(exchange.calls), 9); self.assertTrue(all(c.method == "GET" for c in exchange.calls))
        self.assertTrue(review.value()["draft"]); self.assertEqual(review.value()["creationPermission"], "not-proven")
        self.assertEqual(review.comparison["coverage"], "windowed")
        self.assertNotIn(draft().body, str(review.value())); self.assertNotIn("PRIVATE source", str(review.value()))
        self.assertIn("workflows may run", review.value()["confirmation"])

    def test_one_post_after_durable_claim_and_exact_twelve_request_schedule(self):
        journal = MemoryJournal()
        def check(req, _, status, body):
            if req.method == "POST":
                self.assertTrue(journal.creations["b" * 32]["data"]["claimed"])
                self.assertEqual(req.body, p.canonical(draft().post_body(target())))
            return status, body
        exchange = Exchange(check); result = p.create(prepared(), draft(), exchange, journal)
        self.assertEqual(result["effect"], "created-observed"); p.creation_result(result, prepared(), "create")
        self.assertEqual(len(exchange.calls), 12); self.assertEqual([c.method for c in exchange.calls].count("POST"), 1)
        self.assertFalse(any(draft().body.encode() in raw or b"PRIVATE source" in raw for raw in journal.files.values()))

    def test_moving_refs_changed_account_permissions_and_existing_pr_never_post(self):
        for kind in ("base", "head", "account", "permissions", "existing", "missing"):
            with self.subTest(kind=kind):
                def change(req, n, status, body):
                    if kind == "base" and n == 7 or kind == "head" and n == 8: body["object"]["sha"] = "e" * 40
                    if kind == "account" and n == 1: body["id"] = 99
                    if kind == "permissions" and n == 2: body["permissions"]["push"] = False
                    if kind == "existing" and n == 6: body = [pull()]
                    if kind == "missing" and n == 3: status, body = 404, None
                    return status, body
                e = Exchange(change); j = MemoryJournal(); result = p.create(prepared(), draft(), e, j)
                self.assertEqual(result["effect"], "not-sent"); self.assertEqual(j.files, {})
                self.assertTrue(all(c.method == "GET" for c in e.calls))

    def test_lost_post_is_preserved_and_marker_readback_cannot_attribute_or_resend(self):
        def lost(req, n, status, body):
            if req.method == "POST": raise ReadFailure("network-unavailable")
            return status, body
        j = MemoryJournal(); result = p.create(prepared(), draft(), Exchange(lost), j)
        self.assertEqual(result["effect"], "potentially-applied"); self.assertIsNone(result["acknowledged"])
        reload = MemoryJournal(j.files); reload._load(); record = reload.pending(target())[0]
        e = Exchange(lambda req,n,s,b: (s, [pull()] if "/pulls?" in req.path else b))
        result = p.reconcile(record, e)
        self.assertEqual(result["effect"], "found-unattributed"); p.creation_result(result, prepared(), "reconcile")
        self.assertTrue(all(c.method == "GET" for c in e.calls)); self.assertIsNone(reload.selected)
        with self.assertRaises(p.Refused): reload.claim()

    def test_immutable_original_201_is_recorded_before_readback_and_survives_local_failure(self):
        j = MemoryJournal()
        def failure(req,n,status,body): return (404,None) if n == 11 else (status,body)
        result = p.create(prepared(), draft(), Exchange(failure), j)
        self.assertEqual(result["effect"], "acknowledged-unconfirmed"); self.assertEqual(result["acknowledged"]["id"], "44")
        p.creation_result(result, prepared(), "create")
        reload = MemoryJournal(j.files); reload._load()
        result = p.reconcile(reload.pending(target())[0], Exchange())
        self.assertEqual(result["effect"], "created-observed")
        class FailedReceipt(MemoryJournal):
            def record(self, value): raise OSError("inert receipt write failure")
        result = p.create(prepared(), draft(), Exchange(), FailedReceipt())
        self.assertEqual(result["reason"], "journal-unavailable"); self.assertEqual(result["acknowledged"]["id"], "44")

    def test_cross_nonce_account_project_fence_and_no_loaded_write(self):
        j = MemoryJournal(); j.create_intent(prepared().value())
        reload = MemoryJournal(j.files); reload._load()
        for key in ("marker", "accountId", "projectBinding"):
            v = copy.deepcopy(prepared().value())
            if key == "marker": v["target"]["intent"][key] = "e" * 32
            else: v["target"]["scope"][key] = "99" if key == "accountId" else "f" * 64
            t = p.Target.parse(v["target"]); v["confirmation"] = p.confirmation(t)
            with self.assertRaises(p.Refused): reload.create_intent(v)
        with self.assertRaises(p.Refused): reload.claim()
        self.assertEqual(len(j.files), 1)

    def test_incomplete_pagination_access_failure_and_absence_never_clear_unknown(self):
        record = {"prepared": prepared().value(), "claimed": True, "acknowledged": None}
        for status, rows in ((200, []), (403, None), (404, None), (200, [pull(), pull(), pull()])):
            e = Exchange(lambda req,n,s,b: (status,rows) if "/pulls?" in req.path else (s,b))
            r = p.reconcile(record, e); self.assertEqual(r["effect"], "unresolved")
            self.assertIsNone(r["observed"]); self.assertTrue(all(c.method == "GET" for c in e.calls))

    def test_changed_pr_text_sha_repo_or_immutable_id_does_not_validate_creation(self):
        for key in ("body", "sha", "id", "repo", "draft"):
            def change(req,n,s,b):
                if n == 11:
                    if key == "body": b["body"] += "changed"
                    elif key == "sha": b["head"]["sha"] = "e" * 40
                    elif key == "repo": b["head"]["repo"]["id"] = 77
                    elif key == "draft": b["draft"] = False
                    else: b["id"] = 88
                return s,b
            r = p.create(prepared(), draft(), Exchange(change), MemoryJournal())
            self.assertEqual(r["effect"], "acknowledged-unconfirmed"); self.assertIsNone(r["observed"])

    def test_closed_input_and_body_no_fork_path_token_or_unreviewed_mode(self):
        for change in ({"base": "refs/heads/main"}, {"head": "fork:branch"}, {"head": "main"}, {"title": "bad\nTitle"},
                       {"body": "bidi\u202e"}, {"body": "<!-- mrk-draft-pr:fake -->"}, {"title": "x" * 257}):
            with self.assertRaises(ValueError): draft(**change)
        t = target(); body = draft().post_body(t)
        role = transport.request_role(t, draft(), HttpRequest("POST", "/repos/owner/app/pulls", p.canonical(body)))
        self.assertIs(role, _ResponseRole.PULL_REQUEST_WRITE)
        for key, value in (("draft", False), ("maintainer_can_modify", True), ("token", "not-a-token")):
            bad = {**body, key: value}
            with self.assertRaises(ValueError): transport.request_role(t, draft(), HttpRequest("POST", "/repos/owner/app/pulls", p.canonical(bad)))
        for path in ("/repos/other/app/pulls", "/repos/owner/app/pulls/3/merge", "/repos/owner/app/actions/runs/1/rerun", "https://evil.invalid/pulls"):
            with self.assertRaises(ValueError): transport.request_role(t, draft(), HttpRequest("POST", path, p.canonical(body)))

    def test_aggregate_clock_bytes_and_request_cap_are_real_original_budget(self):
        b = _Budget(100.0, monotonic=lambda: 100.1, _profile=_ExchangeProfile.PULL_REQUEST)
        self.assertEqual(b.end, 160); self.assertEqual(b.body_total_limit, 2 * 1024 * 1024)
        self.assertEqual(_role_limits(_ExchangeProfile.PULL_REQUEST, _ResponseRole.PULL_REQUEST_WRITE), (256*1024, 1024))
        for _ in range(12): b.claim_request()
        with self.assertRaises(ReadFailure): b.claim_request()
        with self.assertRaises(ValueError): _role_limits(_ExchangeProfile.ACTIVITY, _ResponseRole.PULL_REQUEST_WRITE)
        op = p.Operation(target(), lambda _: ReadResult({"status": 200, "body": {"inert": "x" * 250000}, "failure": "none"}, _control()))
        for n in range(8): op.take(str(n), "/user")
        with self.assertRaises(p.Refused): op.take("ninth", "/user")

    def test_private_dialogue_binds_text_hash_and_original_ready_no_secret_public_frame(self):
        t = target(); action = {"kind": "prepare", "target": t.value(), "home": None, "preparedSha256": None}
        raw = p.canonical({"protocol": p.PROTOCOL, "id": "inert", "action": action}) + b"\n"
        r = wire.parse_initial(raw)
        go = {"protocol": p.PROTOCOL, "id": "inert", "go": {"requestSha256": r.digest, "token": "inert-not-a-live-token", "prepared": None, "draft": draft().value()}}
        self.assertEqual(wire.parse_go(p.canonical(go) + b"\n", r)[2].value(), draft().value())
        go["go"]["draft"]["title"] = "Changed text"
        with self.assertRaises(ValueError): wire.parse_go(p.canonical(go) + b"\n", r)
        self.assertNotIn(draft().title.encode(), raw); self.assertNotIn(draft().body.encode(), wire.ready_frame(r))
        result = {"schemaVersion": 1, "kind": "prepare", "reason": "none", "prepared": prepared().value(), "creation": None, "pending": None, "control": _control()}
        public = wire.encode_result(r, result)
        self.assertNotIn(b"inert-not-a-live-token", public); self.assertNotIn(draft().title.encode(), public)

    def test_pending_scope_has_no_fabricated_branch_text_and_rejects_foreign_records(self):
        t = target(intent=None)
        raw = p.canonical({"protocol": p.PROTOCOL, "id": "inert", "action": {"kind": "pending", "target": t.value(), "home": "/inert-task-home", "preparedSha256": None}}) + b"\n"
        r = wire.parse_initial(raw)
        v = {"schemaVersion": 1, "kind": "pending", "reason": "none", "prepared": None, "creation": None,
             "pending": [{"prepared": prepared().value(), "claimed": True, "acknowledged": None}], "control": _control()}
        wire.encode_result(r, v)
        v["pending"][0]["prepared"]["target"]["scope"]["repositoryId"] = "99"
        with self.assertRaises(ValueError): wire.encode_result(r, v)

    def test_unknown_receipt_inventory_never_partially_loads_or_mints_write(self):
        j = MemoryJournal(); j.create_intent(prepared().value()); j.claim()
        j.files["c" * 32 + ".receipt.json"] = b"{}\n"
        with self.assertRaises(ValueError): MemoryJournal(j.files)._load()
        j.files.pop("c" * 32 + ".receipt.json")
        j.files["b" * 32 + ".claim.json"] = b'{"intentSha256":"wrong","phase":"create"}\n'
        with self.assertRaises(ValueError): MemoryJournal(j.files)._load()

    def test_unicode_approved_text_and_file_names_keep_exact_canonical_bytes(self):
        d = draft(title="Réviser l’écran", body="Описание\n日本語")
        t = target(); t.intent.update(titleSha256=p.sha_text(d.title), bodySha256=p.sha_text(d.body))
        self.assertTrue(d.matches(t)); self.assertIn("日本語".encode(), p.canonical(d.post_body(t)))
        def change(req,n,status,body):
            if "/compare/" in req.path: body["files"][0]["filename"] = "écran/日本.swift"
            return status,body
        review, _ = p.prepare(t,d,Exchange(change)); self.assertIn("日本".encode(), p.canonical(review.value()))
        self.assertEqual(p.digest(review), hashlib.sha256(p.canonical(review.value())).hexdigest())

    def test_actual_response_parser_refuses_empty_linked_or_ambiguous_page(self):
        from mobile_release._github_connection_transport import _Head, _response_result
        class Response:
            role = _ResponseRole.PULL_REQUEST_LIST
            maximum = p.BODY_LIMIT
            def __init__(self, headers): self.head = _Head(200,11,headers); self.parts = [b"[]",b""]
            def read(self, _): return self.parts.pop(0)
        for headers in ({"link":["<https://api.github.com/inert>; rel=next"]}, {"link":[None]}, {"link":["first","second"]}):
            b=_Budget(100.0,monotonic=lambda:100.1,_profile=_ExchangeProfile.PULL_REQUEST)
            self.assertEqual(_response_result(Response(headers),b).observation["failure"],"response-limit")
        b=_Budget(100.0,monotonic=lambda:100.1,_profile=_ExchangeProfile.PULL_REQUEST)
        self.assertEqual(_response_result(Response({}),b).observation["body"],[])

    def test_fixed_private_go_cursor_original_deadline_and_32k_overflow(self):
        chunks=[b"x"*4096]*8+[b""]
        with patch.object(wire.time,"monotonic",return_value=100.1), patch.object(wire.os,"read",side_effect=chunks):
            self.assertEqual(len(wire._read_go(12345,100.0)),32*1024)
        with patch.object(wire.time,"monotonic",return_value=100.1), patch.object(wire.os,"read",side_effect=[b"x"*4096]*8+[b"x"]):
            with self.assertRaises(wire.ProtocolError): wire._read_go(12345,100.0)
        with patch.object(wire.time,"monotonic",return_value=160.0), patch.object(wire.os,"read") as unused:
            with self.assertRaises(wire.ProtocolError): wire._read_go(12345,100.0)
            unused.assert_not_called()
