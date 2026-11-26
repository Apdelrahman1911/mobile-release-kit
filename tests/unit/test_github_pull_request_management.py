"""Inert HTTP and the real journal over a byte map; no files/network/processes."""
import copy
import hashlib
import unittest

from mobile_release import github_pull_request as p
from mobile_release import github_pull_request_management as management
from mobile_release import _desktop_github_pull_request as wire
from mobile_release._github_connection_transport import ReadFailure
from unit import test_github_pull_request as fixture


def acknowledged():
    journal = fixture.MemoryJournal()
    result = p.create(fixture.prepared(), fixture.draft(), fixture.Exchange(), journal)
    assert result["effect"] == "created-observed"
    loaded = fixture.MemoryJournal(journal.files)
    loaded._load()
    return loaded


def closed_reply():
    value = fixture.pull()
    # A legitimately merged/converted/edited PR is no longer the old draft.
    value.update(state="closed", draft=False, title="Edited on GitHub", body="Edited description",
                 merged=True, closed_at="2026-10-20T12:00:00Z")
    value["head"]["sha"] = "f" * 40
    return value


def closed_exchange(change=None):
    def reply(request, n, status, value):
        if request.path.endswith("/pulls/3"):
            value = closed_reply()
        return change(request, n, status, value) if change else (status, value)
    return fixture.Exchange(reply)


def next_prepared():
    value = copy.deepcopy(fixture.prepared().value())
    value["target"]["intent"]["marker"] = "e" * 32
    return p.Prepared.parse(value)


class PullRequestManagementTests(unittest.TestCase):
    def test_exact_acknowledged_closed_pr_is_historical_four_gets_and_immutable(self):
        journal = acknowledged()
        old = dict(journal.files)
        exchange = closed_exchange()
        result = p.reconcile(journal.pending(fixture.target())[0], exchange, journal=journal)
        self.assertEqual(result["effect"], "closed-confirmed")
        p.creation_result(result, fixture.prepared(), "reconcile")
        self.assertEqual(len(exchange.calls), 4)
        self.assertTrue(all(c.method == "GET" and c.body is None for c in exchange.calls))
        self.assertTrue(all(journal.files[name] == raw for name, raw in old.items()))
        leaf = journal.files["b" * 32 + ".closed.json"]
        self.assertNotIn(b"Edited description", leaf)
        loaded = fixture.MemoryJournal(journal.files); loaded._load()
        row = loaded.pending(fixture.target())[0]
        self.assertTrue(row["closed"]["merged"])
        self.assertEqual(row["closed"]["number"], "3")
        with self.assertRaises(p.Refused): loaded.claim()
        # Another closure is not a replacement/repair of the old sidecar.
        new = {**row["closed"], "closedAt": "2026-10-21T12:00:00Z"}
        loaded.record_closed(fixture.prepared().value(), new)
        self.assertEqual(loaded.files["b" * 32 + ".closed.json"], leaf)

    def test_closed_then_reopened_at_next_prepare_never_posts(self):
        journal = acknowledged()
        p.reconcile(journal.pending(fixture.target())[0], closed_exchange(), journal=journal)
        next_one = next_prepared()
        def reopened(req, n, status, body):
            return (status, [fixture.pull()]) if "/pulls?" in req.path else (status, body)
        exchange = fixture.Exchange(reopened)
        result = p.create(next_one, fixture.draft(), exchange, journal)
        self.assertEqual(result["reason"], "pull-request-exists")
        self.assertEqual(result["effect"], "not-sent")
        self.assertFalse(any(c.method == "POST" for c in exchange.calls))
        self.assertNotIn("e" * 32 + ".intent.json", journal.files)
        # After a new explicit review, the distinct original can send ONCE.
        def new_pull(req, n, status, body):
            if req.path.endswith("/pulls") or req.path.endswith("/pulls/4"):
                body = fixture.pull(); body["id"] = 45; body["number"] = 4
                body["body"] = fixture.draft().post_body(next_one.target)["body"]
            return status, body
        exchange = fixture.Exchange(new_pull)
        result = p.create(next_one, fixture.draft(), exchange, journal)
        self.assertEqual(result["effect"], "created-observed")
        self.assertEqual(len(exchange.calls), 12)
        self.assertEqual(sum(c.method == "POST" for c in exchange.calls), 1)
        loaded = fixture.MemoryJournal(journal.files); loaded._load()
        with self.assertRaises(p.Refused): loaded.claim()
        # The new unclosed original now fences this pair in turn.
        v = next_one.value(); v["target"]["intent"]["marker"] = "f" * 32
        with self.assertRaises(p.Refused): loaded.create_intent(v)

    def test_uncertain_unsent_or_marker_only_record_can_never_be_closed_or_unfenced(self):
        for claimed in (False, True):
            journal = fixture.MemoryJournal(); journal.create_intent(fixture.prepared().value())
            if claimed: journal.claim()
            loaded = fixture.MemoryJournal(journal.files); loaded._load()
            row = loaded.pending(fixture.target())[0]
            with self.assertRaises(p.Refused):
                loaded.record_closed(row["prepared"], {"id": "44", "number": "3", "closedAt": "2026-10-20T12:00:00Z", "merged": True})
            result = p.reconcile(row, closed_exchange(), journal=loaded)
            self.assertEqual(result["effect"], "unresolved")
            with self.assertRaises(p.Refused): loaded.create_intent(next_prepared().value())
            self.assertFalse(any(n.endswith(".closed.json") for n in loaded.files))
        # Even an attributed closed row cannot hide a second unknown same-pair
        # record. Build the inert inventory directly to exercise the ALL rule.
        good = acknowledged(); p.reconcile(good.pending(fixture.target())[0], closed_exchange(), journal=good)
        other = fixture.MemoryJournal(); other.create_intent(next_prepared().value())
        good.files.update(other.files); loaded = fixture.MemoryJournal(good.files); loaded._load()
        v = fixture.prepared().value(); v["target"]["intent"]["marker"] = "f" * 32
        with self.assertRaises(p.Refused): loaded.create_intent(v)

    def test_exact_id_repo_ref_and_closed_shape_are_required_not_old_text_or_shas(self):
        for field in ("id", "number", "repository", "base", "head", "closedAt", "merged", "open", "missing"):
            with self.subTest(field=field):
                journal = acknowledged()
                def change(req, n, status, body):
                    if req.path.endswith("/pulls/3"):
                        if field == "id": body["id"] = 99
                        elif field == "number": body["number"] = 4
                        elif field == "repository": body["head"]["repo"]["id"] = 99
                        elif field in ("base", "head"): body[field]["ref"] = "other"
                        elif field == "closedAt": body["closed_at"] = None
                        elif field == "merged": body["merged"] = 1
                        elif field == "open": body["state"] = "open"
                        else: status, body = 404, None
                    return status, body
                result = p.reconcile(journal.pending(fixture.target())[0], closed_exchange(change), journal=journal)
                self.assertEqual(result["effect"], "unresolved")
                self.assertFalse(any(n.endswith(".closed.json") for n in journal.files))
                with self.assertRaises(p.Refused): journal.create_intent(next_prepared().value())

    def test_local_record_failure_final_repository_drift_and_lost_get_keep_fence(self):
        for problem in ("write", "repository", "lost"):
            journal = acknowledged()
            if problem == "write":
                def fail(*_): raise OSError("INERT PRIVATE path")
                journal._create = fail
            def change(req, n, status, body):
                if problem == "lost" and n == 3: raise ReadFailure("network-unavailable")
                if problem == "repository" and n == 4: body["id"] = 99
                return status, body
            result = p.reconcile(journal.pending(fixture.target())[0], closed_exchange(change), journal=journal)
            self.assertEqual(result["effect"], "unresolved")
            self.assertEqual(result["acknowledged"]["id"], "44")
            self.assertNotIn("INERT PRIVATE", str(result))
            with self.assertRaises(p.Refused): journal.create_intent(next_prepared().value())

    def test_complete_sidecar_requires_actual_intent_receipt_digest_and_no_orphans(self):
        good = acknowledged(); p.reconcile(good.pending(fixture.target())[0], closed_exchange(), journal=good)
        name = "b" * 32 + ".closed.json"
        row = good.decode(good.files[name], 1024)
        self.assertEqual(row["receiptSha256"], hashlib.sha256(good.files["b" * 32 + ".receipt.json"]).hexdigest())
        for field in ("receiptSha256", "intentSha256", "id", "extra", "orphan", "receipt-missing", "null"):
            files = dict(good.files); bad = copy.deepcopy(row)
            if field in ("receiptSha256", "intentSha256"): bad[field] = "0" * 64
            elif field == "id": bad["closed"]["id"] = "99"
            elif field == "extra": bad["resumeWrite"] = True
            elif field == "null": bad["closed"] = None
            elif field == "orphan": files["e" * 32 + ".closed.json"] = files[name]
            else: files.pop("b" * 32 + ".receipt.json")
            files[name] = p.canonical(bad) + b"\n"
            with self.assertRaises(ValueError): fixture.MemoryJournal(files)._load()
        self.assertEqual(good._max_entries, 32 * 4)
        self.assertEqual(good._max_total_bytes, 32 * (p.MAX_RECORD_BYTES + 3 * 1024))

    def test_optional_closed_pending_schema_never_grants_resume_or_cross_scope(self):
        journal = acknowledged(); p.reconcile(journal.pending(fixture.target())[0], closed_exchange(), journal=journal)
        row = journal.pending(fixture.target())[0]
        self.assertEqual(p.pending_record(row), row)
        for change in ({"closed": None}, {"acknowledged": None}, {"claimed": False}, {"resumeWrite": True}):
            with self.assertRaises(ValueError): p.pending_record({**row, **change})
        target = fixture.target(intent=None)
        initial = wire.parse_initial(p.canonical({"protocol": p.PROTOCOL, "id": "inert", "action": {
            "kind": "pending", "target": target.value(), "home": "/inert-task-home", "preparedSha256": None}}) + b"\n")
        value = {"schemaVersion": 1, "kind": "pending", "reason": "none", "prepared": None, "creation": None,
                 "pending": [row], "control": fixture._control()}
        self.assertIn(b'"closed"', wire.encode_result(initial, value))
        value["pending"][0]["prepared"]["target"]["scope"]["accountId"] = "99"
        with self.assertRaises(ValueError): wire.encode_result(initial, value)

    def test_closure_without_original_journal_or_for_creation_is_not_success(self):
        journal = acknowledged(); row = journal.pending(fixture.target())[0]
        result = p.reconcile(row, closed_exchange())
        self.assertEqual(result["reason"], "journal-unavailable")
        self.assertEqual(result["effect"], "unresolved")
        result = p.reconcile(row, closed_exchange(), journal=journal)
        with self.assertRaises(ValueError): p.creation_result(result, fixture.prepared(), "create")
        with self.assertRaises(ValueError): management.closed_observation({**row.get("closed", {}), "id": "44"}, row["acknowledged"])
