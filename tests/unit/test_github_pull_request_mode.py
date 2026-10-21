"""Actual PR core/journal and private dialogue with inert HTTP, never a provider.

One bounded disk case uses only the supplied nonroot private TMPDIR; it preserves
failed fixtures. Other cases use the existing journal's inert byte-map storage.
"""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest

from mobile_release import github_pull_request as p
from mobile_release import _desktop_github_pull_request as wire
from mobile_release import _github_pull_request_transport as transport
from mobile_release._github_pull_request_journal import Journal
from mobile_release._github_connection_transport import ReadFailure
from mobile_release.github_preflight import HttpRequest
from unit import test_github_pull_request as old
from unit import test_github_pull_request_management as management


def draft(ready=True):
    return p.Draft.parse({**old.draft().value(), **({"creationMode": "ready-for-review"} if ready else {})})


def target(ready=True, marker="b" * 32):
    value = old.target().value()
    value["intent"]["marker"] = marker
    if ready:
        value["intent"]["creationMode"] = "ready-for-review"
    return p.Target.parse(value)


def exchange(ready=True, change=None, marker="b" * 32):
    def reply(request, n, status, body):
        if type(body) is dict and body.get("id") == 44:
            body["draft"] = not ready
            body["body"] = draft(ready).post_body(target(ready, marker))["body"]
        return change(request, n, status, body) if change else (status, body)
    return old.Exchange(reply)


def prepared(ready=True, marker="b" * 32):
    return p.prepare(target(ready, marker), draft(ready), exchange(ready, marker=marker))[0]


class PullRequestModeTests(unittest.TestCase):
    def test_both_modes_use_same_nine_get_review_and_single_twelve_request_create(self):
        for ready in (False, True):
            with self.subTest(ready=ready):
                d, t = draft(ready), target(ready)
                peer = exchange(ready); review, _ = p.prepare(t, d, peer)
                self.assertEqual(len(peer.calls), 9)
                self.assertTrue(all(r.method == "GET" for r in peer.calls))
                self.assertIs(review.value()["draft"], not ready)
                if ready:
                    self.assertIn("Reviewers may be notified", review.value()["confirmation"])
                journal = old.MemoryJournal()
                def entered(req, n, status, body):
                    if req.method == "POST":
                        self.assertTrue(journal.creations["b" * 32]["data"]["claimed"])
                        self.assertEqual(req.body, p.canonical(d.post_body(t)))
                        transport.request_role(t, d, req)
                    return status, body
                peer = exchange(ready, entered)
                result = p.create(review, d, peer, journal)
                self.assertEqual(result["effect"], "created-observed")
                self.assertEqual(len(peer.calls), 12)
                self.assertEqual(sum(r.method == "POST" for r in peer.calls), 1)
                p.creation_result(result, review, "create")

    def test_legacy_draft_canonical_objects_and_all_four_original_leaves_are_unchanged(self):
        d, t, review = draft(False), target(False), prepared(False)
        self.assertEqual(d.value(), {"base": "main", "head": "feature/login", "title": "Review login screen", "body": "What changed\nUser-approved description"})
        self.assertEqual(set(t.intent), {"base", "head", "marker", "titleSha256", "bodySha256"})
        self.assertEqual(review.value()["confirmation"], "Create a draft pull request in owner/app from feature/login into main with the text you reviewed? Existing GitHub workflows may run. No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.")
        self.assertEqual(review.value(), old.prepared().value())
        journal = old.MemoryJournal()
        result = p.create(review, d, exchange(False), journal)
        self.assertEqual(result["effect"], "created-observed")
        raw = p.canonical({"protocol": "mrk-github-pull-request/1", "prepared": review.value()}) + b"\n"
        intent_sha = hashlib.sha256(raw).hexdigest()
        receipt = p.canonical({"intentSha256": intent_sha, "pullRequest": result["acknowledged"]}) + b"\n"
        self.assertEqual(journal.files["b" * 32 + ".intent.json"], raw)
        self.assertEqual(journal.files["b" * 32 + ".claim.json"], p.canonical({"intentSha256": intent_sha, "phase": "create"}) + b"\n")
        self.assertEqual(journal.files["b" * 32 + ".receipt.json"], receipt)
        loaded = old.MemoryJournal(journal.files); loaded._load()
        p.reconcile(loaded.pending(t)[0], management.closed_exchange(), journal=loaded)
        expected = p.canonical({"protocol": p.PROTOCOL, "intentSha256": intent_sha,
            "receiptSha256": hashlib.sha256(receipt).hexdigest(), "closed": {
                "id": "44", "number": "3", "closedAt": "2026-10-20T12:00:00Z", "merged": True}}) + b"\n"
        self.assertEqual(loaded.files["b" * 32 + ".closed.json"], expected)
        before = dict(loaded.files)
        reloaded = old.MemoryJournal(loaded.files); reloaded._load(); reloaded.pending(t)
        self.assertEqual(reloaded.files, before)
        self.assertNotEqual(p.digest(review), p.digest(prepared(True)))

    def test_ready_literal_is_required_on_both_input_and_intent_not_false_alone(self):
        for value in (None, False, True, "draft", "ready", "", {}, []):
            for kind in ("draft", "intent"):
                with self.subTest(value=value, kind=kind), self.assertRaises(ValueError):
                    if kind == "draft": p.Draft.parse({**old.draft().value(), "creationMode": value})
                    else:
                        t = old.target().value(); t["intent"]["creationMode"] = value; p.Target.parse(t)
        for ready in (False, True):
            value = prepared(ready).value(); value["draft"] = ready
            with self.assertRaises(ValueError): p.Prepared.parse(value)
            for bad in (0, 1, None):
                value["draft"] = bad
                with self.assertRaises(ValueError): p.Prepared.parse(value)
        value = prepared(True).value(); del value["target"]["intent"]["creationMode"]
        with self.assertRaises(ValueError): p.Prepared.parse(value)

    def test_cross_mode_private_draft_refuses_before_http_journal_claim_and_body_send(self):
        for ready in (False, True):
            peer = exchange(ready); journal = old.MemoryJournal()
            with self.assertRaises(ValueError): p.create(prepared(ready), draft(not ready), peer, journal)
            self.assertEqual(peer.calls, []); self.assertEqual(journal.files, {})
            request = HttpRequest("POST", "/repos/owner/app/pulls", p.canonical(draft(not ready).post_body(target(not ready))))
            with self.assertRaises(ValueError): transport.request_role(target(ready), draft(ready), request)

    def test_mode_blind_prior_pair_fence_survives_reload_account_alias_and_new_marker(self):
        for first_ready in (False, True):
            journal = old.MemoryJournal(); journal.create_intent(prepared(first_ready).value()); journal.claim()
            original = dict(journal.files)
            loaded = old.MemoryJournal(journal.files); loaded._load()
            next_one = prepared(not first_ready, "e" * 32)
            result = p.create(next_one, draft(not first_ready), exchange(not first_ready), loaded)
            self.assertEqual((result["effect"], result["reason"]), ("not-sent", "previous-attempt"))
            self.assertEqual(loaded.files, original)
            value = next_one.value(); value["target"]["scope"]["accountId"] = "99"
            with self.assertRaises(p.Refused): loaded.create_intent(value)
            with self.assertRaises(p.Refused): loaded.claim()

    def test_existing_open_pr_of_either_mode_and_changed_sha_refuse_before_claim(self):
        for ready in (False, True):
            for other_ready in (False, True):
                def occupied(req, n, status, body):
                    if "/pulls?" in req.path:
                        row = old.pull(); row["draft"] = not other_ready; body = [row]
                    return status, body
                journal = old.MemoryJournal(); peer = exchange(ready, occupied)
                r = p.create(prepared(ready), draft(ready), peer, journal)
                self.assertEqual(r["reason"], "pull-request-exists"); self.assertEqual(journal.files, {})
                self.assertFalse(any(x.method == "POST" for x in peer.calls))
            def moved(req, n, status, body):
                if n == 8: body["object"]["sha"] = "e" * 40
                return status, body
            journal = old.MemoryJournal(); peer = exchange(ready, moved)
            self.assertEqual(p.create(prepared(ready), draft(ready), peer, journal)["reason"], "branches-changed")
            self.assertEqual(journal.files, {})

    def test_actual_201_ack_and_spent_claim_survive_wrong_missing_or_nonboolean_mode(self):
        for ready in (False, True):
            for wrong in (ready, None, "false", 0, 1):
                def returned(req, n, status, body):
                    if req.method == "POST":
                        if wrong is None: body.pop("draft")
                        else: body["draft"] = wrong
                    return status, body
                journal = old.MemoryJournal(); peer = exchange(ready, returned)
                r = p.create(prepared(ready), draft(ready), peer, journal)
                self.assertEqual(r["effect"], "acknowledged-unconfirmed")
                self.assertEqual(r["acknowledged"]["id"], "44")
                self.assertIn("b" * 32 + ".receipt.json", journal.files)
                self.assertEqual(len(peer.calls), 10); self.assertTrue(r["claimed"])
                loaded = old.MemoryJournal(journal.files); loaded._load()
                with self.assertRaises(p.Refused): loaded.claim()

    def test_wrong_get_mode_remains_unresolved_without_erasing_ack_or_rearming_post(self):
        def converted(req, n, status, body):
            if req.path.endswith("/pulls/3"): body["draft"] = True
            return status, body
        journal = old.MemoryJournal()
        r = p.create(prepared(), draft(), exchange(True, converted), journal)
        self.assertEqual(r["effect"], "acknowledged-unconfirmed")
        original = dict(journal.files)
        loaded = old.MemoryJournal(journal.files); loaded._load(); peer = exchange(True, converted)
        r = p.reconcile(loaded.pending(target())[0], peer, journal=loaded)
        self.assertEqual(r["effect"], "unresolved"); self.assertEqual(r["acknowledged"]["id"], "44")
        self.assertTrue(all(x.method == "GET" for x in peer.calls)); self.assertEqual(loaded.files, original)
        with self.assertRaises(p.Refused): loaded.create_intent(prepared(False, "e" * 32).value())

    def test_receipt_write_loss_preserves_ack_and_lost_post_readback_is_only_unattributed(self):
        class FailedReceipt(old.MemoryJournal):
            def record(self, value): raise OSError("inert owned receipt failure")
        journal = FailedReceipt()
        r = p.create(prepared(), draft(), exchange(), journal)
        self.assertEqual(r["effect"], "acknowledged-unconfirmed"); self.assertEqual(r["acknowledged"]["id"], "44")
        self.assertEqual(r["reason"], "journal-unavailable")
        def lost(req, n, status, body):
            if req.method == "POST": raise ReadFailure("network-unavailable")
            return status, body
        journal = old.MemoryJournal(); r = p.create(prepared(), draft(), exchange(True, lost), journal)
        self.assertEqual(r["effect"], "potentially-applied")
        loaded = old.MemoryJournal(journal.files); loaded._load()
        def found(req, n, status, body):
            if "/pulls?" in req.path:
                row = old.pull(); row["draft"] = False; body = [row]
            return status, body
        peer = exchange(True, found); r = p.reconcile(loaded.pending(target())[0], peer)
        self.assertEqual(r["effect"], "found-unattributed"); self.assertIsNone(r["acknowledged"])
        self.assertTrue(all(x.method == "GET" for x in peer.calls))
        with self.assertRaises(p.Refused): loaded.claim()

    def test_closed_old_draft_does_not_replay_and_new_ready_still_needs_fresh_checks(self):
        journal = management.acknowledged()
        p.reconcile(journal.pending(target(False))[0], management.closed_exchange(), journal=journal)
        before = dict(journal.files)
        next_one = prepared(True, "e" * 32)
        def new_pr(req, n, status, body):
            if type(body) is dict and body.get("id") == 44:
                body["id"], body["number"] = 45, 4
            return status, body
        r = p.create(next_one, draft(True), exchange(True, new_pr, marker="e" * 32), journal)
        self.assertEqual(r["effect"], "created-observed")
        self.assertTrue(all(journal.files[n] == raw for n, raw in before.items()))
        loaded = old.MemoryJournal(journal.files); loaded._load()
        with self.assertRaises(p.Refused): loaded.claim()
        with self.assertRaises(p.Refused): loaded.create_intent(prepared(False, "f" * 32).value())

    def test_real_private_go_binds_ready_mode_and_digest_without_public_text(self):
        review = prepared()
        raw = p.canonical({"protocol": p.PROTOCOL, "id": "inert", "action": {"kind": "create", "target": target().value(),
            "home": "/inert-task-home", "preparedSha256": p.digest(review)}}) + b"\n"
        initial = wire.parse_initial(raw)
        go = {"protocol": p.PROTOCOL, "id": "inert", "go": {"requestSha256": initial.digest, "token": "not-a-live-token",
              "prepared": review.value(), "draft": draft().value()}}
        self.assertEqual(wire.parse_go(p.canonical(go) + b"\n", initial)[2].value(), draft().value())
        for container in ("draft", "prepared"):
            bad = copy.deepcopy(go)
            if container == "draft": del bad["go"]["draft"]["creationMode"]
            else: bad["go"]["prepared"]["draft"] = True
            with self.assertRaises(ValueError): wire.parse_go(p.canonical(bad) + b"\n", initial)
        duplicate = p.canonical(go).replace(b'"creationMode":"ready-for-review"', b'"creationMode":"ready-for-review","creationMode":"ready-for-review"', 1)
        with self.assertRaises(ValueError): wire.parse_go(duplicate + b"\n", initial)
        self.assertNotIn(draft().title.encode(), raw); self.assertNotIn(b"not-a-live-token", wire.ready_frame(initial))

    def test_actual_exclusive_journal_cold_reopen_preserves_ready_bytes_and_cross_mode_fence(self):
        if os.geteuid() == 0:
            self.skipTest("Physical journal requires the reviewed nonroot private-TMPDIR recipe")
        tmp = os.environ.get("TMPDIR")
        self.assertTrue(tmp and Path(tmp).is_absolute())
        info = os.stat(tmp, follow_symlinks=False)
        self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode)), (os.geteuid(), 0o700))
        home = tempfile.mkdtemp(prefix="pr-mode-journal-", dir=tmp)
        # No automatic finally deletion: a failed assertion/close preserves this
        # tiny known fixture for inspection. No host home or Git repository used.
        journal = Journal(home, end=time.monotonic() + 60)
        try:
            journal.open()
            result = p.create(prepared(), draft(), exchange(), journal)
            self.assertEqual(result["effect"], "created-observed")
        finally:
            journal.close()
        leaf = Path(home).joinpath(*journal.suffix)
        before = {p.name: p.read_bytes() for p in leaf.iterdir()}
        self.assertEqual(len(before), 3)
        cold = Journal(home, end=time.monotonic() + 60)
        try:
            cold.open(); rows = cold.pending(target())
            self.assertEqual(len(rows), 1); self.assertIs(rows[0]["prepared"]["draft"], False)
            with self.assertRaises(p.Refused): cold.claim()
            with self.assertRaises(p.Refused): cold.create_intent(prepared(False, "e" * 32).value())
        finally:
            cold.close()
        self.assertEqual({p.name: p.read_bytes() for p in leaf.iterdir()}, before)
        shutil.rmtree(home)
