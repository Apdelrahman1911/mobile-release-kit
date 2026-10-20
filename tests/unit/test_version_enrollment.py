"""Finite fake HTTP reads only: no GitHub/Store/files/processes or native proof."""
from __future__ import annotations

import base64
import copy
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release import desktop_version_enrollment as wire
from mobile_release import version_enrollment as e
from mobile_release import version_allocation as a
from mobile_release import version_policy as p
from mobile_release._github_connection_transport import ReadResult, _control
from test_version_allocation import initial, request, observations, reply, NOW, COMMIT

TARGET = e.Target("a" * 64, "fixture/version-test", "456", "123")


class Remote:
    """Serial original-read fixture; all response/control values are DATA."""
    def __init__(self, ledger=None, previous=None):
        self.ledger = ledger or initial()[0]
        self.previous = previous
        self.calls = []
        self.override = {}
        self.head = COMMIT
        self.reader = e._Reader(TARGET, previous, self.send)

    def send(self, role, http):
        index = len(self.calls)
        self.calls.append((role, http))
        self.assert_request(http)
        if index in self.override:
            value = self.override[index]
            return value() if callable(value) else value
        if role == e.ROLE_ACCOUNT:
            return reply({"id": 456, "login": "fixture-user"})
        if role == e.ROLE_REPOSITORY:
            return reply({"id": 123, "full_name": TARGET.repository, "archived": False,
                          "visibility": "private", "default_branch": "main"})
        if role == e.ROLE_PROTECTION:
            return reply({"enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
                          "allow_deletions": {"enabled": False}})
        if role == e.ROLE_REF:
            return reply({"ref": "refs/heads/" + a.LEDGER_BRANCH,
                          "object": {"type": "commit", "sha": self.head}})
        if role == e.ROLE_LEDGER:
            raw = self.ledger.to_bytes()
            return reply({"type": "file", "path": a.LEDGER_PATH, "encoding": "base64", "size": len(raw),
                          "sha": a.blob_sha(raw), "content": base64.b64encode(raw).decode() + "\n"})
        assert role == e.ROLE_COMPARE and self.previous is not None
        return reply({"status": "identical" if self.previous.commit == self.head else "ahead",
                      "base_commit": {"sha": self.previous.commit}, "merge_base_commit": {"sha": self.previous.commit}})

    @staticmethod
    def assert_request(http):
        assert http.method == "GET" and http.body is None

    def run(self, **kwargs):
        return e.execute(TARGET, self.reader, previous=self.previous, **kwargs)


def initial_frame(*, review=None, previous=None):
    return p.canonical({"protocol": e.PROTOCOL, "id": "fixture-read-1", "action": {
        "kind": "review" if review is None else "confirm", "target": TARGET.value(),
        "review": None if review is None else review.value(),
        "previous": None if previous is None else previous.value()}}) + b"\n"


class EnrollmentTests(unittest.TestCase):
    def test_current_canonical_genesis_and_full_chain_are_reviewed_without_sha_input(self):
        ledger = initial()[0].append(request(), observations(), now=NOW)
        remote = Remote(ledger)
        result = remote.run()
        self.assertEqual(result["reason"], "none")
        offer = e.Offer.parse(result["offer"])
        self.assertEqual(offer.checkpoint, a.Checkpoint(1, ledger.head_sha256, COMMIT))
        self.assertEqual(offer.version, ledger.last_version)
        self.assertEqual(offer.authority.genesis_sha256, ledger.genesis.sha256)
        self.assertEqual(len(remote.calls), 8)
        self.assertTrue(all(r.method == "GET" and r.body is None for _, r in remote.calls))
        self.assertNotIn("floor", json.dumps(result).lower())
        with self.assertRaises(e.Refused):
            remote.reader.read("account")

    def test_missing_ledger_or_inaccessible_protection_never_becomes_new_counter(self):
        for index, reason in ((2, "protection-unavailable"), (4, "counter-missing")):
            remote = Remote()
            remote.override[index] = reply(status=404, control=_control("not-found-or-inaccessible"))
            result = remote.run()
            self.assertEqual(result["reason"], reason)
            self.assertIsNone(result["offer"])
            self.assertEqual(len(remote.calls), index + 1)
            self.assertEqual(result["control"]["reason"], "not-found-or-inaccessible")

    def test_minimum_classic_protection_is_required_before_and_after(self):
        good = {"enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False}}
        for index in (2, 6):
            for key in good:
                bad = copy.deepcopy(good)
                bad[key]["enabled"] = not bad[key]["enabled"]
                remote = Remote()
                remote.override[index] = reply(bad)
                result = remote.run()
                self.assertEqual(result["reason"], "protection-unsupported")
                self.assertIsNone(result["offer"])
        remote = Remote()
        remote.override[2] = reply({"rulesets": [{"enforcement": "active"}]})
        self.assertEqual(remote.run()["reason"], "protection-unsupported")

    def test_account_repository_and_final_ref_must_match_original_native_pins(self):
        mutations = {0: {"id": 789, "login": "other"},
                     1: {"id": 789, "full_name": TARGET.repository, "archived": False,
                         "visibility": "private", "default_branch": "main"},
                     5: {"ref": "refs/heads/" + a.LEDGER_BRANCH, "object": {"type": "commit", "sha": "2" * 40}},
                     7: {"id": 123, "full_name": "other/repository", "archived": False,
                         "visibility": "private", "default_branch": "main"}}
        for index, body in mutations.items():
            remote = Remote()
            remote.override[index] = reply(body)
            result = remote.run()
            self.assertIsNone(result["offer"])
            self.assertIn(result["reason"], {"target-changed", "authority-changed"})
            self.assertEqual(len(remote.calls), index + 1)

    def test_full_ledger_canonical_bytes_blob_and_chain_are_not_snapshot_assertions(self):
        remote = Remote()
        original = remote.send(e.ROLE_LEDGER, type("Q", (), {"method": "GET", "body": None})()).observation["body"]
        for change in (lambda b: b.update(sha="b" * 40), lambda b: b.update(size=b["size"] + 1),
                       lambda b: b.update(content=base64.b64encode(b'{}\n').decode(), size=3, sha=a.blob_sha(b'{}\n')),
                       lambda b: b.update(type="symlink")):
            body = copy.deepcopy(original)
            change(body)
            remote = Remote()
            remote.override[4] = reply(body)
            self.assertEqual(remote.run()["reason"], "ledger-invalid")

    def test_confirm_rechecks_exact_offer_and_existing_checkpoint_ancestry(self):
        ledger = initial()[0].append(request(), observations(), now=NOW)
        offer = e.Offer.parse(Remote(ledger).run()["offer"])
        previous = a.Checkpoint(0, ledger.genesis.sha256, "2" * 40)
        remote = Remote(ledger, previous)
        self.assertEqual(remote.run(review=offer)["offer"], offer.value())
        self.assertEqual(len(remote.calls), 9)
        self.assertEqual(remote.calls[5][1].path,
                         "/repos/fixture/version-test/compare/" + previous.commit + "..." + COMMIT + "?per_page=1&page=1")
        remote = Remote(ledger, previous)
        remote.override[5] = reply({"status": "ahead", "base_commit": {"sha": previous.commit},
                                    "merge_base_commit": {"sha": COMMIT}})
        self.assertEqual(remote.run(review=offer)["reason"], "authority-rewound")
        remote = Remote(ledger, replace(previous, head_sha256="f" * 64))
        self.assertEqual(remote.run(review=offer)["reason"], "authority-rewound")
        self.assertEqual(len(remote.calls), 5)  # No compare when retained prefix already conflicts.

    def test_confirm_cannot_refresh_changed_review_or_reset_to_current_head(self):
        offer = e.Offer.parse(Remote().run()["offer"])
        remote = Remote()
        remote.head = "2" * 40
        self.assertEqual(remote.run(review=offer)["reason"], "review-changed")
        self.assertEqual(len(remote.calls), 4)
        changed = replace(offer, blob="b" * 40)
        self.assertEqual(Remote().run(review=changed)["reason"], "review-changed")

    def test_read_control_refusal_survives_even_success_shaped_body(self):
        for control in (_control("cancelled"), _control("expired"), _control("rate-limited", 60)):
            remote = Remote()
            remote.override[7] = reply({"id": 123, "full_name": TARGET.repository, "archived": False,
                                       "visibility": "private", "default_branch": "main"}, control=control)
            result = remote.run()
            self.assertIsNone(result["offer"])
            self.assertEqual(result["control"], control)
            self.assertEqual(result["reason"], control["reason"])

    def test_finite_schedule_consumes_unknown_exchange_and_forbids_arbitrary_endpoints(self):
        def interrupted():
            raise KeyboardInterrupt
        remote = Remote()
        remote.override[0] = interrupted
        with self.assertRaises(KeyboardInterrupt):
            remote.run()
        with self.assertRaises(e.Refused):
            remote.reader.read("account")
        for role, method, path in ((e.ROLE_REF, "PUT", "/repos/fixture/version-test/git/ref/heads/" + a.LEDGER_BRANCH),
                                   (e.ROLE_LEDGER, "GET", "/repos/fixture/version-test/contents/other?ref=" + COMMIT),
                                   (e.ROLE_ACCOUNT, "GET", "/users/fixture"),
                                   ("standard", "GET", "/user")):
            with self.assertRaises(e.Refused):
                e.validate_endpoint(role, method, path)


class EnrollmentWireTests(unittest.TestCase):
    def test_initial_go_result_exact_binding_and_no_token_in_output(self):
        request = wire.parse_initial(initial_frame())
        self.assertEqual(json.loads(wire.ready_frame(request))["ready"]["requestSha256"], request.digest)
        go = {"protocol": e.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest, "token": "fixture-token"}}
        self.assertEqual(wire.parse_go(p.canonical(go) + b"\n", request), "fixture-token")
        go["go"]["requestSha256"] = "f" * 64
        with self.assertRaises(e.Refused):
            wire.parse_go(p.canonical(go) + b"\n", request)
        result = Remote().run()
        raw = wire.encode_result(request, result)
        self.assertLess(len(raw), wire.RESULT_LIMIT)
        self.assertNotIn(b"fixture-token", raw)
        result["control"] = _control("cancelled")
        with self.assertRaises(e.Refused):
            wire.encode_result(request, result)

    def test_previous_checkpoint_requires_exact_confirm_review(self):
        offer = e.Offer.parse(Remote().run()["offer"])
        parsed = wire.parse_initial(initial_frame(review=offer, previous=offer.checkpoint))
        self.assertEqual(parsed.previous, offer.checkpoint)
        value = json.loads(initial_frame())
        value["action"]["previous"] = offer.checkpoint.value()
        with self.assertRaises(e.Refused):
            wire.parse_initial(p.canonical(value) + b"\n")

    def test_worker_borrows_existing_ready_go_helpers_never_closes_or_opens_local_state(self):
        raw = initial_frame()
        request = wire.parse_initial(raw)
        go = p.canonical({"protocol": e.PROTOCOL, "id": request.id,
                          "go": {"requestSha256": request.digest, "token": "fixture-token"}}) + b"\n"
        writes, reads = [], []
        remote = Remote()
        with patch.object(wire.time, "monotonic", return_value=100.0), \
             patch.object(wire, "_write_response", side_effect=lambda fd, data: writes.append((fd, data))), \
             patch.object(wire, "_read_request", side_effect=lambda fd, end: reads.append((fd, end)) or go), \
             patch.object(e, "make_reader", return_value=remote.reader):
            wire.run_owned(20, 21, raw, started=99.0, runtime_dir="/fixture/runtime")
        self.assertEqual(reads, [(20, 159.0)])
        self.assertEqual([fd for fd, _ in writes], [21, 21])
        self.assertIn("ready", json.loads(writes[0][1]))
        self.assertEqual(json.loads(writes[1][1])["result"]["reason"], "none")

    def test_malformed_input_or_elapsed_original_clock_never_reaches_http(self):
        raw = initial_frame()
        for now in (98.0, 159.0, float("nan")):
            with patch.object(wire.time, "monotonic", return_value=now), patch.object(e, "make_reader") as make:
                with self.assertRaises(wire.ProtocolError):
                    wire.run_owned(20, 21, raw, started=99.0, runtime_dir="/fixture/runtime")
                make.assert_not_called()


if __name__ == "__main__":
    unittest.main()
