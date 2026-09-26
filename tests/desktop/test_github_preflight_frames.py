"""Inert journal-record/two-frame contracts, not filesystem or native evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest

from mobile_release import _desktop_github_preflight_engine as engine
from mobile_release import _github_preflight_journal as journal
from mobile_release import github_preflight as policy
from test_github_preflight import PRIVATE, RUN, execute, prepared, target


def initial(kind: str = "dispatch") -> dict:
    action = policy.Action(kind, target(), None if kind == "prepare" else prepared(),
                           str(RUN) if kind == "track" else None)
    return {"protocol": policy.PROTOCOL, "id": "github-preflight-1", "action": action.value(),
            "pendingScope": None, "home": None if kind == "prepare" else "/home/mrk"}


def frame(value: object) -> bytes:
    return journal.canonical(value) + b"\n"


class GitHubPreflightFrameTests(unittest.TestCase):
    def test_intent_and_run_are_exact_canonical_noncredential_records(self):
        raw = journal.intent_bytes(prepared())
        self.assertEqual(journal.parse_intent(raw), prepared())
        self.assertNotIn(PRIVATE.encode(), raw)
        digest = hashlib.sha256(raw).hexdigest()
        run = journal.run_bytes(digest, str(RUN))
        self.assertEqual(journal.parse_run(run, digest), str(RUN))
        for invalid in (raw[:-1], raw + b"\n", b" " + raw, raw.replace(b'"schemaVersion":1', b'"schemaVersion":true')):
            with self.assertRaises(ValueError):
                journal.parse_intent(invalid)
        for key, value in (("intentSha256", "e" * 64), ("attempt", 2), ("schemaVersion", True),
                           ("runId", RUN), ("token", PRIVATE), ("outcome", "success")):
            changed = json.loads(run); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                journal.parse_run(frame(changed), digest)

    def test_intent_rejects_broadened_authority_and_modified_caller(self):
        value = json.loads(journal.intent_bytes(prepared()))
        for key, altered in (("token", PRIVATE), ("dispatchAllowed", True), ("runId", str(RUN))):
            with self.assertRaises(ValueError):
                journal.parse_intent(frame({**value, key: altered}))
        changed = copy.deepcopy(value)
        changed["prepared"]["callerSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            journal.parse_intent(frame(changed))

    def test_initial_contains_no_credential_and_binds_exact_ready_digest(self):
        for kind, status in (("prepare", "not-applicable"), ("dispatch", "durable-intent"),
                             ("track", "matched-intent"), ("reconcile", "matched-intent")):
            raw = frame(initial(kind)); request = engine.parse_initial(raw)
            ready = json.loads(engine.ready_frame(request))
            self.assertLessEqual(len(engine.ready_frame(request)), engine.MAX_READY_BYTES)
            self.assertEqual(ready, {"protocol": policy.PROTOCOL, "id": request.id,
                                    "ready": {"requestSha256": hashlib.sha256(raw).hexdigest(), "journal": status}})
            changed = initial(kind); changed["token"] = PRIVATE
            with self.assertRaises(ValueError):
                engine.parse_initial(frame(changed))

    def test_initial_and_go_frames_reject_extra_pipelined_duplicate_or_unbound_input(self):
        request = engine.parse_initial(frame(initial()))
        good = {"protocol": policy.PROTOCOL, "id": request.id,
                "go": {"requestSha256": request.digest, "token": PRIVATE}}
        self.assertEqual(engine.parse_go(frame(good), request), PRIVATE)
        for raw in (frame(good) + frame(good), frame(good) + b" ", frame(good).replace(b'"go":', b'"go":null,"go":'),
                    frame({**good, "url": "https://other.invalid/"}), frame({**good, "id": "different"}),
                    frame({**good, "go": {"requestSha256": "0" * 64, "token": PRIVATE}})):
            with self.assertRaises(ValueError):
                engine.parse_go(raw, request)
        for raw in (frame(initial()) + frame(good), frame(initial())[:-1], b" " + frame(initial()),
                    b'{"x":' * 40 + b"null" + b"}" * 40 + b"\n"):
            with self.assertRaises(ValueError):
                engine.parse_initial(raw)

    def test_pending_is_fresh_native_scope_only_and_go_contains_no_token(self):
        value = initial(); value["action"] = None
        value["pendingScope"] = {key: target().value()[key] for key in
                                 ("projectBinding", "repository", "accountId", "repositoryId")}
        request = engine.parse_initial(frame(value))
        go = {"protocol": policy.PROTOCOL, "id": request.id,
              "go": {"requestSha256": request.digest, "token": None}}
        self.assertIsNone(engine.parse_go(frame(go), request))
        go["go"]["token"] = PRIVATE
        with self.assertRaises(ValueError):
            engine.parse_go(frame(go), request)
        for change in ({"home": None}, {"action": initial()["action"]},
                       {"pendingScope": {**value["pendingScope"], "token": PRIVATE}}):
            with self.assertRaises(ValueError):
                engine.parse_initial(frame({**value, **change}))
        result = engine.encode_result(request, None, [{"prepared": prepared().value(), "runId": str(RUN)}])
        self.assertNotIn(PRIVATE.encode(), result)
        self.assertIsNone(json.loads(result)["result"])

    def test_final_result_preserves_accepted_uncertain_and_observed_distinctions(self):
        for kind in ("prepare", "dispatch", "track", "reconcile"):
            request = engine.parse_initial(frame(initial(kind)))
            result, _ = execute(kind)
            final = json.loads(engine.encode_result(request, result))
            self.assertEqual(final["result"], result)
            self.assertIsNone(final["pending"])
            if kind == "dispatch":
                self.assertEqual(final["result"]["effect"], "accepted")
                self.assertIsNone(final["result"]["run"])
                result["effect"] = "not-sent"
                with self.assertRaises(ValueError):
                    engine.encode_result(request, result)
            result["token"] = PRIVATE
            with self.assertRaises(ValueError):
                engine.encode_result(request, result)


if __name__ == "__main__":
    unittest.main()
