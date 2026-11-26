"""Closed Push DATA comparisons, not native source, ACK or join authority."""
from dataclasses import replace
import hashlib
import json
import stat
import unittest
from unittest.mock import patch

from mobile_release import _desktop_git_push_protocol as wire
from mobile_release import git_repository_push as push
from mobile_release import git_push_transaction as tx
from mobile_release import git_push_wire as packets
from mobile_release import git_service as core
import test_desktop_git_local_protocol as original_fixture


def frame(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture(*, phase="prepare"):
    row = original_fixture.fixture(phase=phase)
    row["protocol"] = wire.PROTOCOL
    row["action"] = {"kind": "push", "expectedRevision": "a" * 64, "expectedReferenceRevision": "c" * 64,
        "remote": "origin", "localRef": "refs/heads/main", "remoteRef": "refs/heads/main",
        "oldOid": "7" * 40, "newOid": "8" * 40, "connectionSessionId": "selected-connection",
        "expectedConnectionRevision": 8}
    row["target"] = {"repository": "fixture/relay", "login": "chosen-user", "accountId": "11", "repositoryId": "22"}
    return row


def compared(*, phase="apply"):
    row = fixture(phase=phase)
    request = wire.parse_request(frame(row))
    selected = request.action.selected
    before = core.Observation(request.action.expected_revision, selected.new_oid, selected.local_ref, (), ("origin",), ())
    index = core._Stamp("file", (1, 3, stat.S_IFREG | 0o600, 12, 123, 456), "2" * 64)
    snapshot = core._Snapshot(before, {}, index, b"inert index", {}, {}, {}, {})
    plan = push.PushPlan("origin", request.target, request.action.expected_reference_revision,
                         (selected.new_oid,), ("d" * 64,), (("hooks", None),), object(), snapshot)
    review = push.PushReview(plan, push._review_digest(plan))
    if phase == "apply":
        row["reviewDigest"] = review.digest
        request = wire.parse_request(frame(row))
    return request, review, push.PushIntent.from_plan(plan, review.digest)


def ack(request, sent):
    return {"protocol": wire.PROTOCOL, "kind": "ack", "id": request.id, "digest": request.digest,
            "candidateDigest": sent.digest, "journalRevision": request.journal_revision + 1}


def transmission(request):
    selected = request.action.selected
    body = packets.BodyDigest(160, "b" * 64, 32, "d" * 40, 0)
    response = packets.Status("ok", selected.remote_ref, selected.old_oid, selected.new_oid, "e" * 64, 100, 0)
    return tx.Returned("apply", selected, "f" * 64, body, response, "1" * 64)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        guard = patch("subprocess.Popen", side_effect=AssertionError("no process in Push DATA tests"))
        guard.start(); self.addCleanup(guard.stop)

    def test_fixed_prepare_apply_keep_selected_connection_and_original_native_context(self):
        for phase in ("prepare", "apply"):
            request = wire.parse_request(frame(fixture(phase=phase)))
            self.assertEqual((request.phase, request.action.kind, request.target.selected),
                             (phase, "push", request.action.selected))
            self.assertEqual(request.tool.path, wire.TOOL_PATH)
            self.assertEqual((request.target.account_id, request.action.expected_connection_revision), ("11", 8))
            self.assertNotIn("chosen-user", repr(request))
            self.assertEqual(json.loads(wire.ready(request))["digest"], hashlib.sha256(frame(fixture(phase=phase))).hexdigest())

    def test_no_implicit_new_branch_force_fetch_or_private_input_in_public_request(self):
        for field, values in (("kind", ("fetch", "init", "commit", "force-push")),
            ("localRef", ("main", "refs/tags/main", "refs/heads/../main")),
            ("remoteRef", ("HEAD", "refs/remotes/origin/main", "refs/heads/é")),
            ("oldOid", (None, "0" * 40, "8" * 40)), ("newOid", (None, "0" * 40, "7" * 40)),
            ("remote", ("-x", "a/b", "x" * 65)),
            ("expectedConnectionRevision", (True, 0, (1 << 32) - 1))):
            for value in values:
                row = fixture(); row["action"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(frame(row))
        for field in ("force", "token", "argv", "branchName", "lease"):
            row = fixture(); row["action"][field] = "inert-private-sentinel"
            with self.assertRaises(wire.ProtocolError) as caught:
                wire.parse_request(frame(row))
            self.assertNotIn("inert-private-sentinel", str(caught.exception))

    def test_prepare_cannot_gain_candidate_authority_and_apply_requires_original_fields(self):
        for phase in ("prepare", "apply"):
            for field, bad in (("reviewDigest", None if phase == "apply" else "b" * 64),
                               ("journalRevision", None if phase == "apply" else 4)):
                row = fixture(phase=phase); row[field] = bad
                with self.subTest(phase=phase, field=field), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(frame(row))
        for key in ("protocol", "native", "clock", "target"):
            row = fixture(); del row[key]
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        row = fixture(); row["target"]["reference"] = row["action"]["remoteRef"]
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(row))  # No accidental Fetch target codec.

    def test_one_bounded_frame_original_clock_and_digest_private_go(self):
        raw = frame(fixture())
        for bad in (raw + raw, raw + b"\n", b"x" * (wire.REQUEST_LIMIT + 1),
                    raw.replace(b'"phase":', b'"phase":"apply","phase":')):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(bad)
        for bad in (0, True, 100_000_000_000, 111_000_000_000):
            row = fixture(); row["clock"]["hardEndNs"] = bad
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(frame(row))
        request = wire.parse_request(raw)
        go = {"protocol": wire.PROTOCOL, "kind": "go", "id": request.id, "digest": request.digest,
              "token": "inert-not-a-credential"}
        self.assertEqual(wire.private_go(request, frame(go)), go["token"])
        for field, value in (("protocol", "mrk-git-remote/1"), ("digest", "f" * 64), ("id", "other")):
            bad = dict(go); bad[field] = value
            with self.assertRaises(wire.ProtocolError):
                wire.private_go(request, frame(bad))

    def test_candidate_binds_complete_original_plan_and_ack_exact_next_revision(self):
        request, review, intent = compared()
        sent = wire.candidate(request, review, intent)
        self.assertEqual(json.loads(sent.raw)["intent"], intent.as_dict())
        self.assertEqual(wire.acknowledged(request, sent, frame(ack(request, sent))), request.journal_revision + 1)
        for changes in (dict(old_oid="9" * 40), dict(expected_index="9" * 64), dict(account_id="99"),
                        dict(commits_sha256="9" * 64), dict(remote="elsewhere")):
            with self.subTest(changes=changes), self.assertRaises(wire.ProtocolError):
                wire.candidate(request, review, replace(intent, **changes))
        for field, value in (("candidateDigest", "e" * 64), ("journalRevision", request.journal_revision + 2),
                             ("id", "other"), ("keep", {})):
            row = ack(request, sent); row[field] = value
            with self.assertRaises(wire.ProtocolError):
                wire.acknowledged(request, sent, frame(row))
        prepare, before, preparing = compared(phase="prepare")
        with self.assertRaises(wire.ProtocolError):
            wire.candidate(prepare, before, preparing)

    def test_public_success_needs_same_returned_send_data_not_git_zero_or_foreign_intent(self):
        request, _, intent = compared()
        result = core.MutationResult(request.id, "push", "succeeded", "settled", None, None, intent)
        values = dict(result=result, effect_phase="remote-returned", first_failure_ns=None,
                      cleanup_end_ns=request.hard_end_ns)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, **values)
        returned = transmission(request)
        row = json.loads(wire.terminal(request, "ok", reason=None, transmission=returned, **values))
        self.assertEqual(row["transmission"]["body"]["sha256"], returned.body.body_sha256)
        self.assertIsNone(row["result"]["observation"])
        for changed in (replace(intent, account_id="99"), replace(intent, local_ref="refs/heads/other")):
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, transmission=returned,
                              **{**values, "result": replace(result, intent=changed)})

    def test_retained_known_failure_is_not_unknown_and_late_stop_is_not_success(self):
        request, _, intent = compared()
        first = 95_000_000_000
        result = core.MutationResult(request.id, "push", "recovery-required", "settled", "authorization", None, intent)
        row = json.loads(wire.terminal(request, "ok", reason=None, result=result,
            effect_phase="candidate-entered", retained_paths=("mrk-git-push-inert",),
            first_failure_ns=first, cleanup_end_ns=first + 10_000_000_000))
        self.assertEqual(row["result"]["state"], "recovery-required")
        self.assertIsNone(row["transmission"])
        for path in ("../mrk-git-push-a", "mrk-git-a/mrk-git-push-b/extra", "mrk-git-a/../mrk-git-push-b",
                     "mrk-git-push-a/mrk-git-push-b", "mrk-git-/mrk-git-push-b"):
            with self.subTest(path=path), self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, result=result,
                    effect_phase="candidate-entered", retained_paths=(path,),
                    first_failure_ns=first, cleanup_end_ns=first + 10_000_000_000)
        for bad in ("unknown", "cleanup-unknown"):
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(request, "ok", reason=None, result=replace(result, reason=bad),
                    effect_phase="candidate-entered", first_failure_ns=first, cleanup_end_ns=first + 10_000_000_000)
        with self.assertRaises(wire.ProtocolError):
            wire.terminal(request, "ok", reason=None, result=replace(result, state="succeeded", reason=None),
                transmission=transmission(request), effect_phase="remote-returned",
                first_failure_ns=first, cleanup_end_ns=first + 10_000_000_000)
        row = json.loads(wire.terminal(request, "cleanup-unknown", reason="unknown",
            first_failure_ns=None, cleanup_end_ns=request.hard_end_ns))
        self.assertIsNone(row["result"]); self.assertIsNone(row["transmission"])


if __name__ == "__main__":
    unittest.main()
