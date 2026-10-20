"""Closed DATA only: no FD, credential, process, HTTP or native ACK issuer."""
from dataclasses import replace
from pathlib import Path
import stat
import unittest

from mobile_release import _git_push_private_protocol as p
from mobile_release import _git_remote_private_protocol as old
from mobile_release import git_push_wire as w
from mobile_release import git_remote_control as controls
from test_git_push_transport import TARGET
from test_git_push_wire import command, pack, offered, status, REMOTE


PARENT = (1, 2, stat.S_IFDIR | 0o700, 96, 100, 100, 1000, 1000, 2)
INITIAL = (1, 3, stat.S_IFREG | 0o600, 0, 100, 100, 1000, 1000, 1)
CLOCK = p.Clock("a" * 64, 145_000_000_000, 155_000_000_000)


def binding(mode="apply"):
    return p.Binding("operation-1", CLOCK, mode, "b" * 64, "origin", TARGET, (1000, 1, 9),
                     Path("/synthetic/.git/mrk-git-push-held"), PARENT, INITIAL if mode == "apply" else None)


def body():
    stream = w.PackStream(command(), TARGET.selected, offered())
    stream.feed(pack())
    value = stream.finish()
    stamp = (*INITIAL[:3], value.body_bytes, 200, 200, *INITIAL[6:])
    return value, stamp


def response(outcome="ok"):
    raw = status(b"unpack ok", ("ok " + REMOTE).encode() if outcome == "ok"
                 else ("ng " + REMOTE + " SYNTHETIC_UPSTREAM_DETAIL").encode())
    return w.status_response(raw, TARGET.selected, offered(), command())


class GitPushPrivateProtocolTests(unittest.TestCase):
    def test_challenge_full_original_clock_pair_target_and_body_round_trip(self):
        for mode in ("review", "apply"):
            value = binding(mode)
            self.assertEqual(p.challenge(value.challenge()), value)
            self.assertEqual(value.nonce, CLOCK.nonce)
            self.assertEqual(value.work_end_ns, CLOCK.work_end_ns)
            self.assertEqual(value.hard_end_ns, CLOCK.hard_end_ns)
            self.assertNotIn(str(value.path), repr(value))
            self.assertFalse(hasattr(value, "join") or hasattr(value, "grant_native"))

    def test_foreign_nonce_account_clock_or_mode_never_adopts_binding(self):
        value = binding()
        for name, change in (("nonce", "c" * 32), ("protocol", old.PROTOCOL),
                             ("mode", "review"), ("clock", {"workEndNs": CLOCK.work_end_ns, "hardEndNs": CLOCK.hard_end_ns + 1})):
            row = p._decode(value.challenge())
            row[name] = change
            with self.subTest(name=name), self.assertRaises(p.PrivateError):
                p.challenge(p._encode(row))
        grant = value.grant("SYNTHETIC_PRIVATE_INPUT")
        with self.assertRaises(p.PrivateError):
            replace(value, clock=p.Clock("c" * 64, CLOCK.work_end_ns, CLOCK.hard_end_ns)).accept_grant(grant)

    def test_one_hook_tuple_and_mode_reply_cannot_be_cross_used(self):
        value = binding()
        hook = value.hook()
        self.assertEqual(value.accept_message(hook.request()), hook)
        hook.accept_reply(hook.reply())
        with self.assertRaises(p.PrivateError):
            binding("review").hook().accept_reply(hook.reply())
        with self.assertRaises(p.PrivateError):
            value.accept_message(replace(hook, line=hook.line.replace(TARGET.selected.new_oid.encode(), b"c" * 40)).request())
        with self.assertRaises(p.PrivateError):
            value.accept_message(replace(hook, review_digest="c" * 64).request())
        self.assertNotIn(b"token", hook.reply())
        self.assertEqual(p._decode(binding("review").hook().reply())["phase"], "compared")

    def test_send_is_exact_sealed_original_inode_and_digest_not_a_path_capability(self):
        value = binding()
        digest, stamp = body()
        self.assertEqual(value.accept_message(value.send(digest, stamp)), p.Send(digest, stamp))
        self.assertEqual(p._decode(value.send_reply(digest))["body"], digest.body_sha256)
        for changed in ((stamp[0], stamp[1] + 1, *stamp[2:]), (*stamp[:3], stamp[3] + 1, *stamp[4:]),
                        (*stamp[:8], 2)):
            with self.assertRaises(p.PrivateError):
                value.send(digest, changed)
        with self.assertRaises(p.PrivateError):
            binding("review").send(digest, stamp)
        with self.assertRaises(p.PrivateError):
            p.body_value(replace(digest, body_bytes=w.MAX_BODY + 1))
        with self.assertRaises(p.PrivateError):
            p.body_value(replace(digest, advertised_objects=True))

    def test_completed_return_requires_exact_report_and_after_read_not_just_git_exit(self):
        value = binding()
        for arguments in ({}, {"advertisement_sha256": "d" * 64},
                          {"advertisement_sha256": "d" * 64, "response": response()}):
            with self.assertRaises(p.PrivateError):
                value.returned("ok", **arguments)
        raw = value.returned("ok", advertisement_sha256="d" * 64, response=response(), after_sha256="e" * 64)
        returned = value.accept_message(raw)
        self.assertEqual(returned.response, response())
        self.assertIsNone(returned.first_failure_ns)
        self.assertFalse(hasattr(returned, "native_joined"))
        with self.assertRaises(p.PrivateError):
            binding("review").accept_message(raw)

    def test_known_negative_and_late_unknown_keep_receipt_and_original_cleanup_endpoint(self):
        value = binding()
        control = {"reason": "rate-limited", "credentialExpiresAt": None, "cooldownSeconds": 600, "cooldownBlocked": False}
        raw = value.returned("unknown", "cleanup-unknown", first_failure_ns=120_000_000_000,
            cleanup_end_ns=130_000_000_000, control=control, advertisement_sha256="d" * 64,
            response=response(), after_sha256=None)
        returned = value.accept_message(raw)
        self.assertEqual(returned.control, control)
        self.assertEqual(returned.response.outcome, "ok")
        self.assertEqual(returned.cleanup_end_ns, 130_000_000_000)
        with self.assertRaises(p.PrivateError):
            value.returned("unknown", "cleanup-unknown", first_failure_ns=120_000_000_000,
                cleanup_end_ns=CLOCK.hard_end_ns)
        refused = value.accept_message(value.returned("refused", "remote-rejected", first_failure_ns=120_000_000_000,
            cleanup_end_ns=130_000_000_000, control=controls.refusal(controls.empty(), "remote-rejected"),
            advertisement_sha256="d" * 64, response=response("rejected")))
        self.assertEqual(refused.response.outcome, "rejected")
        self.assertNotIn("SYNTHETIC_UPSTREAM_DETAIL", repr(refused))

    def test_malformed_extra_and_old_fetch_actions_never_become_push_phases(self):
        value = binding()
        for raw in (value.request() + b"\n", b"{}\n", value.request()[:-1],
                    p._encode(value.envelope("store")), p._encode(value.envelope("erase")),
                    p._encode(value.envelope("get", extra=True))):
            with self.assertRaises(p.PrivateError):
                value.accept_message(raw)
        with self.assertRaises(p.PrivateError):
            old.challenge(value.challenge())

    def test_complete_phase_bytes_fit_original_peer_aggregate_and_secret_stays_private(self):
        value, (digest, stamp) = binding(), body()
        returned = value.returned("ok", advertisement_sha256="d" * 64, response=response(), after_sha256="e" * 64)
        helper_to_parent = value.request() + value.hook().request() + value.send(digest, stamp) + returned
        parent_to_helpers = value.challenge() + value.grant("A" * 4096) + value.hook().reply() + value.send_reply(digest)
        self.assertLessEqual(len(helper_to_parent), p.FRAME_LIMIT)
        self.assertLessEqual(len(parent_to_helpers), 2 * p.FRAME_LIMIT)
        self.assertLessEqual(len(returned), p.RETURN_LIMIT)
        self.assertEqual(value.accept_grant(value.grant("SYNTHETIC_PRIVATE_INPUT")), "SYNTHETIC_PRIVATE_INPUT")
        for public in (value.request(), value.hook().reply(), value.send_reply(digest), returned):
            self.assertNotIn(b"SYNTHETIC_PRIVATE_INPUT", public)
        # Escaping is charged inside the unchanged single-frame limit too.
        with self.assertRaises(p.PrivateError):
            value.grant('"' * 4096)


if __name__ == "__main__":
    unittest.main()
