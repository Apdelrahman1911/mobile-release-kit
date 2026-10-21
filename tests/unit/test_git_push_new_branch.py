"""Closed create-only bytes/real parsers with inert FD/HTTP returns only.

No process, live provider, credential, native original or qualification. The
unchanged Push helpers and HTTP body parser execute against existing fixtures.
"""
from dataclasses import replace
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from mobile_release import git_push_new_branch as first
from mobile_release import git_push_wire as wire
from mobile_release import git_push_transport as transport
from mobile_release import _git_push_private_protocol as private
from mobile_release import _desktop_git_push_protocol as protocol
from mobile_release import _desktop_git_push_helper as helper
from test_git_push_body import _Returns
from test_git_push_transport import Exchange, ACCOUNT, REPOSITORY
from test_git_push_wire import packet, pack, status, advertisement_raw, NEW, OLD, OTHER
from test_git_push_private_protocol import PARENT, INITIAL, CLOCK, binding
from test_desktop_git_push_protocol import fixture, frame


REF = "refs/heads/new-branch"
SELECTED = first.Selection(REF, REF, first.ZERO, NEW)
TARGET = transport.Target("fixture/relay", "chosen-user", "11", "22", SELECTED)
CAPS = b"report-status report-status-v2 side-band-64k quiet object-format=sha1 agent=git/synthetic"


def empty_raw():
    return advertisement_raw(caps=CAPS, refs=(("capabilities^{}", first.ZERO),))


def offered():
    return wire.advertisement(empty_raw(), SELECTED)


def command():
    raw = packet((first.ZERO + " " + NEW + " " + REF).encode()
                 + b"\0 report-status-v2 side-band-64k quiet object-format=sha1") + b"0000"
    return wire.command(raw, SELECTED, offered())


def exchange(world, *, mode="apply", advertisement=None, response=None):
    before = empty_raw() if advertisement is None else advertisement
    after = advertisement_raw(caps=CAPS, refs=((REF, NEW),))
    result = status(b"unpack ok", ("ok " + REF).encode()) if response is None else response
    rows = ([ACCOUNT, REPOSITORY, before, result, ACCOUNT, REPOSITORY, after] if mode == "apply"
            else [ACCOUNT, REPOSITORY, before, ACCOUNT, REPOSITORY])
    value = Exchange(mode=mode, current=world.io.current, responses=rows)
    # The fixture transport is comparison DATA, not an admitted native owner.
    value.wrapper = transport._PushTransport(TARGET, mode, value.exchange, value.clock,
                                             world.io.current, value.failure)
    return value


class GitPushNewBranchWireTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no process in DATA checks")))

    def test_closed_kind_never_inferred_from_zero_or_equal_target(self):
        self.assertEqual(wire.selection_kind(SELECTED), first.KIND)
        for kind, old, new in (("push", first.ZERO, NEW), (first.KIND, OLD, NEW),
                               (first.KIND, first.ZERO, first.ZERO), ("force-push", first.ZERO, NEW)):
            with self.subTest(kind=kind, old=old), self.assertRaises(wire.WireError):
                wire.selection(kind, REF, REF, old, new)
        for other in ("refs/heads/other", "refs/tags/new-branch", "new-branch"):
            with self.assertRaises(wire.WireError):
                first.Selection(REF, other, first.ZERO, NEW)

    def test_sole_first_empty_capability_row_is_forwarded_unchanged(self):
        value = offered()
        self.assertEqual(value.refs, ())
        self.assertEqual(value.git_bytes(), empty_raw()[value.prefix_bytes:])
        self.assertEqual(value.capabilities, tuple(CAPS.split()))
        ordinary = wire.Selection(REF, REF, OLD, NEW)
        with self.assertRaises(wire.WireError):
            wire.advertisement(empty_raw(), ordinary)
        for refs in ((("capabilities^{}", first.ZERO), ("capabilities^{}", first.ZERO)),
                     (("capabilities^{}", first.ZERO), ("refs/heads/other", OTHER)),
                     (("refs/heads/other", OTHER), ("capabilities^{}", first.ZERO)),
                     ((REF, first.ZERO),), (("capabilities^{}", OLD),)):
            with self.subTest(refs=refs), self.assertRaises(wire.WireError):
                wire.advertisement(advertisement_raw(caps=CAPS, refs=refs), SELECTED)
        for bad in (empty_raw()[:-1], empty_raw() + b"0000", advertisement_raw(refs=())):
            with self.assertRaises(wire.WireError):
                wire.advertisement(bad, SELECTED)

    def test_missing_in_nonempty_ad_is_allowed_but_every_occupied_tip_refuses(self):
        raw = advertisement_raw(caps=CAPS, refs=(("refs/heads/other", OTHER),))
        self.assertEqual(wire.advertisement(raw, SELECTED).refs, (("refs/heads/other", OTHER),))
        for oid in (OLD, NEW, OTHER):
            with self.assertRaises(wire.WireError) as caught:
                wire.advertisement(advertisement_raw(caps=CAPS, refs=((REF, oid),)), SELECTED)
            self.assertEqual(caught.exception.reason, "target-changed")

    def test_one_command_preserves_expected_zero_and_exact_status_v2_options(self):
        request = command()
        self.assertIn((first.ZERO + " " + NEW + " " + REF).encode(), request.raw)
        raw = status(b"unpack ok", ("ok " + REF).encode(),
                     ("option old-oid " + first.ZERO).encode(), ("option new-oid " + NEW).encode())
        value = wire.status_response(raw, SELECTED, offered(), request)
        self.assertEqual((value.reference, value.old_oid, value.new_oid), (REF, first.ZERO, NEW))
        with self.assertRaises(wire.WireError):
            wire.status_response(raw.replace(first.ZERO.encode(), OLD.encode()), SELECTED, offered(), request)
        for bad in (request.raw.replace(first.ZERO.encode(), OLD.encode()),
                    request.raw[:-4] + packet((first.ZERO + " " + NEW + " refs/heads/other").encode()) + b"0000"):
            with self.assertRaises(wire.WireError):
                wire.command(bad, SELECTED, offered())

    def test_after_and_get_only_reconciliation_do_not_grant_another_creation(self):
        present = advertisement_raw(caps=CAPS, refs=((REF, NEW),))
        self.assertEqual(wire.after_advertisement(present, SELECTED).refs, ((REF, NEW),))
        self.assertEqual(wire.reconcile_advertisement(present, SELECTED).state, "matches-intended")
        self.assertEqual(wire.reconcile_advertisement(empty_raw(), SELECTED).state, "not-returned")
        with self.assertRaises(wire.WireError):
            wire.after_advertisement(empty_raw(), SELECTED)
        with self.assertRaises(wire.WireError):
            wire.advertisement(present, SELECTED)

    def test_private_challenge_and_hook_keep_kind_without_fabricated_remote(self):
        value = replace(binding(), remote=None, target=TARGET)
        self.assertEqual(private.challenge(value.challenge()), value)
        row = private._decode(value.challenge())
        self.assertIsNone(row["remote"])
        self.assertEqual(row["target"]["kind"], first.KIND)
        hook = value.hook()
        self.assertEqual(private._decode(hook.request())["kind"], first.KIND)
        self.assertEqual(value.accept_message(hook.request()), hook)
        for wrong in (replace(hook, kind="push"), replace(hook, line=hook.line.replace(first.ZERO.encode(), OLD.encode()))):
            with self.assertRaises(private.PrivateError):
                value.accept_message(wrong.request())
        for key, changed in (("remote", "origin"), ("target", {k: v for k, v in row["target"].items() if k != "kind"})):
            bad = dict(row); bad[key] = changed
            with self.assertRaises((private.PrivateError, wire.WireError)):
                private.challenge(private._encode(bad))
        # Ordinary private bytes retain their original no-kind ABI.
        self.assertNotIn("kind", private._decode(binding().challenge())["target"])
        self.assertNotIn("kind", private._decode(binding().hook().request()))

    def test_native_request_explicit_kind_null_remote_and_clock_remain_exact(self):
        row = fixture()
        row["action"].update(kind=first.KIND, remote=None, localRef=REF, remoteRef=REF, oldOid=first.ZERO, newOid=NEW)
        request = protocol.parse_request(frame(row))
        self.assertIs(type(request.target.selected), first.Selection)
        self.assertEqual(request.action.kind, first.KIND)
        self.assertIsNone(request.action.remote)
        self.assertEqual(request.hard_end_ns - request.work_end_ns, 10_000_000_000)
        for key, value in (("kind", "push"), ("remote", "origin"), ("oldOid", OLD), ("remoteRef", "refs/heads/other")):
            changed = {**row, "action": {**row["action"], key: value}}
            with self.subTest(key=key), self.assertRaises(protocol.ProtocolError):
                protocol.parse_request(frame(changed))


class GitPushNewBranchHelperTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no process in DATA checks")))
        self.world = _Returns(self)

    def test_same_review_helper_five_gets_flush_eof_no_body_or_post(self):
        original = exchange(self.world, mode="review")
        source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n0000")
        output = []
        instance = helper._ReviewHelper(original.wrapper, read=source.read, write=output.append,
                                        current=self.world.io.current)
        value = instance.run()
        self.assertEqual((value.local_ref, value.remote_ref, value.old_oid), (REF, REF, first.ZERO))
        self.assertEqual([row[0] for row in original.calls], ["GET"] * 5)
        self.assertEqual(b"".join(output), b"connect\n\n\n" + offered().git_bytes())
        self.assertTrue(instance.input_eof and instance.finished)
        self.assertEqual(original.sent, [])
        self.assertEqual(self.world.content, b"")

    def test_same_apply_helper_one_zero_old_body_no_force_and_no_second_send(self):
        original = exchange(self.world)
        source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + command().raw + pack())
        output, acks = [], []
        instance = helper._Helper(original.wrapper, self.world.io, read=source.read, write=output.append,
                                   current=self.world.io.current, send_point=lambda *args: acks.append(args))
        value = instance.run()
        self.assertEqual(value.old_oid, first.ZERO)
        self.assertTrue(instance.finished and instance.pack_eof and instance.send_point_returned)
        self.assertEqual(len(acks), 1)
        self.assertEqual([row[0] for row in original.calls].count("POST"), 1)
        self.assertEqual(b"".join(original.sent), command().raw + pack())
        self.assertEqual(value.body.body_sha256, hashlib.sha256(command().raw + pack()).hexdigest())
        with self.assertRaises(transport.PushError):
            instance.run()
        self.assertEqual(len(acks), 1)

    def test_occupied_including_same_new_refuses_before_stock_hook_body_or_post(self):
        for oid in (OLD, NEW):
            original = exchange(self.world, mode="review", advertisement=advertisement_raw(caps=CAPS, refs=((REF, oid),)))
            source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n0000")
            instance = helper._ReviewHelper(original.wrapper, read=source.read, write=lambda value: None,
                                            current=self.world.io.current)
            with self.assertRaises((wire.WireError, transport.PushError)):
                instance.run()
            self.assertEqual([row[0] for row in original.calls], ["GET"] * 3)
            self.assertEqual(original.sent, [])
            self.assertFalse(instance.finished)

    def test_racing_server_rejection_and_truncated_status_never_get_after_or_retry(self):
        for raw in (status(b"unpack ok", ("ng " + REF + " already exists").encode()), b"0008unpa"):
            original = exchange(self.world, response=raw)
            source = io.BytesIO(b"capabilities\nconnect git-receive-pack\n" + command().raw + pack())
            output, acks = [], []
            instance = helper._Helper(original.wrapper, self.world.io, read=source.read, write=output.append,
                                       current=self.world.io.current, send_point=lambda *args: acks.append(args))
            with self.assertRaises((transport.PushError, wire.WireError)):
                instance.run()
            self.assertEqual(len(original.calls), 4)
            self.assertEqual(len(acks), 1)
            self.assertTrue(instance.send_point_returned)
            self.assertFalse(instance.finished)
            count = len(original.sent)
            with self.assertRaises(transport.PushError):
                instance.run()
            self.assertEqual(len(original.sent), count)
            # A fresh inert backing for the next independent fixture, never
            # reusing the failed production body's original file/phase.
            self.world = _Returns(self)


if __name__ == "__main__":
    unittest.main()
