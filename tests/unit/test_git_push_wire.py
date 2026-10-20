"""Inert receive-pack bytes only; no command, provider, descriptor or authority."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

from mobile_release import git_push_wire as wire


OLD, NEW, OTHER = "a" * 40, "b" * 40, "c" * 40
LOCAL, REMOTE = "refs/heads/work", "refs/heads/main"
SELECTED = wire.Selection(LOCAL, REMOTE, OLD, NEW)


def packet(value):
    return f"{len(value) + 4:04x}".encode("ascii") + value


def advertisement_raw(*, caps=b"report-status report-status-v2 side-band-64k quiet atomic ofs-delta "
                              b"delete-refs push-options object-format=sha1 agent=git/synthetic", refs=None):
    rows = refs if refs is not None else ((REMOTE, OLD), ("refs/heads/other", OTHER))
    raw = packet(b"# service=git-receive-pack\n") + b"0000"
    for index, (reference, oid) in enumerate(rows):
        raw += packet((oid + " " + reference).encode("ascii") + (b"\0" + caps if index == 0 else b"") + b"\n")
    return raw + b"0000"


def offered(**values):
    return wire.advertisement(advertisement_raw(**values), SELECTED)


def command(*, offer=None, caps=b"report-status-v2 side-band-64k quiet object-format=sha1 agent=git/synthetic",
            reference=REMOTE, old=OLD, new=NEW):
    raw = packet((old + " " + new + " " + reference).encode("ascii") + b"\0 " + caps) + b"0000"
    return wire.command(raw, SELECTED, offered() if offer is None else offer)


def pack(body=b"not-real-objects", *, version=2, objects=1):
    value = b"PACK" + version.to_bytes(4, "big") + objects.to_bytes(4, "big") + body
    return value + hashlib.sha1(value).digest()


def status(*rows, sideband=True, progress=b""):
    raw = b"".join(packet(row + b"\n") for row in rows) + b"0000"
    if sideband:
        raw = (packet(b"\x02" + progress) if progress else b"") + packet(b"\x01" + raw) + b"0000"
    return raw


class GitPushWireTests(unittest.TestCase):
    def setUp(self):
        forbidden = patch("subprocess.Popen", side_effect=AssertionError("No process in DATA checks"))
        forbidden.start()
        self.addCleanup(forbidden.stop)

    def refuses(self, function, *args, reason=None):
        with self.assertRaises(wire.WireError) as caught:
            function(*args)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_selection_refuses_delete_create_equal_or_nonbranch(self):
        self.assertEqual(SELECTED.old_oid, OLD)
        for values in ((LOCAL, REMOTE, "0" * 40, NEW), (LOCAL, REMOTE, OLD, "0" * 40),
                       (LOCAL, REMOTE, OLD, OLD), (LOCAL, "refs/tags/main", OLD, NEW),
                       ("work", REMOTE, OLD, NEW), (LOCAL, REMOTE, OLD, "B" * 40),
                       (LOCAL, REMOTE, OLD, "b" * 64), (LOCAL, "refs/heads/x\ny", OLD, NEW)):
            self.refuses(wire.Selection, *values)

    def test_http_preamble_removed_without_rewriting_actual_advertisement(self):
        value = offered()
        self.assertTrue(value.git_bytes().startswith(packet(
            (OLD + " " + REMOTE).encode() + b"\0" + b" ".join(value.capabilities) + b"\n")))
        self.assertEqual(value.git_bytes(), value.raw[value.prefix_bytes:])
        self.assertEqual(value.refs[0], (REMOTE, OLD))
        self.assertEqual(wire.advertisement(value.raw, SELECTED), value)

    def test_incomplete_wrong_service_extra_flush_and_version_two_refuse(self):
        raw = offered().raw
        for malformed in (raw[:-1], raw + b"0000", raw.replace(b"receive-pack", b"upload-pack"),
                          b"0000", packet(b"version 2\n") + b"0000", raw[offered().prefix_bytes:]):
            self.refuses(wire.advertisement, malformed, SELECTED)

    def test_missing_changed_duplicate_and_symbolic_ref_are_not_old_tip(self):
        for refs in (((REMOTE, OTHER),), (("refs/heads/other", OLD),),
                     ((REMOTE, OLD), (REMOTE, OLD)), ((REMOTE, OLD), (".have", OTHER)),
                     ((REMOTE, OLD), ("refs/tags/tag^{}", OTHER))):
            with self.assertRaises(wire.WireError):
                offered(refs=refs)
        for caps in (b"report-status object-format=sha256", b"report-status unknown", b"quiet",
                     b"report-status report-status", b"report-status symref=HEAD:refs/tags/x"):
            with self.assertRaises(wire.WireError):
                offered(caps=caps)

    def test_complete_advertisement_reference_bound(self):
        refs = [(REMOTE, OLD)] + [(f"refs/heads/r{index}", OTHER) for index in range(wire.MAX_REFS - 1)]
        self.assertEqual(len(offered(refs=refs).refs), wire.MAX_REFS)
        with self.assertRaises(wire.WireError):
            offered(refs=refs + [("refs/heads/over", OTHER)])

    def test_after_uses_exact_intended_oid_without_reusing_before_comparison(self):
        before = offered()
        raw = before.raw.replace(OLD.encode(), NEW.encode(), 1)
        self.assertEqual(wire.after_advertisement(raw, SELECTED).refs[0], (REMOTE, NEW))
        self.refuses(wire.advertisement, raw, SELECTED, reason="target-changed")
        self.refuses(wire.after_advertisement, before.raw, SELECTED, reason="target-changed")

    def test_reconciliation_is_complete_read_only_comparison_not_retry_permission(self):
        original = offered().raw
        for raw, state, oid in (
                (original, "still-old", OLD),
                (original.replace(OLD.encode(), NEW.encode(), 1), "matches-intended", NEW),
                (original.replace(OLD.encode(), OTHER.encode(), 1), "other", OTHER),
                (advertisement_raw(refs=(("refs/heads/other", OLD),)), "not-returned", None)):
            value = wire.reconcile_advertisement(raw, SELECTED)
            self.assertEqual((value.state, value.observed_oid), (state, oid))
            self.assertEqual(value.response_sha256, hashlib.sha256(raw).hexdigest())
            self.assertFalse(hasattr(value, "retry") or hasattr(value, "native_joined"))
        self.refuses(wire.reconcile_advertisement, original[:-1], SELECTED)

    def test_command_keeps_exact_expected_old_and_one_requested_update(self):
        value = command()
        self.assertTrue(value.status_v2 and value.sideband)
        for change in ({"old": OTHER}, {"new": OTHER}, {"reference": "refs/heads/other"}):
            with self.assertRaises(wire.WireError):
                command(**change)
        extra = packet((OLD + " " + NEW + " refs/heads/other").encode())
        self.refuses(wire.command, value.raw[:-4] + extra + b"0000", SELECTED, offered())
        self.refuses(wire.command, b"0000", SELECTED, offered())
        self.refuses(wire.command, value.raw + b"0000", SELECTED, offered())

    def test_command_cannot_add_force_options_shallow_certificate_or_forged_offer(self):
        for caps in (b"report-status-v2 push-options", b"report-status-v2 atomic", b"report-status-v2 session-id=x",
                     b"report-status report-status-v2", b"quiet", b"report-status-v2 object-format=sha256",
                     b"report-status-v2 report-status-v2", b"report-status-v2\nrefs/heads/other"):
            with self.assertRaises(wire.WireError):
                command(caps=caps)
        actual = offered(caps=b"report-status")
        forged = replace(actual, capabilities=(b"report-status", b"report-status-v2"))
        self.refuses(wire.command, command().raw, SELECTED, forged)
        for prefix in (packet(b"shallow " + OLD.encode()), packet(b"push-cert\n")):
            self.refuses(wire.command, prefix + command().raw, SELECTED, offered())

    def test_pack_stream_all_split_positions_binds_envelope_and_opaque_checksum(self):
        value, request = pack(), command()
        for split in range(len(value) + 1):
            stream = wire.PackStream(request, SELECTED, offered())
            for chunk in (value[:split], value[split:]):
                if chunk:
                    stream.feed(chunk)
            digest = stream.finish()
            self.assertEqual(digest.body_bytes, len(request.raw) + len(value))
            self.assertEqual(digest.body_sha256, hashlib.sha256(request.raw + value).hexdigest())
            self.assertEqual(digest.pack_sha1, value[-20:].hex())
            self.assertEqual(digest.advertised_objects, 1)
            self.refuses(stream.finish)
            self.refuses(stream.feed, b"x")

    def test_pack_body_limit_includes_command_and_failure_is_sticky(self):
        value, request = pack(), command()
        with patch.object(wire, "MAX_BODY", len(request.raw) + len(value)):
            stream = wire.PackStream(request, SELECTED, offered())
            stream.feed(value)
            self.assertEqual(stream.finish().body_bytes, wire.MAX_BODY)
            stream = wire.PackStream(request, SELECTED, offered())
            stream.feed(value)
            self.refuses(stream.feed, b"x", reason="response-limit")
            self.assertTrue(stream.failed)
            self.refuses(stream.finish)

    def test_pack_partial_wrong_checksum_or_header_never_finishes(self):
        value = pack()
        for wrong in (value[:-1], value + b"x", value[:-20] + b"x" * 20, pack(version=4),
                      b"notpack" + value[7:]):
            stream = wire.PackStream(command(), SELECTED, offered())
            stream.feed(wrong)
            self.refuses(stream.finish)
            self.assertTrue(stream.failed)
        # No novelty claim: the target may already exist under another remote
        # ref. A legitimate zero-object PACK remains the stock server's check.
        stream = wire.PackStream(command(), SELECTED, offered())
        stream.feed(pack(b"", objects=0))
        self.assertEqual(stream.finish().advertised_objects, 0)

    def test_both_report_formats_return_codes_only_not_remote_reason_or_join(self):
        for v2 in (False, True):
            request = command(caps=b"report-status-v2" if v2 else b"report-status")
            raw = status(b"unpack ok", b"ok " + REMOTE.encode(), sideband=False)
            result = wire.status_response(raw, SELECTED, offered(), request)
            self.assertEqual((result.outcome, result.old_oid, result.new_oid), ("ok", OLD, NEW))
            refused = status(b"unpack ok", b"ng " + REMOTE.encode() + b" SYNTHETIC_PRIVATE_REJECTION", sideband=False)
            result = wire.status_response(refused, SELECTED, offered(), request)
            self.assertEqual(result.outcome, "rejected")
            self.assertNotIn("SYNTHETIC_PRIVATE", repr(result))
            self.assertFalse(hasattr(result, "settled") or hasattr(result, "native_joined"))

    def test_sideband_status_accepts_original_split_frames_and_counts_private_progress(self):
        inner = status(b"unpack ok", b"ok " + REMOTE.encode(), sideband=False)
        for split in range(1, len(inner)):
            raw = packet(b"\x02synthetic progress\n") + packet(b"\x01" + inner[:split]) + packet(b"\x01" + inner[split:]) + b"0000"
            result = wire.status_response(raw, SELECTED, offered(), command())
            self.assertEqual(result.outcome, "ok")
            self.assertEqual(result.progress_bytes, len(b"synthetic progress\n"))

    def test_status_v2_optional_fields_must_match_same_actual_update(self):
        rows = (b"unpack ok", b"ok " + REMOTE.encode(), b"option refname " + REMOTE.encode(),
                b"option old-oid " + OLD.encode(), b"option new-oid " + NEW.encode())
        self.assertEqual(wire.status_response(status(*rows), SELECTED, offered(), command()).outcome, "ok")
        for tail in (b"option refname refs/heads/other", b"option old-oid " + OTHER.encode(),
                     b"option new-oid " + OTHER.encode(), b"option forced-update", b"option anything x"):
            self.refuses(wire.status_response, status(*rows[:2], tail), SELECTED, offered(), command())
        self.refuses(wire.status_response, status(*rows[:3], rows[2]), SELECTED, offered(), command())
        request = command(caps=b"report-status side-band-64k")
        self.refuses(wire.status_response, status(*rows[:3]), SELECTED, offered(), request)

    def test_partial_contradictory_extra_ref_unpack_error_or_fatal_is_not_success(self):
        good = status(b"unpack ok", b"ok " + REMOTE.encode())
        for raw in (good[:-1], good + b"0000", b"0000",
                    status(b"unpack error", b"ok " + REMOTE.encode()),
                    status(b"unpack ok", b"ok refs/heads/other"),
                    status(b"unpack ok", b"ok " + REMOTE.encode(), b"ok " + REMOTE.encode()),
                    packet(b"\x03SYNTHETIC_PRIVATE_FATAL") + b"0000"):
            failure = self.refuses(wire.status_response, raw, SELECTED, offered(), command())
            self.assertNotIn("SYNTHETIC_PRIVATE", str(failure))
        refusal = status(b"unpack rejected", b"ng " + REMOTE.encode() + b" rejected")
        self.assertEqual(wire.status_response(refusal, SELECTED, offered(), command()).outcome, "rejected")

    def test_response_and_progress_limits_precede_success(self):
        raw = status(b"unpack ok", b"ok " + REMOTE.encode(), progress=b"12345")
        with patch.object(wire, "MAX_PROGRESS", 4):
            self.refuses(wire.status_response, raw, SELECTED, offered(), command(), reason="response-limit")
        self.refuses(wire.status_response, b"0" * (wire.MAX_METADATA + 1), SELECTED, offered(), command(), reason="response-limit")


if __name__ == "__main__":
    unittest.main()
