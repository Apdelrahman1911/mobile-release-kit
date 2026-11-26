"""Inert protocol bytes only: no Git, process, descriptor, HTTP or native IO.

Packet/round comparisons do not qualify a provider, original clock, private
pipe close or any publication. Opaque test PACK bytes are NOT valid Git objects.
"""
from __future__ import annotations

from dataclasses import replace
import unittest
from unittest.mock import patch

from mobile_release import git_remote_wire as wire


OID = "a" * 40
OTHER = "b" * 40
REF = "refs/heads/main"
SELECTED = wire.Selection(REF, OID)


def packet(value: bytes) -> bytes:
    return f"{len(value) + 4:04x}".encode("ascii") + value


def metadata(*rows: bytes) -> bytes:
    return b"".join(packet(row + b"\n") for row in rows) + b"0000"


def offered(*features: bytes) -> wire.Advertisement:
    fetch = b"fetch" + (b"=" + b" ".join(features) if features else b"")
    return wire.advertisement(metadata(b"version 2", b"agent=git/synthetic",
        b"ls-refs=unborn", fetch, b"object-format=sha1"))


def request(command: bytes, *rows: bytes) -> bytes:
    return (packet(b"command=" + command + b"\n")
        + packet(b"agent=git/synthetic\n") + packet(b"object-format=sha1\n")
        + b"0001" + metadata(*rows))


def fetch(*flags: bytes, wants_ref: bool = False) -> bytes:
    wanted = (b"want-ref " + REF.encode()) if wants_ref else b"want " + OID.encode()
    return request(b"fetch", *flags, wanted, b"done")


def response(*, sideband: bool = False, wants_ref: bool = False) -> bytes:
    def line(value):
        return packet((b"\x01" if sideband else b"") + value + b"\n")
    prefix = (line(b"wanted-refs") + line(OID.encode() + b" " + REF.encode())
              + b"0001") if wants_ref else b""
    return prefix + line(b"packfile") + packet(b"\x01PACKopaque-test-data") + b"0000"


class GitRemoteWireTests(unittest.TestCase):
    def refuses(self, function, *args, reason=None):
        with self.assertRaises(wire.WireError) as caught:
            function(*args)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_selection_is_bounded_exact_head_data(self):
        self.assertEqual(SELECTED.reference, REF)
        # A leading dash in a FULL ref is legal and is not a Git option.
        self.assertEqual(wire.Selection("refs/heads/-legal", OID).oid, OID)
        for ref in ("main", "refs/tags/main", "refs/heads/a..b",
                    "refs/heads/a\\b", "refs/heads/a\nb", "refs/heads/\N{SNOWMAN}",
                    "refs/heads/" + "a" * 256):
            with self.subTest(ref=ref):
                self.refuses(wire.Selection, ref, OID)
        for oid in ("0" * 40, "A" * 40, "a" * 64, "a" * 39, 1):
            self.refuses(wire.Selection, REF, oid)

    def test_packet_decoder_all_split_positions_and_exact_original_bytes(self):
        raw = packet(b"one\n") + b"0001" + packet(b"two") + b"0000"
        expected = ((b"one\n", packet(b"one\n")), (1, b"0001"),
                    (b"two", packet(b"two")), (0, b"0000"))
        for at in range(len(raw) + 1):
            decoder = wire._Packets(100, 10)
            actual = ()
            for part in (raw[:at], raw[at:]):
                if part:
                    actual += decoder.feed(part)
            decoder.finish()
            self.assertEqual(actual, expected)
            self.refuses(decoder.feed, b"0000")
            self.refuses(decoder.finish)

    def test_empty_payload_packet_is_framed_then_refused_by_consumer(self):
        decoder = wire._Packets(4, 1)
        self.assertEqual(decoder.feed(b"0004"), ((b"", b"0004"),))
        decoder.finish()
        self.refuses(wire.advertisement, b"0004" + b"0000")

    def test_invalid_truncated_or_oversized_framing_poison_original(self):
        for raw in (b"xxxx", b"0003", b"ffff", b"00g0"):
            decoder = wire._Packets(100, 10)
            self.refuses(decoder.feed, raw)
            self.assertTrue(decoder.failed)
            self.refuses(decoder.feed, b"0000")
        for raw in (b"00", b"0005", b"0010x"):
            decoder = wire._Packets(100, 10)
            decoder.feed(raw)
            self.refuses(decoder.finish)
            self.assertTrue(decoder.failed)
        decoder = wire._Packets(7, 2)
        decoder.feed(b"0000")
        self.refuses(decoder.feed, b"0000", reason="response-limit")
        decoder = wire._Packets(12, 1)
        self.refuses(decoder.feed, b"00000000", reason="response-limit")

    def test_advertisement_keeps_actual_v2_capabilities(self):
        value = offered(b"shallow", b"wait-for-done", b"filter", b"ref-in-want",
                        b"sideband-all", b"packfile-uris")
        self.assertTrue(value.agent and value.unborn)
        self.assertIn(b"ref-in-want", value.fetch_features)
        self.assertEqual(wire.advertisement(value.raw), value)

    def test_dumb_v0_v1_missing_duplicate_unknown_capabilities_refused(self):
        for raw in (b"not-a-packet", metadata(b"version 1", b"fetch", b"ls-refs"),
                    metadata(b"version 2", b"ls-refs"),
                    metadata(b"version 2", b"fetch", b"fetch", b"ls-refs"),
                    metadata(b"version 2", b"fetch=unknown", b"ls-refs"),
                    metadata(b"version 2", b"fetch", b"ls-refs", b"object-format=sha256"),
                    metadata(b"version 2", b"fetch", b"ls-refs", b"unknown")):
            with self.subTest(raw=raw):
                self.refuses(wire.advertisement, raw)

    def test_metadata_cannot_embed_helper_response_end_or_extra_document(self):
        value = offered().raw
        for raw in (value + b"0000", value + b"0002", value[:-4] + b"0002",
                    value[:-4] + b"0001"):
            self.refuses(wire.advertisement, raw)

    def test_ls_refs_requires_exact_selected_prefix(self):
        raw = request(b"ls-refs", b"peel", b"symrefs", b"unborn",
                      b"ref-prefix " + REF.encode())
        self.assertIsNone(wire.ls_refs_request(raw, SELECTED, offered()))
        for rows in ((b"ref-prefix refs/heads/",), (b"ref-prefix refs/heads/other",),
                     (b"peel",), (b"ref-prefix " + REF.encode(), b"server-option=bad"),
                     (b"ref-prefix " + REF.encode(), b"ref-prefix " + REF.encode())):
            self.refuses(wire.ls_refs_request, request(b"ls-refs", *rows), SELECTED, offered())

    def test_requests_cannot_bypass_observed_capabilities_or_add_headers(self):
        original = offered()
        forged = replace(original, fetch_features=frozenset({b"ref-in-want"}))
        self.refuses(wire.fetch_request, fetch(wants_ref=True), SELECTED, forged)
        normal = fetch()
        for raw in (normal.replace(b"0001", packet(b"server-option=bad\n") + b"0001"),
                    normal.replace(b"0001", b"00010001"),
                    normal + b"0000", normal[:-4], b"0" * (wire.MAX_REQUEST + 1)):
            self.refuses(wire.fetch_request, raw, SELECTED, original)

    def test_ls_refs_response_binds_exact_nonzero_sha1(self):
        raw = metadata(OID.encode() + b" " + REF.encode())
        self.assertEqual(wire.ls_refs_response(raw, SELECTED), OID)
        self.assertEqual(wire.ls_refs_response(raw, wire.Selection(REF, None)), OID)
        self.refuses(wire.ls_refs_response, raw, wire.Selection(REF, OTHER), reason="target-changed")
        self.refuses(wire.ls_refs_response, b"0000", SELECTED, reason="target-changed")
        for row in (b"unborn " + REF.encode(), b"0" * 40 + b" " + REF.encode(),
                    OID.encode() + b" " + REF.encode() + b" symref-target:refs/heads/other"):
            self.refuses(wire.ls_refs_response, metadata(row), SELECTED)
        self.refuses(wire.ls_refs_response, raw[:-4] + raw, SELECTED)

    def test_ls_refs_count_bound(self):
        rows = [OID.encode() + f" refs/heads/branch{i}".encode() for i in range(257)]
        self.refuses(wire.ls_refs_response, metadata(*rows), SELECTED, reason="response-limit")

    def test_fetch_exact_want_and_optional_server_supported_want_ref(self):
        value = wire.fetch_request(fetch(b"thin-pack", b"no-progress", b"ofs-delta"),
                                   SELECTED, offered())
        self.assertFalse(value.wants_ref or value.sideband_all)
        value = wire.fetch_request(fetch(b"sideband-all", wants_ref=True), SELECTED,
                                   offered(b"ref-in-want", b"sideband-all"))
        self.assertTrue(value.wants_ref and value.sideband_all)
        self.refuses(wire.fetch_request, fetch(wants_ref=True), SELECTED, offered())
        self.refuses(wire.fetch_request, fetch(b"sideband-all"), SELECTED, offered())
        self.refuses(wire.fetch_request, fetch(), wire.Selection(REF, None), offered())

    def test_fetch_forbids_haves_shallow_uri_filters_tags_and_extra_wants(self):
        for extra in (b"have " + OTHER.encode(), b"shallow " + OID.encode(),
                      b"deepen 1", b"filter blob:none", b"packfile-uris https",
                      b"include-tag", b"want " + OTHER.encode(), b"done", b"unknown"):
            self.refuses(wire.fetch_request, fetch(extra), SELECTED, offered())
        self.refuses(wire.fetch_request, request(b"fetch", b"want " + OTHER.encode(), b"done"),
                     SELECTED, offered())

    def test_fetch_stream_preserves_frames_at_every_split_and_no_response_end(self):
        for sideband, want_ref in ((False, False), (False, True), (True, False), (True, True)):
            original = offered(b"ref-in-want", b"sideband-all")
            raw_request = fetch(*(b"sideband-all",) if sideband else (), wants_ref=want_ref)
            raw = response(sideband=sideband, wants_ref=want_ref)
            for at in range(len(raw) + 1):
                stream = wire.FetchStream(SELECTED, original, raw_request)
                received = ()
                for part in (raw[:at], raw[at:]):
                    if part:
                        received += stream.feed(part)
                stream.finish()
                self.assertEqual(b"".join(received), raw)
                self.assertEqual(stream.pack_bytes, len(b"PACKopaque-test-data"))
                self.refuses(stream.finish)
                self.refuses(stream.feed, b"0000")

    def test_fetch_stream_refuses_unsolicited_sections_before_forwarding(self):
        for section in (b"shallow-info", b"packfile-uris", b"acknowledgments", b"wanted-refs"):
            stream = wire.FetchStream(SELECTED, offered(), fetch())
            self.refuses(stream.feed, packet(section + b"\n"), reason="unsupported-protocol")
            self.assertTrue(stream.failed)
            self.refuses(stream.feed, response())

    def test_fetch_stream_wanted_ref_must_match_and_be_single(self):
        for line in (OTHER.encode() + b" " + REF.encode(), OID.encode() + b" refs/heads/other"):
            stream = wire.FetchStream(SELECTED, offered(b"ref-in-want"), fetch(wants_ref=True))
            stream.feed(packet(b"wanted-refs\n"))
            self.refuses(stream.feed, packet(line + b"\n"), reason="target-changed")
        stream = wire.FetchStream(SELECTED, offered(b"ref-in-want"), fetch(wants_ref=True))
        prefix = packet(b"wanted-refs\n") + packet(OID.encode() + b" " + REF.encode() + b"\n")
        stream.feed(prefix)
        self.refuses(stream.feed, packet(OID.encode() + b" " + REF.encode() + b"\n"))

    def test_remote_progress_stays_in_private_pipe_and_error_text_is_redacted(self):
        stream = wire.FetchStream(SELECTED, offered(), fetch())
        private_progress = packet(b"\x02SYNTHETIC_PRIVATE_PROGRESS\n")
        raw = packet(b"packfile\n") + private_progress + packet(b"\x01PACKx") + b"0000"
        self.assertEqual(b"".join(stream.feed(raw)), raw)
        stream.finish()
        stream = wire.FetchStream(SELECTED, offered(), fetch())
        failure = self.refuses(stream.feed,
            packet(b"packfile\n") + packet(b"\x03SYNTHETIC_PRIVATE_ERROR"))
        self.assertNotIn("SYNTHETIC_PRIVATE", str(failure))
        self.assertNotIn("SYNTHETIC_PRIVATE", repr(failure))

    def test_progress_and_aggregate_byte_limits_not_full_response_allocation(self):
        with patch.object(wire, "MAX_PROGRESS", 8):
            stream = wire.FetchStream(SELECTED, offered(), fetch())
            stream.feed(packet(b"packfile\n"))
            self.refuses(stream.feed, packet(b"\x02" + b"x" * 9), reason="response-limit")
        with patch.object(wire, "MAX_PACK_RESPONSE", 32):
            stream = wire.FetchStream(SELECTED, offered(), fetch())
            self.refuses(stream.feed, response(), reason="response-limit")
        self.assertEqual(wire.MAX_PACK_RESPONSE, 32 * 1024 * 1024)

    def test_stream_missing_extra_terminal_and_wrong_band_refuse(self):
        for raw in (response()[:-4], response() + b"0000", response()[:-4] + b"0002",
                    packet(b"packfile\n") + b"0000", packet(b"packfile\n") + packet(b"\x04PACK")):
            stream = wire.FetchStream(SELECTED, offered(), fetch())
            with self.assertRaises(wire.WireError):
                stream.feed(raw)
                stream.finish()
            self.assertTrue(stream.failed)

    def test_base_exception_does_not_reopen_the_same_stream(self):
        stream = wire.FetchStream(SELECTED, offered(), fetch())
        original = KeyboardInterrupt()
        with patch.object(stream.decoder, "feed", side_effect=original):
            with self.assertRaises(KeyboardInterrupt) as caught:
                stream.feed(b"0000")
        self.assertIs(caught.exception, original)
        self.assertTrue(stream.failed)
        self.refuses(stream.feed, response())
        self.refuses(stream.finish)


if __name__ == "__main__":
    unittest.main()
