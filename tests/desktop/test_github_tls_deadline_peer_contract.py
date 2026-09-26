"""Focused DATA models for T4/T5 original peer methods; no native qualification.

Only selected definitions/constants are loaded from the actual fixture AST.
No fixture imports, main/admit/run, socket/SSL constructors, fd IO, resource
limits, network, process or clock wait is executed by these eight test methods.
Execution still belongs to the separately reviewed focused-test environment.
"""
from __future__ import annotations

import ast
import errno
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


PEER = Path(__file__).resolve().parents[2] / "desktop/src-tauri/tests/fixtures/github_tls_peer.py"


def model() -> tuple[dict, list]:
    tree = ast.parse(PEER.read_text(encoding="utf-8"), filename=str(PEER))
    definitions = {"Refused", "require", "dns_question", "DeadlinePeer"}
    constants = {"DEADLINE_CASES", "SCOPE", "INSTALLED_SCOPE", "PROXY_PORT", "DNS_LIMIT", "TRICKLE_BODY", "TRICKLE_COUNT", "WIRE_LIMIT"}
    selected = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
    for item in tree.body:
        if isinstance(item, (ast.ClassDef, ast.FunctionDef)) and item.name in definitions:
            selected.append(item)
        elif isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name) and item.targets[0].id in constants:
            selected.append(item)
    if len(selected) != 1 + len(definitions) + len(constants):
        raise AssertionError("The selected peer definitions/constants changed")
    events = []
    environment = {"__name__": "github_tls_deadline_peer_model", "emit": events.append,
        "remaining": lambda: 16.0, "time": SimpleNamespace(monotonic=lambda: 100.0),
        "os": SimpleNamespace(read=Mock(), close=Mock()), "select": SimpleNamespace(select=Mock()),
        "errno": errno}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), str(PEER), "exec"), environment)
    return environment, events


def question(kind: int, identifier: int = 42) -> bytes:
    return (identifier.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x03api\x06github\x03com\x00" + kind.to_bytes(2, "big") + b"\x00\x01")


class DeadlinePeerContractTests(unittest.TestCase):
    def test_dns_fixed_questions_withhold_and_bound_every_datagram(self):
        env, events = model()
        decode = env["dns_question"]
        self.assertEqual(decode(question(1)), (42, 1))
        self.assertEqual(decode(question(28)), (42, 28))
        for invalid in (question(15), question(1) + b"x", question(1).replace(b"api", b"bad"),
                        question(1)[:2] + b"\x81" + question(1)[3:], question(1)[:-1] + b"\x02"):
            with self.subTest(invalid=invalid), self.assertRaises(env["Refused"]):
                decode(invalid)
        peer = env["DeadlinePeer"]("T5-dns")
        original = SimpleNamespace(recvfrom=Mock(side_effect=[
            *((question(kind), ("127.0.0.1", 45000)) for kind in (1, 28) * 4), BlockingIOError()]))
        peer.sockets["dns"] = original
        peer.receive_dns()
        self.assertEqual((peer.record["dnsQuestions"], peer.record["dnsA"], peer.record["dnsAAAA"], peer.record["dnsReplies"]), (8, 4, 4, 0))
        self.assertEqual(peer.transactions, {(42, 1), (42, 28)})
        self.assertEqual(len(events), 8)
        self.assertTrue(all(item["event"] == "dns-question" for item in events))
        original.recvfrom.side_effect = [(question(1), ("127.0.0.1", 45000))]
        with self.assertRaises(env["Refused"]):
            peer.receive_dns()
        self.assertEqual(peer.record["dnsQuestions"], 8)


    def test_installed_dns_admits_only_normal_empty_edns0_and_trust_ad_questions(self):
        env, _ = model()
        decode = env["dns_question"]

        def normal_query(flags=0x0100, udp_size=1232):
            raw = question(1)
            return (raw[:2] + flags.to_bytes(2, "big") + raw[4:10] + b"\x00\x01" + raw[12:]
                    + b"\x00\x00\x29" + udp_size.to_bytes(2, "big") + b"\x00" * 6)

        for raw in (question(1), question(28), normal_query(), normal_query(flags=0x0120),
                    normal_query(udp_size=512), normal_query(udp_size=4096)):
            with self.subTest(raw=raw):
                self.assertIn(decode(raw, installed=True), ((42, 1), (42, 28)))
        valid = normal_query()
        for raw in (normal_query(flags=0x8180), normal_query(flags=0x0110),
                    normal_query(udp_size=511), normal_query(udp_size=4097),
                    valid[:-1] + b"\x01", valid[:-6] + b"\x01" + b"\x00" * 5,
                    valid[:-5] + b"\x01" + b"\x00" * 4,
                    valid[:-4] + b"\x80" + b"\x00" * 3,
                    valid + b"x", valid[:10] + b"\x00\x02" + valid[12:]):
            with self.subTest(raw=raw), self.assertRaises(env["Refused"]):
                decode(raw, installed=True)
        # The legacy fixed T5 schema is not silently broadened.
        with self.assertRaises(env["Refused"]):
            decode(valid)
        with self.assertRaises(env["Refused"]):
            decode(normal_query(flags=0x0120))

    def test_installed_dns_keeps_actual_source_and_closes_only_acquired_originals(self):
        env, events = model()
        peer = env["DeadlinePeer"]("G-dns-withhold", installed=True)
        original = SimpleNamespace(recvfrom=Mock(side_effect=[
            (question(1, 19), ("127.0.0.7", 45000)),
            (question(28, 20), ("127.0.0.7", 45000)), BlockingIOError()]), close=Mock())
        peer.sockets["dns"] = original
        peer.receive_dns()
        source = {"address": "127.0.0.7", "port": 45000, "questionId": 19, "questionType": 1}
        self.assertEqual(peer.record["dnsSource"], source)
        self.assertEqual([event["dnsSource"] for event in events], [source, source])
        self.assertEqual((peer.record["dnsQuestions"], peer.record["dnsReplies"], peer.record["requests"]), (2, 0, 0))
        self.assertIsNone(peer.sockets["primary"])
        # A real libc retry can use a new UDP port. It does not replace the
        # first endpoint that the existing original Child observer must join.
        original.recvfrom.side_effect = [(question(1), ("127.0.0.7", 45001)), BlockingIOError()]
        peer.receive_dns()
        self.assertEqual(peer.record["dnsSource"], source)
        self.assertEqual(events[-1]["dnsSource"], source)
        self.assertEqual(peer.record["dnsQuestions"], 3)
        for address in (("127.0.0.1", 45000), ("127.0.0.7", 0), ("192.0.2.1", 45000)):
            original.recvfrom.side_effect = [(question(1), address)]
            with self.subTest(address=address), self.assertRaises(env["Refused"]):
                peer.receive_dns()
            self.assertEqual(peer.record["dnsQuestions"], 3)
        original.recvfrom.side_effect = [BlockingIOError()]
        env["select"].select.return_value = ([0], [], [])
        env["os"].read.side_effect = [b"S", b""]
        peer.finish_observation()
        self.assertTrue(peer.completion["dnsEmpty"])
        self.assertFalse(peer.completion["dnsClosed"])
        self.assertIsNone(peer.completion["primaryEmpty"])
        self.assertIsNone(peer.completion["primaryClosed"])
        original.close.assert_not_called()
        peer.close()
        peer.close()
        original.close.assert_called_once_with()
        env["os"].close.assert_called_once_with(0)
        self.assertTrue(peer.record["allSocketsClosed"])
        self.assertTrue(peer.completion["dnsClosed"])
        self.assertIsNone(peer.completion["primaryClosed"])
        self.assertEqual(peer.record["wireReadBytes"], [])
        self.assertEqual(peer.record["wireWriteBytes"], [])
        self.assertEqual(peer.record["replyBytes"], [])

    def test_control_requires_exact_byte_then_original_eof(self):
        env, _ = model()
        peer = env["DeadlinePeer"]("T5-dns")
        env["os"].read.side_effect = [b"S", b""]
        peer.receive_control()
        self.assertEqual(peer.completion["bytes"], 1)
        self.assertFalse(peer.completion["eof"])
        peer.receive_control()
        self.assertTrue(peer.completion["eof"])
        for blocks in ([b""], [b"SS"], [b"X"], [b"S", b"X"]):
            peer = env["DeadlinePeer"]("T5-dns")
            env["os"].read.side_effect = blocks
            with self.subTest(blocks=blocks), self.assertRaises(env["Refused"]):
                for _ in blocks:
                    peer.receive_control()

    def test_simultaneous_connection_wins_control_and_uncertain_close_retains_failure(self):
        env, _ = model()
        peer = env["DeadlinePeer"]("T4-owner-clear")
        accepted = SimpleNamespace(close=Mock(side_effect=OSError(errno.EIO, "synthetic")))
        primary = SimpleNamespace(setblocking=Mock(), accept=Mock(return_value=(accepted, ("127.0.0.1", 40000))), close=Mock())
        proxy = SimpleNamespace(setblocking=Mock(), accept=Mock(side_effect=BlockingIOError), close=Mock())
        peer.sockets.update(primary=primary, proxy=proxy)
        env["select"].select.return_value = ([0, primary], [], [])
        with self.assertRaises(env["Refused"]):
            peer.finish_observation()
        self.assertIs(peer.unexpected["primary"], accepted)
        self.assertEqual(peer.completion["primaryUnexpected"], 1)
        env["os"].read.assert_not_called()
        peer.close()
        peer.close()  # No original close retry, including failed accepted socket.
        accepted.close.assert_called_once_with()
        primary.close.assert_called_once_with()
        proxy.close.assert_called_once_with()
        env["os"].close.assert_called_once_with(0)
        self.assertFalse(peer.record["allSocketsClosed"])
        self.assertFalse(peer.unexpected_closed["primary"])
        self.assertTrue(peer.completion["closed"])

    def test_original_final_empty_accepts_are_separate_from_control_and_close(self):
        env, _ = model()
        peer = env["DeadlinePeer"]("T4-ambient-fixed")
        for role in ("primary", "proxy"):
            peer.sockets[role] = SimpleNamespace(setblocking=Mock(), accept=Mock(side_effect=BlockingIOError), close=Mock())
        env["select"].select.return_value = ([0], [], [])
        env["os"].read.side_effect = [b"S", b""]
        peer.finish_observation()
        self.assertEqual((peer.completion["bytes"], peer.completion["eof"]), (1, True))
        self.assertTrue(peer.completion["primaryEmpty"])
        self.assertTrue(peer.completion["proxy"]["empty"])
        self.assertFalse(peer.completion["closed"])
        for role in ("primary", "proxy"):
            peer.sockets[role].accept.assert_called_once_with()
            peer.sockets[role].close.assert_not_called()
        peer.close()
        self.assertTrue(peer.record["allSocketsClosed"])
        self.assertTrue(peer.completion["primaryClosed"])
        self.assertTrue(peer.completion["proxy"]["closed"])

    def test_body_progress_requires_successful_wire_flush_not_schedule_or_plaintext(self):
        env, events = model()
        peer = env["DeadlinePeer"]("T5-helper-read")
        peer.record["phase"] = "read"
        connection = SimpleNamespace(written_bytes=100, read_bytes=50, outgoing=SimpleNamespace(pending=0),
            original=SimpleNamespace(setblocking=Mock()))
        connection.respond = Mock(side_effect=lambda *_: setattr(connection, "written_bytes", 123))
        peer.client = connection
        peer.connections = [connection]
        peer.send_byte()
        connection.respond.assert_called_once_with(b"{", False)
        self.assertEqual(peer.record["bodyBytes"], 1)
        self.assertEqual(peer.next_byte, 101.0)
        self.assertEqual(events[0]["wireWriteBytes"], 123)
        self.assertEqual(events[0]["event"], "body-byte")
        events.clear()
        connection.respond.side_effect = None  # Queued/no actual wire delta.
        with self.assertRaises(env["Refused"]):
            peer.send_byte()
        self.assertEqual(events, [])
        self.assertEqual(peer.record["bodyBytes"], 1)
        connection.respond.side_effect = OSError(errno.EIO, "synthetic")
        with self.assertRaises(OSError):
            peer.send_byte()
        self.assertIsNone(peer.record["clientStop"])
        connection.respond.side_effect = BrokenPipeError(errno.EPIPE, "synthetic")
        peer.send_byte()
        self.assertEqual(events[0]["event"], "client-stop")
        self.assertEqual(peer.record["clientStop"], "broken-pipe")
        self.assertIsNone(peer.next_byte)
        self.assertEqual(peer.record["bodyBytes"], 1)

    def test_clienthello_requires_sni_pending_flight_and_zero_server_wire(self):
        env, events = model()
        peer = env["DeadlinePeer"]("T5-handshake")
        class WantRead(Exception):
            pass
        class WantWrite(Exception):
            pass
        env["ssl"] = SimpleNamespace(SSLWantReadError=WantRead, SSLWantWriteError=WantWrite)
        original = SimpleNamespace(settimeout=Mock(), recv=Mock(return_value=b"synthetic-clienthello"), send=Mock())
        outgoing = SimpleNamespace(pending=0)
        connection = SimpleNamespace(original=original, outgoing=outgoing, read_bytes=0, written_bytes=0,
            incoming=SimpleNamespace(write=lambda block: len(block)))
        calls = []
        def handshake():
            calls.append(True)
            if len(calls) == 2:
                peer.record["sni"] = 1
                outgoing.pending = 120
            raise WantRead()
        connection.tls = SimpleNamespace(do_handshake=handshake)
        peer.accept = lambda _: connection
        peer.connections = [connection]
        peer.withhold_handshake(None)
        self.assertEqual(peer.record["withheldWireBytes"], 120)
        self.assertEqual(peer.record["phase"], "handshake")
        self.assertEqual(peer.record["handshakes"], 0)
        self.assertEqual(events[0]["event"], "client-hello")
        self.assertEqual(events[0]["wireWriteBytes"], 0)
        original.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
