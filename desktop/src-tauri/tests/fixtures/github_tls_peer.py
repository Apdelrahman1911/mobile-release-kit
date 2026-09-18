"""Fixed synthetic T1--T3 peer. Not a general server or production trust path.

SOURCE authoring is not permission to run this file. Only the independently
admitted disposable Linux namespace entry may start it, with an original Child
and bounded pipe readers already retained by the Rust fixture. The parent's
16-second endpoint starts at original creation; our secondary endpoint never
renews it. No thread, child, TLS/private API, arbitrary endpoint or input script.
"""
from __future__ import annotations

import time

_BEGIN = time.monotonic()

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import stat
import sys

CASES = ("T1-source", "T1-zip", "T2-root", "T2-name", "T2-expired",
         "T3-clean", "T3-ragged", "T3-length", "T3-chunk")
SCOPE = "github-tls-peer-v1"
HOST = "api.github.com"
AUTHORIZATION = b"Bearer INERT_NOT_A_CREDENTIAL"
REQUEST_LIMIT = 8 * 1024
WIRE_LIMIT = 128 * 1024
REPLY_LIMIT = 64 * 1024
FIXTURE_LIMIT = 16 * 1024
CASE_SECONDS = 16.0
AUTH_ALERTS = frozenset({"TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE",
                         "TLSV1_ALERT_CERTIFICATE_UNKNOWN", "SSLV3_ALERT_CERTIFICATE_EXPIRED"})


class Refused(Exception):
    """Only an internally selected, redacted code; never a peer/input repr."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def remaining() -> float:
    now = time.monotonic()
    require(_BEGIN <= now < _BEGIN + CASE_SECONDS, "deadline")
    return _BEGIN + CASE_SECONDS - now


def identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def fixed_body(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.geteuid() and before.st_mode & 0o022 == 0
            and 0 < before.st_size <= maximum, "inputs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(os.fstat(descriptor)) == identity(before), "inputs")
        chunks, count = [], 0
        while count <= before.st_size:
            remaining()
            block = os.read(descriptor, min(4096, before.st_size + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
        require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before)
                and identity(path.lstat()) == identity(before), "inputs")
        return b"".join(chunks)
    finally:
        original, descriptor = descriptor, -1
        os.close(original)  # One original close; a failure is not retried.


def admit() -> Path:
    expected = {"MRK_DESKTOP_HOSTED_CHECKS", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT",
                "MRK_TLS_ORIGINAL_UID", "MRK_TLS_ORIGINAL_GID", "MRK_TLS_PARENT_NETNS",
                "MRK_TLS_PARENT_MNTNS", "MRK_TLS_NETNS", "MRK_TLS_MNTNS",
                "MRK_TLS_PEER_SHA256", "LANG", "LC_ALL"}
    require(set(os.environ) == expected and sys.platform == "linux"
            and sys.flags.isolated == 1 and sys.flags.no_site == 1
            and sys.dont_write_bytecode and sys.flags.optimize == 0
            and os.environ["MRK_DESKTOP_HOSTED_CHECKS"] == "github-readonly-tls-v1"
            and os.environ["GITHUB_ACTIONS"] == "true"
            and os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
            and os.environ["LANG"] == os.environ["LC_ALL"] == "C", "admission")
    ids = []
    for name in ("MRK_TLS_ORIGINAL_UID", "MRK_TLS_ORIGINAL_GID"):
        value = os.environ[name]
        require(re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None
                and int(value) < 2**32 - 1, "admission")
        ids.append(int(value))
    require(os.getresuid() == (ids[0],) * 3 and os.getresgid() == (ids[1],) * 3
            and os.getgroups() == [], "admission")
    for kind, variable in (("net", "NETNS"), ("mnt", "MNTNS")):
        parent = os.environ["MRK_TLS_PARENT_" + variable]
        current = os.environ["MRK_TLS_" + variable]
        require(re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", parent) is not None
                and re.fullmatch(kind + r":\[[1-9][0-9]{0,19}\]", current) is not None
                and current != parent and os.readlink("/proc/self/ns/" + kind) == current,
                "admission")
    with open("/proc/self/status", "rb") as status:
        raw = status.read(16 * 1024 + 1)
    require(len(raw) <= 16 * 1024, "admission")
    fields = dict(line.split(b":", 1) for line in raw.splitlines() if b":" in line)
    require(fields.get(b"NoNewPrivs", b"").strip() == b"1", "admission")
    for name in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        require(fields.get(name, b"").strip() == b"0000000000000000", "admission")
    for resource_id, limit in ((resource.RLIMIT_AS, 256 * 1024 * 1024),
                               (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0),
                               (resource.RLIMIT_FSIZE, 0)):
        _, hard = resource.getrlimit(resource_id)
        require(hard == resource.RLIM_INFINITY or hard >= limit, "admission")
        resource.setrlimit(resource_id, (limit, limit))
    source = Path(__file__)
    require(source.is_absolute() and source.name == "github_tls_peer.py", "inputs")
    expected_hash = os.environ["MRK_TLS_PEER_SHA256"]
    require(re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None
            and hashlib.sha256(fixed_body(source, 64 * 1024)).hexdigest() == expected_hash,
            "inputs")
    fixtures = source.with_name("github_tls")
    directory = fixtures.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == ids[0]
            and directory.st_mode & 0o022 == 0, "inputs")
    return fixtures


def script(case: str) -> tuple[tuple[bytes, bytes, bool], ...]:
    account = {"id": 11, "login": "owner"}
    repository = {"id": 22, "full_name": "owner/app", "default_branch": "main",
                  "visibility": "private", "archived": False,
                  "permissions": {"pull": True, "push": False, "admin": False}}
    paths = [b"/user", b"/repos/owner/app", b"/repos/owner/app/actions/workflows?per_page=100&page=1"]
    bodies = [account, repository, {"total_count": 0, "workflows": []}]
    if case == "T1-zip":
        rows = [{"id": 1001 + i, "path": f".github/workflows/synthetic-{i:03}.yml", "state": "active"}
                for i in range(101)]
        bodies[2] = {"total_count": 101, "workflows": rows[:100]}
        paths.append(b"/repos/owner/app/actions/workflows?per_page=100&page=2")
        bodies.append({"total_count": 101, "workflows": rows[100:]})
    paths.append(b"/repos/owner/app")
    bodies.append(repository)
    result = []
    for index, (path, body) in enumerate(zip(paths, bodies, strict=True)):
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        framing = b""
        payload = encoded
        if index == 0 and case == "T3-length":
            framing = b"Content-Length: " + str(len(encoded) + 1).encode("ascii") + b"\r\n"
        elif index == 0 and case == "T3-chunk":
            framing = b"Transfer-Encoding: chunked\r\n"
            payload = format(len(encoded) + 1, "x").encode("ascii") + b"\r\n" + encoded
        reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n" + framing + b"\r\n" + payload
        require(len(reply) <= REPLY_LIMIT, "script")
        result.append((path, reply, case != "T3-ragged"))
        if case.startswith("T2-") or case in {"T3-ragged", "T3-length", "T3-chunk"}:
            break
    require(1 <= len(result) <= 5, "script")
    return tuple(result)


class Connection:
    def __init__(self, original: socket.socket) -> None:
        self.original = original
        self.incoming = self.outgoing = self.tls = None
        self.read_bytes = self.written_bytes = self.reply_bytes = 0
        self.close_claimed = self.closed = False

    def attach(self, context: ssl.SSLContext) -> None:
        # The original is already in main's retained list before either BIO or
        # SSLObject construction can fail. These public wrappers own no socket.
        require(self.tls is self.incoming is self.outgoing is None, "tls-state")
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    def flush(self) -> None:
        while self.outgoing.pending:
            remaining()
            require(self.written_bytes < WIRE_LIMIT, "wire-limit")
            block = self.outgoing.read(min(16384, self.outgoing.pending, WIRE_LIMIT - self.written_bytes))
            require(bool(block), "wire-limit")
            view = memoryview(block)
            while view:
                self.original.settimeout(remaining())
                count = self.original.send(view)
                remaining()
                require(0 < count <= len(view), "tcp")
                self.written_bytes += count
                view = view[count:]

    def receive(self) -> None:
        self.flush()
        require(self.read_bytes < WIRE_LIMIT, "wire-limit")
        self.original.settimeout(remaining())
        block = self.original.recv(min(16384, WIRE_LIMIT - self.read_bytes))
        remaining()
        if block:
            self.read_bytes += len(block)
            require(self.incoming.write(block) == len(block), "tls-alert")
        else:
            self.incoming.write_eof()

    def handshake(self) -> None:
        while True:
            remaining()
            try:
                self.tls.do_handshake()
                self.flush()
                require(self.tls.selected_alpn_protocol() == "http/1.1", "unexpected-request")
                return
            except ssl.SSLWantReadError:
                self.receive()
            except ssl.SSLWantWriteError:
                self.flush()

    def request(self, path: bytes, record: dict) -> None:
        raw = bytearray()
        while not raw.endswith(b"\r\n\r\n"):
            remaining()
            require(len(raw) < REQUEST_LIMIT, "request-limit")
            try:
                block = self.tls.read(min(4096, REQUEST_LIMIT - len(raw)))
            except ssl.SSLWantReadError:
                self.receive()
                continue
            except ssl.SSLWantWriteError:
                self.flush()
                continue
            require(bool(block), "unexpected-request")
            raw.extend(block)
            record["decryptedBytes"] += len(block)
            require(b"\r\n\r\n" not in raw[:-4], "unexpected-request")
        expected = b"GET " + path + b" HTTP/1.1\r\n" + b"\r\n".join((
            b"Host: api.github.com", b"User-Agent: MobileReleaseKit-Desktop/0.3.0",
            b"Accept: application/vnd.github+json", b"X-GitHub-Api-Version: 2022-11-28",
            b"Accept-Encoding: identity", b"Connection: close", b"Authorization: " + AUTHORIZATION)) + b"\r\n\r\n"
        require(bytes(raw) == expected, "unexpected-request")
        record["requests"] += 1
        record["authBytes"] += len(AUTHORIZATION)

    def respond(self, reply: bytes, close_notify: bool) -> bool:
        view = memoryview(reply)
        while view:
            remaining()
            try:
                count = self.tls.write(view[:16384])
            except ssl.SSLWantReadError:
                self.receive()
                continue
            except ssl.SSLWantWriteError:
                self.flush()
                continue
            require(0 < count <= len(view) and self.reply_bytes + count <= REPLY_LIMIT, "script")
            self.reply_bytes += count
            view = view[count:]
            self.flush()
        if not close_notify:
            # Same application records; no TLS unwrap/close-notify on this path.
            return False
        try:
            self.tls.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # Public MemoryBIO unwrap emits close-notify before asking for the
            # client's reply. Always flush it; we do not claim reciprocity.
            pass
        require(self.outgoing.pending > 0, "tls-alert")
        self.flush()
        return True

    def close(self) -> None:
        if not self.close_claimed:
            self.close_claimed = True
            self.original.close()
            self.closed = True


def emit(value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= 4096, "output")
    view = memoryview(raw)
    while view:
        count = os.write(1, view)
        require(0 < count <= len(view), "output")
        view = view[count:]


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        os.write(2, b"github-tls-peer: admission\n")
        return 71
    case = sys.argv[1]
    base = {"schemaVersion": 1, "scope": SCOPE, "case": case}
    record = {**base, "state": "finished", "status": "failed", "code": "admission",
              "connections": 0, "handshakes": 0, "requests": 0, "decryptedBytes": 0,
              "authBytes": 0, "closeNotify": 0, "tlsRefused": False,
              "wireReadBytes": [], "wireWriteBytes": [], "replyBytes": [], "allSocketsClosed": False}
    listener, listener_closed, connections = None, False, []
    unregistered = None  # Original accept result remains owned during allocation.
    complete = False
    try:
        directory = admit()
        cert_name = {"T2-name": "wrong-san.pem", "T2-expired": "api-expired.pem"}.get(case, "api-valid.pem")
        certificate, key = directory / cert_name, directory / "server-key.pem"
        before = (fixed_body(certificate, FIXTURE_LIMIT), fixed_body(key, FIXTURE_LIMIT))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.keylog_filename = None
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(str(certificate), str(key))
        require(before == (fixed_body(certificate, FIXTURE_LIMIT), fixed_body(key, FIXTURE_LIMIT)), "inputs")
        del before  # Key bytes are never sent to logs, reports or another file.
        sni_count = [0]

        def server_name(_connection: ssl.SSLObject, name: str | None, _context: ssl.SSLContext) -> int | None:
            if name != HOST:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            sni_count[0] += 1
            return None

        context.set_servername_callback(server_name)
        schedule = script(case)
        remaining()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(remaining())
        # Later cases use the same fixed endpoint after original-owner finality.
        # Reuse only retired TCP TIME_WAIT slots, never share an active listener:
        # SO_REUSEPORT is deliberately absent and bind/listen still fail closed.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 443))
        listener.listen(1)
        emit({**base, "state": "ready"})
        for index, (path, reply, clean) in enumerate(schedule):
            listener.settimeout(remaining())
            unregistered, address = listener.accept()
            connection = Connection(unregistered)
            connections.append(connection)
            unregistered = None
            record["connections"] += 1
            try:
                require(address[0] == "127.0.0.1" and 0 < address[1] < 65536, "unexpected-request")
                connection.attach(context)
                try:
                    connection.handshake()
                    record["handshakes"] += 1
                    connection.request(path, record)
                except ssl.SSLError as error:
                    require(case.startswith("T2-") and error.reason in AUTH_ALERTS
                            and record["handshakes"] == record["decryptedBytes"]
                            == record["requests"] == record["authBytes"] == 0,
                            "tls-alert")
                    record["tlsRefused"] = True
                if case.startswith("T2-"):
                    require(record["tlsRefused"] and sni_count[0] == 1, "tls-alert")
                else:
                    require(sni_count[0] == index + 1, "unexpected-request")
                    record["closeNotify"] += int(connection.respond(reply, clean))
            finally:
                connection.close()
        require(record["connections"] == len(schedule), "script")
        complete = True
        record["code"] = None
    except Refused as error:
        record["code"] = error.args[0]
    except (TimeoutError, socket.timeout):
        record["code"] = "deadline"
    except ssl.SSLError:
        record["code"] = "tls-alert"
    except OSError:
        record["code"] = "tcp"
    except BaseException:
        record["code"] = "internal"
    finally:
        # Every original is attempted independently. A previous close failure
        # is retained, not retried or converted into a successful outcome.
        unregistered_closed = unregistered is None
        if unregistered is not None:
            try:
                unregistered.close()
                unregistered_closed = True
            except BaseException:
                record["code"] = record["code"] or "close"
        for connection in connections:
            try:
                connection.close()
            except BaseException:
                record["code"] = record["code"] or "close"
        if listener is not None:
            try:
                listener.close()
                listener_closed = True
            except BaseException:
                record["code"] = record["code"] or "close"
        record["wireReadBytes"] = [connection.read_bytes for connection in connections]
        record["wireWriteBytes"] = [connection.written_bytes for connection in connections]
        record["replyBytes"] = [connection.reply_bytes for connection in connections]
        record["allSocketsClosed"] = (listener_closed and unregistered_closed
                                      and all(connection.closed for connection in connections))
        if complete and record["allSocketsClosed"] and record["code"] is None:
            record["status"] = "passed"
        try:
            emit(record)
        except BaseException:
            return 74  # Parent still needs original wait and both pipe joins.
    return 0 if record["status"] == "passed" else 71


if __name__ == "__main__":
    raise SystemExit(main())
