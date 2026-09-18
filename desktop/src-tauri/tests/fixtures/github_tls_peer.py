"""Fixed synthetic T1--T6 peer. Not a general server or production trust path.

SOURCE authoring is not permission to run this file. Only the independently
admitted disposable Linux namespace entry may start it, with an original Child
and bounded pipe readers already retained by the Rust fixture. The parent's
16-second endpoint starts at original creation; our secondary endpoint never
renews it. No thread, child, TLS/private API, arbitrary endpoint or input script.
"""
from __future__ import annotations

import time

_BEGIN = time.monotonic()

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import socket
import ssl
import stat
import sys

ORIGINAL_CASES = ("T1-source", "T1-zip", "T2-root", "T2-name", "T2-expired",
                  "T3-clean", "T3-ragged", "T3-length", "T3-chunk")
STREAMING_CASES = ("T6-header", "T6-body", "T6-chunk-metadata", "T6-unauthorized",
                   "T6-rate-expiry", "T6-target", "T6-redirect")
CASES = ORIGINAL_CASES + STREAMING_CASES  # The separately reported original16 lane.
DEADLINE_CASES = ("T4-owner-clear", "T4-ambient-fixed", "T4-ambient-no-rescue",
                  "T5-dns", "T5-handshake", "T5-read", "T5-helper-read")
EARLY_REFUSAL_CASES = frozenset(case for case in STREAMING_CASES if case != "T6-target")
SCOPE = "github-tls-peer-v1"
HOST = "api.github.com"
AUTHORIZATION = b"Bearer INERT_NOT_A_CREDENTIAL"
REQUEST_LIMIT = 8 * 1024
WIRE_LIMIT = 128 * 1024
REPLY_LIMIT = 64 * 1024
FIXTURE_LIMIT = 16 * 1024
CASE_SECONDS = 16.0
REDIRECT_PORT = 18889
PROXY_PORT = 18888
DNS_LIMIT = 8
TRICKLE_BODY = b'{"id":11,"login":"owner"}'
TRICKLE_COUNT = 14  # Initial byte, then13 real one-second intervals; never complete.
_OUTPUT_BYTES = 0
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
    bodies.append({**repository, "id": 23} if case == "T6-target" else repository)
    result = []
    for index, (path, body) in enumerate(zip(paths, bodies, strict=True)):
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        framing = b""
        payload = encoded
        status_line = b"HTTP/1.1 200 OK\r\n"
        if index == 0 and case == "T3-length":
            framing = b"Content-Length: " + str(len(encoded) + 1).encode("ascii") + b"\r\n"
        elif index == 0 and case == "T3-chunk":
            framing = b"Transfer-Encoding: chunked\r\n"
            payload = format(len(encoded) + 1, "x").encode("ascii") + b"\r\n" + encoded
        elif index == 0 and case == "T6-header":
            # Five individually valid8107-byte fields cross aggregate32KiB,
            # not the8KiB line or64-field limit. No malformed syntax substitute.
            framing = b"".join(b"X-" + str(i).encode("ascii") + b": " + b"a" * 8100 + b"\r\n" for i in range(5))
        elif index == 0 and case == "T6-body":
            # Valid JSON if consumed completely, exactly256KiB+1 body bytes.
            # No Content-Length/chunk precheck: refusal must occur during reads.
            payload = b'{"pad":"' + b"x" * (256 * 1024 + 1 - 10) + b'"}'
        elif index == 0 and case == "T6-chunk-metadata":
            framing = b"Transfer-Encoding: chunked\r\n"
            decoded = b"{" + b" " * 298 + b"}"
            # Each extension line is116 bytes, each data chunk one byte. The
            # supported grammar's35405 framing bytes cross32KiB before4096
            # chunks, body limits or invalid JSON can determine the result.
            payload = b"".join(b"1;x=" + b"a" * 110 + b"\r\n" + bytes([byte]) + b"\r\n" for byte in decoded) + b"0\r\n\r\n"
        elif index == 0 and case == "T6-unauthorized":
            status_line = b"HTTP/1.1 401 Unauthorized\r\n"
            payload = b"irrelevant-not-json"
        elif index == 0 and case == "T6-rate-expiry":
            status_line = b"HTTP/1.1 429 Too Many Requests\r\n"
            framing = b"Retry-After: 120\r\nGitHub-Authentication-Token-Expiration: unsupported\r\n"
            payload = b"irrelevant-not-json"
        elif index == 0 and case == "T6-redirect":
            status_line = b"HTTP/1.1 302 Found\r\n"
            framing = b"Location: https://127.0.0.1:18889/redirect\r\n"
            payload = b"irrelevant-not-json"
        reply = status_line + b"Content-Type: application/json\r\nConnection: close\r\n" + framing + b"\r\n" + payload
        require(len(reply) <= (320 * 1024 if case == "T6-body" else REPLY_LIMIT), "script")
        result.append((path, reply, case != "T3-ragged"))
        if case.startswith("T2-") or case in {"T3-ragged", "T3-length", "T3-chunk"} or case in EARLY_REFUSAL_CASES:
            break
    require(1 <= len(result) <= 5, "script")
    return tuple(result)


class Connection:
    def __init__(self, original: socket.socket, *, wire_limit: int = WIRE_LIMIT, reply_limit: int = REPLY_LIMIT) -> None:
        self.original = original
        self.wire_limit, self.reply_limit = wire_limit, reply_limit
        self.incoming = self.outgoing = self.tls = None
        self.read_bytes = self.written_bytes = self.reply_bytes = 0
        self.reply_stage, self.reply_stop = "reply", "none"
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
            require(self.written_bytes < self.wire_limit, "wire-limit")
            block = self.outgoing.read(min(16384, self.outgoing.pending, self.wire_limit - self.written_bytes))
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
        require(self.read_bytes < self.wire_limit, "wire-limit")
        self.original.settimeout(remaining())
        block = self.original.recv(min(16384, self.wire_limit - self.read_bytes))
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
            require(0 < count <= len(view) and self.reply_bytes + count <= self.reply_limit, "script")
            self.reply_bytes += count
            view = view[count:]
            self.flush()
        if not close_notify:
            # Same application records; no TLS unwrap/close-notify on this path.
            return False
        self.reply_stage = "notify"
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


def reply_close(case: str, connection: Connection, error: BaseException) -> None:
    """Closed expected client-close categories, only around the actual reply.

    These do not prove what the client read. The separately checked product
    projection and original settlement remain mandatory. Timeout, arbitrary
    OSError/SSLError and any handshake/request/sole-close failure are not allowed.
    """
    require(case in EARLY_REFUSAL_CASES and connection.reply_stage in {"reply", "notify"}, "reply-close")
    kind = None
    if type(error) is BrokenPipeError and error.errno == errno.EPIPE:
        kind = "broken-pipe"
    elif type(error) is ConnectionResetError and error.errno == errno.ECONNRESET:
        kind = "connection-reset"
    elif type(error) is ssl.SSLEOFError and error.errno == ssl.SSL_ERROR_EOF and error.reason == "UNEXPECTED_EOF_WHILE_READING":
        kind = "tls-eof"
    elif type(error) is ssl.SSLZeroReturnError and error.errno == ssl.SSL_ERROR_ZERO_RETURN:
        kind = "tls-close-notify"
    require(kind is not None, "reply-close")
    connection.reply_stop = connection.reply_stage + ":" + kind


def no_pending(listener: socket.socket, slot: int, unexpected: list, completion: dict) -> bool:
    """A single nonblocking accept, retaining any actual original before checks.

    Fixed slots are allocated before readiness. Never drain, replace or discard
    an accepted socket to turn an unexpected connection into negative evidence.
    """
    require(unexpected[slot] is None, "unexpected-connection")
    try:
        unexpected[slot], _address = listener.accept()
    except BlockingIOError:
        return True
    if slot == 0:
        completion["primaryUnexpected"] += 1
    else:
        completion["redirect"]["unexpected"] += 1
    raise Refused("unexpected-connection")


def complete_listener_observation(listener: socket.socket, redirect: socket.socket | None,
                                  control_fd: int, unexpected: list, completion: dict) -> None:
    """Wait for the original parent's S+EOF, then probe the same endpoints.

    The parent alone correlates this byte with positive original product
    settlement. Our byte/EOF/probe facts and its retained writer join are distinct.
    No sleep, renewed endpoint, replacement descriptor or inferred readiness.
    """
    listener.setblocking(False)
    endpoints = (listener, redirect)
    readers = [listener, control_fd]
    if redirect is not None:
        redirect.setblocking(False)
        readers.append(redirect)
    signal = bytearray()
    while True:
        ready, _, _ = select.select(readers, [], [], remaining())
        remaining()
        # An actual pending connection wins even if S/EOF was readable in the
        # same select observation. Each accepted original stays in its fixed slot.
        for slot, endpoint in enumerate(endpoints):
            if endpoint is not None and endpoint in ready:
                no_pending(endpoint, slot, unexpected, completion)
        if control_fd not in ready:
            continue
        try:
            block = os.read(control_fd, 2 - len(signal))
        except BlockingIOError:
            continue
        if block:
            signal.extend(block)
            completion["bytes"] = len(signal)
            require(signal == b"S", "control")
        else:
            completion["eof"] = True
            require(signal == b"S", "control")
            break
    # Positive finality comes from the parent's original book. Only these real
    # post-rendezvous BlockingIOError observations establish no pending accepts.
    for slot, endpoint in enumerate(endpoints):
        if endpoint is not None:
            remaining()
            empty = no_pending(endpoint, slot, unexpected, completion)
            remaining()
            if slot == 0:
                completion["primaryEmpty"] = empty
            else:
                completion["redirect"]["empty"] = empty


def emit(value: dict) -> None:
    global _OUTPUT_BYTES
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    require(len(raw) <= 4096 and _OUTPUT_BYTES + len(raw) <= 8 * 1024, "output")
    _OUTPUT_BYTES += len(raw)
    view = memoryview(raw)
    while view:
        count = os.write(1, view)
        require(0 < count <= len(view), "output")
        view = view[count:]


def original_main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        os.write(2, b"github-tls-peer: admission\n")
        return 71
    case = sys.argv[1]
    controlled = case in STREAMING_CASES
    completion = {"bytes": 0, "eof": False, "closed": False,
                  "primaryEmpty": False, "primaryUnexpected": 0, "primaryClosed": False,
                  "redirect": {"empty": False, "unexpected": 0, "closed": False}
                              if case == "T6-redirect" else None} if controlled else None
    base = {"schemaVersion": 1, "scope": SCOPE, "case": case}
    record = {**base, "state": "finished", "status": "failed", "code": "admission",
              "connections": 0, "handshakes": 0, "requests": 0, "decryptedBytes": 0,
              "authBytes": 0, "closeNotify": 0, "tlsRefused": False,
              "wireReadBytes": [], "wireWriteBytes": [], "replyBytes": [], "allSocketsClosed": False}
    listener, listener_closed, connections = None, False, []
    redirect, redirect_closed = None, False
    control_fd, control_closed, control_close_claimed = (0 if controlled else None), False, False
    # Fixed raw-socket custody slots exist before either listener's readiness;
    # assignment, not a fallible wrapper/list append, retains any extra accept.
    unexpected, unexpected_closed = [None, None], [False, False]
    unregistered = None  # Original accept result remains owned during allocation.
    complete = False
    emission_failed = False
    try:
        directory = admit()
        if control_fd is not None:
            original_control = os.fstat(control_fd)
            require(stat.S_ISFIFO(original_control.st_mode) and original_control.st_uid == os.geteuid(), "control")
            os.set_blocking(control_fd, False)
        cert_name = {"T2-name": "wrong-san.pem", "T2-expired": "api-expired.pem"}.get(case, "api-valid.pem")
        certificate, key = directory / cert_name, directory / "server-key.pem"
        before = (fixed_body(certificate, FIXTURE_LIMIT), fixed_body(key, FIXTURE_LIMIT))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.keylog_filename = None
        if controlled:
            # The new receipt's conservative outbound-wire floors assume no
            # TLS compression. Observe the selected runtime option explicitly;
            # never infer client consumption from queued TLS plaintext bytes.
            require(bool(context.options & ssl.OP_NO_COMPRESSION), "tls-state")
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
        if case == "T6-redirect":
            # Original sink exists before the302 can be consumed. It is plain
            # TCP intentionally: any redirect connection, not a completed TLS
            # handshake, fails this fixed no-follow observation.
            remaining()
            redirect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            redirect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            redirect.bind(("127.0.0.1", REDIRECT_PORT))
            redirect.listen(1)
            redirect.setblocking(False)
        emit({**base, "state": "ready"})
        for index, (path, reply, clean) in enumerate(schedule):
            listener.settimeout(remaining())
            unregistered, address = listener.accept()
            connection = Connection(unregistered,
                                    wire_limit=512 * 1024 if case == "T6-body" else WIRE_LIMIT,
                                    reply_limit=320 * 1024 if case == "T6-body" else REPLY_LIMIT)
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
                    try:
                        notified = connection.respond(reply, clean)
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError) as error:
                        # This narrow catch surrounds ONLY a post-request reply,
                        # never handshake, request, sole-close or arbitrary IO.
                        if case not in EARLY_REFUSAL_CASES:
                            raise  # Preserve the original nine error semantics.
                        reply_close(case, connection, error)
                        notified = False
                    record["closeNotify"] += int(notified)
            finally:
                connection.close()
        require(record["connections"] == len(schedule), "script")
        if completion is not None:
            complete_listener_observation(listener, redirect, control_fd, unexpected, completion)
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
        for slot, original in enumerate(unexpected):
            if original is not None:
                try:
                    original.close()  # Sole attempt; retain on uncertain close.
                    unexpected_closed[slot] = True
                except BaseException:
                    record["code"] = record["code"] or "close"
        if listener is not None:
            try:
                listener.close()
                listener_closed = True
            except BaseException:
                record["code"] = record["code"] or "close"
        if redirect is not None:
            try:
                redirect.close()
                redirect_closed = True
            except BaseException:
                record["code"] = record["code"] or "close"
        if control_fd is not None and not control_close_claimed:
            control_close_claimed = True
            try:
                os.close(control_fd)  # Original inherited fd0; no dup/reopen.
                control_closed = True
            except BaseException:
                record["code"] = record["code"] or "close"
        record["wireReadBytes"] = [connection.read_bytes for connection in connections]
        record["wireWriteBytes"] = [connection.written_bytes for connection in connections]
        record["replyBytes"] = [connection.reply_bytes for connection in connections]
        record["allSocketsClosed"] = (listener_closed and unregistered_closed
                                      and all(connection.closed for connection in connections)
                                      and all(original is None or unexpected_closed[slot] for slot, original in enumerate(unexpected))
                                      and (redirect is None or redirect_closed))
        if completion is not None:
            completion["closed"] = control_closed
            completion["primaryClosed"] = listener_closed
            if completion["redirect"] is not None:
                completion["redirect"]["closed"] = redirect_closed
            record["completion"] = completion
            record["replyStops"] = [connection.reply_stop for connection in connections]
        if complete and record["allSocketsClosed"] and (not controlled or control_closed) and record["code"] is None:
            record["status"] = "passed"
        try:
            emit(record)
        except BaseException:
            emission_failed = True
    if emission_failed:
        return 74  # Parent still needs original wait and both pipe joins.
    return 0 if record["status"] == "passed" else 71


def dns_question(raw: bytes) -> tuple[int, int]:
    """Closed libc question shape, not a DNS server/parser for arbitrary data."""
    name = b"\x03api\x06github\x03com\x00"
    require(len(raw) == 12 + len(name) + 4 and len(raw) <= 512
            and raw[2:12] == b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            and raw[12:12 + len(name)] == name and raw[-2:] == b"\x00\x01",
            "dns-question")
    kind = int.from_bytes(raw[-4:-2], "big")
    require(kind in {1, 28}, "dns-question")
    return int.from_bytes(raw[:2], "big"), kind


class DeadlinePeer:
    """Only the seven literal T4/T5 scripts and their original completion pipe.

    No new supervisor, task, thread, configurable endpoint or replacement socket.
    As in accepted T6, S+EOF is a disposal rendezvous, never client finality by
    itself. Rust must send it only after its original client book settles.
    """

    def __init__(self, case: str) -> None:
        require(case in DEADLINE_CASES, "admission")
        self.case = case
        self.base = {"schemaVersion": 1, "scope": SCOPE, "case": case}
        self.record = {**self.base, "state": "finished", "status": "failed", "code": "admission",
            "connections": 0, "handshakes": 0, "requests": 0, "decryptedBytes": 0,
            "authBytes": 0, "closeNotify": 0, "tlsRefused": False, "sni": 0,
            "wireReadBytes": [], "wireWriteBytes": [], "replyBytes": [], "allSocketsClosed": False,
            "phase": "pending", "withheldWireBytes": 0, "bodyBytes": 0,
            "incompleteBody": False, "clientStop": None, "progressCount": 0,
            "dnsQuestions": 0, "dnsA": 0, "dnsAAAA": 0, "dnsReplies": 0}
        self.completion = {"bytes": 0, "eof": False, "closed": False,
            "primaryEmpty": False, "primaryUnexpected": 0, "primaryClosed": False,
            "proxy": {"empty": False, "unexpected": 0, "closed": False}
                     if case.startswith("T4-") else None,
            "dnsEmpty": False if case == "T5-dns" else None,
            "dnsClosed": False if case == "T5-dns" else None}
        self.record["completion"] = self.completion
        # Original slots, including allocation-failure accept custody, precede
        # creation/readiness. Every sole close is independently attempted later.
        self.sockets = {"primary": None, "proxy": None, "dns": None}
        self.closed = {"primary": False, "proxy": False, "dns": False}
        self.unexpected = {"primary": None, "proxy": None}
        self.unexpected_closed = {"primary": False, "proxy": False}
        self.unregistered = None
        self.connections: list[Connection] = []
        self.client: Connection | None = None
        self.signal = bytearray()
        self.close_claimed = False
        self.control_close_claimed = False
        self.transactions: set[tuple[int, int]] = set()
        self.next_byte: float | None = None

    def progress(self, event: str) -> None:
        require(event in {"dns-question", "client-hello", "first-get", "body-byte", "client-stop"}
                and self.record["progressCount"] < 24, "output")
        self.record["progressCount"] += 1
        # The normally driven ORIGINAL Rust reader timestamps each complete
        # frame. Do not replace that observation with this peer's clock/sleeps.
        emit({**self.base, "state": "progress", "event": event,
            "sequence": self.record["progressCount"], "requests": self.record["requests"],
            "bodyBytes": self.record["bodyBytes"],
            "wireReadBytes": sum(item.read_bytes for item in self.connections),
            "wireWriteBytes": sum(item.written_bytes for item in self.connections),
            "dnsQuestions": self.record["dnsQuestions"], "dnsA": self.record["dnsA"],
            "dnsAAAA": self.record["dnsAAAA"], "clientStop": self.record["clientStop"]})

    def listen(self, role: str, port: int) -> None:
        require((role, port) in {("primary", 443), ("proxy", PROXY_PORT)}
                and self.sockets[role] is None, "socket-state")
        self.sockets[role] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        original = self.sockets[role]
        original.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        original.bind(("127.0.0.1", port))
        original.listen(1)
        original.setblocking(False)

    def accept(self, context: ssl.SSLContext) -> Connection:
        listener = self.sockets["primary"]
        listener.settimeout(remaining())
        self.unregistered, address = listener.accept()
        connection = Connection(self.unregistered)
        self.connections.append(connection)
        self.unregistered = None
        self.record["connections"] += 1
        require(address[0] == "127.0.0.1" and 0 < address[1] < 65536, "unexpected-request")
        connection.attach(context)
        return connection

    def no_pending(self, role: str) -> bool:
        require(role in {"primary", "proxy"} and self.unexpected[role] is None, "unexpected-connection")
        try:
            self.unexpected[role], _address = self.sockets[role].accept()
        except BlockingIOError:
            return True
        if role == "primary":
            self.completion["primaryUnexpected"] += 1
        else:
            self.completion["proxy"]["unexpected"] += 1
        raise Refused("unexpected-connection")

    def receive_dns(self) -> None:
        while True:
            remaining()
            try:
                raw, address = self.sockets["dns"].recvfrom(513)
            except BlockingIOError:
                return
            require(address[0] == "127.0.0.1" and 0 < address[1] < 65536
                    and self.record["dnsQuestions"] < DNS_LIMIT, "dns-question")
            transaction, kind = dns_question(raw)
            # A/AAAA may legitimately have equal16-bit IDs. Bind each original
            # question's (ID,type), allow its retransmission, and retain no raw
            # packet. The eight-datagram bound includes every retransmission.
            self.transactions.add((transaction, kind))
            self.record["dnsQuestions"] += 1
            self.record["dnsA" if kind == 1 else "dnsAAAA"] += 1
            self.progress("dns-question")
            # Deliberately NO UDP write/send/forward. Retain only the bounded
            # original transaction mapping, not packet content in any receipt.

    def receive_control(self) -> None:
        try:
            block = os.read(0, 2 - len(self.signal))
        except BlockingIOError:
            return
        if block:
            self.signal.extend(block)
            self.completion["bytes"] = len(self.signal)
            require(self.signal == b"S", "control")
        else:
            self.completion["eof"] = True
            require(self.signal == b"S", "control")

    def stopped(self, kind: str) -> None:
        require(self.case in {"T5-handshake", "T5-read", "T5-helper-read"}
                and self.record["phase"] in {"handshake", "read"}
                and self.record["clientStop"] is None
                and kind in {"tcp-eof", "connection-reset", "broken-pipe", "tls-close-notify"}, "client-stop")
        self.record["clientStop"] = kind
        self.next_byte = None
        self.progress("client-stop")

    def observe_client(self) -> None:
        connection = self.client
        require(connection is not None and self.record["clientStop"] is None, "socket-state")
        require(connection.read_bytes < WIRE_LIMIT, "wire-limit")
        try:
            block = connection.original.recv(min(16384, WIRE_LIMIT - connection.read_bytes))
        except BlockingIOError:
            return
        except ConnectionResetError as error:
            require(type(error) is ConnectionResetError and error.errno == errno.ECONNRESET, "tcp")
            self.stopped("connection-reset")
            return
        if not block:
            self.stopped("tcp-eof")
            return
        connection.read_bytes += len(block)
        # No client application bytes are valid after the one original GET;
        # after an unsent ServerHello even a further client TLS flight is not
        # this fixed withheld-handshake script. Never send a server alert here.
        require(self.record["phase"] == "read", "unexpected-request")
        require(connection.incoming.write(block) == len(block), "tls-alert")
        try:
            decoded = connection.tls.read(1)
        except ssl.SSLWantReadError:
            return  # Bounded partial incoming TLS record, not close evidence.
        except ssl.SSLZeroReturnError as error:
            require(type(error) is ssl.SSLZeroReturnError and error.errno == ssl.SSL_ERROR_ZERO_RETURN, "tls-alert")
            self.stopped("tls-close-notify")
            return
        require(decoded == b"", "unexpected-request")
        self.stopped("tls-close-notify")

    def send_byte(self) -> None:
        connection = self.client
        require(connection is not None and self.record["phase"] == "read"
                and self.record["clientStop"] is None
                and self.record["bodyBytes"] < TRICKLE_COUNT < len(TRICKLE_BODY), "script")
        index = self.record["bodyBytes"]
        before = connection.written_bytes
        try:
            connection.respond(TRICKLE_BODY[index:index + 1], False)
        except (BrokenPipeError, ConnectionResetError) as error:
            # Only the actual post-GET wire send may use these two categories.
            # The original reader timestamps this close; Rust must reject it
            # if early or inconsistent with the original client/frame window.
            if type(error) is BrokenPipeError and error.errno == errno.EPIPE:
                self.stopped("broken-pipe")
            elif type(error) is ConnectionResetError and error.errno == errno.ECONNRESET:
                self.stopped("connection-reset")
            else:
                raise
            return
        require(connection.written_bytes > before and connection.outgoing.pending == 0, "trickle-progress")
        self.record["bodyBytes"] += 1
        self.record["incompleteBody"] = True
        # Actual successful flush precedes progress. No catch-up burst, queued
        # plaintext, scheduled sleep or delayed publication substitutes for it.
        self.progress("body-byte")
        self.next_byte = (time.monotonic() + 1.0
                          if self.record["bodyBytes"] < TRICKLE_COUNT else None)
        connection.original.setblocking(False)

    def finish_observation(self) -> None:
        for role in ("primary", "proxy"):
            if self.sockets[role] is not None:
                self.sockets[role].setblocking(False)
        if self.client is not None:
            self.client.original.setblocking(False)
        while not self.completion["eof"]:
            readers = [0, self.sockets["primary"]]
            readers.extend(self.sockets[role] for role in ("proxy", "dns") if self.sockets[role] is not None)
            if self.client is not None and self.record["clientStop"] is None:
                readers.append(self.client.original)
            wait = remaining()
            if self.next_byte is not None:
                wait = min(wait, max(0.0, self.next_byte - time.monotonic()))
            ready, _, _ = select.select(readers, [], [], wait)
            remaining()
            # Pending accepts WIN even with simultaneous S+EOF. This reuses
            # the accepted original-listener horizon, not script-length proof.
            for role in ("primary", "proxy"):
                if self.sockets[role] is not None and self.sockets[role] in ready:
                    self.no_pending(role)
            if self.sockets["dns"] is not None and self.sockets["dns"] in ready:
                self.receive_dns()
            if self.client is not None and self.record["clientStop"] is None and self.client.original in ready:
                self.observe_client()
            if 0 in ready:
                self.receive_control()
            if not self.completion["eof"] and self.next_byte is not None and time.monotonic() >= self.next_byte:
                self.send_byte()
        remaining()
        self.completion["primaryEmpty"] = self.no_pending("primary")
        if self.sockets["proxy"] is not None:
            self.completion["proxy"]["empty"] = self.no_pending("proxy")
        if self.sockets["dns"] is not None:
            self.receive_dns()  # Finite <=8; returns only on original EAGAIN.
            self.completion["dnsEmpty"] = True
            require(self.record["dnsQuestions"] > 0, "dns-question")
        if self.client is not None and self.record["clientStop"] is None:
            self.observe_client()  # Final original nonblocking observation.
        require(self.client is None or self.record["clientStop"] is not None, "client-stop")
        remaining()

    def withhold_handshake(self, context: ssl.SSLContext) -> None:
        self.client = self.accept(context)
        connection = self.client
        while True:
            remaining()
            try:
                connection.tls.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                if self.record["sni"] == 1 and connection.outgoing.pending > 0:
                    break
                require(connection.outgoing.pending == 0 and connection.read_bytes < WIRE_LIMIT, "tls-state")
                connection.original.settimeout(remaining())
                block = connection.original.recv(min(16384, WIRE_LIMIT - connection.read_bytes))
                remaining()
                require(bool(block), "tls-alert")
                connection.read_bytes += len(block)
                require(connection.incoming.write(block) == len(block), "tls-alert")
            else:
                raise Refused("tls-state")  # A completed handshake is not withheld.
        require(connection.written_bytes == 0 and self.record["handshakes"] == 0, "tls-state")
        self.record["withheldWireBytes"] = connection.outgoing.pending
        self.record["phase"] = "handshake"
        self.progress("client-hello")
        # Do not call receive()/flush()/respond()/unwrap(): the actual pending
        # server flight remains in this same MemoryBIO through client settlement.

    def run(self) -> None:
        directory = admit()  # Peer keeps FSIZE=0; the real probe must NOT inherit it.
        control = os.fstat(0)
        require(stat.S_ISFIFO(control.st_mode) and control.st_uid == os.geteuid(), "control")
        os.set_blocking(0, False)
        context = None
        if self.case != "T5-dns":
            certificate, key = directory / "api-valid.pem", directory / "server-key.pem"
            before = (fixed_body(certificate, FIXTURE_LIMIT), fixed_body(key, FIXTURE_LIMIT))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.keylog_filename = None
            context.set_alpn_protocols(["http/1.1"])
            context.load_cert_chain(str(certificate), str(key))
            require(before == (fixed_body(certificate, FIXTURE_LIMIT), fixed_body(key, FIXTURE_LIMIT)), "inputs")
            del before

            def server_name(_connection: ssl.SSLObject, name: str | None, _context: ssl.SSLContext) -> int | None:
                if name != HOST:
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
                self.record["sni"] += 1
                return None

            context.set_servername_callback(server_name)
        self.listen("primary", 443)
        if self.case.startswith("T4-"):
            self.listen("proxy", PROXY_PORT)
        if self.case == "T5-dns":
            self.sockets["dns"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sockets["dns"].bind(("127.0.0.1", 53))
            self.sockets["dns"].setblocking(False)
            self.record["phase"] = "dns"
        remaining()
        emit({**self.base, "state": "ready"})
        if self.case == "T5-handshake":
            self.withhold_handshake(context)
        elif self.case in {"T5-read", "T5-helper-read"}:
            self.client = self.accept(context)
            self.client.handshake()
            self.record["handshakes"] += 1
            self.client.request(b"/user", self.record)
            require(self.record["sni"] == 1, "tls-state")
            self.record["phase"] = "read"
            self.progress("first-get")
            headers = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                       b"Content-Length: " + str(len(TRICKLE_BODY)).encode("ascii") + b"\r\n\r\n")
            self.client.respond(headers, False)
            self.send_byte()
        elif self.case.startswith("T4-"):
            refused = self.case == "T4-ambient-no-rescue"
            schedule = script("T2-root" if refused else "T1-source")
            self.record["phase"] = "ambient"
            for index, (path, reply, clean) in enumerate(schedule):
                connection = self.accept(context)
                try:
                    try:
                        connection.handshake()
                        self.record["handshakes"] += 1
                        connection.request(path, self.record)
                        if self.record["requests"] == 1:
                            self.progress("first-get")
                    except ssl.SSLError as error:
                        require(refused and error.reason in AUTH_ALERTS
                                and self.record["handshakes"] == self.record["decryptedBytes"]
                                == self.record["requests"] == self.record["authBytes"] == 0, "tls-alert")
                        self.record["tlsRefused"] = True
                    require(self.record["sni"] == index + 1, "tls-state")
                    if refused:
                        require(self.record["tlsRefused"], "tls-alert")
                    else:
                        self.record["closeNotify"] += int(connection.respond(reply, clean))
                finally:
                    connection.close()
            require(self.record["connections"] == len(schedule), "script")
        self.finish_observation()

    def close(self) -> None:
        if self.close_claimed:
            return
        self.close_claimed = True

        def close_error() -> None:
            self.record["code"] = self.record["code"] or "close"

        unregistered_closed = self.unregistered is None
        if self.unregistered is not None:
            try:
                self.unregistered.close()
                unregistered_closed = True
            except BaseException:
                close_error()
        for connection in self.connections:
            try:
                connection.close()  # Original class refuses retry after uncertainty.
            except BaseException:
                close_error()
        for role, original in self.unexpected.items():
            if original is not None:
                try:
                    original.close()
                    self.unexpected_closed[role] = True
                except BaseException:
                    close_error()
        for role, original in self.sockets.items():
            if original is not None:
                try:
                    original.close()
                    self.closed[role] = True
                except BaseException:
                    close_error()
        if not self.control_close_claimed:
            self.control_close_claimed = True
            try:
                os.close(0)  # Original inherited pipe, never duplicated/reopened.
                self.completion["closed"] = True
            except BaseException:
                close_error()
        self.completion["primaryClosed"] = self.closed["primary"]
        if self.completion["proxy"] is not None:
            self.completion["proxy"]["closed"] = self.closed["proxy"]
        if self.case == "T5-dns":
            self.completion["dnsClosed"] = self.closed["dns"]
        self.record["wireReadBytes"] = [item.read_bytes for item in self.connections]
        self.record["wireWriteBytes"] = [item.written_bytes for item in self.connections]
        self.record["replyBytes"] = [item.reply_bytes for item in self.connections]
        self.record["allSocketsClosed"] = (self.sockets["primary"] is not None and unregistered_closed
            and all(item.closed for item in self.connections)
            and all(original is None or self.closed[role] for role, original in self.sockets.items())
            and all(original is None or self.unexpected_closed[role] for role, original in self.unexpected.items()))


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in DEADLINE_CASES:
        return original_main()  # Original sixteen scripts/frames/expectations unchanged.
    peer = DeadlinePeer(sys.argv[1])
    complete = False
    emission_failed = False
    try:
        peer.run()
        peer.record["code"] = None
        complete = True
    except Refused as error:
        peer.record["code"] = error.args[0]
    except (TimeoutError, socket.timeout):
        peer.record["code"] = "deadline"
    except ssl.SSLError:
        peer.record["code"] = "tls-alert"
    except OSError:
        peer.record["code"] = "tcp"
    except BaseException:
        peer.record["code"] = "internal"
    finally:
        peer.close()
        if complete and peer.record["code"] is None and peer.record["allSocketsClosed"] and peer.completion["closed"]:
            peer.record["status"] = "passed"
        try:
            emit(peer.record)
        except BaseException:
            emission_failed = True
    if emission_failed:
        return 74  # Preserve pending exceptions; parent still needs original joins.
    return 0 if peer.record["status"] == "passed" else 71


if __name__ == "__main__":
    raise SystemExit(main())
