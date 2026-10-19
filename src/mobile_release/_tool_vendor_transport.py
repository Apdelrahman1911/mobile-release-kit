"""One-use, tokenless HTTPS transfer for the four compiled public archives.

No networking imports, CA lookup or connection occurs on import/construction.
The native ToolAcquisition role must lend its admitted CA bytes and retain the
original child/driver/joins. This module cannot borrow a GitHub credential role.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Callable
from urllib.parse import urlsplit

from ._tool_acquisition_spec import AcquisitionError, Archive, CHUNK, PROFILES, require, vendor_url

HEADER_LIMIT = 32 * 1024
HEADER_LINE_LIMIT = 8192
HEADER_COUNT = 64
CA_LIMIT = 512 * 1024
_FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


@dataclass(frozen=True, slots=True)
class Head:
    status: int
    length: int | None
    location: str | None


def read_head(readline: Callable[[int], bytes], checkpoint: Callable[[], None]) -> Head:
    """Bounded DATA parser; no http.client defaults, folded fields or retries."""
    total = 0

    def line() -> bytes:
        nonlocal total
        checkpoint()
        value = readline(HEADER_LINE_LIMIT + 1)
        require(type(value) is bytes and len(value) <= HEADER_LINE_LIMIT and value.endswith(b"\r\n"), "framing")
        total += len(value)
        require(total <= HEADER_LIMIT, "framing")
        checkpoint()
        return value[:-2]

    first = line()
    require(re.fullmatch(rb"HTTP/1\.[01] [0-9]{3} [\x20-\x7e]*", first) is not None, "framing")
    status = int(first[9:12])
    fields: dict[bytes, list[bytes]] = {}
    for count in range(HEADER_COUNT + 1):
        value = line()
        if not value:
            break
        require(count < HEADER_COUNT, "framing")
        key, colon, content = value.partition(b":")
        require(bool(colon) and _FIELD.fullmatch(key) is not None
                and all(byte == 9 or 0x20 <= byte <= 0x7e for byte in content), "framing")
        key = key.lower()
        fields.setdefault(key, []).append(content.strip(b" \t"))
    else:
        raise AcquisitionError("framing")
    require(b"transfer-encoding" not in fields, "framing")
    require(fields.get(b"content-encoding", [b"identity"]) == [b"identity"], "framing")
    length = None
    if b"content-length" in fields:
        values = fields[b"content-length"]
        require(len(values) == 1 and re.fullmatch(rb"[0-9]{1,12}", values[0]) is not None, "framing")
        length = int(values[0])
    location = None
    if b"location" in fields:
        require(len(fields[b"location"]) == 1 and 0 < len(fields[b"location"][0]) <= 4096, "redirect")
        location = fields[b"location"][0].decode("ascii")
    return Head(status, length, location)


def redirect_target(original_host: str, location: str | None, count: int) -> tuple[str, str]:
    require(original_host == "github.com" and count == 0 and type(location) is str, "redirect")
    require(len(location) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in location)
            and "\\" not in location, "redirect")
    try:
        parsed = urlsplit(location)
        require(parsed.scheme == "https" and parsed.netloc in
                ("release-assets.githubusercontent.com", "release-assets.githubusercontent.com:443")
                and parsed.hostname == "release-assets.githubusercontent.com" and not parsed.fragment
                and len(parsed.path) <= 2048 and len(parsed.query) <= 2048, "redirect")
    except ValueError:
        raise AcquisitionError("redirect") from None
    require(re.fullmatch(r"/github-production-release-asset/[0-9A-Za-z_./-]+", parsed.path, re.ASCII) is not None
            and all(part not in ("", ".", "..") for part in parsed.path.split("/")[1:]), "redirect")
    # This service-generated query is never logged, cached or returned to the UI.
    return parsed.hostname, parsed.path + ("?" + parsed.query if parsed.query else "")


class PublicVendorTransfer:
    """Fixed GET only; original objects and ambiguous closes are retained.

    A write callback belongs to the same checked cache owner, not a request.
    Neither archive DATA nor a successful return establishes native finality.
    """
    def __init__(self, *, profile: str, ca_pem: bytes, deadline: float,
                 checkpoint: Callable[[], None]):
        require(type(profile) is str and profile in PROFILES)
        require(type(ca_pem) is bytes and 0 < len(ca_pem) <= CA_LIMIT)
        require(type(deadline) in (int, float) and time.monotonic() < deadline <= time.monotonic() + 1200)
        self.profile, self.ca_pem, self.deadline, self.checkpoint = profile, ca_pem, deadline, checkpoint
        self.originals: list[object] = []
        self.used: set[str] = set()
        self.unknown = False

    def _remaining(self) -> float:
        self.checkpoint()
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "cancelled")
        return min(10.0, remaining)

    def copy(self, archive: Archive, write: Callable[[bytes], None]) -> None:
        require(type(archive) is Archive and not self.unknown and archive.sha256 not in self.used, "already-used")
        host, path = vendor_url(archive.component, archive.url, self.profile)
        self._remaining()
        self.used.add(archive.sha256)  # Claim before imports, DNS or connection.
        import http.client
        import ssl

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.keylog_filename = None
            context.set_alpn_protocols(["http/1.1"])
            context.options &= ~getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0)
            context.load_verify_locations(cadata=self.ca_pem.decode("ascii"))
        except Exception:
            raise AcquisitionError("network") from None
        # Never default roots, urllib/netrc/proxy handlers or inherited tokens.
        for redirect in range(2):
            self._remaining()
            owner = self
            records: list[object] = []
            socket_slot: list[object | None] = [None]

            def checkpoint() -> None:
                timeout = owner._remaining()
                if socket_slot[0] is not None:
                    socket_slot[0].settimeout(timeout)

            class Response(http.client.HTTPResponse):
                def __init__(self, *args, **kwargs):
                    self.close_claimed = False
                    records.append(self)  # Before the stdlib acquires its file.
                    owner.originals.append(self)
                    try:
                        super().__init__(*args, **kwargs)
                    except BaseException:
                        owner.unknown = True
                        raise

                def begin(self):
                    if self.headers is not None:
                        return
                    self.head = read_head(self.fp.readline, checkpoint)
                    self.status = self.code = self.head.status
                    self.reason = ""
                    self.version = 11
                    self.headers = self.msg = http.client.HTTPMessage()
                    self.chunked = False
                    self.chunk_left = None
                    self.length = self.head.length
                    # We never reuse this connection. Keep sole explicit close
                    # custody instead of getresponse()'s eager will_close close.
                    self.will_close = False

                def close(self):
                    if self.close_claimed:
                        return
                    self.close_claimed = True
                    try:
                        super().close()
                    except BaseException:
                        owner.unknown = True
                        raise

            class Connection(http.client.HTTPSConnection):
                def __init__(self):
                    self.close_claimed = False
                    records.append(self)
                    owner.originals.append(self)
                    super().__init__(host, 443, timeout=owner._remaining(), context=context)
                    self.response_class = Response
                    self.auto_open = 0
                    self.set_debuglevel(0)

                def connect(self):
                    try:
                        http.client.HTTPConnection.connect(self)
                        socket_slot[0] = self.sock
                        checkpoint()
                        self.sock = context.wrap_socket(self.sock, server_hostname=host, suppress_ragged_eofs=False)
                        socket_slot[0] = self.sock
                        checkpoint()
                    except BaseException:
                        # A failed/interrupted creator is not proof that no
                        # original socket/file handoff happened. Parent native
                        # driver/joins contain the child; this role stays fenced.
                        owner.unknown = True
                        raise

                def close(self):
                    if self.close_claimed:
                        return
                    self.close_claimed = True
                    try:
                        super().close()
                    except BaseException:
                        owner.unknown = True
                        raise

            primary: BaseException | None = None
            next_target = None
            try:
                connection = Connection()
                connection.connect()
                checkpoint()
                connection.request("GET", path, headers={"Accept": "application/octet-stream",
                    "Accept-Encoding": "identity", "Connection": "close", "User-Agent": "MobileReleaseKit-ToolPreparation/1"})
                response = connection.getresponse()
                checkpoint()
                if response.head.status in (301, 302, 303, 307, 308):
                    next_target = redirect_target(host, response.head.location, redirect)
                else:
                    require(response.head.status == 200 and response.head.location is None, "network")
                    require(response.head.length == archive.size, "framing")
                    count = 0
                    while count < archive.size:
                        checkpoint()
                        data = response.fp.read(min(CHUNK, archive.size - count))
                        require(type(data) is bytes and 0 < len(data) <= min(CHUNK, archive.size - count), "framing")
                        checkpoint()
                        write(data)
                        count += len(data)
                    checkpoint()
                    require(response.fp.read(1) == b"", "framing")
                    checkpoint()
            except BaseException as error:
                primary = error
            finally:
                # Original objects retain their one-attempt close latches even
                # when the first close raises or another cleanup is attempted.
                for original in reversed(records):
                    try:
                        original.close()
                    except BaseException as error:
                        self.unknown = True
                        if primary is None:
                            primary = error
            if self.unknown:
                raise AcquisitionError("unknown") from None
            if primary is not None:
                if isinstance(primary, (AcquisitionError, KeyboardInterrupt, SystemExit)):
                    raise primary
                raise AcquisitionError("network") from None
            self._remaining()
            if next_target is None:
                return
            host, path = next_target
        raise AcquisitionError("redirect")
