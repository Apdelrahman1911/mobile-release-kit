"""Fixed-code issuer worker and independent lifetime supervisor. No Store access.

The supervisor never invokes native crypto itself. Its child and OpenSSL inherit
its owned group, so a killed outer Store validator cannot strand native work.
"""
from __future__ import annotations

import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from .errors import ValidationError
from .ios_profiles import (
    COMPLETION_MARKER, MAX_PROFILE_BYTES, completion_frame, profile_environment, read_profile_bytes, worker_command,
)
from .ios_profile_trust import MAX_CERTIFICATE_BYTES, MAX_CERTIFICATES, pem_certificates, require, verify_profile_signer

SUPERVISOR_SECONDS = 25
OPENSSL_SECONDS = 20
OID_DATA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
OID_SIGNED_DATA = OID_DATA[:-1] + b"\x02"
STRONG_DIGESTS = frozenset(b"\x60\x86\x48\x01\x65\x03\x04\x02" + bytes([index]) for index in (1, 2, 3))


def cms_payload_and_certificates(raw: bytes) -> tuple[bytes, tuple[bytes, ...]]:
    """Frame supported attached DER SignedData, without claiming crypto validity."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PROFILE_BYTES)

    def item(offset, end):
        require(offset + 2 <= end)
        start = offset
        tag, size = raw[offset:offset + 2]
        require(tag & 0x1f != 0x1f)
        offset += 2
        if size & 0x80:
            count = size & 0x7f
            require(0 < count <= 4 and offset + count <= end and raw[offset] != 0)
            size = int.from_bytes(raw[offset:offset + count], "big")
            require(size >= 128)
            offset += count
        require(size <= end - offset)
        return tag, offset, offset + size, start

    def children(container, maximum):
        _, position, end, _ = container
        result = []
        while position < end:
            require(len(result) < maximum)
            child = item(position, end)
            result.append(child)
            position = child[2]
        return result

    def content(node):
        return raw[node[1]:node[2]]

    def digest(node):
        require(node[0] == 0x30)
        algorithm = children(node, 2)
        require(1 <= len(algorithm) <= 2 and algorithm[0][0] == 6 and content(algorithm[0]) in STRONG_DIGESTS)
        require(len(algorithm) == 1 or (algorithm[1][0] == 5 and content(algorithm[1]) == b""))
        return content(algorithm[0])

    outer = item(0, len(raw))
    require(outer[0] == 0x30 and outer[2] == len(raw))
    parts = children(outer, 2)
    require(len(parts) == 2 and parts[0][0] == 6 and content(parts[0]) == OID_SIGNED_DATA and parts[1][0] == 0xa0)
    wrapped = children(parts[1], 1)
    require(len(wrapped) == 1 and wrapped[0][0] == 0x30)
    fields = children(wrapped[0], 6)
    require(5 <= len(fields) <= 6 and fields[0][0] == 2 and content(fields[0]) in (b"\x01", b"\x03"))
    require(fields[1][0] == 0x31)
    algorithms = children(fields[1], 1)
    require(len(algorithms) == 1)
    digest_oid = digest(algorithms[0])
    require(fields[2][0] == 0x30)
    encapsulated = children(fields[2], 2)
    require(len(encapsulated) == 2 and encapsulated[0][0] == 6 and content(encapsulated[0]) == OID_DATA and encapsulated[1][0] == 0xa0)
    payloads = children(encapsulated[1], 1)
    require(len(payloads) == 1 and payloads[0][0] == 4 and bool(content(payloads[0])))
    require(fields[3][0] == 0xa0 and fields[-1][0] == 0x31)
    if len(fields) == 6:
        require(fields[4][0] == 0xa1)  # Optional, bounded native-decoded CRLs; never independent authority.
        require(all(child[0] == 0x30 for child in children(fields[4], MAX_CERTIFICATES)))
    signers = children(fields[-1], 1)
    require(len(signers) == 1 and signers[0][0] == 0x30)
    signer_fields = children(signers[0], 7)
    require(5 <= len(signer_fields) <= 7 and signer_fields[0][0] == 2)
    require((content(signer_fields[0]), signer_fields[1][0]) in ((b"\x01", 0x30), (b"\x03", 0x80)))
    # Neither a strong unused DigestAlgorithms entry nor native defaults may
    # hide a weak SignerInfo digest. OpenSSL still authenticates the actual
    # signed attributes, signature algorithm, identifier and certificate.
    require(digest(signer_fields[2]) == digest_oid)
    cert_nodes = children(fields[3], MAX_CERTIFICATES)
    require(bool(cert_nodes) and all(node[0] == 0x30 and node[2] - node[3] <= MAX_CERTIFICATE_BYTES for node in cert_nodes))
    certificates = tuple(raw[node[3]:node[2]] for node in cert_nodes)
    require(len(set(certificates)) == len(certificates))
    return content(payloads[0]), certificates


def verify_cms(raw: bytes, directory: Path) -> bytes:
    payload, certificates = cms_payload_and_certificates(raw)
    source, output, signer_file = (directory / name for name in ("verify-input.der", "native-content.bin", "native-signer.pem"))
    require(not any(path.exists() or path.is_symlink() for path in (source, output, signer_file)))
    with source.open("xb") as handle:
        source.chmod(0o600)
        handle.write(raw)
    # -noverify disables ONLY certificate trust here. Signature verification is
    # mandatory; actual production-purpose issuer trust is a separate next gate.
    result = subprocess.run(
        ["/usr/bin/openssl", "cms", "-verify", "-binary", "-inform", "DER", "-noverify",
         "-in", str(source), "-out", str(output), "-signer", str(signer_file)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=profile_environment(directory), timeout=OPENSSL_SECONDS, check=False,
    )
    require(result.returncode == 0)
    require(read_profile_bytes(source) == raw and read_profile_bytes(output) == payload)
    signers = pem_certificates(read_profile_bytes(signer_file, maximum=MAX_CERTIFICATE_BYTES * 2))
    require(len(signers) == 1 and signers[0] in certificates)
    verify_profile_signer(signers[0], certificates)
    return payload


def _require_lifetime(parent_pid: int, expires: float) -> None:
    require(os.getppid() == parent_pid and time.monotonic() < expires)


def supervise(directory: Path, parent_pid: int) -> int:
    # Establish ownership before spawn or any input read. Calling this directly
    # inside somebody else's process group must NOT authorize killing that group.
    leader = os.getpid()
    if os.getpgrp() != leader or parent_pid <= 1:
        return 1
    expires = time.monotonic() + SUPERVISOR_SECONDS
    process = None
    try:
        _require_lifetime(parent_pid, expires)
        process = subprocess.Popen(
            worker_command("--worker", directory), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=profile_environment(directory),  # No new session/group: native descendants stay owned.
        )
        while process.poll() is None:
            _require_lifetime(parent_pid, expires)
            time.sleep(0.05)
        _require_lifetime(parent_pid, expires)
        require(process.returncode == 0)
        payload = read_profile_bytes(directory / "verified-content.bin")
        _require_lifetime(parent_pid, expires)
        descriptor = sys.stdout.fileno()
        os.set_blocking(descriptor, False)
        frame = completion_frame(payload)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_WRITE)
            # Separate the payload from the terminal success commit point. Every
            # authorization/lifetime check precedes completion of that marker;
            # once fully emitted, only unconditional cleanup remains.
            for part in (frame[:-len(COMPLETION_MARKER)], COMPLETION_MARKER):
                view = memoryview(part)
                while view:
                    _require_lifetime(parent_pid, expires)
                    for _, _ in selector.select(0.05):
                        _require_lifetime(parent_pid, expires)
                        try:
                            count = os.write(descriptor, view[:64 * 1024])
                        except BlockingIOError:
                            continue
                        require(count > 0)
                        view = view[count:]
        return 0
    finally:
        # Never delegate success cleanup solely to a parent which could die at
        # the handoff. The supervisor retains group ownership even after a fully
        # committed result and intentionally terminates itself with descendants.
        os.killpg(leader, signal.SIGKILL)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        require(len(arguments) in (2, 3))
        mode, name = arguments[:2]
        directory = Path(name)
        require(directory.is_absolute() and not directory.is_symlink() and directory.is_dir())
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700)
        os.umask(0o077)
        if mode == "--supervise" and len(arguments) == 3:
            return supervise(directory, int(arguments[2]))
        require(mode == "--worker" and len(arguments) == 2 and sys.platform == "darwin")
        payload = verify_cms(read_profile_bytes(directory / "cms.der"), directory)
        with (directory / "verified-content.bin").open("xb") as handle:
            handle.write(payload)
        return 0
    except (ValidationError, OSError, ValueError, subprocess.SubprocessError):
        # Nothing from native tools, profile values, paths or exceptions goes to logs.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
