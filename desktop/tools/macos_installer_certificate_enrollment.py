#!/usr/bin/env python3
"""Fixed Installer public-leaf bootstrap; no key extraction, import or signing.

Exact leaf extraction is not team, role, chain, private-key or signing proof.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import threading
import time

EXPECTED_SHA1 = "2176c921a318fd50510672b92022813c4e617fbd"
REF = "refs/heads/verify/desktop-macos-installer-certificate-enrollment"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
WORKFLOW = ".github/workflows/desktop-macos-installer-certificate-enrollment.yml"
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
TEMP = Path("/Users/runner/work/_temp")
SECRETS = ("MRK_MACOS_INSTALLER_P12_BASE64", "MRK_MACOS_INSTALLER_P12_PASSWORD")
P12_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 512 * 1024
DER_LIMIT = 16384
OPENSSL = "/usr/bin/openssl"


FAILURE_PHASES = ("entry", "admission", "inputs", "private-input", "pkcs12", "fingerprint", "x509", "private-cleanup", "publication")


class Refused(Exception):
    def __init__(self, phase=None):
        self.phase = phase if phase in FAILURE_PHASES else "entry"
        super().__init__()


def require(condition):
    if not condition:
        raise Refused()


def credentials(encoded, password):
    require(type(encoded) is str and 4 <= len(encoded) <= 4 * ((P12_LIMIT + 2) // 3)
            and encoded.isascii() and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded) is not None)
    require(type(password) is str and 0 < len(password) <= 4096
            and not any(c in password for c in "\x00\r\n"))
    password_bytes = password.encode("utf-8", errors="strict")
    require(len(password_bytes) <= 4096)
    body = base64.b64decode(encoded, validate=True)
    require(0 < len(body) <= P12_LIMIT and base64.b64encode(body).decode("ascii") == encoded)
    return body, password_bytes + b"\n"


def admit(environment):
    sha = environment.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != "0" * 40)
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_REF": REF, "GITHUB_WORKFLOW_SHA": sha,
                "GITHUB_WORKFLOW_REF": REPOSITORY + "/" + WORKFLOW + "@" + REF,
                "GITHUB_WORKSPACE": str(CHECKOUT), "MRK_EXPECTED_SHA": sha,
                "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "RUNNER_TEMP": str(TEMP)}
    require(all(environment.get(k) == v for k, v in expected.items()))
    require(all(type(environment.get(k)) is str and re.fullmatch(r"[1-9][0-9]{0,15}", environment[k])
                and int(environment[k]) <= 9007199254740991 for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")))
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0
            and os.getuid() == os.geteuid() and os.getgid() == os.getegid())
    require(Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_installer_certificate_enrollment.py")
    head = CHECKOUT / ".git/HEAD"
    require(stat.S_ISREG(head.lstat().st_mode) and head.stat().st_size == 41
            and head.read_bytes() == (sha + "\n").encode("ascii"))
    require(stat.S_ISDIR(TEMP.lstat().st_mode))
    output = TEMP / ("mrk-installer-public-" + sha + "-" + environment["GITHUB_RUN_ID"] + "-" + environment["GITHUB_RUN_ATTEMPT"])
    require(not os.path.lexists(output))
    return TEMP, output


def _file_output_limit():
    # Only this fixed child limit is changed after fork; the owner is single-threaded.
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))


def _clock(deadline):
    require(time.monotonic() < deadline)


def _run(argv, input_bytes, private, name, deadline):
    timeout = min(15.0, deadline - time.monotonic() - 5.0)
    require(timeout > 0 and threading.active_count() == 1)
    fd = os.open(private / name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "w+b", closefd=False) as output:
            # run() kills AND waits for this original child on timeout; stdout is
            # a capped regular file, stderr is never captured or published.
            result = subprocess.run(argv, input=input_bytes, stdout=output, stderr=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(private),
                                         "TMPDIR": str(private), "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
                                    cwd=private, shell=False, close_fds=True, timeout=timeout,
                                    preexec_fn=_file_output_limit, check=False)
            _clock(deadline)
            require(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
                    and result.returncode == 0 and tuple(result.args) == tuple(argv))
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1 and 0 < info.st_size <= OUTPUT_LIMIT)
            output.seek(0)
            body = output.read(OUTPUT_LIMIT + 1)
            after = os.fstat(fd)
            require(len(body) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
            return body
    finally:
        os.close(fd)


def select_leaf(pem):
    require(type(pem) is bytes and 0 < len(pem) <= OUTPUT_LIMIT)
    # Bag attributes are private uninterpreted text, never outputs. Any other
    # PEM object (including a key) or incomplete certificate block refuses.
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    require(pem.count(b"-----BEGIN ") == pem.count(begin)
            and pem.count(b"-----END ") == pem.count(end)
            and 1 <= pem.count(begin) == pem.count(end) <= 8)
    blocks = list(re.finditer(rb"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----", pem))
    require(len(blocks) == pem.count(begin))
    selected = []
    for block in blocks:
        encoded = block[1].replace(b"\r", b"").replace(b"\n", b"")
        require(0 < len(encoded) <= 4 * ((DER_LIMIT + 2) // 3))
        der = base64.b64decode(encoded, validate=True)
        require(0 < len(der) <= DER_LIMIT and base64.b64encode(der) == encoded)
        if hashlib.sha1(der).hexdigest() == EXPECTED_SHA1:
            selected.append(der)
    require(len(selected) == 1)
    return selected[0]


def _write(fd, body):
    offset = 0
    while offset < len(body):
        count = os.write(fd, body[offset:])
        require(type(count) is int and count > 0)
        offset += count
    os.fsync(fd)


def enroll(environment):
    deadline = time.monotonic() + 90.0
    # Pop both even when validation/admission later fails. No child inherits
    # either name; clearing references is NOT a claim of memory zeroization.
    encoded = environment.pop(SECRETS[0], None)
    password = environment.pop(SECRETS[1], None)
    body = password_input = None
    phase = "admission"
    try:
        require(threading.active_count() == 1)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        parent, public = admit(environment)
        phase = "inputs"
        body, password_input = credentials(encoded, password)
        encoded = password = None
        phase = "private-input"
        with tempfile.TemporaryDirectory(prefix="mrk-installer-certificate.", dir=parent) as name:
            private = Path(name)
            require(stat.S_IMODE(private.stat().st_mode) == 0o700)
            fd = os.open(private / "identity.p12", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                _write(fd, body)
                require(os.fstat(fd).st_size == len(body) and stat.S_IMODE(os.fstat(fd).st_mode) == 0o600)
            finally:
                os.close(fd)
            phase = "pkcs12"
            pem = _run([OPENSSL, "pkcs12", "-in", str(private / "identity.p12"), "-nokeys", "-passin", "stdin"],
                       password_input, private, "certificates.pem", deadline)
            body = password_input = None
            phase = "fingerprint"
            leaf = select_leaf(pem)
            pem = None
            phase = "x509"
            parsed = _run([OPENSSL, "x509", "-inform", "DER", "-outform", "DER"], leaf, private, "validated.der", deadline)
            require(parsed == leaf and hashlib.sha1(parsed).hexdigest() == EXPECTED_SHA1)
            _clock(deadline)
            phase = "private-cleanup"
        # Both actual subprocesses and every private file context ended; the
        # encrypted P12, bag attributes and private directory MUST be gone.
        require(not os.path.lexists(private))
        _clock(deadline)
        phase = "publication"
        os.mkdir(public, 0o700)  # Exclusive, never overwrite/adopt an earlier run.
        fd = os.open(public / "leaf.der", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            _write(fd, leaf)
            require(os.fstat(fd).st_size == len(leaf))
        finally:
            os.close(fd)
        _clock(deadline)
        return public / "leaf.der"
    except BaseException:
        raise Refused(phase) from None
    finally:
        encoded = password = body = password_input = None


def main():
    try:
        require(len(sys.argv) == 1)
        enroll(os.environ)
        return 0
    except BaseException as error:
        # Only the closed phase is public; never output, paths or exception text.
        phase = error.phase if type(error) is Refused and error.phase in FAILURE_PHASES else "entry"
        print("Public certificate enrollment refused: " + phase + ".", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
