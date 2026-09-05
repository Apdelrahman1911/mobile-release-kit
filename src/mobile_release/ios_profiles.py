"""Authenticated modern provisioning content; never a substitute for app signing.

Both CMS layers need independent Apple issuer authority before the existing typed
DER/plist comparison. Historical accepted-build recovery must retain its original
authenticated validation, not call this current-policy gate again.
"""
from __future__ import annotations

import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from sys import exc_info
from typing import Any

from .cancellation import CleanupScope, DefaultCancellation
from .errors import ValidationError
from .inspection import InspectionDeadline

MAX_PROFILE_BYTES = 4 * 1024 * 1024
COMPLETION_MAGIC = b"MRK-PROFILE-CMS\x01\n"
COMPLETION_MARKER = b"\x00MRK-CMS-COMPLETE\x01\n"
MAX_COMPLETION_BYTES = len(COMPLETION_MAGIC) + 4 + MAX_PROFILE_BYTES + len(COMPLETION_MARKER)
CAPTURE_SECONDS = 30
CLEANUP_SECONDS = 3
CLEANUP_RETRIES = 60
AUTHENTICATION_ERROR = (
    "Apple provisioning-profile signature or production issuer could not be authenticated; "
    "use a current Apple-issued profile and supported macOS toolkit, not a decode-only workaround"
)
BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from mobile_release.ios_profile_auth import main; raise SystemExit(main())"
)


def completion_frame(content: bytes) -> bytes:
    """Private trusted-child IPC; this framing is not Apple issuer authority."""
    if type(content) is not bytes or not 0 < len(content) <= MAX_PROFILE_BYTES:
        raise ValidationError("authenticated profile content exceeds its safety bound")
    return COMPLETION_MAGIC + len(content).to_bytes(4, "big") + content + COMPLETION_MARKER


def completed_content(frame: bytes) -> bytes:
    header = len(COMPLETION_MAGIC) + 4
    if type(frame) is bytes and header + len(COMPLETION_MARKER) < len(frame) <= MAX_COMPLETION_BYTES:
        size = int.from_bytes(frame[len(COMPLETION_MAGIC):header], "big")
        if (frame.startswith(COMPLETION_MAGIC) and 0 < size <= MAX_PROFILE_BYTES
                and len(frame) == header + size + len(COMPLETION_MARKER)
                and frame.endswith(COMPLETION_MARKER)):
            return frame[header:header + size]
    raise ValidationError(AUTHENTICATION_ERROR + "; missing or malformed private completion frame")


def _profile_cancellation() -> DefaultCancellation:
    return DefaultCancellation(
        ValidationError, "Apple profile cancellation handlers could not be restored; no upload is authorized",
    )


def _close_profile_descriptor(descriptor: int) -> None:
    # Ownership must be cleared BEFORE this call. An error may mean close took
    # effect; retrying this number could close a reused foreign descriptor.
    try:
        os.close(descriptor)
    except OSError:
        raise ValidationError("Apple profile descriptor cleanup could not be confirmed; end this process before retrying") from None


def read_profile_bytes(path: Path, *, maximum: int = MAX_PROFILE_BYTES) -> bytes:
    """Take one bounded no-follow snapshot with explicit raw descriptor ownership."""
    if type(maximum) is not int or not 0 < maximum <= MAX_PROFILE_BYTES:
        raise ValidationError("provisioning input read bound is invalid")
    descriptor = None
    cancellation = _profile_cancellation()

    def cleanup() -> None:
        nonlocal descriptor
        if descriptor is not None:
            closing, descriptor = descriptor, None
            _close_profile_descriptor(closing)

    scope = CleanupScope(cancellation, cleanup, owns_cancellation=True)
    try:
        with scope:
            cancellation.install()
            cancellation.activate()
            with cancellation.deferred():
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
                raise ValidationError("provisioning input must be a nonempty bounded regular file")
            content = bytearray()
            while len(content) <= maximum:
                chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(content) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in attributes):
                raise ValidationError("provisioning input changed while being inspected")
            return bytes(content)
    except OSError:
        raise ValidationError("provisioning input could not be read safely") from None
    finally:
        scope.__exit__(*exc_info())


def profile_environment(directory: Path) -> dict[str, str]:
    # Deliberately no user HOME, application PATH, runtime injection, keychain,
    # Store/OIDC capability, signing password or profile value in this boundary.
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(directory),
            "TMPDIR": str(directory), "LC_ALL": "C", "LANG": "C"}


def worker_command(mode: str, directory: Path, parent_pid: int | None = None) -> list[str]:
    command = [sys.executable, "-I", "-S", "-B", "-c", BOOTSTRAP,
               str(Path(__file__).resolve().parent.parent), mode, str(directory)]
    if parent_pid is not None:
        command.append(str(parent_pid))
    return command


def _reap_profile_group(process: subprocess.Popen) -> None:
    """Reconcile only the exact group we created; delivery alone is not absence."""
    expires = time.monotonic() + CLEANUP_SECONDS
    absent = False
    try:
        for _ in range(CLEANUP_RETRIES):
            if not absent:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    absent = True  # Never signal again after observed absence.
                except PermissionError:
                    # macOS returns EPERM for existing zombie-only groups. This
                    # is unresolved, not success: reap our leader, then retry.
                    pass
            remaining = expires - time.monotonic()
            if remaining <= 0:
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
            if absent and process.returncode is not None:
                return
            remaining = expires - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
    except (OSError, subprocess.SubprocessError):
        pass
    raise ValidationError("Apple profile worker cleanup could not be confirmed; no upload is authorized")


def _capture_profile(
    directory: Path, deadline: InspectionDeadline, *, cancellation: DefaultCancellation | None = None,
) -> bytes:
    """Own a separate supervisor group, including when spawn/IO is interrupted."""
    process = selector = None
    owns_cancellation = cancellation is None
    cancellation = cancellation if cancellation is not None else _profile_cancellation()
    output = bytearray()
    expires = time.monotonic() + CAPTURE_SECONDS

    def cleanup() -> None:
        nonlocal selector
        try:
            if selector is not None:
                closing, selector = selector, None
                try:
                    closing.close()
                except (OSError, ValueError):
                    raise ValidationError("Apple profile selector cleanup could not be confirmed") from None
        finally:
            if process is not None:
                try:
                    _reap_profile_group(process)
                finally:
                    if process.stdout is not None:
                        try:
                            process.stdout.close()
                        except (OSError, ValueError):
                            raise ValidationError("Apple profile worker output cleanup could not be confirmed") from None

    scope = CleanupScope(cancellation, cleanup, owns_cancellation=owns_cancellation)
    try:
        with scope:
            if owns_cancellation:
                cancellation.install()
                cancellation.activate()
            deadline.check()
            cancellation.check()
            # Protect native creation through assignment, not the capture loop.
            with cancellation.deferred():
                process = subprocess.Popen(
                    worker_command("--supervise", directory, os.getpid()), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env=profile_environment(directory), start_new_session=True,
                )
            assert process.stdout is not None
            with cancellation.deferred():
                selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                deadline.check()
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    raise ValidationError("Apple profile authentication timed out; no decode-only fallback is permitted")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_COMPLETION_BYTES:
                            raise ValidationError("authenticated profile content exceeds its safety bound")
            result = process.wait(timeout=max(0.01, expires - time.monotonic()))
            deadline.check()
            if time.monotonic() >= expires:
                raise ValidationError("Apple profile authentication timed out; no decode-only fallback is permitted")
            # A kill alone is not success: the exact complete frame, deadlines,
            # cancellation and confirmed group/handle cleanup are all required.
            if result != -signal.SIGKILL:
                raise ValidationError(AUTHENTICATION_ERROR)
            return completed_content(bytes(output))
    except (OSError, subprocess.SubprocessError):
        raise ValidationError("Apple profile authentication could not complete safely; no upload is authorized") from None
    finally:
        scope.__exit__(*exc_info())


def authenticate_cms(content: bytes, *, deadline: InspectionDeadline) -> bytes:
    deadline.check()
    if type(content) is not bytes or not 0 < len(content) <= MAX_PROFILE_BYTES:
        raise ValidationError("provisioning CMS input exceeds its supported bounds")
    if sys.platform != "darwin":
        raise ValidationError("Apple provisioning-profile authentication requires macOS")
    scratch = descriptor = None
    cancellation = _profile_cancellation()

    def cleanup() -> None:
        nonlocal descriptor
        try:
            if descriptor is not None:
                closing, descriptor = descriptor, None
                _close_profile_descriptor(closing)
        finally:
            if scratch is not None:
                try:
                    scratch.cleanup()
                except OSError:
                    raise ValidationError("Apple profile private workspace cleanup could not be confirmed") from None

    # Capture borrows this guard so scratch/source cleanup precedes restoration.
    # Parent SIGKILL/power loss can still leave the exact private owned directory.
    scope = CleanupScope(cancellation, cleanup, owns_cancellation=True)
    try:
        with scope:
            cancellation.install()
            cancellation.activate()
            with cancellation.deferred():
                scratch = tempfile.TemporaryDirectory(prefix="mobile-release-profile-auth-")
            directory = Path(scratch.name)
            with cancellation.deferred():
                descriptor = os.open(directory / "cms.der", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            remaining = memoryview(content)
            while remaining:
                chunk = remaining[:64 * 1024]
                count = os.write(descriptor, chunk)
                if not 0 < count <= len(chunk):
                    raise ValidationError("Apple profile private input could not be written completely")
                remaining = remaining[count:]
            with cancellation.deferred():
                closing, descriptor = descriptor, None
                _close_profile_descriptor(closing)
            return _capture_profile(directory, deadline, cancellation=cancellation)
    except OSError:
        raise ValidationError("Apple profile private input could not be prepared safely") from None
    finally:
        scope.__exit__(*exc_info())


def decode_authenticated_profile(content: bytes, *, deadline: InspectionDeadline | None = None) -> dict[str, Any]:
    from .ios_der import decode_der_dictionary
    from .ios_entitlements import correlate_profile, load_plist_dictionary

    deadline = deadline if deadline is not None else InspectionDeadline()
    outer = load_plist_dictionary(authenticate_cms(content, deadline=deadline), deadline=deadline)
    encoded = outer.get("DER-Encoded-Profile")
    if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_PROFILE_BYTES:
        raise ValidationError("modern iOS profile requires its authoritative DER-Encoded-Profile; legacy-only profiles are unsupported")
    authoritative = decode_der_dictionary(authenticate_cms(encoded, deadline=deadline), profile=True, deadline=deadline)
    return correlate_profile(outer, authoritative, deadline=deadline)


def load_authenticated_profile(path: Path, *, deadline: InspectionDeadline | None = None) -> dict[str, Any]:
    deadline = deadline if deadline is not None else InspectionDeadline()
    deadline.check()
    return decode_authenticated_profile(read_profile_bytes(path), deadline=deadline)
