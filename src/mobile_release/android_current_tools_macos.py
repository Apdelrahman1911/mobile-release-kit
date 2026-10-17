"""Three registered-Mac current-AAB readers under the existing command owner.

The request is nominated DATA, not native admission or release permission.
The local Execute parent still owns the full registered tree and SH lease.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import android_build_tools as common
from . import android_build_tools_macos as mac
from . import _store_lane_contract as wire
from .build_inputs import finite_scratch
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy
from .credentials import artifact_validation_environment
from .errors import ValidationError
from .owned_process import ProcessCleanupError, run_owned

REQUEST_LIMIT = 16 * 1024
READ_BYTES = 64 * 1024
# Seven original reads, each with its complete bounded no-follow ancestry.
ORIGINAL_LIMIT = 128
ROLES = ("bundletool", "jarsigner", "keytool")
NOMINAL_SECONDS = (60, 120, 30)
FAILURE = "registered current-AAB tooling could not be confirmed"


def need(value):
    if not value:
        raise ValidationError(FAILURE)


def request_data(raw: str):
    need(type(raw) is str and 0 < len(raw) <= REQUEST_LIMIT)
    value = mac._json(raw.encode("utf-8"), REQUEST_LIMIT, shaped=False)
    common._keys(value, {"schemaVersion", "toolchain", "runDeadlineNs", "hardDeadlineNs"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    endpoints = []
    for name in ("runDeadlineNs", "hardDeadlineNs"):
        item = value[name]
        need(type(item) is str and re.fullmatch(r"[1-9][0-9]{0,18}", item) is not None)
        endpoints.append(int(item))
    run, hard = endpoints
    now = time.monotonic_ns()
    need(now < run <= now + 3600 * 10**9 and hard - run == 5 * 10**9 and hard <= 2**63 - 1)
    selected = mac.binding(value["toolchain"])
    return selected, run, hard


def predecode(raw, checkpoint):
    """Allocation quote only; existing Mac JSON/schema parser remains authority."""
    need(type(raw) is bytes and 0 < len(raw) <= common.MAX_MANIFEST_BYTES)
    depth = nodes = 0
    quoted = escaped = primitive = False
    for index, byte in enumerate(raw):
        if index % READ_BYTES == 0:
            checkpoint()
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
            continue
        if byte == 34: quoted, primitive = True, False; nodes += 1
        elif byte in (91, 123): depth += 1; nodes += 1; primitive = False
        elif byte in (93, 125): depth -= 1; primitive = False
        elif byte in (9, 10, 13, 32, 44, 58): primitive = False
        elif not primitive: nodes += 1; primitive = True
        need(0 <= depth <= 16 and nodes <= common.MAX_MANIFEST_NODES)
    need(not quoted and not escaped and depth == 0)
    # Retained originals, worst-width decode/strings and transient pair/profile
    # objects; no fake external-owner budget and no post-allocation admission.
    quote = 13 * len(raw) + 256 * nodes + (8 << 20)
    need(quote <= 128 << 20)
    checkpoint()
    return quote


class RegisteredCurrentTools:
    """Fixed input originals and command observations; no new process owner."""

    def __init__(self, raw, scratch):
        self.binding, self.run_end, self.hard_end = request_data(raw)
        self.scratch, self.guard = scratch, scratch.cancellation
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.reader = _Reader(self.guard)
        self.headers, self.leaves = [], []
        self.profile = None
        self.pending = None
        self.commands = []
        self.failed = self.closed = self.close_claimed = False
        self.original_quote = 0

    def point(self, *, cleanup=False):
        need(self.pid == os.getpid() and self.thread is threading.current_thread())
        need(not self.closed and time.monotonic_ns() < (self.hard_end if cleanup else self.run_end))
        self.guard.check()
        if not cleanup:
            need(not self.failed and not self.close_claimed)
        self.scratch._check()

    def _join(self):
        expected = self.binding.identity
        roots = [n for n in self.reader.nodes if n.directory and str(n.canonical) == self.binding.root]
        need(bool(roots))
        for node in roots:
            observed = os.fstat(self.reader._number(node.slot))
            need(common._identity(observed, directory=True, stable_contents=False, mac=True)[:5] == expected)
        for node in self.reader.nodes:
            # Parent's native grant admits the entire tree; these originals
            # independently retain root-owned protected path/role correspondence.
            actual = os.fstat(self.reader._number(node.slot))
            need(common._identity(actual, directory=node.directory, stable_contents=not node.directory, mac=True)
                 == common._identity(node.observed, directory=node.directory, stable_contents=not node.directory, mac=True))
        self.reader.terminal()

    def _acquire(self, relative, maximum):
        path = Path(self.binding.root) / relative
        need(self.original_quote + len(path.parts) <= ORIGINAL_LIMIT)
        self.original_quote += len(path.parts)  # Before the first actual open.
        node = self.reader.acquire(path, _Policy(False, 1, maximum), None)
        self._join()
        return node

    def _bytes(self, node):
        os.lseek(self.reader._number(node.slot), 0, os.SEEK_SET)
        return self.reader.read(node)

    def _hash(self, node):
        fd = self.reader._number(node.slot)
        os.lseek(fd, 0, os.SEEK_SET)
        remaining, digest = node.observed.st_size, hashlib.sha256()
        while remaining:
            self.point(cleanup=True)
            chunk = os.read(fd, min(READ_BYTES, remaining))
            need(bool(chunk))
            digest.update(chunk)
            remaining -= len(chunk)
        need(os.read(fd, 1) == b"")
        return digest.hexdigest()

    def acquire(self):
        self.point()
        need(sys.platform == "darwin" and hasattr(os.stat_result, "st_flags"))
        platform = os.uname().machine
        need((self.binding.profile == mac.PROFILE and platform == "arm64") or
             (self.binding.profile == mac.INTEL_PROFILE and platform == "x86_64"))
        raw = []
        for name, cap in zip(mac.HEADERS, mac.HEADER_LIMITS):
            node = self._acquire(name, cap)
            content = self._bytes(node)
            self.headers.append((node, hashlib.sha256(content).hexdigest()))
            raw.append(content)
        for content in raw:
            predecode(content, self.point)
        self.profile = mac.parse_profile(raw[1], raw[2], raw[0], self.binding)
        roles = dict(self.profile.roles)
        names = (roles["java"], f"{self.profile.java_home}/bin/jarsigner",
                 f"{self.profile.java_home}/bin/keytool", roles["bundletool"])
        specs = {item.path: item for item in self.profile.files}
        need(len(set(names)) == 4)
        # All seven full walks fit the fixed original book before role opens.
        need(self.original_quote + sum(len((Path(self.binding.root)/name).parts) for name in names) <= ORIGINAL_LIMIT)
        for name in names:
            spec = specs[name]
            node = self._acquire(name, spec.size)
            self.leaves.append((node, spec.sha256))
            need(node.observed.st_size == spec.size and stat.S_IMODE(node.observed.st_mode) == spec.mode)
        self.post()

    def post(self):
        self.point(cleanup=True)
        self._join()
        for node, expected in (*self.headers, *self.leaves):
            need(self._hash(node) == expected)
        self._join()

    def _command_seal(self, evidence, role):
        # Called only by the existing CommandCallEvidence fixed-role hook.
        self.point()
        need(self.pending is not None and self.pending[0] is evidence and self.pending[1] == role)
        _, _, argv, environment, timing, nominal = self.pending
        need(self.commands[-1] is evidence)
        return argv, self.scratch._path, environment, timing, nominal

    def _command_timing(self, evidence):
        self.point()
        need(self.pending is not None and self.pending[0] is evidence)
        self._join()
        need(time.monotonic_ns() < self.pending[4].run)
        return self.pending[4]

    def _call(self, role, path):
        self.point()
        index = len(self.commands)
        need(index < len(ROLES) and role == ROLES[index] and self.profile is not None and self.pending is None)
        self.post()
        home = f"{self.binding.root}/{self.profile.java_home}"
        jvm = (*common._jvm_arguments(self.scratch._path, bundletool=True), "-XX:-UsePerfData")
        if role == "bundletool":
            argv = (f"{home}/bin/java", *jvm, "-jar", f"{self.binding.root}/{dict(self.profile.roles)['bundletool']}",
                    "dump", "manifest", f"--bundle={path}", "--module=base")
        else:
            args = ("-verify", "-strict", str(path)) if role == "jarsigner" else ("-printcert", "-jarfile", str(path))
            argv = (f"{home}/bin/{role}", *("-J" + arg for arg in jvm), *args)
        environment = artifact_validation_environment({"HOME": str(self.scratch._path), "TMPDIR": str(self.scratch._path),
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "JAVA_HOME": home})
        from ._command_process import CommandCallEvidence, CLEANUP_NS
        nominal = NOMINAL_SECONDS[index]
        run = min(self.run_end - CLEANUP_NS, time.monotonic_ns() + nominal * 10**9)
        need(time.monotonic_ns() < run)
        timing = wire.Timing(wire.clock_label(), run, run + CLEANUP_NS)
        evidence = CommandCallEvidence(self.guard)
        self.commands.append(evidence)
        self.pending = (evidence, role, argv, environment, timing, nominal)
        try:
            evidence._reserve_current_android(self, role)
            result = run_owned(argv, cwd=self.scratch._path, environ=environment, capture=True,
                timeout=nominal, output_limit=2 * 1024**2, cancellation=self.guard, _evidence=evidence)
            return result
        except BaseException:
            self.failed = True
            raise
        finally:
            self.pending = None
            # Read-only POST still attempted after a known command error. It
            # cannot turn unknown native finality into success or scratch cleanup.
            with self.guard.deferred(check_on_exit=False):
                try:
                    self.post()
                except BaseException:
                    self.failed = True
                    raise

    def manifest(self, path):
        result = self._call("bundletool", path)
        if result.returncode:
            self.failed = True
            raise ValidationError(FAILURE)
        return result.stdout

    def signature(self, path):
        from .android import _jar_signature_policy
        result = self._call("jarsigner", path)
        try:
            return _jar_signature_policy(result.returncode, result.stdout, result.stderr)
        except BaseException:
            self.failed = True
            raise

    def fingerprint(self, path):
        from .android import _keytool_fingerprint
        result = self._call("keytool", path)
        try:
            return _keytool_fingerprint(result.returncode, result.stdout)
        except BaseException:
            self.failed = True
            raise

    def validate(self, path, *, expected_application_id, release, expected_fingerprint):
        from .android import validate_aab_structure, _inspect_aab_contents
        from .reporting import Finding, Status
        names = validate_aab_structure(path)
        return _inspect_aab_contents(path, [Finding("android.aab.structure", Status.PASS,
            f"Validated {len(names)} final AAB entries.", category="android-artifact")],
            expected_application_id=expected_application_id, release=release,
            expected_fingerprint=expected_fingerprint, require_tools=True, check_signer=True,
            cancellation=self.guard, current_tools=self)

    def close(self):
        if self.close_claimed:
            need(self.closed)
            return
        self.close_claimed = True
        first = None
        with self.guard.deferred(check_on_exit=False):
            try:
                if self.reader.nodes:
                    self.post()
            except BaseException as error:
                first = error
            try:
                self.reader.close()
                self.reader.assert_closed()
                self.closed = True
            except BaseException as error:
                self.guard._abort(error)
                raise ProcessCleanupError(FAILURE) from None
        if first is not None:
            raise first


@contextmanager
def registered_current_tools(raw):
    request_data(raw)  # Refuse malformed/expired selection before scratch creation.
    with finite_scratch(layout="online-runner") as scratch:
        owner = RegisteredCurrentTools(raw, scratch)
        scope = CleanupScope(owner.guard, owner.close, owns_cancellation=False,
                             fork_cleanup=owner.reader.after_fork_child, first_primary=True)
        try:
            with scope:
                owner.acquire()
                yield owner
                owner.point()
                need(not owner.failed and len(owner.commands) == 3)
        finally:
            scope.__exit__(*sys.exc_info())
        need(owner.closed)
