"""Closed hosted Environment fixture, never a product/bootstrap fallback.

Only the reviewed native entry supplies core + one precreated control.json.
This file also contains the two fixed ordinary-owned targets. No arbitrary
argv, runner, resolver, environment enable or lifetime/result constructor exists.
"""
import sys
import time

# Count fixture imports, source checks and preparation in the original child
# allowance. Inert imports by contract tests do not even read this clock.
_ENTRY_STARTED = time.monotonic() if __name__ == "__main__" else None

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat


CONTROL_LIMIT = 65536
SOURCE_LIMIT = 512 * 1024
READY_MARKER = b"MRK_ENVIRONMENT_TARGET_READY_V1\n"
CAP_STDOUT, CAP_STDERR = 8192, 8193
CASES = frozenset({"L3a", "L3b", "L3c", "L3d", "L4", "L5"})
CONTROL_KEYS = frozenset({"schemaVersion", "case", "runId", "ownerGeneration", "context", "profile",
    "python", "core", "cwd", "projectRoot", "inputManifestSha256", "shimSha256", "observerSha256", "relayIdentity"})
CONTEXT_KEYS = frozenset({"projectId", "draftRevision", "baselineGeneration", "platform", "operation"})
PROFILES = {"linux-gnu-x86_64": ("linux", "x86_64"), "macos-arm64": ("darwin", "arm64")}
_ROOTS = []
_SUBJECT_STARTED = False
_ENGINE_OBSERVATION = None
_PAUSE = signal.pause
_CLI_MODE = False
_CLI_SETTLED = False
_CLI_STAGE = "entry"
_CLI_DIAGNOSTIC_WRITTEN = False
_CLI_DIAGNOSTIC_WRITE = os.write

# A closed compatibility selection, not a unittest discovery/CLI escape hatch.
OFFLINE_CLI_SCOPE = "offline-preflight-native-v1"
OFFLINE_CLI_IDS = (
    "tests.unit.test_cli_and_build.CliBuildTests.test_local_preflight_checks_receive_explicit_credentials_file_values",
    "tests.unit.test_cli_and_build.CliBuildTests.test_offline_build_reports_private_dependency_token_gate_before_gradle",
    "tests.unit.test_owned_process.CommandContractTests.test_adapter_passes_authoritative_objects_without_manufacturing_a_result",
    "tests.unit.test_default_cancellation.DefaultCancellationTests.test_pending_cancellation_preserves_body_or_cleanup_error_and_checks_only_normal_exit",
    "tests.unit.test_build_inputs.BuildInputTests.test_reserved_aliases_refuse_targets_and_early_project_admission",
    "tests.unit.test_config_discovery.ConfigDiscoveryTests.test_shared_version_text_parser_preserves_file_grammar_and_errors",
    "tests.unit.test_config_discovery.ConfigDiscoveryTests.test_empty_xcconfig_assignment_does_not_consume_next_line",
    "tests.unit.test_credentials_metadata.CredentialMetadataTests.test_android_metadata_isolated_from_ios_changes_and_secret_patterns",
    "tests.unit.test_android_release_notes.AndroidReleaseNotesTests.test_shared_corpus_checks_text_reader_and_preflight_without_normalization",
    "tests.unit.test_cli_and_build.CliBuildTests.test_application_artifact_check_receives_only_minimal_runtime_environment",
    "tests.unit.test_ios_correspondence.IOSPreflightCorrespondenceTests.test_project_artifact_check_cannot_modify_the_original_after_validation",
)
OFFLINE_CASES = ("PF01", "PF02", "PF03", "PF04a", "PF04b", "PF05a", "PF05b", "PF06", "PF07")
OFFLINE_CLI_BINDINGS = ("schemaVersion", "scope", "inputsSha256", "sourceSha", "sourceTree", "runId",
                        "attempt", "platform", "startedNs", "deadlineNs")
OFFLINE_CLI_CONTROL_KEYS = frozenset((*OFFLINE_CLI_BINDINGS, "python", "core", "source", "root"))
OFFLINE_CLI_STAGES = frozenset(("entry", "source-admission", "imports", "saved-configs", "selection",
    "progress", "restoration", "result", "clock-restoration", *(f"leaf-{number}" for number in range(1, 12))))


def _offline_cli_diagnostic(kind):
    """One best-effort fixed diagnostic on original stderr, never a receipt."""
    global _CLI_DIAGNOSTIC_WRITTEN
    if not _CLI_MODE or _CLI_DIAGNOSTIC_WRITTEN:
        return
    _CLI_DIAGNOSTIC_WRITTEN = True  # No retry, even after a lost/partial write.
    stage = _CLI_STAGE if _CLI_STAGE in OFFLINE_CLI_STAGES else "entry"
    if kind not in {"deadline", "test-failed", "admission-failed", "unsettled-originals", "restoration-failed"}:
        kind = "admission-failed"
    raw = f"OFFLINE_CLI11_FAILURE stage={stage} kind={kind}\n".encode("ascii")
    try:
        _CLI_DIAGNOSTIC_WRITE(2, raw)
    except BaseException:
        pass  # Reporting cannot replace the primary error or authorize cleanup.


class RetainedUnknown(BaseException):
    """Original custody cannot be released by an exception reporter."""


class OfflineCLIDeadline(Exception):
    """An ordinary failure for unittest; the separate deadline latch is final."""


class OfflineCLIUnknown(RetainedUnknown, KeyboardInterrupt):
    """Unittest must unwind immediately, not run more cleanup callbacks."""


def require(value):
    if not value:
        raise AssertionError("fixed Environment fixture refused")


def hexadecimal(value, width):
    return type(value) is str and len(value) == width and all(c in "0123456789abcdef" for c in value)


def absolute(value):
    return (type(value) is str and value.startswith("/") and len(value) <= 4096
            and all(ord(c) >= 32 and ord(c) != 127 and c != "\\" for c in value)
            and all(part and part not in {".", ".."} for part in value[1:].split("/")))


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _constant(_value):
    raise AssertionError("non-finite fixture DATA")


def parse_control(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CONTROL_LIMIT)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    require(type(value) is dict and set(value) == CONTROL_KEYS
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["case"]) is str and value["case"] in CASES
            and hexadecimal(value["runId"], 32) and hexadecimal(value["ownerGeneration"], 32)
            and type(value["profile"]) is str and value["profile"] in PROFILES
            and all(absolute(value[key]) for key in ("python", "core", "cwd", "projectRoot"))
            and all(hexadecimal(value[key], 64) for key in ("inputManifestSha256", "shimSha256", "observerSha256")))
    context, identity = value["context"], value["relayIdentity"]
    require(type(context) is dict and set(context) == CONTEXT_KEYS
            and type(context["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", context["projectId"]) is not None
            and all(type(context[key]) is int and 0 <= context[key] < 2**32 - 1 for key in ("draftRevision", "baselineGeneration"))
            and context["platform"] == "android" and context["operation"] == "build"
            and type(identity) is list and len(identity) == 4
            and all(type(part) is int and part >= 0 for part in identity)
            and stat.S_ISREG(identity[3]) and stat.S_IMODE(identity[3]) == 0o600)
    return value


class ReadSlot:
    """One preregistered source/control read and one observed original close."""
    def __init__(self):
        self.fd, self.state = None, "NEW"
        self.identity, self.error = None, None
        self.open, self.read, self.fstat, self.close = os.open, os.read, os.fstat, os.close
        _ROOTS.append(self)

    @staticmethod
    def facts(details):
        return (details.st_dev, details.st_ino, details.st_mode, details.st_uid, details.st_gid,
                details.st_nlink, details.st_size, details.st_mtime_ns, details.st_ctime_ns)

    def content(self, path, limit, *, mode=None):
        require(self.state == "NEW" and absolute(str(path)))
        self.state = "OPENING"
        try:
            self.fd = self.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            self.state = "OPEN"
            details = self.fstat(self.fd)
            self.identity = self.facts(details)
            require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1 and details.st_uid == os.getuid()
                    and 0 <= details.st_size <= limit and stat.S_IMODE(details.st_mode) & 0o022 == 0
                    and (mode is None or stat.S_IMODE(details.st_mode) == mode))
            content = bytearray()
            while len(content) <= limit:
                chunk = self.read(self.fd, min(65536, limit + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            require(len(content) == details.st_size and self.facts(self.fstat(self.fd)) == self.identity)
            return bytes(content)
        except BaseException as error:
            self.error = error
            raise
        finally:
            if self.state == "OPEN":
                descriptor, self.fd = self.fd, None
                self.state = "UNKNOWN"
                try:
                    self.close(descriptor)
                    self.state = "CLOSED"
                except BaseException as error:
                    if self.error is None:
                        self.error = error
            if self.state != "CLOSED":
                raise RetainedUnknown()


def _runtime_flags():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and sys.version_info[:3] == (3, 14, 7) and os.name == "posix"
            and sys.platform in {"linux", "darwin"} and os.getuid() != 0)


def parse_offline_cli_control(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CONTROL_LIMIT)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    require(type(value) is dict and set(value) == OFFLINE_CLI_CONTROL_KEYS
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == OFFLINE_CLI_SCOPE and value["platform"] in {"linux", "macos"}
            and hexadecimal(value["inputsSha256"], 64)
            and all(hexadecimal(value[key], 40) and value[key] != "0" * 40 for key in ("sourceSha", "sourceTree"))
            and all(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]) is not None
                    for key in ("runId", "attempt"))
            and all(absolute(value[key]) for key in ("python", "core", "source", "root"))
            and value["core"] == value["source"] + "/src"
            and all(type(value[key]) is int and 0 < value[key] < 2**63 for key in ("startedNs", "deadlineNs"))
            and value["deadlineNs"] - value["startedNs"] == 90_000_000_000)
    return value


def offline_saved_configs(value):
    """Byte correspondence only; the existing core parses these exact texts."""
    require(type(value) is list and len(value) == len(OFFLINE_CASES))
    for row, label in zip(value, OFFLINE_CASES):
        require(type(row) is dict and set(row) == {"case", "rawText", "size", "sha256"}
                and row["case"] == label and type(row["rawText"]) is str
                and type(row["size"]) is int and 0 < row["size"] <= 32768
                and hexadecimal(row["sha256"], 64))
        content = row["rawText"].encode("utf-8", "strict")
        require(len(content) == row["size"] and hashlib.sha256(content).hexdigest() == row["sha256"])
    return value


class OfflineCLIClock:
    """One original absolute endpoint; no subprocess, timer thread or renewal."""
    def __init__(self, started, deadline):
        self.started, self.deadline = started, deadline
        self.expired, self.state = False, "NEW"
        self.now = time.monotonic_ns
        self.getsignal, self.signal = signal.getsignal, signal.signal
        self.gettimer, self.timer = signal.getitimer, signal.setitimer
        self.previous = None
        self.handler = self.expire
        _ROOTS.append(self)

    def expire(self, _number, _frame):
        self.expired = True
        raise OfflineCLIDeadline("closed CLI11 aggregate deadline")

    def check(self):
        if self.expired or self.now() >= self.deadline:
            self.expire(None, None)

    def install(self):
        require(self.state == "NEW" and self.started <= self.now())
        self.check()
        require(self.gettimer(signal.ITIMER_REAL) == (0.0, 0.0))
        self.previous = self.getsignal(signal.SIGALRM)
        require(self.previous == signal.SIG_DFL)
        self.state = "UNKNOWN"
        require(self.signal(signal.SIGALRM, self.handler) == self.previous)
        require(self.timer(signal.ITIMER_REAL, max(1, self.deadline - self.now()) / 1_000_000_000) == (0.0, 0.0))
        self.state = "ACTIVE"

    def finish(self):
        require(self.state == "ACTIVE" and self.getsignal(signal.SIGALRM) is self.handler)
        self.state = "UNKNOWN"
        self.timer(signal.ITIMER_REAL, 0.0)
        require(self.signal(signal.SIGALRM, self.previous) is self.handler)
        self.state = "CLOSED"


class OfflineCLIWrite:
    """One exclusive bounded report and actual original close, never a retry."""
    def __init__(self):
        self.fd, self.state = None, "NEW"
        _ROOTS.append(self)

    def write(self, path, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        require(self.state == "NEW" and len(raw) <= 32768)
        self.state = "OPENING"
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        self.state = "OPEN"
        primary = None
        try:
            remaining = memoryview(raw)
            while remaining:
                count = os.write(self.fd, remaining)
                require(type(count) is int and 0 < count <= len(remaining))
                remaining = remaining[count:]
        except BaseException as error:
            primary = error
            raise
        finally:
            number, self.fd = self.fd, None
            self.state = "UNKNOWN"
            try:
                os.close(number)
                self.state = "CLOSED"
            except BaseException as error:
                _ROOTS.append(error)
                if primary is None:
                    raise RetainedUnknown() from error
        require(self.state == "CLOSED" and ReadSlot().content(str(path), 32768, mode=0o600) == raw)


class OfflineIterator:
    """Borrow one original scandir iterator below glob's error-catching layer."""
    def __init__(self, row, original):
        self.row, self.original = row, original

    def __iter__(self):
        return self

    def __next__(self):
        if self.row["state"] == "CLOSED":
            raise StopIteration
        require(self.row["state"] == "OPEN")
        try:
            return next(self.original)
        except StopIteration:
            self.close()  # Observe the original public close return as well.
            raise
        except BaseException as error:
            self.row["error"] = error
            raise

    def __enter__(self):
        require(self.row["state"] == "OPEN")
        require(self.original.__enter__() is self.original)
        return self

    def close(self):
        if self.row["state"] == "CLOSED":
            return
        require(self.row["state"] == "OPEN")
        self.row["state"] = "UNKNOWN"
        result = self.original.close()
        self.row["state"] = "CLOSED"
        return result

    def __exit__(self, *error):
        if self.row["state"] == "CLOSED":
            return False
        require(self.row["state"] == "OPEN")
        self.row["state"] = "UNKNOWN"
        result = self.original.__exit__(*error)
        self.row["state"] = "CLOSED"
        return result


class OfflineContext:
    """Retain the original manager and its real entry/exit, including failures."""
    def __init__(self, row, original, before_exit=None):
        self.row, self.original, self.before_exit = row, original, before_exit

    def __enter__(self):
        self.row["state"] = "UNKNOWN"
        result = self.original.__enter__()
        self.row["state"] = "OPEN"
        return result

    def __exit__(self, *error):
        require(self.row["state"] == "OPEN")
        if self.before_exit is not None:
            self.before_exit()
        self.row["state"] = "UNKNOWN"
        result = self.original.__exit__(*error)
        self.row["state"] = "CLOSED"
        return result


class OfflineCLIObservation:
    """Observe the fixed tests' original owners, never create a process owner.

    os.open/mkdir/link/close MUST remain the real builtins: build-input refusal
    evidence deliberately checks their identity. File streams retain their
    original types/objects; their close observer invokes the already-bound
    original method. A runtime that bypasses that observer cannot pass.
    """
    def __init__(self, command, inputs, cancellation, temporary, clock):
        self.command, self.inputs, self.guard_type = command, inputs, cancellation
        self.temporary, self.clock = temporary, clock
        self.commands, self.active, self.guards, self.invocations = [], [], [], []
        self.resources, self.temps, self.patches = [], [], []
        self.closed, self.opening = False, 0
        self.original_run, self.original_publish = command.run_command, command._Outer.publish
        self.original_guard, self.original_invocation = cancellation.__init__, inputs.InvocationCustody.__init__
        self.original_temp_init, self.original_temp_cleanup = temporary.TemporaryDirectory.__init__, temporary.TemporaryDirectory.cleanup
        self.original_fd_init = inputs._FD.__init__
        _ROOTS.append(self)

    def counts(self):
        return len(self.commands), len(self.invocations), len(self.guards)

    def mark(self):
        return len(self.invocations), len(self.guards), len(self.resources)

    def row(self, kind, owner=None):
        self.clock.check()
        require(len(self.resources) < 8192)
        row = {"kind": kind, "owner": owner, "state": "OPENING"}
        self.resources.append(row)  # Before the original acquisition.
        return row

    def patch(self, owner, name, replacement):
        original = getattr(owner, name)
        self.patches.append((owner, name, original, replacement))
        setattr(owner, name, replacement)

    def command_call(self, *args, **kwargs):
        self.clock.check()
        require(len(self.commands) < 256)
        index = len(self.commands)
        self.commands.append(None)
        self.active.append(index)
        try:
            return self.original_run(*args, **kwargs)
        finally:
            require(self.active.pop() == index)

    def publish(self, engine):
        outcome = self.original_publish(engine)
        require(self.active and self.commands[self.active[-1]] is None and engine.slot.read() is outcome)
        self.commands[self.active[-1]] = outcome
        return outcome

    def stream(self, row, value):
        row["owner"] = value  # Hold the actual returned object, never a proxy.
        row["state"] = "OPEN"
        original = value.close

        def close():
            if row["state"] == "CLOSED":
                return None  # No second original call, including finalizers.
            if row["state"] != "OPEN":
                raise RetainedUnknown()
            row["state"] = "UNKNOWN"
            result = original()
            require(value.closed is True)
            row["state"] = "CLOSED"
            return result

        # Original IOBase/Zip member context exits must dispatch through this
        # actual object's close. A read-only/unsupported attribute is refusal.
        value.close = close
        require(value.close is close)
        row["close"] = close
        return value

    def opener(self, original, *, descriptor=False):
        def opened(*args, **kwargs):
            if self.active or self.opening:
                return original(*args, **kwargs)
            row = self.row("stream")
            self.opening += 1
            try:
                value = original(*args, **kwargs)
            except OSError as error:
                # Only a direct named builtin refusal establishes no file. A
                # failed FD->file handoff is never that receipt.
                if (not descriptor and error.errno in {2, 13, 17, 20, 21, 30, 36, 40}
                        and error.__traceback__.tb_next is None):
                    row["state"] = "CLOSED"
                raise
            finally:
                self.opening -= 1
            return self.stream(row, value)
        return opened

    def scanner(self, original):
        def scanned(*args, **kwargs):
            if self.active:
                return original(*args, **kwargs)
            row = self.row("iterator")
            value = original(*args, **kwargs)
            row["owner"], row["state"] = value, "OPEN"
            adapter = OfflineIterator(row, value)
            row["adapter"] = adapter
            return adapter
        return scanned

    def context(self, original, *, facility=False):
        def manager(*args, **kwargs):
            mark = self.mark()
            row = self.row("facility" if facility else "descriptor-context")
            value = original(*args, **kwargs)
            row["owner"] = value
            gate = (lambda: self.require_closed(mark, ignore=row)) if facility else None
            adapter = OfflineContext(row, value, gate)
            row["adapter"] = adapter
            return adapter
        return manager

    def synchronous(self, original):
        # The exact valid-config / Mach-O paths have no swallowed close error.
        # Unexpected exceptions keep the original frame rooted and prohibit
        # fixture deletion; they are not converted into positive no-effect.
        def called(*args, **kwargs):
            row = self.row("synchronous-context")
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                row["error"] = error
                raise
            row["state"] = "CLOSED"
            return result
        return called

    def resources_closed(self, start, *, ignore=None):
        for row in self.resources[start:]:
            if row is ignore:
                continue
            if row["kind"] == "build-fd":
                value = row["owner"]
                if (row["state"] != "OPEN" or value.number is not None
                        or value.close_state != "CLOSED"):
                    return False
            elif row["state"] != "CLOSED":
                return False
        return True

    def scan_failed(self):
        # glob can swallow an iteration error and still close its iterator.
        # Closure permits settlement/owned cleanup, never a successful leaf or
        # another test. Keep the original error latched after CLOSED.
        return any(row["kind"] == "iterator" and "error" in row for row in self.resources)

    def require_closed(self, mark=(0, 0, 0), *, ignore=None):
        try:
            require(not self.active and not self.command._RETAINED
                    and all(value is not None and value.original_finality is not None for value in self.commands))
            for row in self.invocations[mark[0]:]:
                require(row["ready"] and row["owner"]._offline_preflight_closed(row["owner"].cancellation))
            for row in self.guards[mark[1]:]:
                guard = row["owner"]
                require(row["ready"])
                verdict = guard.lifetime_ledger.verdict()
                require(verdict.complete and not verdict.fatal and verdict.contained and verdict.cleanup_complete
                        and verdict.profile_calls == 0 and guard.handler_state in {"RESTORED", "NOT_INSTALLED"})
            require(self.resources_closed(mark[2], ignore=ignore))
        except BaseException as error:
            _ROOTS.append(error)
            raise OfflineCLIUnknown() from error

    def install(self, *, builtins, io, zipfile, config, macho, artifacts, metadata):
        def guard_init(actual, *args, **kwargs):
            self.clock.check()
            require(len(self.guards) < 256)
            row = {"owner": actual, "ready": False}
            self.guards.append(row)
            self.original_guard(actual, *args, **kwargs)
            row["ready"] = True

        def invocation_init(actual, *args, **kwargs):
            self.clock.check()
            require(len(self.invocations) < 128)
            row = {"owner": actual, "ready": False}
            self.invocations.append(row)
            self.original_invocation(actual, *args, **kwargs)
            row["ready"] = True

        def fd_init(actual, *args, **kwargs):
            row = self.row("build-fd", actual)
            self.original_fd_init(actual, *args, **kwargs)
            row["state"] = "OPEN"

        def temp_init(actual, *args, **kwargs):
            self.clock.check()
            require(len(self.temps) < 64)
            row = {"owner": actual, "mark": self.mark(), "state": "OPENING"}
            self.temps.append(row)  # Also retains its original finalizer.
            self.original_temp_init(actual, *args, **kwargs)
            row["identity"] = ReadSlot.facts(os.lstat(actual.name))
            row["state"] = "OPEN"

        def temp_cleanup(actual):
            rows = [row for row in self.temps if row["owner"] is actual]
            require(len(rows) == 1)
            row = rows[0]
            if row["state"] == "CLOSED":
                return
            require(row["state"] == "OPEN")
            self.require_closed(row["mark"])
            details = os.lstat(actual.name)
            # Directory mtime/size change as fixtures are written; identity,
            # owner and mode may not. No pathname alone grants deletion.
            require(ReadSlot.facts(details)[:5] == row["identity"][:5]
                    and stat.S_ISDIR(details.st_mode) and stat.S_IMODE(details.st_mode) == 0o700)
            row["state"] = "UNKNOWN"
            self.original_temp_cleanup(actual)
            self.require_closed(row["mark"])  # Includes rmtree's own iterators/FDs.
            require(not os.path.lexists(actual.name))
            row["state"] = "CLOSED"

        archive_init, archive_close, archive_open = zipfile.ZipFile.__init__, zipfile.ZipFile.close, zipfile.ZipFile.open

        def zip_init(actual, *args, **kwargs):
            row = self.row("archive", actual)
            archive_init(actual, *args, **kwargs)
            row["state"] = "OPEN"

        def zip_close(actual):
            rows = [row for row in self.resources if row["kind"] == "archive" and row["owner"] is actual]
            require(len(rows) == 1)
            row = rows[0]
            if row["state"] == "CLOSED":
                return
            require(row["state"] in {"OPENING", "OPEN"})
            row["state"] = "UNKNOWN"
            result = archive_close(actual)
            require(actual.fp is None and actual._fileRefCnt == 0 and not actual._writing)
            row["state"] = "CLOSED"
            return result

        def zip_open(actual, *args, **kwargs):
            row = self.row("archive-member")
            return self.stream(row, archive_open(actual, *args, **kwargs))

        def published(actual):
            return self.publish(actual)

        read_note = metadata._read_android_release_note

        def note(*args, **kwargs):
            row = self.row("note-handoff")
            start = len(self.resources)
            try:
                return read_note(*args, **kwargs)
            finally:
                # Invalid UTF/text is checked AFTER this exact returned stream
                # closed. The raw os.open -> fdopen gap is not silently lost.
                if (any(value["kind"] == "stream" for value in self.resources[start:])
                        and self.resources_closed(start)):
                    row["state"] = "CLOSED"

        self.patch(self.command, "run_command", self.command_call)
        self.patch(self.command._Outer, "publish", published)
        self.patch(self.guard_type, "__init__", guard_init)
        self.patch(self.inputs.InvocationCustody, "__init__", invocation_init)
        self.patch(self.inputs._FD, "__init__", fd_init)
        self.patch(self.temporary.TemporaryDirectory, "__init__", temp_init)
        self.patch(self.temporary.TemporaryDirectory, "cleanup", temp_cleanup)
        self.patch(builtins, "open", self.opener(builtins.open))
        self.patch(io, "open", self.opener(io.open))
        self.patch(os, "fdopen", self.opener(os.fdopen, descriptor=True))
        self.patch(os, "scandir", self.scanner(os.scandir))
        self.patch(zipfile.ZipFile, "__init__", zip_init)
        self.patch(zipfile.ZipFile, "close", zip_close)
        self.patch(zipfile.ZipFile, "open", zip_open)
        self.patch(config, "load_config", self.synchronous(config.load_config))
        wrapped_macho = self.synchronous(macho.inspect_macho)
        require(artifacts.inspect_macho is macho.inspect_macho)
        self.patch(macho, "inspect_macho", wrapped_macho)
        self.patch(artifacts, "inspect_macho", wrapped_macho)
        self.patch(artifacts, "_source_descriptor", self.context(artifacts._source_descriptor))
        self.patch(metadata, "_read_android_release_note", note)

    def leaf_closed(self):
        self.require_closed()
        require(all(row["state"] == "CLOSED" for row in self.temps)
                and self.inputs._ENV_OWNER is None and self.inputs._ENV_TAINTED is False)
        require(all(getattr(owner, name) is replacement for owner, name, _original, replacement in self.patches))

    def restore(self):
        self.leaf_closed()
        for owner, name, original, replacement in reversed(self.patches):
            require(getattr(owner, name) is replacement)
            setattr(owner, name, original)
        self.closed = True


def _offline_cli_admit(core, control_path, value):
    _runtime_flags()
    require(absolute(core) and absolute(control_path) and Path(control_path).name == "offline-cli11-control.json")
    root, source = Path(value["root"]), Path(value["source"])
    scratch = root / "offline-cli11"
    platform = "linux" if sys.platform == "linux" else "macos"
    require(Path(control_path).parent == root and core == value["core"]
            and value["python"] == os.path.abspath(sys.executable) and value["platform"] == platform
            and os.getcwd() == str(scratch) and Path(__file__) == source / "tests/native_desktop_environment.py"
            and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("MRK_DESKTOP_HOSTED_CHECKS") == OFFLINE_CLI_SCOPE
            and os.environ.get("GITHUB_SHA") == value["sourceSha"]
            and os.environ.get("GITHUB_RUN_ID") == value["runId"]
            and os.environ.get("GITHUB_RUN_ATTEMPT") == value["attempt"]
            and os.environ.get("GITHUB_REF") == ("refs/heads/verify/desktop-offline-preflight-native"
                + ("-macos" if platform == "macos" else "")))
    raw = ReadSlot().content(str(root / "environment-native-inputs.json"), 256 * 1024, mode=0o600)
    require(hashlib.sha256(raw).hexdigest() == value["inputsSha256"])
    inputs = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    require(type(inputs) is dict and inputs["schemaVersion"] == 1
            and all(inputs[key] == value[key] for key in
                    ("scope", "sourceSha", "sourceTree", "runId", "attempt", "platform", "root", "source", "python")))
    for key, path in (("root", root), ("source", source), ("offline-cli11", scratch)):
        details = path.lstat()
        require(stat.S_ISDIR(details.st_mode) and details.st_uid == os.getuid()
                and not stat.S_IMODE(details.st_mode) & 0o022)
        expected = inputs["originalDirectories"][key]
        require(expected == {"device": str(details.st_dev), "inode": str(details.st_ino),
                             "mode": details.st_mode, "uid": details.st_uid, "gid": details.st_gid})
    require(stat.S_IMODE(scratch.lstat().st_mode) == 0o700 and not tuple(scratch.iterdir()))
    rows = inputs["sourceFiles"]
    require(type(rows) is list and 0 < len(rows) <= 2048)
    names, size = [], 0
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "size", "sha256"}
                and type(row["path"]) is str and re.fullmatch(r"[A-Za-z0-9_./-]+", row["path"]) is not None
                and not row["path"].startswith("/") and not any(part in {"", ".", ".."} for part in row["path"].split("/"))
                and type(row["size"]) is int and 0 <= row["size"] <= 8 * 1024 * 1024
                and hexadecimal(row["sha256"], 64))
        size += row["size"]
        require(size <= 64 * 1024 * 1024)
        content = ReadSlot().content(str(source / row["path"]), row["size"])
        require(len(content) == row["size"] and hashlib.sha256(content).hexdigest() == row["sha256"])
        names.append(row["path"])
    require(names == sorted(set(names)))
    offline_saved_configs(inputs["savedConfigs"])
    return value, inputs, frozenset(names)


def _offline_cli_import_paths(core, source):
    require(absolute(core) and absolute(str(source)) and core == str(source / "src"))
    # Legacy fixtures import workflow.* from tests/workflow. The tests package
    # itself is a namespace rooted at source/tests, not an ambient installation.
    return (core, str(source), str(source / "tests"))


def _offline_cli_modules(source, names):
    for name, module in tuple(sys.modules.items()):
        if name == "tests":
            require(getattr(module, "__file__", None) is None
                    and tuple(getattr(module, "__path__", ())) == (str(source / "tests"),))
        elif (name == "mobile_release" or name.startswith("mobile_release.") or name.startswith("tests.")
                or name == "workflow" or name.startswith("workflow.")):
            filename = getattr(module, "__file__", None)
            require(type(filename) is str and absolute(filename))
            relative = str(Path(filename).relative_to(source))
            require(relative in names and relative.endswith(".py"))
            prefix = ("src/mobile_release/" if name.startswith("mobile_release")
                      else "tests/workflow/" if name == "workflow" or name.startswith("workflow.") else "tests/")
            require(relative.startswith(prefix))


def offline_cli_compatibility(core, control_path):
    """Exactly CLI11 before Cargo/native work; no discovery or arbitrary argv."""
    global _SUBJECT_STARTED, _CLI_MODE, _CLI_SETTLED, _CLI_STAGE
    _CLI_MODE = True
    _runtime_flags()
    require(absolute(core) and absolute(control_path) and Path(control_path).name == "offline-cli11-control.json")
    value = parse_offline_cli_control(ReadSlot().content(control_path, CONTROL_LIMIT, mode=0o400))
    clock = OfflineCLIClock(value["startedNs"], value["deadlineNs"])
    clock.install()
    root, source = Path(value["root"]), Path(value["source"])
    binding = {key: value[key] for key in OFFLINE_CLI_BINDINGS}
    rows, saved, observation = [], [], None
    original_path, original_environment = sys.path[:], dict(os.environ)
    temporary, original_temp = None, None
    reason, code = "admission-failed", 78
    try:
        _CLI_STAGE = "source-admission"
        clock.check()
        value, inputs, source_names = _offline_cli_admit(core, control_path, value)
        require(not any(name in {"mobile_release", "tests", "workflow"}
                        or name.startswith(("mobile_release.", "tests.", "workflow.")) for name in sys.modules))
        sys.path[:0] = _offline_cli_import_paths(core, source)
        _CLI_STAGE = "imports"
        import builtins
        import io
        import tempfile
        import unittest
        import zipfile
        from mobile_release import _command_process as command
        from mobile_release import build_inputs, config, ios_artifacts, macho, metadata
        from mobile_release.cancellation import DefaultCancellation
        temporary, original_temp = tempfile, tempfile.tempdir
        tempfile.tempdir = str(root / "offline-cli11")
        os.environ["TMPDIR"] = tempfile.tempdir
        _CLI_STAGE = "saved-configs"
        for row in inputs["savedConfigs"]:
            clock.check()
            config.parse_config_text(row["rawText"])
            saved.append({"case": row["case"], "sha256": row["sha256"]})
        observation = OfflineCLIObservation(command, build_inputs, DefaultCancellation, tempfile, clock)
        observation.install(builtins=builtins, io=io, zipfile=zipfile, config=config, macho=macho,
                            artifacts=ios_artifacts, metadata=metadata)
        _SUBJECT_STARTED = True
        cases = []
        _CLI_STAGE = "selection"
        for name in OFFLINE_CLI_IDS:
            clock.check()
            suite = unittest.defaultTestLoader.loadTestsFromName(name)
            selected = list(suite)
            require(len(selected) == 1 and isinstance(selected[0], unittest.TestCase)
                    and selected[0].id() == name and selected[0].countTestCases() == 1)
            cases.append(selected[0])
        # Leaf5 restores its test-local global facility before TD cleanup.
        # Observe actual invocation closure BEFORE that original restoration.
        facility = sys.modules["tests.unit.test_build_inputs"]
        observation.patch(facility, "_environment_facility", observation.context(facility._environment_facility, facility=True))
        _offline_cli_modules(source, source_names)
        observation.leaf_closed()
        require(not observation.scan_failed())
        _CLI_STAGE = "progress"
        OfflineCLIWrite().write(root / "offline-cli11-progress.json",
            {**binding, "phase": "started", "selectedIds": list(OFFLINE_CLI_IDS)})
        environment = dict(os.environ)
        reason = "test-failed"
        for index, case in enumerate(cases, 1):
            _CLI_STAGE = f"leaf-{index}"
            clock.check()
            before = observation.counts()
            result = unittest.TextTestRunner(verbosity=2, failfast=True).run(unittest.TestSuite([case]))
            # No next test, deletion or restoration on an unsettled original.
            observation.leaf_closed()
            require(dict(os.environ) == environment)
            _offline_cli_modules(source, source_names)
            good = (result.testsRun == 1 and result.wasSuccessful() and not result.skipped
                    and not result.expectedFailures and not result.unexpectedSuccesses and not observation.scan_failed())
            after = observation.counts()
            rows.append({"id": case.id(), "status": "passed" if good else "failed",
                         **dict(zip(("commands", "invocations", "guards"), (b - a for a, b in zip(before, after))))})
            if not good:
                _offline_cli_diagnostic("test-failed")
                break
        if len(rows) == len(OFFLINE_CLI_IDS) and all(row["status"] == "passed" for row in rows):
            clock.check()
            reason, code = "none", 0
        else:
            code = 1
    except OfflineCLIDeadline as error:
        _ROOTS.append(error)
        reason, code = "deadline", 1
        _offline_cli_diagnostic(reason)
    except RetainedUnknown:
        _offline_cli_diagnostic("unsettled-originals")
        raise
    except BaseException as error:
        _ROOTS.append(error)
        code = 1
        _offline_cli_diagnostic(reason)
    finally:
        _CLI_STAGE = "restoration"
        if observation is not None:
            observation.restore()  # Raises/retains, never drops originals on an error.
        if temporary is not None:
            temporary.tempdir = original_temp
        sys.path[:] = original_path
        os.environ.clear()
        os.environ.update(original_environment)
    require(all(getattr(slot, "state", "CLOSED") in {"NEW", "CLOSED", "ACTIVE"} for slot in _ROOTS))
    if clock.expired or clock.now() >= clock.deadline:
        reason, code = "deadline", 1
        _offline_cli_diagnostic(reason)
    finished = clock.now()
    _CLI_STAGE = "result"
    OfflineCLIWrite().write(root / "offline-cli11-result.json", {**binding, "finishedNs": finished,
        "status": "passed" if code == 0 else "failed", "physicalFinality": True, "selected": 11,
        "tests": rows, "savedConfigs": saved, "reason": reason})
    # Output close/readback and timer restoration also precede original wait0.
    if clock.now() >= clock.deadline:
        code = 1
        _offline_cli_diagnostic("deadline")
    _CLI_STAGE = "clock-restoration"
    clock.finish()
    require(all(getattr(slot, "state", "CLOSED") in {"NEW", "CLOSED"} for slot in _ROOTS))
    _CLI_SETTLED = True
    return code


def _admit(core, control_path):
    _runtime_flags()
    require(absolute(core) and absolute(control_path) and absolute(__file__)
            and Path(control_path).name == "control.json")
    value = parse_control(ReadSlot().content(control_path, CONTROL_LIMIT, mode=0o400))
    root = Path(control_path).parent
    details = root.lstat()
    require(stat.S_ISDIR(details.st_mode) and stat.S_IMODE(details.st_mode) == 0o700
            and details.st_uid == os.getuid() and not root.is_symlink()
            and value["relayIdentity"][2] == os.getuid()
            and value["core"] == core and value["python"] == os.path.abspath(sys.executable)
            and value["cwd"] == os.getcwd() and PROFILES[value["profile"]] == (sys.platform, os.uname().machine))
    shim = Path(__file__)
    require(shim.name == "native_desktop_environment.py" and shim.parent.name == "tests")
    observer = shim.parent / "workflow" / "command_bootstrap_fixture.py"
    require(hashlib.sha256(ReadSlot().content(shim, SOURCE_LIMIT)).hexdigest() == value["shimSha256"]
            and hashlib.sha256(ReadSlot().content(observer, SOURCE_LIMIT)).hexdigest() == value["observerSha256"])
    # Native bound the complete Inputs/source/runtime manifest before this fixed
    # spawn. Its supplied digest is an identity, not a newly invented trust root.
    return value, root, observer


def _write_target(descriptor, data):
    remaining = memoryview(data)
    while remaining:
        try:
            count = os.write(descriptor, remaining)
        except BlockingIOError:
            time.sleep(0.01)
            continue
        require(type(count) is int and 0 < count <= len(remaining))
        remaining = remaining[count:]


def _target(kind, started):
    _runtime_flags()
    require(kind in {"--target-active", "--target-cap"})
    if kind == "--target-cap":
        # The marker is INSIDE stdout's8192, not an extra allowance. C's actual
        # source counters, not this intent or an exception string, prove the cap.
        _write_target(1, READY_MARKER + b"x" * (CAP_STDOUT - len(READY_MARKER)))
        _write_target(2, b"y" * CAP_STDERR)
    else:
        _write_target(1, READY_MARKER)
        # Fixed cooperative work only. The unchanged ordinary owner has its
        # earlier integer<=3s bound and original STOP route; no child/trace FD.
        while time.monotonic() < started + 5.0:
            time.sleep(0.01)
    return 0


def _git_path(path, profile):
    if profile == "linux-gnu-x86_64":
        return path == "/usr/bin/git"
    return (path == "/Library/Developer/CommandLineTools/usr/bin/git"
            or re.fullmatch(r"/Applications/Xcode(?:_[A-Za-z0-9_.-]+)?\.app/Contents/Developer/usr/bin/git", path) is not None)


class EngineObservation:
    """Retain the unchanged original engine; never construct a second owner."""
    def __init__(self, engine_type, request_type, guard_type, input_type, service_type, value, started):
        self.engine_type, self.request_type = engine_type, request_type
        self.guard_type, self.input_type, self.service_type = guard_type, input_type, service_type
        self.value, self.started, self.original = value, started, engine_type.__init__
        self.engine = self.request = self.guard = self.source = self.service = None
        self.installed = self.settled_observed = self.stop_attempted = False
        self.errors = []
        _ROOTS.append(self)

        def initialize(actual, original_started):
            require(self.engine is None and type(actual) is self.engine_type)
            self.engine = actual  # Before the one unchanged initializer/effects.
            require(original_started is self.started)
            return self.original(actual, original_started)

        self.initialize = initialize

    def install(self):
        require(not self.installed and self.engine_type.__init__ is self.original)
        self.installed = True
        self.engine_type.__init__ = self.initialize

    def bind(self):
        actual = self.engine
        require(type(actual) is self.engine_type and actual.started is self.started
                and type(actual.request) is self.request_type and type(actual.guard) is self.guard_type
                and type(actual.input) is self.input_type and type(actual.service) is self.service_type)
        request, guard, source, service = actual.request, actual.guard, actual.input, actual.service
        require(source.guard is guard and source.acquired and source.active and source.request_returned
                and service.request is request and service.guard is guard and service.source is source
                and request.run_id == self.value["runId"] and request.owner_generation == self.value["ownerGeneration"]
                and request.context == self.value["context"]
                and request.native == {key: self.value[key] for key in ("profile", "projectRoot", "cwd")})
        if self.request is None:
            self.request, self.guard, self.source, self.service = request, guard, source, service
        require(self.request is request and self.guard is guard and self.source is source and self.service is service)
        return guard, source

    def settled(self):
        guard, source = self.bind()
        verdict = guard.lifetime_ledger.verdict()
        require(verdict.complete and not verdict.fatal and verdict.contained and verdict.cleanup_complete
                and verdict.profile_calls == 0 and guard.handler_state == "RESTORED"
                and guard._environment_source is None and source.closed and source.close_claimed
                and not source.custody_unknown and self.service.lookup.closed
                and all(slot.owned and slot.close_claimed and slot.closed
                        for slot in (self.engine.output, self.engine.error_output)))
        self.settled_observed = True

    def stop(self):
        # A failed initializer may never have created/acquired input. Do not
        # invent that object or acquisition, consult a pathname, or run cleanup.
        actual = self.engine
        source = None if actual is None else getattr(actual, "input", None)
        if self.stop_attempted or type(source) is not self.input_type or not source.acquired:
            return
        self.stop_attempted = True
        try:
            require(source.guard is None or source.guard is getattr(actual, "guard", None))
            source.stop("cancelled")  # Only this retained original input's STOP.
        except BaseException as error:
            self.errors.append(error)

    def restore(self):
        require(self.settled_observed and not self.stop_attempted and not self.errors
                and self.installed and self.engine_type.__init__ is self.initialize)
        self.engine_type.__init__ = self.original


class GitSeam:
    """One fixed redirection after the real DiagnosticsRun/ToolLookup admission."""
    def __init__(self, value, case, original, observation, tool_environment):
        self.value, self.case, self.original = value, case, original
        self.observation, self.tool_environment = observation, tool_environment
        self.guard, self.source, self.error = None, None, None
        self.intercepts, self.other_calls, self.no_next = 0, 0, True
        self.missing_reason = "git-not-admitted"
        _ROOTS.append(self)

    def __call__(self, argv, *, environ, cwd, timeout, capture, text, output_limit, cancellation):
        if self.intercepts:
            self.no_next = False
            raise AssertionError("no command after the fixed intercepted call")
        guard, source = self.observation.bind()
        require(cancellation is guard and guard._environment_source is source
                and source.active and source.request_returned and source.acquired and not source.close_claimed
                and type(argv) is tuple and len(argv) == 2 and all(type(arg) is str for arg in argv)
                and isinstance(cwd, Path) and str(cwd) == self.value["cwd"]
                and type(timeout) is int and 1 <= timeout <= 3 and capture is True and text is False
                and type(output_limit) is int and output_limit == 16384 and type(environ) is dict)
        if self.guard is None:
            self.guard, self.source = guard, source
        require(self.guard is guard and self.source is source)
        is_git = argv[1] == "--version" and _git_path(argv[0], self.value["profile"])
        role = "git" if is_git else "developer-selection" if argv == ("/usr/bin/xcode-select", "-p") else "java"
        # These role environments are identical for Java/javac/Git/selector.
        # The real source-bound call site has already admitted/rechecked the
        # current tool; this check is not a fabricated ToolBinding or resolver.
        require(environ == self.tool_environment(self.value["profile"], role)
                and (argv[1] in {"-p", "-version"} or is_git))
        options = dict(environ=environ, cwd=cwd, timeout=timeout, capture=capture,
                       text=text, output_limit=output_limit, cancellation=guard)
        if not is_git:
            self.other_calls += 1
            require(self.other_calls <= 4)
            return self.original(argv, **options)  # Mac selector never uses the Git observer/nonce.
        guard.check()
        remaining = int(source.work_end - time.monotonic())
        if remaining < 1:
            self.missing_reason = "insufficient-work-margin"
            source.stop("timed-out")
            guard.check()
            raise AssertionError("original STOP did not stop the call")
        options["timeout"] = min(timeout, 3, remaining)
        self.intercepts = 1
        kind = "--target-cap" if self.value["case"] in {"L4", "L5"} else "--target-active"
        target = (self.value["python"], "-I", "-S", "-B", str(Path(__file__)), kind)
        with self.case:
            try:
                self.original(target, **options)  # Unchanged ordinary owner, exact original guard.
            except BaseException as error:
                self.error = error
                raise  # Preserve the actual object and typed original ledger.
            raise AssertionError("fixed incomplete helper unexpectedly returned complete output")


def _settled_facts(value, seam, case, relay, process_error):
    require(seam.intercepts == 1 and seam.no_next and seam.error is not None and case.held_settled
            and case.released and not case.errors and not relay.broken)
    case.require_finality()
    verdict = seam.guard.lifetime_ledger.verdict()
    require(verdict.complete and not verdict.fatal and verdict.contained and verdict.cleanup_complete
            and verdict.command_dispatched is True and verdict.profile_calls == 0
            and seam.guard.handler_state == "RESTORED" and seam.source.closed)
    outcome, rows = case.outcome, case.rows
    require(outcome.original_finality is not None and outcome.run_tool.attempted and outcome.no_target is None
            and outcome.result_integrity == "incomplete")
    capture = rows["C"]["capture"]
    require(capture["failed"] is False and capture["limit"] == 16384
            and all(type(capture[key]) is int and capture[key] >= 0 for key in ("stdout", "stderr")))
    stop_before_work = None
    if value["case"] in {"L4", "L5"}:
        require(isinstance(seam.error, process_error) and seam.error.dispatched is True
                and seam.error.contained is True and seam.error.cleanup_complete is True
                and seam.source.stop_reason == "none" and capture["overflow"] is True
                and capture["stdout"] == CAP_STDOUT and capture["stderr"] == CAP_STDERR)
    else:
        require(capture["stdout"] == len(READY_MARKER) and capture["stderr"] == 0 and capture["overflow"] is False
                and relay.ready_sent and seam.source.stop_reason == "cancelled")
        ready, stopped = rows["C"].get("target_ready"), rows["C"].get("stop_received")
        require(ready is not None and stopped is not None
                and all(type(stopped[key]) is int for key in ("run", "at", "remaining"))
                and stopped["run"] == outcome._engine.ctx.run and ready["run"] == stopped["run"]
                and type(ready["at"]) is int and ready["at"] <= stopped["at"]
                and stopped["remaining"] == stopped["run"] - stopped["at"]
                and 1 <= stopped["remaining"] <= 3_000_000_000)
        stop_before_work = stopped["remaining"]
    reason = seam.source.stop_reason if seam.source.stop_reason != "none" else "command-incomplete"
    # C/A normal return gates + their actual waits and W's actual target bytes
    # prove trace closes. No owner_finish row or CLOEXEC alone supplies them.
    c_close = outcome._engine.wait.status_code in (0, 2) and outcome._engine.wait.status_code == rows["C"]["owner_finish"]["code"]
    a_close = rows["C"]["owner_wait"]["code"] in (0, 2) and rows["C"]["owner_wait"]["code"] == rows["A"]["owner_finish"]["code"]
    w_close = set(rows["W"]) == {"boot"} and outcome._engine.outputs[0].startswith(READY_MARKER)
    return {"intercepts": 1, "readyObserved": relay.ready_sent, "noNextCall": seam.no_next, "reason": reason, "coreCode": 0,
        "commandNonce": outcome.nonce.hex(), "recipeSha256": hashlib.sha256(case.recipe.encode()).hexdigest(),
        "resultIntegrity": outcome.result_integrity, "dispatched": outcome.run_tool.attempted,
        "contained": verdict.contained, "cleanupComplete": verdict.cleanup_complete,
        "cWait": outcome._engine.wait.status_code, "aWait": rows["C"]["owner_wait"]["code"],
        "cFinish": rows["C"]["owner_finish"]["code"], "aFinish": rows["A"]["owner_finish"]["code"],
        "targetWait": {key: rows["A"]["owner_wait"][key] for key in ("kind", "code")},
        "targetMarker": outcome._engine.outputs[0].startswith(READY_MARKER),
        "readersJoined": all(task.joined for task in outcome._engine.ctx.tasks)
            and rows["C"]["owner_io"]["joined"] and rows["A"]["owner_io"]["joined"],
        "traceCloses": {"o": all(slot["state"] == "CLOSED" for slot in case.slots), "c": c_close, "a": a_close, "w": w_close},
        "stopBeforeWorkNs": stop_before_work,
        "capture": {key: capture[key] for key in ("stdout", "stderr", "limit", "overflow")}}


def main():
    global _SUBJECT_STARTED, _ENGINE_OBSERVATION
    started = _ENTRY_STARTED
    require(type(started) is float)
    if len(sys.argv) == 4 and sys.argv[1] == "--offline-cli11":
        return offline_cli_compatibility(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 2 and sys.argv[1] in {"--target-active", "--target-cap"}:
        return _target(sys.argv[1], started)
    require(len(sys.argv) == 3)
    value, root, observer_path = _admit(sys.argv[1], sys.argv[2])
    observer = runpy.run_path(str(observer_path))  # Exact native-bound source, before subject effects.
    require(observer["OBSERVE_READY"] == READY_MARKER and observer["OBSERVE_HELD"] == "observe-held")
    relay = observer["ObserveRelay"](str(root / "relay.trace"), tuple(value["relayIdentity"]),
        case=value["case"], run_id=value["runId"], owner_generation=value["ownerGeneration"])
    _ROOTS.extend((observer, relay))
    relay.acquire()
    sys.path.insert(0, value["core"])
    from mobile_release import _command_process as command
    from mobile_release import _desktop_environment_engine as engine
    from mobile_release import environment_diagnostics as service
    from mobile_release._desktop_environment_control import EnvironmentInput
    from mobile_release._desktop_environment_protocol import EnvironmentRequest, context_value
    from mobile_release.cancellation import DefaultCancellation
    from mobile_release.environment_diagnostics_tools import tool_environment
    from mobile_release.owned_process import ProcessError
    require(context_value(value["context"]) == value["context"])
    case = observer["CommandCase"](command, root / "command", "observe-held")
    _ROOTS.extend((case, command, engine, service))
    case.prepare_held(relay)  # All files/readers/recipe before service/lookup admission.
    original = service.run_owned
    observation = EngineObservation(engine._Engine, EnvironmentRequest, DefaultCancellation,
        EnvironmentInput, service.DiagnosticsRun, value, started)
    _ENGINE_OBSERVATION = observation
    observation.install()
    seam = GitSeam(value, case, original, observation, tool_environment)
    service.run_owned = seam
    _SUBJECT_STARTED = True
    code = engine.main(started=started)  # Same actual engine, scope/input/guard/terminal/stdio closes.
    require(code == 0 and not engine._RETAINED and not command._RETAINED and service.run_owned is seam)
    observation.settled()  # Also binds an unexecuted run's actual original request.
    if seam.intercepts == 0:
        case.close_unactivated()
        relay.finish("unexecuted", {"intercepts": 0, "readyObserved": False, "observerClosed": case.held_settled,
            "noNextCall": seam.no_next, "reason": seam.missing_reason, "coreCode": code})
    else:
        facts = _settled_facts(value, seam, case, relay, ProcessError)
        relay.finish("settled", facts)
    require(relay.close_owned())  # This actual return, plus native wait0, is the relay close gate.
    require(all(slot.state == "CLOSED" for slot in _ROOTS if type(slot) is ReadSlot))
    require(service.run_owned is seam)
    observation.restore()  # Both wrappers remain on any unresolved/error tail.
    service.run_owned = original
    relay.release()
    return code


def _stop_before_retention(error):
    _ROOTS.append(error)
    if _ENGINE_OBSERVATION is not None:
        _ENGINE_OBSERVATION.stop()  # Actual STOP before parking, never a new owner.


def retain_originals(error):
    # No new reader/report owner, PID search, cleanup retry or task replacement.
    # The native owner continues its original STOP/joins through H; unresolved
    # originals stay rooted here until the outer hosted timeout disposes the VM.
    # That disposal is deliberately not a successful application receipt.
    _offline_cli_diagnostic("unsettled-originals")
    _stop_before_retention(error)
    while True:
        try:
            _PAUSE()
        except BaseException:
            pass  # No exception reporter may drop these original retained slots.


if __name__ == "__main__":
    try:
        result = main()
    except RetainedUnknown as error:
        retain_originals(error)
    except BaseException as error:
        _offline_cli_diagnostic("restoration-failed" if _CLI_STAGE in {"restoration", "clock-restoration"} else "admission-failed")
        if ((_SUBJECT_STARTED and not (_CLI_MODE and _CLI_SETTLED))
                or any(getattr(slot, "state", "CLOSED") not in {"NEW", "CLOSED"} for slot in _ROOTS)):
            retain_originals(error)
        result = 78
    raise SystemExit(result)
