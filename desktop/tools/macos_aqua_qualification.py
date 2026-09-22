#!/usr/bin/env python3
"""Four fixed, source-bound installed Mac Aqua cases; never a general runner.

Importing this module loads only stdlib DATA/parsers. The native main alone
admits the hosted user/source, prepares exclusive synthetic fixtures, and loads
the unchanged source run_owned. No Store, release, alternate command or cleanup
controller is provided. Unknown invocation finality preserves the fixtures.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")
EXECUTABLE = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mobile-release-kit-desktop"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-aqua"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-aqua.yml@" + REF
MARKER = b"MRK_MACOS_AQUA_RESULT="
OUTPUT_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 16383
SCOPE = "programmatic genuine controls; no Store, release, distribution or physical-device evidence"
FAILURE_STEPS = frozenset((
    "Bootstrap Environment ReadEnvironment Dashboard ChooseCancel CancelProject CancelSettled ReadCancelled "
    "ChooseProject SetProject OpenProject ProjectSettled Snapshot Settings Suggest Suggestion Adopt Draft "
    "Validate Validation Preview Previewed RequirementsPage LoadRequirements Requirements GitHubPage "
    "GitHubRepository GitHubSha GitHubPropose GitHubProposal ReturnSettings KeepReviewing KeptReview "
    "ReadbackPage Refresh Readback SavedSettings ChangeDraft ChangedDraft MutateIgnore CloseCancel "
    "QuitCancel QuitCancelled RetainedReview Close Quit Exit PickerPending Reload Lost"
).split()) | frozenset(f"{name}({number})" for name in (
    "Prepare", "Review", "OpenConfirmation", "Confirmation", "Acknowledge", "Acknowledged", "Apply", "Applied") for number in (0, 1))
FAILURE_REASONS = frozenset((
    "observer-invariant observer-deadline observer-record-unavailable observer-data-check "
    "native-wrong-thread native-step native-pending-custody native-original-id native-kind native-not-started "
    "native-ineligible native-action-attempted native-action-returned native-callback-returned "
    "native-response-present native-selection-present native-close-attempted native-closed "
    "native-attachment-lost native-preaction-history native-dismissed native-duplicate-action "
    "cancel-unexpected-project cancel-duplicate-result adapter-wrong-thread adapter-book-borrow "
    "adapter-original-call adapter-original-owner adapter-original-binding adapter-missing-facts "
    "adapter-missing-panel adapter-ineligible adapter-native-observation adapter-native-action "
    "asset_invalid_request asset_closed asset_unqualified asset_unsupported_platform "
    "asset_unsupported_filesystem asset_unsupported_format asset_busy asset_source_refused "
    "asset_source_changed asset_material_limit asset_parser_limit asset_project_overlap "
    "asset_exclusion_unconfirmed asset_capacity assessment_context_stale asset_user_cancelled "
    "asset_review_expired asset_deadline asset_document_lost asset_shutdown asset_cleanup_unknown"
).split())
SOURCE = (b'plugins { id("com.android.application") }\n'
          b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
KEEP = b"MRK_MACOS_AQUA_KEEP\n"
IGNORE_PREFIX = b"# MRK Mac Aqua user ignore\nuser-output/\n"
IGNORE_RULES = (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
                b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n"
                b".mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n")
STALE = b"# MRK Mac Aqua stale base\n"
# Literal public fixture DATA, not another core configuration serializer.
CONFIG = b'''{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
OWNER_PINS = {
    "owned_process.py": "430a596c5069b7acf248334d1f60fdd12ad8212cf9c2e9dfef717c9ba2179c02",
    "_command_process.py": "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68",
    "_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "cancellation.py": "1840232213e877e26c4cebd1434b3b851f9fa4c6961baa26eeaae9fa1442db78",
}


class Refused(Exception):
    """A fixed public diagnostic label, never an OS/path/child transcript."""


def need(condition, label):
    if not condition:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Binding:
    source: str
    run: str
    attempt: str

    def checked(self):
        need(type(self.source) is str and re.fullmatch(r"[0-9a-f]{40}", self.source), "source-binding")
        need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (self.run, self.attempt)), "run-binding")
        return self

    def root(self):
        self.checked()
        return Path("/private/tmp") / f"mrk-macos-aqua-{self.source}-{self.run}-{self.attempt}"

    def public(self):
        return {"sourceCommit": self.source, "runId": self.run, "runAttempt": self.attempt}


def expected_result(binding, case):
    binding.checked()
    need(case in CASES, "case-binding")
    first, stale, lost = case == "first-save", case == "noop-stale", case in ("picker-loss", "save-loss")
    plans = {
        "create": [("release/mobile-release.json", "create", None, 684), (".gitignore", "append", 40, 248)],
        "preserve": [("release/mobile-release.json", "preserve", 684, 684), (".gitignore", "preserve", 248, 248)],
        "replace": [("release/mobile-release.json", "replace", 684, 690), (".gitignore", "preserve", 248, 248)],
    }
    rows = {
        "first-save": [(1, 1, "create", 2, True, "committed", "clean", "none", "none"),
                       (1, 2, "preserve", 0, False, "not_started", "not_created", "cancelled", "shutdown")],
        "noop-stale": [(1, 1, "preserve", 1, True, "unchanged", "not_created", "none", "none"),
                       (2, 1, "replace", 1, True, "not_started", "not_created", "stale_revision", "none")],
        "picker-loss": [],
        "save-loss": [(1, 1, "create", 0, False, "not_started", "not_created", "cancelled", "window_lost")],
    }
    sessions = []
    for draft, baseline, plan, confirmations, applied, effect, journal, reason, native in rows[case]:
        sessions.append({"draftRevision": draft, "baselineGeneration": baseline,
            "files": [dict(zip(("path", "action", "beforeBytes", "afterBytes"), row)) for row in plans[plan]],
            "createReleaseDirectory": plan == "create", "reviewMatched": True, "confirmationsOpened": confirmations,
            "acknowledged": applied, "apply": applied,
            "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": reason},
            "nativeReason": native, "nativeFinality": "settled", "writerFrames": 3 if applied else 2,
            "stdoutFrames": 3, "originalsJoined": True})
    return {"schemaVersion": 1, **binding.public(), "case": case, "instrumentedEngineeringApp": True,
        "shippingBinaryQualified": False, "distributionQualified": False, "methods": "eight-passive", "actionsAvailable": False,
        "native": {"projectCancelSettled": first, "selectedPathMatched": case != "picker-loss",
            "panelAttachments": [True, True, first, first],
            "controlReturns": [first, case != "picker-loss", case != "picker-loss", first, True],
            "quitCancelKeptOriginalReview": first, "originalDocumentAndQuitSettled": True},
        "saveSessions": sessions, "freshCoreReadback": first, "syntheticFileReadback": True,
        "staleMarkerWriterReturnedAndClosed": stale,
        "reload": {"requested": lost, "dispatchReturned": lost, "navigationDenied": lost, "secondStarted": False,
            "originalLossSettled": lost, "webProcessCrashTested": False},
        "originalRelayJoined": True, "actualExit": True, "scope": SCOPE}


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-result-key")
        result[key] = value
    return result


def _exact(actual, expected):
    # Python's True == 1 (and 1.0 == 1) must not accept substituted evidence.
    need(type(actual) is type(expected), "result-type")
    if type(expected) is dict:
        need(actual.keys() == expected.keys(), "result-keys")
        for key in expected:
            _exact(actual[key], expected[key])
    elif type(expected) is list:
        need(len(actual) == len(expected), "result-count")
        for left, right in zip(actual, expected):
            _exact(left, right)
    else:
        need(actual == expected, "result-value")


def parse_result(stdout, stderr, binding, case):
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= OUTPUT_LIMIT, "result-capture")
    need(not any(token in stream for stream in (stdout, stderr)
                 for token in (b"MRK_MACOS_AQUA_FAILURE", b"MRK_MACOS_AQUA=")), "inner-failure-marker")
    need(stdout.count(MARKER) == 1 and MARKER not in stderr, "result-marker-count")
    lines = stdout.split(b"\n")
    records = [line[len(MARKER):] for line in lines[:-1] if line.startswith(MARKER)]
    need(len(records) == 1 and 0 < len(records[0]) <= JSON_LIMIT and b"\r" not in records[0], "result-record")
    try:
        value = json.loads(records[0].decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("result-constant")))
    except (ValueError, RecursionError, UnicodeError) as error:
        raise Refused("result-json") from error
    expected = expected_result(binding, case)
    if case in ("picker-loss", "save-loss"):
        need(type(value) is dict and type(value.get("reload")) is dict, "reload-object")
        reload = value["reload"]
        denied, started = reload.get("navigationDenied"), reload.get("secondStarted")
        need(type(denied) is bool and type(started) is bool and (denied or started), "reload-loss-route")
        expected["reload"]["navigationDenied"], expected["reload"]["secondStarted"] = denied, started
    _exact(value, expected)
    return value


def failure_step(stdout, stderr):
    # Finite Rust Step labels only; never publish arbitrary child log text.
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > OUTPUT_LIMIT:
        return None
    prefix = b"MRK_MACOS_AQUA_FAILURE_STEP="
    rows = [line[len(prefix):] for stream in (stdout, stderr) for line in stream.split(b"\n") if line.startswith(prefix)]
    if len(rows) != 1 or len(rows[0]) > 40:
        return None
    try:
        label = rows[0].decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_STEPS else None


def failure_reason(stdout, stderr):
    """Optional closed DATA only; malformed/partial output never grants success."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > OUTPUT_LIMIT:
        return None
    marker = b"MRK_MACOS_AQUA_FAILURE_REASON"
    # Count malformed candidates too, including an embedded or incomplete row
    # accompanying a valid one. Only one exact, newline-terminated row is useful.
    if sum(stream.count(marker) for stream in (stdout, stderr)) != 1:
        return None
    prefix = marker + b"="
    rows = [line[len(prefix):] for stream in (stdout, stderr)
            for line in stream.split(b"\n")[:-1] if line.startswith(prefix)]
    if len(rows) != 1 or not 0 < len(rows[0]) <= 48:
        return None
    try:
        label = rows[0].decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_REASONS else None


@dataclass(frozen=True)
class Node:
    # dev, inode, complete mode, uid, gid, nlink, size, mtime_ns, ctime_ns.
    identity: tuple
    sha256: str | None
    entries: tuple | None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_data(case, final):
    need(case in CASES and type(final) is bool, "fixture-case")
    saved = case == "noop-stale" or final and case == "first-save"
    files = {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
             ".gitignore": IGNORE_PREFIX + (IGNORE_RULES if saved else b"") + (STALE if final and case == "noop-stale" else b"")}
    directories = {".": (0o700, (".gitignore", "app", "keep.txt", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",))}
    if saved:
        files["release/mobile-release.json"] = CONFIG
        directories["."] = (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties"))
        directories["release"] = (0o755, ("mobile-release.json",))
    return files, directories


def _shape(snapshot, case, final, uid, gid):
    files, directories = fixture_data(case, final)
    need(type(snapshot) is dict and snapshot.keys() == files.keys() | directories.keys(), "fixture-roster")
    for path, node in snapshot.items():
        need(type(node) is Node and type(node.identity) is tuple and len(node.identity) == 9
             and all(type(v) is int and v >= 0 for v in node.identity), "fixture-identity")
        facts = node.identity
        need(facts[3:5] == (uid, gid), "fixture-owner")
        if path in files:
            need(facts[2] == stat.S_IFREG | 0o600 and facts[5] == 1 and facts[6] == len(files[path])
                 and node.sha256 == digest(files[path]) and node.entries is None, "fixture-file")
        else:
            mode, entries = directories[path]
            need(facts[2] == stat.S_IFDIR | mode and node.sha256 is None and node.entries == entries, "fixture-directory")


def validate_snapshot(original, current, case, final, uid, gid):
    _shape(original, case, False, uid, gid)
    _shape(current, case, final, uid, gid)
    for path, before in original.items():
        after = current[path]
        if before.entries is not None:
            need(after.identity[:5] == before.identity[:5], "fixture-directory-replaced")
        elif final and case == "first-save" and path == ".gitignore":
            need(after.identity[:2] != before.identity[:2], "save-ignore-not-replaced")
        elif final and case == "noop-stale" and path == ".gitignore":
            need(after.identity[:6] == before.identity[:6], "stale-ignore-replaced")
        else:
            need(after.identity == before.identity, "fixture-original-changed")
    return {"completeRoster": True, "expectedBytesAndModes": True, "originalIdentitiesMatched": True,
            "transactionResidueAbsent": True, "files": len(fixture_data(case, final)[0]),
            "configSha256": current.get("release/mobile-release.json").sha256 if "release/mobile-release.json" in current else None,
            "ignoreSha256": current[".gitignore"].sha256, "ignoreBytes": current[".gitignore"].identity[6]}


def app_environment(state, uid, username):
    need(type(uid) is int and uid > 0 and type(username) is str
         and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "native-user")
    return {"HOME": str(state / "home"), "TMPDIR": str(state / "tmp") + "/",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"}


class Fixtures:
    """Finite helper-owned file custody, never process/Store custody."""

    def __init__(self, binding, uid, gid):
        self.binding, self.uid, self.gid = binding, uid, gid
        self.path = binding.root()
        self.fds = set()
        self.close_errors = 0
        self.first_close_error = None
        self.inflight = False
        self.last_returned = False
        self.app_returncode = self.inner_failure_step = self.inner_failure_reason = None
        self.case = None
        self.stage = "prepare"
        self.projects, self.states, self.originals = {}, {}, {}

    def _open(self, name, parent=None, *, directory=False, create=False):
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, 0o600, dir_fd=parent)
        self.fds.add(fd)
        need(not os.get_inheritable(fd), "fixture-descriptor-inheritance")
        return fd

    def _close(self, fd):
        need(fd in self.fds, "fixture-close-not-original")
        self.fds.remove(fd)  # This original close is never repeated on error.
        try:
            os.close(fd)
            return True
        except BaseException as error:
            self.close_errors += 1
            if self.first_close_error is None:
                self.first_close_error = error
            return False

    @contextmanager
    def _temporary(self, fd):
        original_error = None
        try:
            yield fd
        except BaseException as error:
            original_error = error
            raise
        finally:
            closed = self._close(fd)
            if not closed and original_error is None:
                raise self.first_close_error

    def _mkdir(self, parent, name, mode=0o700):
        os.mkdir(name, 0o700, dir_fd=parent)  # Refuse occupied paths; never adopt.
        fd = self._open(name, parent, directory=True)
        original = signature(os.fstat(fd))
        need(signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original
             and original[2] == stat.S_IFDIR | 0o700 and original[3] == self.uid,
             "fixture-created-directory-custody")
        # Darwin can inherit the parent's group even without setgid. Normalize
        # only this fresh, private, caller-owned original, before widening it.
        if original[4] != self.gid:
            os.fchown(fd, -1, self.gid)
        current = signature(os.fstat(fd))
        need(current[:4] == original[:4] and current[4] == self.gid,
             "fixture-created-directory-group")
        self._named(parent, name, fd, 0o700)
        if mode != 0o700:
            os.fchmod(fd, mode)  # Only this newly and exclusively created dir.
            self._named(parent, name, fd, mode)
        return fd

    def _named(self, parent, name, fd, mode):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        info = os.fstat(fd)
        need(signature(before) == signature(info) and info.st_mode == stat.S_IFDIR | mode
             and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-directory-custody")

    def _write(self, parent, name, body):
        with self._temporary(self._open(name, parent, create=True)) as fd:
            info = os.fstat(fd)
            need(info.st_mode == stat.S_IFREG | 0o600 and info.st_nlink == 1
                 and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-created-file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(count > 0, "fixture-write")
                offset += count

    def prepare(self):
        self.parent = self._open("/private/tmp", directory=True)
        p = os.fstat(self.parent)
        need(p.st_mode == stat.S_IFDIR | 0o1777 and p.st_uid == 0, "temporary-parent")
        self.root = self._mkdir(self.parent, self.path.name)
        self.state = self._mkdir(self.root, "state")
        for case in CASES:
            project = self._mkdir(self.root, case)
            self.projects[case] = project
            with self._temporary(self._mkdir(project, "app")) as app:
                self._write(app, "build.gradle.kts", SOURCE)
            self._write(project, "version.properties", VERSION)
            self._write(project, "keep.txt", KEEP)
            self._write(project, ".gitignore", IGNORE_PREFIX + (IGNORE_RULES if case == "noop-stale" else b""))
            if case == "noop-stale":
                with self._temporary(self._mkdir(project, "release", 0o755)) as release:
                    self._write(release, "mobile-release.json", CONFIG)
            state = self._mkdir(self.state, case)
            self.states[case] = state
            for child in ("home", "tmp"):
                with self._temporary(self._mkdir(state, child)):
                    pass
            self.originals[case] = self._capture(case, False)
        self._namespace()

    def _namespace(self):
        need(signature(os.stat("/private/tmp", follow_symlinks=False))[:6] == signature(os.fstat(self.parent))[:6], "temporary-parent-replaced")
        self._named(self.parent, self.path.name, self.root, 0o700)
        self._named(self.root, "state", self.state, 0o700)
        self._roster(self.root, (*CASES, "state"), "fixture-namespace-roster")
        self._roster(self.state, CASES, "fixture-state-roster")
        for case in CASES:
            self._named(self.root, case, self.projects[case], 0o700)
            self._named(self.state, case, self.states[case], 0o700)

    def _roster(self, fd, expected, label):
        # A fresh openat(".") description, not dup(retained_fd), gives each
        # scan its own cursor. Never depend on a supplier's iterator rewind.
        before = signature(os.fstat(fd))
        with self._temporary(self._open(".", fd, directory=True)) as reader:
            need(signature(os.fstat(reader)) == before, "fixture-roster-original")
            iterator = os.scandir(reader)
            original_error = None
            try:
                names = []
                for entry in iterator:
                    need(len(names) < len(expected), label)  # Consume at most expected+1.
                    names.append(entry.name)
                observed = tuple(sorted(names))
                need(observed == tuple(sorted(expected)), label)
                need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before,
                     "fixture-roster-read-race")
                return observed
            except BaseException as error:
                original_error = error
                raise
            finally:
                try:
                    iterator.close()  # One consuming close; never retry it.
                except BaseException as error:
                    self.close_errors += 1
                    if self.first_close_error is None:
                        self.first_close_error = error
                    if original_error is None:
                        raise

    def _file(self, parent, name, body):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(before.st_mode == stat.S_IFREG | 0o600 and before.st_nlink == 1 and before.st_size == len(body), "fixture-file-shape")
        with self._temporary(self._open(name, parent)) as fd:
            original = signature(before)
            need(signature(os.fstat(fd)) == original, "fixture-file-open-race")
            chunks, remaining = [], len(body) + 1
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            actual = b"".join(chunks)
            need(actual == body and signature(os.fstat(fd)) == original
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original, "fixture-file-readback")
            return Node(original, digest(actual), None)

    def _capture(self, case, final):
        files, directories = fixture_data(case, final)
        snapshot = {}
        project = self.projects[case]
        for path, (mode, entries) in directories.items():
            @contextmanager
            def directory():
                if path == ".":
                    yield project
                else:
                    with self._temporary(self._open(path, project, directory=True)) as opened:
                        self._named(project, path, opened, mode)
                        yield opened
            with directory() as fd:
                before = signature(os.fstat(fd))
                observed = self._roster(fd, entries, "fixture-directory-roster")
                for name, body in files.items():
                    parent, _, leaf = name.rpartition("/")
                    if (parent or ".") == path:
                        snapshot[name] = self._file(fd, leaf, body)
                need(signature(os.fstat(fd)) == before, "fixture-directory-read-race")
                snapshot[path] = Node(before, None, observed)
        _shape(snapshot, case, final, self.uid, self.gid)
        return snapshot

    def before_call(self, case):
        self.case, self.stage = case, "before-invocation"
        self._namespace()
        validate_snapshot(self.originals[case], self._capture(case, False), case, False, self.uid, self.gid)
        state = self.states[case]
        self._roster(state, ("home", "tmp"), "fresh-state-roster")
        for name in ("home", "tmp"):
            with self._temporary(self._open(name, state, directory=True)) as fd:
                self._named(state, name, fd, 0o700)
                self._roster(fd, (), "fresh-state-not-empty")

    def readback(self, case):
        need(not self.inflight and self.last_returned, "readback-without-return")
        self.stage = "independent-readback"
        self._namespace()
        return validate_snapshot(self.originals[case], self._capture(case, True), case, True, self.uid, self.gid)

    def close(self):
        need(not self.inflight, "fixture-finality-unknown")
        for fd in tuple(self.fds):
            self._close(fd)
        if self.first_close_error is not None:
            raise self.first_close_error


def run_cases(binding, fixtures, run_owned, uid, username, emit):
    """The sole invocation seam. Inert tests supply a non-executing callable."""
    for case in CASES:
        fixtures.before_call(case)
        state = binding.root() / "state" / case
        argv = [EXECUTABLE, case]
        fixtures.stage, fixtures.inflight, fixtures.last_returned = "invocation", True, False
        fixtures.app_returncode = fixtures.inner_failure_step = fixtures.inner_failure_reason = None
        # Only the original public return contract clears this flag. An
        # exception/interruption or foreign/malformed result leaves finality
        # unknown, with no readback, close or later invocation.
        result = run_owned(argv, environ=app_environment(state, uid, username), cwd=state,
                           timeout=60, capture=True, text=False, output_limit=OUTPUT_LIMIT)
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list
             and len(result.args) == 2 and all(type(arg) is str for arg in result.args) and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "owner-return-contract")
        fixtures.inflight, fixtures.last_returned, fixtures.stage = False, True, "result-validation"
        fixtures.app_returncode = result.returncode
        fixtures.inner_failure_step = failure_step(result.stdout, result.stderr)
        fixtures.inner_failure_reason = failure_reason(result.stdout, result.stderr)
        need(result.returncode == 0, "app-return")
        report = parse_result(result.stdout, result.stderr, binding, case)
        readback = fixtures.readback(case)
        emit({"schemaVersion": 1, "type": "macos-aqua-case", **binding.public(), "case": case,
              "originalCallReturned": True, "observer": report, "independentReadback": readback})


def admit(environment, root):
    # Platform/user APIs are evaluated only in the actual native entry.
    import platform
    import pwd
    import threading
    need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].split(".")[0] == "26", "native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid == os.geteuid() and uid > 0 and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "native-main-user")
    binding = Binding(environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID"), environment.get("GITHUB_RUN_ATTEMPT")).checked()
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF,
                "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": binding.source, "GITHUB_WORKSPACE": str(root)}
    need(all(environment.get(key) == value for key, value in required.items()), "hosted-source-route")
    # Actions' reviewed checkout is detached at this exact source. No Git
    # command/credential lookup or alternate worktree/ref parser is needed.
    head = root / ".git" / "HEAD"
    head_info = head.lstat()
    need(stat.S_ISREG(head_info.st_mode) and head_info.st_size == 41
         and head.read_bytes() == binding.source.encode("ascii") + b"\n", "checkout-source")
    username = pwd.getpwuid(uid).pw_name
    app_environment(binding.root() / "state" / CASES[0], uid, username)
    return binding, uid, gid, username


def load_owner(root):
    need(not any(name == "mobile_release" or name.startswith("mobile_release.") for name in sys.modules), "owner-already-imported")
    for name, expected in OWNER_PINS.items():
        path = root / "src" / "mobile_release" / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024 and digest(path.read_bytes()) == expected, "owner-source-pin")
    sys.path.insert(0, str(root / "src"))
    try:
        from mobile_release import owned_process
    finally:
        sys.path.pop(0)
    need(Path(owned_process.__file__).absolute() == root / "src" / "mobile_release" / "owned_process.py", "owner-source-route")
    return owned_process


def diagnostic(error, owner, fixtures):
    # Preserve individual typed public lifetime facts, not a synthesized pass
    # from a later exception. Missing fields remain unknown (JSON null).
    pending, seen, facts = [error], set(), []
    while pending and len(seen) < 16:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if owner is not None and isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            row = {"type": "interrupted" if isinstance(current, owner.ProcessInterrupted) else "process-error"}
            for source, target in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanup_complete", "cleanupComplete")):
                value = getattr(current, source, None)
                row[target] = value if type(value) is bool else None
            facts.append(row)
        pending.extend((current.__context__, current.__cause__))
    label = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "helper-or-owner-error"
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "helper-refused"
    return {"schemaVersion": 1, "type": "macos-aqua-failure", "status": "failed", "reason": label,
            "case": fixtures.case if fixtures else None, "stage": fixtures.stage if fixtures else "admission-or-source",
            "originalCallReturned": fixtures.last_returned if fixtures else False,
            "appReturncode": fixtures.app_returncode if fixtures else None,
            "innerFailureStep": fixtures.inner_failure_step if fixtures else None,
            "innerFailureReason": fixtures.inner_failure_reason if fixtures else None,
            "invocationFinality": "unknown" if fixtures and fixtures.inflight else "no-pending-invocation",
            "innerOutput": "unavailable" if fixtures and fixtures.inflight else "not-exported",
            "typedLifetimeFacts": facts, "exceptionChainTruncated": bool(pending),
            "fixtureCloseErrors": fixtures.close_errors if fixtures else 0,
            "fixturesPreserved": True, "laterCasesStopped": True}


def emit_record(value, stream):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    need(len(data.encode("ascii")) <= 24 * 1024, "outer-result-bound")
    stream.write(data + "\n")
    stream.flush()


def main():
    fixtures = owner = binding = None
    original_error = None
    try:
        need(len(sys.argv) == 1, "arguments-not-supported")
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, username = admit(os.environ, root)
        owner = load_owner(root)  # Native main only; no module-import-time core.
        os.umask(0o077)
        fixtures = Fixtures(binding, uid, gid)
        fixtures.prepare()
        run_cases(binding, fixtures, owner.run_owned, uid, username, lambda value: emit_record(value, sys.stdout))
    except BaseException as error:
        original_error = error
    if fixtures is not None and not fixtures.inflight:
        try:
            fixtures.close()
        except BaseException as error:
            if original_error is None:
                original_error = error  # Never overwrite an earlier failure.
    if original_error is not None:
        # The original exception object reaches this boundary unchanged. This
        # CLI emits bounded DATA and a nonzero status, never its traceback,
        # arbitrary message, child transcript or private source/project paths.
        try:
            emit_record(diagnostic(original_error, owner, fixtures), sys.stderr)
        except BaseException:
            pass  # Output loss remains failure; there is no diagnostic retry.
        return 130 if isinstance(original_error, KeyboardInterrupt) else 1
    try:
        emit_record({"schemaVersion": 1, "type": "macos-aqua-complete", **binding.public(), "cases": list(CASES),
                     "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
                     "instrumentedEngineeringApp": True, "shippingBinaryQualified": False, "distributionQualified": False}, sys.stdout)
    except BaseException:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
