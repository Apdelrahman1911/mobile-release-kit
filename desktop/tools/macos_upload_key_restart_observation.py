"""One fixed cold-reopen comparison in the EXISTING installed fixture owner.

No process launch, credential import, native finality constructor, provider, or
cleanup policy lives here. The two calls remain in run_cases. This book retains
the original fixture's FDs across the real first process exit and second call;
all of those FDs are closed by Fixtures, not by a replacement lifetime owner.
"""
import hashlib
import os
from pathlib import Path
import re
import stat


SCOPE = PROJECT = "upload-key-cold-restart"
PRODUCE = "upload-key-cold-produce"
REOPEN = "upload-key-cold-reopen"
CASES = (PRODUCE, REOPEN)
TIMEOUT = 495
OBSERVER_SECONDS = 480
RECORD_LIMIT = 248 + 4096 + 8 + 128 * 1024 + 64 * 1024
STATE_LIMIT = 1024 * 1024 + 52
PRIVATE_LIMIT = RECORD_LIMIT + 2 * STATE_LIMIT + 4096
APP = "dev.mobile-release-kit.desktop"
APP_NAMES = ("credential-vault-v1", "service-v1", "service-v1.reservation")
REOPEN_FIELDS = frozenset((
    "mechanism normalGenerationEnabled execution testResult openedExisting initialized generationAttempted "
    "lookupHelper inventoryRows authenticatedStoredRead explicitlyBoundSavedKey originalCount "
    "allOriginalsSettled finalDocumentEmpty automaticallyAssigned backupCreated releaseSigningQualified "
    "physicalMacEvidence privateContentsExported rowRetirement"
).split())


def need(condition, label="upload-key-cold-restart"):
    if not condition:
        raise ValueError(label)


def fixture_path(binding, native_home, case):
    """Compiled fixture ABI, never a name taken from an observer report."""
    need(case in CASES and type(native_home) is str and native_home.startswith("/")
         and native_home != "/" and len(native_home.encode("utf-8")) <= 4096
         and "\x00" not in native_home
         and all(part not in ("", ".", "..") for part in native_home.split("/")[1:]))
    need(type(binding.source) is str and re.fullmatch(r"[0-9a-f]{40}", binding.source) is not None
         and all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) is not None
                 for v in (binding.run, binding.attempt)))
    return Path(native_home) / "Library/Application Support" / (
        f"mrk-macos-aqua-upload-key-{binding.source}-{binding.run}-{binding.attempt}-{SCOPE}") / PROJECT / APP


def report(value, case):
    """The original parser ALSO checks the complete producer/helper reports.

    Missing tools/provider is still an honest nonexecution, but it is NOT a
    first phase that can release a cold-reopen invocation.
    """
    need(case in CASES and type(value) is dict)
    need(value.get("execution") == "executed" and value.get("testResult") == "positive",
         "upload-key-cold-first-not-positive" if case == PRODUCE else "upload-key-cold-reopen-not-positive")
    if case == PRODUCE:
        # The outer existing _upload_report validates every actual producer,
        # native, child/coordinator and disposal axis, with its unchanged body.
        need(value.get("mechanism") == "same-original-upload-key-v1"
             and value.get("authenticatedReopenReadback") is True
             and value.get("originalCount") == 9 and type(value["originalCount"]) is int)
        return value
    need(value.keys() == REOPEN_FIELDS and value["mechanism"] == "fresh-process-upload-key-reuse-v1")
    for key in ("openedExisting", "authenticatedStoredRead", "explicitlyBoundSavedKey",
                "allOriginalsSettled", "finalDocumentEmpty"):
        need(value[key] is True)
    for key in ("normalGenerationEnabled", "initialized", "generationAttempted", "automaticallyAssigned",
                "backupCreated", "releaseSigningQualified", "physicalMacEvidence", "privateContentsExported"):
        need(value[key] is False)
    need(type(value["inventoryRows"]) is int and value["inventoryRows"] == 1
         and type(value["originalCount"]) is int and value["originalCount"] == 6
         and type(value["lookupHelper"]) is dict
         and value["rowRetirement"] == "disposable-hosted-account-only")
    return value


def _names(fixtures, directory):
    """Discover at most the fixed four vault names, before retaining a body."""
    before = fixtures._upload_signature(directory)
    with fixtures._temporary(fixtures._open(".", directory, directory=True)) as reader:
        need(fixtures._upload_signature(reader) == before, "upload-key-cold-roster-original")
        iterator, original_error = os.scandir(reader), None
        try:
            names = []
            for entry in iterator:
                need(len(names) < 4 and type(entry.name) is str and len(entry.name) <= 64
                     and entry.name not in names, "upload-key-cold-roster")
                names.append(entry.name)
            need(fixtures._upload_signature(directory) == before
                 and fixtures._upload_signature(reader) == before, "upload-key-cold-roster-changed")
            return tuple(sorted(names))
        except BaseException as error:
            original_error = error
            raise
        finally:
            try:
                iterator.close()  # One original close; never retry it.
            except BaseException as error:
                fixtures.close_errors += 1
                if fixtures.first_close_error is None:
                    fixtures.first_close_error = error
                if original_error is None:
                    raise


def _hash(fixtures, parent, name, fd, original, low, high):
    """Bound BEFORE reads; hash private bytes in chunks, never export them."""
    held = fixtures._upload_signature(fd)
    need(held == original == fixtures._upload_named_signature(parent, name)
         and held[2] == stat.S_IFREG | 0o600 and held[3:6] == (fixtures.uid, fixtures.gid, 1)
         and low <= held[6] <= high, "upload-key-cold-file-custody")
    hashed, offset = hashlib.sha256(), 0
    while offset < held[6]:
        part = os.pread(fd, min(65536, held[6] - offset), offset)
        need(type(part) is bytes and 0 < len(part) <= min(65536, held[6] - offset),
             "upload-key-cold-file-read")
        hashed.update(part)
        offset += len(part)
    need(os.pread(fd, 1, offset) == b"" and fixtures._upload_signature(fd) == original
         and fixtures._upload_named_signature(parent, name) == original, "upload-key-cold-file-changed")
    return hashed.digest()


class Pair:
    """Finite two-call comparison DATA, not a native receipt or phase runner."""

    def __init__(self):
        self.entered = self.readbacks = self.emitted = 0
        self.directories, self.files = [], []
        self.bytes = 0

    def _original(self, fixtures):
        need(fixtures.cases == CASES and fixtures.upload_cold is self
             and not fixtures.inflight and fixtures.close_errors == 0
             and fixtures.first_close_error is None, "upload-key-cold-original-order")

    def before_call(self, fixtures, case):
        self._original(fixtures)
        need(case in CASES and self.entered == self.readbacks == self.emitted == CASES.index(case),
             "upload-key-cold-call-order")
        self.entered += 1  # This fixed attempt never rearms after a refusal.
        fixtures._vault_namespace_current()
        if case == PRODUCE:
            need(not self.files and not self.directories and not fixtures.last_returned
                 and not fixtures.vault_completed, "upload-key-cold-producer-reused")
            fixtures._roster(fixtures.vault_parents[case], (), "upload-key-cold-application-collision")
        else:
            need(fixtures.last_returned and fixtures.vault_completed == {PRODUCE},
                 "upload-key-cold-before-first-return")
            self.recheck(fixtures)

    def _directory(self, fixtures, parent, name, expected):
        fd = fixtures._open(name, parent, directory=True)
        before = fixtures._upload_signature(fd)
        fixtures._named(parent, name, fd, 0o700)
        need(all(before[:2] != entry[3][:2] for entry in self.directories)
             and all(before[:2] != entry[3][:2] for entry in self.files), "upload-key-cold-alias")
        # Retain before the first fallible read/scan. Fixtures already owns fd.
        self.directories.append((parent, name, fd, before, tuple(expected)))
        fixtures._roster(fd, expected, "upload-key-cold-directory-roster")
        return fd

    def _file(self, fixtures, parent, name, low, high):
        fd = fixtures._open(name, parent)
        held = fixtures._upload_signature(fd)
        need(held[0] == fixtures._upload_signature(parent)[0]
             and all(held[:2] != entry[3][:2] for entry in self.files)
             and all(held[:2] != entry[3][:2] for entry in self.directories), "upload-key-cold-alias")
        # A failure still leaves the actual FD in the original finite roster.
        row = [parent, name, fd, held, low, high, None]
        self.files.append(row)
        need(0 <= held[6] <= high and self.bytes <= PRIVATE_LIMIT - held[6], "upload-key-cold-byte-bound")
        self.bytes += held[6]
        row[6] = _hash(fixtures, parent, name, fd, held, low, high)

    def _retain(self, fixtures):
        need(not self.directories and not self.files, "upload-key-cold-already-retained")
        parent = fixtures.vault_parents[PRODUCE]
        fixtures._named(fixtures.vault_namespace, PROJECT, parent, 0o700)
        fixtures._roster(parent, (APP,), "upload-key-cold-application-roster")
        app = self._directory(fixtures, parent, APP, APP_NAMES)
        # Open and retain before examining names; the directory itself remains
        # a single original (not a second adoption based on discovered names).
        vault = fixtures._open("credential-vault-v1", app, directory=True)
        before = fixtures._upload_signature(vault)
        fixtures._named(app, "credential-vault-v1", vault, 0o700)
        need(all(before[:2] != row[3][:2] for row in self.directories), "upload-key-cold-alias")
        names = _names(fixtures, vault)
        records = [name for name in names if re.fullmatch(r"record-[0-9a-f]{32}", name)]
        need(len(records) == 1 and records[0] != "record-" + "0" * 32
             and set(names) == {"vault-lock", "initialization-reservation", "vault-header", records[0]},
             "upload-key-cold-singleton")
        self.directories.append((app, "credential-vault-v1", vault, before, names))
        for name, low, high in (("vault-lock", 0, 0), ("initialization-reservation", 48, 48),
                                ("vault-header", 104, 104), (records[0], 257, RECORD_LIMIT)):
            self._file(fixtures, vault, name, low, high)
        self._file(fixtures, app, "service-v1.reservation", len(b"MRK service root v1\n") + 16,
                   len(b"MRK service root v1\n") + 16)
        reservation = len(b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n")
        expected = {"owner.lock": (0, 0), "reservation": (reservation, reservation),
                    "projects.state": (53, STATE_LIMIT), "credential-references.state": (53, STATE_LIMIT),
                    "version-allocations.state": (52, 52)}
        service = self._directory(fixtures, app, "service-v1", expected)
        for name, (low, high) in expected.items():
            self._file(fixtures, service, name, low, high)
        self.recheck(fixtures)

    def recheck(self, fixtures):
        self._original(fixtures)
        need(len(self.directories) == 3 and len(self.files) == 10
             and 0 < self.bytes <= PRIVATE_LIMIT, "upload-key-cold-incomplete-roster")
        for parent, name, fd, original, expected in self.directories:
            need(fd in fixtures.fds and fixtures._upload_signature(fd) == original,
                 "upload-key-cold-directory-changed")
            fixtures._named(parent, name, fd, 0o700)
            fixtures._roster(fd, expected, "upload-key-cold-directory-roster")
        for parent, name, fd, original, low, high, hashed in self.files:
            need(fd in fixtures.fds and type(hashed) is bytes and len(hashed) == 32
                 and _hash(fixtures, parent, name, fd, original, low, high) == hashed,
                 "upload-key-cold-ciphertext-changed")
        for parent, name, fd, original, _ in self.directories:
            need(fixtures._upload_signature(fd) == original, "upload-key-cold-directory-changed")
            fixtures._named(parent, name, fd, 0o700)
        need(fixtures.close_errors == 0 and fixtures.first_close_error is None,
             "upload-key-cold-close-unknown")

    def readback(self, fixtures, case, value):
        self._original(fixtures)
        need(case in CASES and fixtures.last_returned and self.entered == CASES.index(case) + 1
             and self.readbacks == self.emitted == CASES.index(case), "upload-key-cold-readback-order")
        report(value, case)
        source = fixtures.readback(case)  # Original source reader; no new walker.
        if case == PRODUCE:
            self._retain(fixtures)
        else:
            self.recheck(fixtures)
        fixtures.vault_completed.add(case)
        fixtures._vault_namespace_current()
        self.readbacks += 1
        return {**source, "uploadKeyColdRestart": {
            "sameHeldPrivateOriginals": True, "completePrivateRoster": True,
            "ciphertextAndHeaderUnchanged": case == REOPEN, "coldProcessReturned": case == REOPEN,
            "retainedPrivateFileBytes": self.bytes, "privateContentsExported": False,
            "keychainInspectedByOwner": False, "retainedForDisposableAccountRetirement": True}}

    def after_emit(self, fixtures, case):
        """Called ONLY after emit_checked returns, including its runtime POST."""
        self._original(fixtures)
        need(case in CASES and fixtures.last_returned and self.emitted == CASES.index(case)
             and self.entered == self.readbacks == CASES.index(case) + 1, "upload-key-cold-post-order")
        self.emitted += 1

    def finished(self, fixtures):
        self._original(fixtures)
        need(self.entered == self.readbacks == self.emitted == 2 and fixtures.last_returned
             and fixtures.vault_completed == set(CASES), "upload-key-cold-pair-incomplete")
        self.recheck(fixtures)
