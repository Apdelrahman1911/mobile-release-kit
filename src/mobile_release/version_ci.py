"""Consume an existing shared reservation in the pinned candidate workflow.

This is a read-only allocation/source check, not a hosted allocator, a fresh
Store observation, native consent, or authority to rebuild/repeat an upload.
The original workflow intent/handoff/recovery owners remain unchanged.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import version_allocation as allocation
from . import version_policy as policy
from . import version_text
from . import workflow
from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, parse_config_text
from .errors import ConfigurationError
from .owned_process import ProcessCleanupError, run_owned

AUTHORITY_ENV = "MOBILE_RELEASE_VERSION_AUTHORITY"
TRAILER = "MRK-Version-Reservation"
SETTINGS_LIMIT = 4096
COMMIT_LIMIT = 16 * 1024
DIFF_LIMIT = 16 * 1024
HTTP_LIMIT = 1024 * 1024
WORK_SECONDS = 60
MAX_GIT_CALLS = 12
MAX_HTTP_CALLS = 8
_OID = re.compile(r"[0-9a-f]{40}\Z")
_ROW_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_TRAILER_LINE = re.compile(rb"MRK-Version-Reservation: ([0-9a-f-]{36}) ([0-9a-f]{64})\Z")
_TRAILER_OTHER = re.compile(rb"[A-Za-z0-9][A-Za-z0-9-]*: [^\x00-\x1f\x7f]*\Z")
_MESSAGES = {
    "settings": "CI counter settings are missing or invalid. Copy the settings from a completed reservation into the protected MOBILE_RELEASE_VERSION_AUTHORITY variable; no manual fallback was selected.",
    "trailer": "This CI project requires one exact MRK version-reservation commit trailer. Copy it from the completed reservation; do not substitute a build number or another candidate.",
    "authority": "The shared counter or its retained checkpoint could not be verified. Preserve its existing state; CI does not create, reset or allocate a counter.",
    "candidate": "The selected reservation does not match this repository, branch, platform or candidate. CI never replaces the candidate or assigns another number.",
    "source": "Reserved CI currently needs one version-only commit directly after the reserved source. Commit other changes before reserving, then apply the reserved version and commit that change separately.",
    "read": "The bounded CI reservation read did not complete. No allocation or Store operation was authorized; preserve the existing candidate.",
    "deadline": "The original CI reservation read expired or its clock changed. No allocation or Store operation was authorized.",
}


class Refused(workflow.WorkflowError):
    """Fixed safe diagnostics: no Git stderr, config text or response echo."""

    def __init__(self, reason: str):
        self.reason = reason if reason in _MESSAGES else "read"
        super().__init__(_MESSAGES[self.reason])


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


@dataclass(frozen=True, slots=True)
class Settings:
    """Protected CI opt-in DATA, exported from an already joined reservation."""

    authority: allocation.AuthorityRegistration
    checkpoint: allocation.Checkpoint

    @classmethod
    def parse(cls, raw: str) -> Settings:
        try:
            _need(type(raw) is str and 0 < len(raw) <= SETTINGS_LIMIT, "settings")
            encoded = raw.encode("utf-8")
            _need(len(encoded) <= SETTINGS_LIMIT, "settings")
            row = policy._object(allocation._decode_json(encoded, limit=SETTINGS_LIMIT,
                nodes=64, depth=5, exact=True), {"schemaVersion", "authority", "checkpoint"})
            _need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1, "settings")
            result = cls(allocation.AuthorityRegistration.parse(row["authority"]),
                         allocation.Checkpoint.parse(row["checkpoint"]))
            _need(result.authority.protected_branch, "settings")
            return result
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise Refused("settings") from None


@dataclass(frozen=True, slots=True)
class Selection:
    candidate_id: str
    row_sha256: str


@dataclass(frozen=True, slots=True)
class Checked:
    """Result DATA. Never feed this to a native edit/Store grant constructor."""

    candidate_id: str
    row_sha256: str
    source_commit: str
    source_tree: str
    version_name: str
    version_build: int


def commit_selection(message: bytes) -> Selection | None:
    """Exactly one canonical trailer in the final trailer paragraph.

    A marker elsewhere, alternate case, duplicate or continuation is not an
    invitation to silently fall back to manual mode.
    """
    _need(type(message) is bytes and len(message) <= COMMIT_LIMIT and b"\0" not in message,
          "trailer")
    lines = message.rstrip(b"\n").split(b"\n")
    marker = TRAILER.lower().encode("ascii")
    occurrences = [i for i, line in enumerate(lines) if marker in line.lower()]
    if not occurrences:
        return None
    _need(len(occurrences) == 1, "trailer")
    at = occurrences[0]
    match = _TRAILER_LINE.fullmatch(lines[at])
    _need(match is not None, "trailer")
    start = len(lines) - 1
    while start > 0 and lines[start - 1] != b"":
        start -= 1
    _need(at >= start and start > 0 and all(_TRAILER_OTHER.fullmatch(line) for line in lines[start:]),
          "trailer")
    assert match is not None
    candidate, row_hash = (v.decode("ascii") for v in match.groups())
    _need(_UUID.fullmatch(candidate) is not None and _ROW_HASH.fullmatch(row_hash) is not None,
          "trailer")
    return Selection(candidate, row_hash)


def _object(raw: bytes, kind: str, oid: str, limit: int) -> bytes:
    _need(type(raw) is bytes and len(raw) <= limit and _OID.fullmatch(oid) is not None, "source")
    digest = hashlib.sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    _need(digest == oid, "source")
    return raw


def _commit(raw: bytes, oid: str) -> tuple[str, tuple[str, ...], bytes]:
    _object(raw, "commit", oid, COMMIT_LIMIT)
    header, separator, message = raw.partition(b"\n\n")
    _need(bool(separator) and b"\0" not in header and b"\r" not in header, "source")
    rows = header.split(b"\n")
    trees = [line[5:] for line in rows if line.startswith(b"tree ")]
    parents = [line[7:] for line in rows if line.startswith(b"parent ")]
    _need(len(trees) == 1 and rows[0] == b"tree " + trees[0] and len(parents) <= 16, "source")
    try:
        tree = trees[0].decode("ascii")
        parsed = tuple(parent.decode("ascii") for parent in parents)
    except UnicodeError:
        raise Refused("source") from None
    _need(_OID.fullmatch(tree) is not None and all(_OID.fullmatch(p) for p in parsed), "source")
    return tree, parsed, message


def _config_entry(raw: bytes) -> str:
    # Literal fixed path; no -r and no worktree/dereference of an unrelated entry.
    match = re.fullmatch(rb"100(?:644|755) blob ([0-9a-f]{40})\trelease/mobile-release\.json\0", raw)
    _need(match is not None, "source")
    assert match is not None
    return match[1].decode("ascii")


def _version_delta(raw: bytes, source: str) -> tuple[str, str]:
    # FULL diff, not a path-filtered diff: exactly one complete ordinary M row.
    # Equal off-path trees/modes/symlinks/gitlinks are not enumerated or opened.
    match = re.fullmatch(rb":(100(?:644|755)) \1 ([0-9a-f]{40}) ([0-9a-f]{40}) M\0([^\0]+)\0", raw)
    _need(match is not None, "source")
    assert match is not None
    _need(match[4] == source.encode("utf-8") and match[2] != match[3], "source")
    return match[2].decode("ascii"), match[3].decode("ascii")


class _Read:
    """One fixed call schedule on the existing Git/gh original owners."""

    _git_limit = MAX_GIT_CALLS
    _http_limit = MAX_HTTP_CALLS

    def __init__(self, root: Path, context: workflow.Context, github: workflow.GitHub,
                 guard: DefaultCancellation):
        self.root, self.context, self.github, self.guard = root, context, github, guard
        self.started = self.last = time.monotonic()
        _need(type(self.started) in (int, float) and math.isfinite(self.started), "deadline")
        self.end = self.started + WORK_SECONDS
        self.git_calls = self.http_calls = 0
        self.prefix = "repos/" + context.repository["fullName"] + "/"

    def remaining(self) -> int:
        self.guard.check()
        now = time.monotonic()
        _need(type(now) in (int, float) and math.isfinite(now) and self.last <= now < self.end,
              "deadline")
        self.last = now
        remaining = math.floor(self.end - now)
        _need(remaining >= 1, "deadline")
        return min(10, remaining)

    def git(self, args: list[str], maximum: int) -> bytes:
        timeout = self.remaining()
        self.git_calls += 1
        _need(self.git_calls <= self._git_limit, "read")
        env = {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_PAGER": "cat"}
        command = ["git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=" + os.devnull, "-c", "protocol.allow=never", "-C", str(self.root), *args]
        result = run_owned(command, environ=env, cwd=self.root, timeout=timeout, capture=True,
            text=False, output_limit=maximum, cancellation=self.guard)
        self.remaining()  # Actual C/A/W return is necessary, not a result-shaped receipt.
        _need(result.returncode == 0 and type(result.stdout) is bytes and len(result.stdout) <= maximum,
              "read")
        return result.stdout

    def json(self, suffix: str) -> dict:
        timeout = self.remaining()
        self.http_calls += 1
        _need(self.http_calls <= self._http_limit, "read")
        # Every call, including commits and the final ref, is fresh/bounded.
        # Do not use GitHub.tree()/_trees/_comparisons with their old defaults.
        body = self.github.json(self.prefix + suffix if suffix else self.prefix[:-1],
                                maximum=HTTP_LIMIT, timeout=timeout)
        self.remaining()
        _need(type(body) is dict, "read")
        return body

    def head(self, commit: str, tree: str | None = None) -> None:
        _need(self.git(["rev-parse", "--verify", "HEAD"], 64) == (commit + "\n").encode("ascii"), "source")
        if tree is not None:
            _need(self.git(["rev-parse", "--verify", "HEAD^{tree}"], 64) == (tree + "\n").encode("ascii"), "source")

    def commit(self, oid: str) -> tuple[str, tuple[str, ...], bytes]:
        _need(_OID.fullmatch(oid) is not None, "source")
        return _commit(self.git(["cat-file", "commit", oid], COMMIT_LIMIT), oid)

    def blob(self, oid: str, maximum: int) -> bytes:
        return _object(self.git(["cat-file", "blob", oid], maximum), "blob", oid, maximum)

    def remote_commit(self, oid: str, tree: str) -> None:
        body = self.json("git/commits/" + oid)
        _need(body.get("sha") == oid and type(body.get("tree")) is dict
              and body["tree"].get("sha") == tree, "source")

    def verify(self, settings: Settings, final: str, reference: str, selected: tuple[str, ...]) -> Checked:
        self.head(final)
        final_tree, parents, message = self.commit(final)
        trailer = commit_selection(message)
        _need(trailer is not None, "trailer")
        assert trailer is not None
        authority = settings.authority
        _need(authority.repository == self.context.repository["fullName"]
              and authority.repository_id == self.context.repository["id"], "authority")
        reference_path = "git/ref/heads/" + allocation.LEDGER_BRANCH
        try:
            allocation._repository_identity(self.json(""), authority)
            ledger_commit = allocation._ref_commit(self.json(reference_path))
            allocation._ancestry(self.json("compare/" + settings.checkpoint.commit + "..." + ledger_commit),
                                 settings.checkpoint.commit, ledger_commit)
            snapshot = allocation._snapshot(self.json("contents/" + allocation.LEDGER_PATH + "?ref=" + ledger_commit),
                ledger_commit, authority, settings.checkpoint)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise Refused("authority") from None
        matches = [item for item in snapshot.ledger.reservations if item.request.candidate_id == trailer.candidate_id]
        _need(len(matches) == 1 and matches[0].sha256 == trailer.row_sha256, "candidate")
        row = matches[0]
        from . import version_future_tag as future_tag
        if row.request.future_tag is not None:
            self._http_limit = MAX_HTTP_CALLS + 2  # Explicit v5 only; old CI stays eight.
            future_tag.check_bound(snapshot.ledger, row, final, final_tree)
            future_tag.check_ref(self.json("git/ref/" + row.request.future_tag.removeprefix("refs/")),
                                 row.request.future_tag, final)
        self._prove(authority, row, final, reference, selected, final_tree, parents)
        try:
            _need(allocation._ref_commit(self.json(reference_path)) == ledger_commit, "authority")
            allocation._repository_identity(self.json(""), authority)
        except (ValueError, TypeError, KeyError):
            raise Refused("authority") from None
        if row.request.future_tag is not None:
            future_tag.check_ref(self.json("git/ref/" + row.request.future_tag.removeprefix("refs/")),
                                 row.request.future_tag, final)
        self.remaining()
        return Checked(row.request.candidate_id, row.sha256, final, final_tree, row.version.name, row.version.build)

    def _prove(self, authority, row, final, reference, selected, final_tree, parents):
        """Same full local/remote B→F proof; no public bypass or partial diff."""
        request = row.request
        _need(request.project_id == authority.project_id and request.version_policy.mode == "automatic"
              and request.source.ref == reference and request.enabled_platforms == selected,
              "candidate")
        # Ledger replay already checked exact versioned policy and observation
        # bindings. These old observations are NOT fresh Store eligibility.
        _need(parents == (request.source.commit,), "source")
        before_tree, _, _ = self.commit(request.source.commit)
        _need(before_tree == request.source.tree, "source")
        self.remote_commit(request.source.commit, before_tree)
        self.remote_commit(final, final_tree)
        config_oid = _config_entry(self.git(["ls-tree", "-z", "--full-tree", request.source.commit,
                                            "--", version_text.CONFIG_PATH], 1024))
        config_raw = self.blob(config_oid, MAX_CONFIG_BYTES)
        _need(hashlib.sha256(config_raw).hexdigest() == request.source.configuration_sha256, "source")
        try:
            config_text = config_raw.decode("utf-8")
            selection = version_text.public_version_selection(config_text)
            config = parse_config_text(config_text)
            enabled = tuple(p for p in ("android", "ios") if config[p].get("enabled") is True)
            _need(enabled == request.enabled_platforms, "source")
            delta = self.git(["diff-tree", "--no-abbrev", "--raw", "-z", "-r", "--no-renames",
                "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "--no-commit-id",
                request.source.commit, final, "--"], DIFF_LIMIT)
            before_oid, after_oid = _version_delta(delta, selection.source)
            before = self.blob(before_oid, MAX_VERSION_BYTES)
            after = self.blob(after_oid, MAX_VERSION_BYTES)
            _need(hashlib.sha256(before).hexdigest() == request.source.version_sha256, "source")
            original = version_text.original_text(selection, before)
            _need(original.values == (request.base_version.name, str(request.base_version.build)), "source")
            _, expected, _ = version_text.prepare_payload(selection, before, "edit",
                {"name": row.version.name, "build": str(row.version.build)})
            _need(after == expected, "source")
        except (ConfigurationError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise Refused("source") from None
        self.head(final, final_tree)



def verify_reserved_source(app_root: Path, context: workflow.Context, *,
                           github: workflow.GitHub | None = None,
                           cancellation: DefaultCancellation | None = None) -> Checked | None:
    """Fixed candidate-only read. None means *unconfigured/manual*, not ready.

    A protected nonempty setting requires a trailer. A trailer with no setting
    refuses. Neither a bad response nor an expired read can choose manual mode.
    Authenticated original workflow recovery must not call this fresh gate.
    """
    # The entry point also runs as ``python -m ...workflow``. Its Context class
    # then belongs to __main__; Python class identity is not release authority.
    # Keep the SAME passed context/client and validate their bound DATA below.
    _need(context.stage == "candidate", "candidate")
    final, reference = context.authority.get("headSha"), context.authority.get("ref")
    _need(type(final) is str and _OID.fullmatch(final) is not None and type(reference) is str
          and reference.startswith("refs/heads/"), "candidate")
    selected = {"android": ("android",), "ios": ("ios",), "both": ("android", "ios")}.get(context.selected_platform)
    _need(selected is not None and context.platform in selected, "candidate")
    root = workflow._safe_path(app_root)
    _need(root.is_dir() and (root / ".git").is_dir() and not (root / ".git").is_symlink(), "source")
    raw_settings = os.environ.get(AUTHORITY_ENV, "")
    settings = Settings.parse(raw_settings) if raw_settings else None
    github = github or workflow.GitHub(context)
    _need(github.context is context, "candidate")
    guard, owns = cancellation_owner(cancellation or github.cancellation, ProcessCleanupError,
                                     "CI version reader cancellation did not settle")
    scope = CleanupScope(guard, lambda: None, owns_cancellation=owns, first_primary=True)
    result = None
    try:
        with scope:
            if owns:
                guard.install()
                guard.activate()
            read = _Read(root, context, github.with_cancellation(guard), guard)
            if settings is None:
                # Preserve ordinary manual commits (including large messages)
                # without a full ledger/source read. Git's fixed trailer format
                # emits only this key; nonempty/malformed output never falls back.
                probe = read.git(["show", "-s", "--format=%(trailers:key=" + TRAILER + ",only)", final, "--"], 4096)
                _need(not probe.strip(), "settings")
            else:
                result = read.verify(settings, final, reference, selected)
    finally:
        scope.__exit__(*sys.exc_info())
    guard.check()
    return result
