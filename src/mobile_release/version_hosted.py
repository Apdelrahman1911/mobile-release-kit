"""Explicit shared reservation in the pinned protected candidate workflow.

ONE existing ledger/allocator; the fixed repository journal is the hosted
implementation of its pending-before-send port, not a native durability ACK.
No build/upload, source edit/push, counter bootstrap or implicit retry. Play
inventory has explicit temporary-edit consent and a durable pre-effect fence.
"""
from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from . import ios_store_versions as ios
from . import android_store_versions as android
from . import paired_store_versions as paired
from . import version_allocation as a
from . import version_allocation_state as state
from . import version_allocation_transport as wire
from . import version_ci as ci
from . import version_enrollment as enrollment
from . import version_policy as p
from . import version_text, workflow
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import ReadResult
from .api._json import bounded_json_text
from .cancellation import CleanupScope, cancellation_owner
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseVersion, parse_config_text
from .github_preflight import HttpRequest
from .owned_process import ProcessCleanupError

JOURNAL_PATH = "release/.mrk-version-ci-state-v1.json"
POLICY_ENV = "MOBILE_RELEASE_VERSION_POLICY"
TOKEN_ENV = "MOBILE_RELEASE_VERSION_GITHUB_TOKEN"
MAX_STATE_BYTES = 128 * 1024
MAX_STATE_NODES = 4096
MAX_REQUESTS = 44
MAX_WRITES = 7  # existing five + one Play pending and one confirmed cleanup
CA_PATH = "desktop/cpython-source-inputs/github-ca.pem"
READ = "hosted-version-read"
HISTORY = "hosted-version-history"
JOURNAL_READ = "hosted-version-journal-read"
JOURNAL_WRITE = "hosted-version-journal-write"
LEDGER_WRITE = "hosted-version-ledger-write"
_ROLES = {READ, HISTORY, JOURNAL_READ, JOURNAL_WRITE, LEDGER_WRITE}
_SHA = r"[0-9a-f]{40}"
_MESSAGE = "Retain Mobile Release Kit hosted version intent"
_PLATFORMS = {"ios": ("ios",), "android": ("android",), "both": paired.PLATFORMS}
_SCHEMAS = {"ios": 2, "android": 3, "both": 4}
_KEEP = object()
_DIAGNOSTICS = {
    "admission": "Use the protected Reserve version action with the exact enabled platforms, enrolled counter and automatic policy. Android/shared reservation also requires explicit temporary Play edit confirmation. This action does not build or upload.",
    "source": "The exact branch, source or selected version changed. Preserve the candidate; commit other changes before selecting another reservation.",
    "journal": "The hosted journal write/read is unconfirmed or conflicts. Preserve it and retry only the exact source/request explicitly; pending attempts never resend the ledger write. Do not delete or reset it.",
    "missing": "The hosted journal is missing but first creation could not be proved. Preserve repository history; do not recreate the journal.",
    "size": "The hosted journal exceeds its bounded size/complexity. All rows are preserved; manual versioning remains available. Do not truncate or reset the journal.",
    "authority": "The enrolled repository, protected counter branch or checkpoint could not be verified. No counter is created or reset.",
    "credential": "Hosted reservation needs its dedicated repository-scoped GitHub App token: Administration read, Contents write and Actions read. Ordinary GITHUB_TOKEN is not a fallback. Preserve any existing candidate and journal.",
    "candidate": "This source already has a different full candidate request. Reuse the exact original policy and inputs; a retry never changes the candidate or number.",
    "store": "Current Store inventory or its original private input is unavailable. No manual/counter-only or single-platform fallback is selected.",
    "google": "Hosted Android/shared reservation requires the selected protected MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64 service-account key (at most 16 KiB). This fixed reader does not accept WIF/ambient ADC. Normal candidate WIF is unchanged.",
    "play-pending": "A temporary Play edit has an unconfirmed outcome in the hosted journal. Preserve the journal and original operation. Do not retry, recreate an edit, reset or clear the fence; automatic remote cleanup recovery is not available here.",
    "read": "The original bounded hosted operation did not finish. Preserve its journal and candidate; do not replay an uncertain write.",
}


class Refused(workflow.WorkflowError):
    def __init__(self, reason: str):
        self.reason = reason if reason in _DIAGNOSTICS else "read"
        super().__init__(_DIAGNOSTICS[self.reason])


def need(value: bool, reason: str = "read") -> None:
    if not value:
        raise Refused(reason)


def _blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class PlayQuery:
    """Pending DATA only; not a cleanup receipt or a second version counter."""
    candidate_id: str
    request_sha256: str
    attempt_id: str

    def __post_init__(self):
        a._uuid(self.candidate_id)
        p._match(self.request_sha256, p._DIGEST)
        a._uuid(self.attempt_id)

    def value(self):
        return {"candidateId": self.candidate_id, "requestSha256": self.request_sha256,
                "attemptId": self.attempt_id}

    @classmethod
    def parse(cls, value):
        row = p._object(value, {"candidateId", "requestSha256", "attemptId"})
        return cls(row["candidateId"], row["requestSha256"], row["attemptId"])

    def require_state(self, original):
        matches = [row.request for row in original.candidates if row.request.candidate_id == self.candidate_id]
        need(len(matches) == 1 and matches[0].sha256 == self.request_sha256
             and "android" in matches[0].enabled_platforms, "journal")


@dataclass(frozen=True, slots=True)
class Envelope:
    revision: int
    state: state.AllocationState
    play_query: PlayQuery | None = None
    schema_version: int = 1

    def to_bytes(self) -> bytes:
        p._integer(self.revision, state.MAX_REVISION, 1)
        need(type(self.state) is state.AllocationState and len(self.state.authorities) == 1, "journal")
        need(type(self.schema_version) is int and self.schema_version in (1, 2), "journal")
        need(self.play_query is None or type(self.play_query) is PlayQuery, "journal")
        if self.play_query is not None:
            self.play_query.require_state(self.state)
        value = {"revision": self.revision, "state": self.state.value()}
        if self.schema_version == 1:
            need(self.play_query is None, "journal")
        else:
            value.update(schemaVersion=2, playQuery=None if self.play_query is None else self.play_query.value())
        raw = p.canonical(value) + b"\n"
        # Bound BOTH incoming and prospective outgoing bytes/nodes before the
        # existing state codec/canonical copies. Never write a too-large row.
        self._decode(raw)
        return raw

    @staticmethod
    def _decode(raw: bytes) -> dict:
        need(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES, "size")
        need(raw.endswith(b"\n") and raw.count(b"\n") == 1, "journal")
        try:
            value = _decode_json(raw[:-1], limit=MAX_STATE_BYTES - 1,
                nodes=MAX_STATE_NODES, depth=20, exact=True)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise Refused("size") from None
        need(type(value) is dict, "journal")
        if "schemaVersion" in value:
            need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 2, "journal")
            return p._object(value, {"schemaVersion", "revision", "state", "playQuery"})
        return p._object(value, {"revision", "state"})

    @classmethod
    def parse(cls, raw: bytes) -> Envelope:
        row = cls._decode(raw)
        try:
            p._integer(row["revision"], state.MAX_REVISION, 1)
            need(type(row["state"]) is dict and row["state"].get("schemaVersion") == 3, "journal")
            result = cls(row["revision"], state.AllocationState.parse(p.canonical(row["state"]) + b"\n"),
                None if row.get("playQuery") is None else PlayQuery.parse(row["playQuery"]), row.get("schemaVersion", 1))
            need(result.to_bytes() == raw, "journal")
            return result
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            raise Refused("journal") from None


def validate_endpoint(role: str, method: str, path: str) -> None:
    """Called only after the original transport admits its closed enum role."""
    need(role in _ROLES)
    _, tail = wire._path(path)
    if role == JOURNAL_WRITE:
        valid = method == "PUT" and tail == "contents/" + JOURNAL_PATH
    elif role == LEDGER_WRITE:
        wire.validate_endpoint(wire.ROLE_LEDGER_WRITE, method, path)
        return
    elif role == JOURNAL_READ:
        valid = method == "GET" and re.fullmatch("contents/" + re.escape(JOURNAL_PATH) + r"\?ref=" + _SHA, tail)
    elif role == HISTORY:
        valid = method == "GET" and re.fullmatch(r"commits\?sha=" + _SHA + r"&path="
            + re.escape(JOURNAL_PATH) + r"&per_page=1&page=1", tail)
    else:
        valid = method == "GET" and (tail == "" and not path.endswith("/")
            or tail == "branches/" + a.LEDGER_BRANCH + "/protection"
            or re.fullmatch(r"git/ref/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", tail)
            or re.fullmatch(r"git/commits/" + _SHA, tail)
            or re.fullmatch(r"compare/" + _SHA + r"\.\.\." + _SHA + r"\?per_page=1&page=1", tail)
            or re.fullmatch("contents/" + re.escape(a.LEDGER_PATH) + r"\?ref=" + _SHA, tail)
            or re.fullmatch(r"actions/runs/[1-9][0-9]{0,19}/attempts/[1-9][0-9]{0,2}", tail))
    need(bool(valid))


def validate_body(role: str, body: object, *, path: str) -> None:
    if role == LEDGER_WRITE:
        wire.validate_body(wire.ROLE_LEDGER_WRITE, body, path=path)
    elif role == JOURNAL_WRITE:
        validate_endpoint(role, "PUT", path)
        need(type(body) is bytes and 0 < len(body) <= a.MAX_HTTP_BYTES)
        value = _decode_json(body, limit=a.MAX_HTTP_BYTES, nodes=9, depth=2, exact=True)
        need(type(value) is dict and set(value) in ({"branch", "message", "content"},
             {"branch", "message", "content", "sha"}) and p.canonical(value) == body)
        need(value["branch"] == a.LEDGER_BRANCH and value["message"] == _MESSAGE)
        if "sha" in value:
            p._match(value["sha"], p._SHA)
        encoded = value["content"]
        need(type(encoded) is str and 0 < len(encoded) <= 4 * ((MAX_STATE_BYTES + 2) // 3))
        raw = base64.b64decode(encoded, validate=True)
        need(base64.b64encode(raw).decode("ascii") == encoded)
        Envelope.parse(raw)  # Structural only; the original Journal checks its retained predecessor.
    else:
        validate_endpoint(role, "GET", path)
        need(body is None)


class _Remote:
    """Fixed repository, one original budget/exchange, no retry or generic CLI."""
    def __init__(self, authority, source, send):
        self.authority, self.source, self.send = authority, source, send
        self.prefix = "/repos/" + authority.repository
        self.calls = 0
        self.stopped = False

    def exchange(self, role, request):
        need(not self.stopped and type(request) is HttpRequest)
        need(request.path == self.prefix or request.path.startswith(self.prefix + "/"))
        validate_endpoint(role, request.method, request.path)
        validate_body(role, request.body, path=request.path)
        self.source.remaining()
        self.calls += 1
        need(self.calls <= MAX_REQUESTS)
        try:
            result = self.send(role, request)
            self.source.remaining()  # includes actual TLS close, not receipt time
            need(type(result) is ReadResult)
            control = _check_control(result.control)
            row = p._object(result.observation, {"status", "body", "failure"})
            bounded_json_text(row, max_bytes=a.MAX_HTTP_BYTES, max_nodes=20_000, max_depth=24)
            need(control["reason"] == "none" and row["failure"] == "none",
                 "credential" if control["reason"] == "unauthorized" else "read")
            need(type(row["status"]) is int and 100 <= row["status"] <= 599)
            if row["status"] not in {200, 201}:
                need(row["body"] is None)
            return result
        except BaseException:
            self.stopped = True
            raise

    def read(self, suffix: str, *, role=READ, missing=False):
        result = self.exchange(role, HttpRequest("GET", self.prefix + ("/" + suffix if suffix else ""), None))
        status, body = result.observation["status"], result.observation["body"]
        if missing and status == 404:
            return None
        need(status == 200 and type(body) is (list if role == HISTORY else dict),
             "credential" if status in {401, 403} else "read")
        return body

    def ref(self):
        return a._ref_commit(self.read("git/ref/heads/" + a.LEDGER_BRANCH))

    def ancestry(self, before, after):
        a._ancestry(self.read("compare/" + before + "..." + after + "?per_page=1&page=1"), before, after)

    def source_current(self):
        reference, commit = self.source.binding.ref, self.source.binding.commit
        body = self.read("git/ref/" + reference[len("refs/"):])
        need(body.get("ref") == reference and type(body.get("object")) is dict
             and body["object"].get("type") == "commit" and body["object"].get("sha") == commit, "source")

    def journal_current(self, commit):
        current = self.ref()
        self.ancestry(commit, current)


def _journal_content(body) -> bytes:
    need(type(body) is dict and body.get("type") == "file" and body.get("path") == JOURNAL_PATH
         and body.get("encoding") == "base64" and "target" not in body and "submodule_git_url" not in body, "journal")
    size, encoded = body.get("size"), body.get("content")
    need(type(size) is int and 0 < size <= MAX_STATE_BYTES, "size")
    need(type(encoded) is str and len(encoded) <= 2 * MAX_STATE_BYTES, "journal")
    raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
    need(len(raw) == size and _blob(raw) == body.get("sha"), "journal")
    return raw


class _Journal(state._AllocationTransitions):
    """Same pure state transitions; ONLY fixed contents CAS acknowledges IO."""
    def __init__(self, remote, settings):
        self.remote, self.settings = remote, settings
        self._poisoned = False
        self.revision, self.blob, self.writes = 0, None, 0
        self.commit = None
        self._local_project_id = self._bound_request = None
        self._loaded = False
        self._schema_version = 1
        self.play_query = self._play_original = None

    def load(self):
        self._usable()
        need(not self._loaded, "journal")
        self._loaded = True  # Failed reads never reopen this original adapter.
        self._poisoned = True  # No transition/reentry until the entire load is verified.
        remote, settings = self.remote, self.settings
        a._repository_identity(remote.read(""), settings.authority)
        enrollment._protection(remote.read("branches/" + a.LEDGER_BRANCH + "/protection"))
        current = remote.ref()
        remote.ancestry(settings.checkpoint.commit, current)
        ledger = a._snapshot(remote.read("contents/" + a.LEDGER_PATH + "?ref=" + current),
                             current, settings.authority, settings.checkpoint)
        body = remote.read("contents/" + JOURNAL_PATH + "?ref=" + current, role=JOURNAL_READ, missing=True)
        self.commit = current
        if body is None:
            history = remote.read("commits?sha=" + current + "&path=" + JOURNAL_PATH + "&per_page=1&page=1", role=HISTORY)
            need(history == [] and remote.ref() == current, "missing")
            self._state = state.AllocationState((state.AuthorityState(settings.authority, ledger.checkpoint),))
        else:
            raw = _journal_content(body)
            original = Envelope.parse(raw)
            self.revision, self.blob, self._state = original.revision, body["sha"], original.state
            self._schema_version, self.play_query = original.schema_version, original.play_query
            retained = self._state.selected(settings.authority)
            ledger.ledger.admit(settings.authority, retained.checkpoint)
            if retained.checkpoint.commit != current:
                remote.ancestry(retained.checkpoint.commit, current)
        self._poisoned = False
        return ledger

    def choose(self, make_request):
        """Find immutable source key first; only a genuinely absent key mints."""
        self._usable()
        need(self.play_query is None or self.remote.source.enabled == ("ios",), "play-pending")
        source = self.remote.source.binding
        matches = [row for row in self._state.candidates
                   if (row.request.source.ref, row.request.source.commit) == (source.ref, source.commit)]
        need(len(matches) <= 1, "candidate")
        if matches:
            selected = matches[0]
            request = make_request(selected.request.candidate_id)
            need(selected.request == request, "candidate")
            self._keep_play_for_ios(request, selected.local_project_id, self._state)
            self._local_project_id, self._bound_request = selected.local_project_id, request
            self.admit_request(self.settings.authority, request)
            return request
        need(self._state.selected(self.settings.authority).pending is None, "journal")
        self._local_project_id = uuid4().hex
        need(all(row.local_project_id != self._local_project_id for row in self._state.enrollments), "candidate")
        request = make_request(str(uuid4()))
        self._bound_request = request
        enrollments = tuple(sorted((*self._state.enrollments,
            state.ProjectEnrollment(self._local_project_id, self.settings.authority.project_id)),
            key=lambda row: row.local_project_id))
        after = state.AllocationState(self._state.authorities, enrollments, self._state.candidates)
        self._store(after.selecting(state.SelectedCandidate(self._local_project_id, request)))
        return request

    def _keep_play_for_ios(self, request, local_project_id, after):
        if self.play_query is None:
            return
        source = self.remote.source
        need(self._schema_version == 2 and type(request) is a.AllocationRequest
             and request.version_policy.schema_version == 2
             and request.enabled_platforms == source.enabled == ("ios",)
             and request.source == source.binding and request.identity_revision == source.identity
             and request.base_version == source.base
             and request.project_id == self.settings.authority.project_id, "play-pending")
        self.play_query.require_state(self._state)
        original = next(row for row in self._state.candidates
                        if row.request.candidate_id == self.play_query.candidate_id)
        enrollment = next(row for row in self._state.enrollments
                          if row.local_project_id == original.local_project_id)
        candidate = after.candidate(local_project_id)
        # iOS progress cannot reinterpret, replace, resolve or unenroll the
        # original Play candidate. Its full reservation is protected too, not
        # merely the request hash stored in PlayQuery.
        need(local_project_id != original.local_project_id
             and request.candidate_id != original.request.candidate_id
             and candidate is not None and candidate.request == request
             and after.candidate(original.local_project_id) == original
             and enrollment in after.enrollments, "play-pending")
        for value in (self._state, after):
            pending = value.selected(self.settings.authority).pending
            need(pending is None or pending.reservation.request == request, "play-pending")

    def begin_play(self, request):
        self.admit_request(self.settings.authority, request)
        need("android" in request.enabled_platforms and self.play_query is None
             and self._play_original is None, "play-pending")
        original = PlayQuery(request.candidate_id, request.sha256, str(uuid4()))
        self._play_original = original  # Retained before the sole pending CAS.
        self._store(self._state, play_query=original)
        return original

    def finish_play(self, request, source, original):
        from .version_hosted_store import Material
        self.admit_request(self.settings.authority, request)
        need(type(original) is PlayQuery and original is self._play_original and self.play_query == original
             and original.request_sha256 == request.sha256, "play-pending")
        need(type(source.material) is Material, "play-pending")
        # This consumes SAME Material's actual joined/closed attempt, never a
        # frame/summary supplied by a caller. A failed CAS cannot consume again.
        source.material._consume_play_cleanup(source, original)
        self._store(self._state, play_query=None)

    def _store(self, after, *, play_query=_KEEP):
        self._usable()
        need(self.revision < state.MAX_REVISION and self.writes < MAX_WRITES, "journal")
        if play_query is _KEEP:
            self._keep_play_for_ios(self._bound_request, self._local_project_id, after)
        else:
            need(after is self._state and self._play_original is not None
                 and ((self.play_query is None and play_query is self._play_original)
                      or (self.play_query is self._play_original and play_query is None)), "play-pending")
        selected_play = self.play_query if play_query is _KEEP else play_query
        schema = 2 if self._schema_version == 2 or play_query is not _KEEP else 1
        raw = Envelope(self.revision + 1, after, selected_play, schema).to_bytes()
        body = {"branch": a.LEDGER_BRANCH, "message": _MESSAGE, "content": base64.b64encode(raw).decode("ascii")}
        if self.blob is not None:
            body["sha"] = self.blob
        self._poisoned = True  # Includes BaseException, reentry and lost ACK.
        self.writes += 1
        try:
            result = self.remote.exchange(JOURNAL_WRITE,
                HttpRequest("PUT", self.remote.prefix + "/contents/" + JOURNAL_PATH, p.canonical(body)))
            row = result.observation
            need(row["status"] == (201 if self.blob is None else 200) and type(row["body"]) is dict, "journal")
            ack = row["body"]
            need(type(ack.get("content")) is dict and ack["content"].get("path") == JOURNAL_PATH
                 and ack["content"].get("sha") == _blob(raw) and type(ack.get("commit")) is dict, "journal")
            commit = p._match(ack["commit"].get("sha"), p._SHA)
            readback = self.remote.read("contents/" + JOURNAL_PATH + "?ref=" + commit, role=JOURNAL_READ)
            need(_journal_content(readback) == raw, "journal")
            self.revision, self.blob, self.commit, self._state = self.revision + 1, _blob(raw), commit, after
            self._schema_version, self.play_query = schema, selected_play
            candidate = after.candidate(self._local_project_id)
            need(candidate is not None and candidate.request == self._bound_request, "journal")
        except Exception:
            raise Refused("journal") from None
        self._poisoned = False


class _Source(ci._Read):
    """Existing owned Git primitives; same original work end for every stage."""
    def __init__(self, root, context, guard):
        super().__init__(root, context, workflow.GitHub(context), guard)
        self.observed_at = self.epoch()
        self.material = None

    def epoch(self):
        value = time.time()
        need(type(value) in (int, float) and math.isfinite(value) and value >= getattr(self, "wall", 0))
        self.wall = value
        return math.floor(value)

    def remaining(self):
        result = super().remaining()
        if getattr(self, "material", None) is not None:
            self.material.check()
        return result

    def entry(self, commit, path, maximum):
        raw = self.git(["ls-tree", "-z", "--full-tree", commit, "--", path], 2048)
        match = re.fullmatch(rb"100(?:644|755) blob ([0-9a-f]{40})\t" + re.escape(path.encode()) + b"\0", raw)
        need(match is not None, "source")
        return self.blob(match[1].decode("ascii"), maximum)

    def capture(self):
        commit, reference = self.context.authority["headSha"], self.context.authority["ref"]
        p.source_ref(reference)
        need(reference.startswith("refs/heads/") and reference != "refs/heads/" + a.LEDGER_BRANCH, "source")
        self.head(commit)
        tree, _, _ = self.commit(commit)
        config_raw = self.entry(commit, version_text.CONFIG_PATH, MAX_CONFIG_BYTES)
        self.config = parse_config_text(config_raw.decode("utf-8"))
        self.enabled = tuple(k for k in paired.PLATFORMS if self.config[k].get("enabled") is True)
        need(self.context.platform in _PLATFORMS and self.enabled == _PLATFORMS[self.context.platform], "admission")
        for platform in self.enabled:
            need(self.config[platform].get("identityStatus") != "blocked", "admission")
        if "ios" in self.enabled:
            selected = self.config["ios"]
            self.app_id, self.bundle_id = selected.get("appStoreAppId"), selected.get("bundleId")
            ios.app_identity(self.app_id, self.bundle_id)
        if "android" in self.enabled:
            self.package = self.config["android"].get("applicationId")
            android.package_identity(self.package)
        self.selection = version_text.public_version_selection(config_raw.decode("utf-8"))
        self.version_raw = self.entry(commit, self.selection.source, MAX_VERSION_BYTES)
        original = version_text.original_text(self.selection, self.version_raw)
        self.base = ReleaseVersion(original.values[0], int(original.values[1]))
        self.binding = p.SourceBinding(commit, tree, reference, hashlib.sha256(config_raw).hexdigest(),
                                       hashlib.sha256(self.version_raw).hexdigest())
        if self.enabled == ("ios",):
            self.identity = p.digest({"platform": "ios", "appId": self.app_id, "bundleId": self.bundle_id})
        else:
            identity = {"platform": self.context.platform, "packageName": self.package}
            if "ios" in self.enabled:
                identity.update(appId=self.app_id, bundleId=self.bundle_id)
            self.identity = p.digest(identity)

    def checked_ca(self, tooling):
        # Same original command budget; a fixed tooling leaf, not caller path.
        app_root = self.root
        self.root = tooling
        try:
            self.head(self.context.trusted_tooling_commit)
            expected = self.entry(self.context.trusted_tooling_commit, CA_PATH, 512 * 1024)
            return hashlib.sha256(expected).hexdigest()
        finally:
            self.root = app_root

    def check(self):
        self.head(self.binding.commit)
        self.remaining()


def _admit(context):
    confirmation = "reserve-version:" + context.platform + (":temporary-play-edit" if context.platform != "ios" else "")
    need(context.stage == "candidate" and context.platform in _PLATFORMS and context.current_job == "version_reserve"
         and context.confirmation == confirmation and context.selected_platform == context.platform
         and os.environ.get("MOBILE_RELEASE_OPERATION") == "reserve-version", "admission")
    need(all(not os.environ.get(key, "") for key in ("MOBILE_RELEASE_RECOVERY_RUN_ID",
        "MOBILE_RELEASE_RECOVERY_CONFIRMATION", "MOBILE_RELEASE_DESKTOP_REQUEST", "MOBILE_RELEASE_DESKTOP_SOURCE_SHA",
        "MOBILE_RELEASE_DESKTOP_EXPECTED_REF")), "admission")
    token = os.environ.get(TOKEN_ENV, "")
    # Shape is not App permission evidence: the original fixed API checks below
    # still establish repository/protection access. Never borrow GH_TOKEN.
    need(1 <= len(token) <= 4096 and all(0x21 <= ord(c) <= 0x7e for c in token), "credential")
    settings = ci.Settings.parse(os.environ.get(ci.AUTHORITY_ENV, ""))
    need(settings.authority.repository == context.repository["fullName"]
         and settings.authority.repository_id == context.repository["id"], "authority")
    policy = p.VersionPolicy.parse(_decode_json(os.environ.get(POLICY_ENV, "").encode("ascii"),
        limit=16 * 1024, nodes=256, depth=6, exact=True))
    need(policy.schema_version == _SCHEMAS[context.platform] and policy.mode == "automatic", "admission")
    policy.increment_for(context.authority["ref"])
    return settings, policy


def _attempt(remote, context):
    expected = context.authority
    body = remote.read(f"actions/runs/{expected['runId']}/attempts/{expected['attempt']}")
    # Reuse the real workflow validator with this one already-bounded response;
    # its cache is LOCAL to this call and not a substitute for another read.
    client = workflow.GitHub(context)
    client._attempts[(expected["runId"], expected["attempt"])] = body
    client.attempt(expected, "candidate")


def _live(source, tooling, token):
    from . import _github_connection_transport as http
    profile = http._ExchangeProfile.HOSTED_VERSION
    expected_ca = source.checked_ca(tooling)
    exchange = http._make_live_exchange(token, started=source.started,
        runtime_dir=str(tooling / "desktop/cpython-source-inputs"), api_version="2026-03-10", _profile=profile,
        _hosted_ca_sha256=expected_ca)
    roles = {role: next(item for item in http._ResponseRole if item.value == role) for role in _ROLES}
    return lambda role, request: exchange(request.method, request.path, request.body, _role=roles[role])


def _reserve(source, settings, selected_policy, remote, material):
    _attempt(remote, source.context)
    journal = _Journal(remote, settings)
    journal.load()
    remote.source_current()
    commit = remote.read("git/commits/" + source.binding.commit)
    need(commit.get("sha") == source.binding.commit and type(commit.get("tree")) is dict
         and commit["tree"].get("sha") == source.binding.tree, "source")
    context_revision = material.context(source)
    # New Play modes move this HEAD check to after the durable Play pending
    # ACK. Selection retains immutable DATA; it cannot authorize a Store call.
    if source.enabled == ("ios",):
        source.check()
    else:
        source.remaining()
    request = journal.choose(lambda candidate: a.AllocationRequest(settings.authority.project_id, candidate,
        source.identity, source.binding, source.base, source.enabled, selected_policy, context_revision))
    if source.enabled == ("ios",):
        inventory = material.observe(source, context_revision)
        need(type(inventory) is ios.CurrentInventory, "store")
        observations = (inventory,)
    else:
        first = material.observe_ios(source, context_revision) if "ios" in source.enabled else None
        if first is not None:
            need(type(first) is ios.CurrentInventory, "store")
        original = journal.begin_play(request)
        source.check()
        remote.source_current()
        remote.journal_current(journal.commit)
        summary = material.observe_android(source, context_revision, original)
        journal.finish_play(request, source, original)
        need(summary["observation"] == "observed", "store")
        current = android.CurrentInventory(source.identity, context_revision, summary["revision"],
            source.observed_at, summary["maxBuild"], tuple(summary["counts"][kind] for kind in android.COUNTS))
        observations = (current,) if first is None else (current, first)
    pending = journal.pending_for(settings.authority, request.candidate_id)

    def send(role, http):
        if role == wire.ROLE_LEDGER_WRITE:
            # Reached ONLY after this exact original Pending CAS+readback ACK.
            original = journal.pending_for(settings.authority, request.candidate_id)
            need(original is not None and original.reservation.request == request, "journal")
            source.check()
            remote.source_current()
            remote.journal_current(journal.commit)
            return remote.exchange(LEDGER_WRITE, http)
        return remote.exchange(READ, http)

    transport = wire._FixedAllocationTransport(request, settings.authority, journal.checkpoint(settings.authority),
        send, reconcile=pending is not None)
    outcome = a.allocate_version(request, settings.authority, transport, journal,
        observations=observations, clock=source.epoch)
    need(outcome.status == "reserved" and outcome.reason == "none" and outcome.reservation is not None, "journal")
    source.check()
    remote.source_current()
    remote.journal_current(journal.commit)
    a._repository_identity(remote.read(""), settings.authority)
    journal.admit_request(settings.authority, request)
    need(journal.selected_candidate(settings.authority).reservation == outcome.reservation, "journal")
    a.current_inventory_policy(request).check_reserved(outcome.reservation.version, selected_policy, enabled=source.enabled,
        identity_revision=request.identity_revision, context_revision=context_revision,
        observations=observations, now=source.epoch())
    _, after, values = version_text.prepare_payload(source.selection, source.version_raw, "edit",
        {"name": outcome.reservation.version.name, "build": str(outcome.reservation.version.build)})
    source.remaining()
    row = outcome.reservation
    return {"schemaVersion": 1, "status": "reserved", "candidateId": request.candidate_id,
        "rowSha256": row.sha256, "sourceCommit": source.binding.commit,
        "sourceRef": source.binding.ref, "configSha256": request.source.configuration_sha256,
        "version": p.version_value(row.version), "releaseEligibility": "not-established",
        "historicalUniqueness": "not-established", "sourceWrite": "not-performed",
        "authorityVariable": p.canonical({"schemaVersion": 1, "authority": settings.authority.value(),
            "checkpoint": journal.checkpoint(settings.authority).value()}).decode("ascii"),
        "commitTrailer": ci.TRAILER + ": " + request.candidate_id + " " + row.sha256,
        "versionFile": {"path": source.selection.source, "beforeSha256": request.source.version_sha256,
            "afterSha256": hashlib.sha256(after).hexdigest(), "replacements": [
                {"start": span[0], "end": span[1], "value": value}
                for span, value in zip(version_text.original_text(source.selection, source.version_raw).spans,
                                       (values["name"], values["build"]))]}}


def reserve(app_root: Path, tooling_root: Path):
    from .version_hosted_store import Material
    selected = os.environ.get("MOBILE_RELEASE_SELECTED_PLATFORM", "")
    need(selected in _PLATFORMS, "admission")
    context = workflow.Context.current("candidate", selected)
    settings, policy = _admit(context)
    root, tooling = workflow._safe_path(app_root), workflow._safe_path(tooling_root)
    need(root.is_dir() and tooling.is_dir() and (root / ".git").is_dir()
         and not (root / ".git").is_symlink(), "source")
    guard, owns = cancellation_owner(None, ProcessCleanupError, "Hosted version cleanup is unconfirmed")
    material = None
    scope = CleanupScope(guard, lambda: None, owns_cancellation=owns, first_primary=True)
    result = None
    try:
        with scope:
            if owns:
                guard.install()
                guard.activate()
            source = _Source(root, context, guard)
            source.capture()
            material = Material(tooling, platform=selected)
            source.material = material
            remote = _Remote(settings.authority, source, _live(source, tooling, os.environ[TOKEN_ENV]))
            result = _reserve(source, settings, policy, remote, material)
    finally:
        scope.__exit__(*sys.exc_info())
    guard.check()
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        need(argv == ["reserve"], "admission")
        result = reserve(Path(os.environ.get("MOBILE_RELEASE_APP_ROOT", "")),
                         Path(os.environ.get("MOBILE_RELEASE_TOOLING_ROOT", "")))
        # Explicit output DATA only. Do not append credentials/raw provider data
        # to Actions output files or automatically commit a project source.
        print(p.canonical(result).decode("ascii"))
        return 0
    except Refused as error:
        print(str(error), file=sys.stderr)  # This type contains only fixed safe text.
        return 1
    except (Exception, KeyboardInterrupt):
        print("Hosted version reservation did not finish; preserve its candidate and journal. No source or Store upload was authorized.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
