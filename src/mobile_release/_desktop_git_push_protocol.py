"""Closed Push facet of the existing native GitLocal request/ACK stream.

Only the original native owner supplies the selected Connection, private
source and Preparing row. These fields compare originals; no JSON value
creates a source lease, credential, review, journal ACK or a native join.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from . import _desktop_git_read_protocol as fields
from . import _git_push_private_protocol as private
from . import git_repository_push as push
from . import git_push_transaction as transaction
from . import git_push_transport as transport
from . import git_push_wire as packets
from . import git_remote_control as controls
from . import git_service as core
from .errors import ValidationError

PROTOCOL = "mrk-git-push/1"
WORK_SECONDS, FINALITY_SECONDS, COMMAND_SECONDS = 45, 55, 45
REQUEST_LIMIT, READY_LIMIT, GO_LIMIT, CANDIDATE_LIMIT, ACK_LIMIT, RESPONSE_LIMIT = 96 * 1024, 512, 8192, 4096, 4096, 32 * 1024
TOOL_PATH, TOOL_LIMIT = fields.TOOL_PATH, fields.TOOL_LIMIT
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")
EFFECTS = ("not-sent", "candidate-entered", "candidate-acknowledged", "send-entered", "send-consumed", "remote-returned")
_ERROR = "The original Git Push request or result was refused."


class ProtocolError(ValidationError):
    pass


def require(condition):
    if not condition:
        raise ProtocolError(_ERROR)


def valid_reason(value):
    return type(value) is str and value in core._REASONS | push._REASONS | transport._REASONS


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    expected_revision: str
    expected_reference_revision: str
    remote: str
    selected: packets.Selection
    connection_session_id: str
    expected_connection_revision: int
    kind: str = "push"

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
            "expectedReferenceRevision": self.expected_reference_revision, "remote": self.remote,
            "localRef": self.selected.local_ref, "remoteRef": self.selected.remote_ref,
            "oldOid": self.selected.old_oid, "newOid": self.selected.new_oid,
            "connectionSessionId": self.connection_session_id,
            "expectedConnectionRevision": self.expected_connection_revision}


def action(value):
    row = fields._keys(value, ("kind", "expectedRevision", "expectedReferenceRevision", "remote", "localRef", "remoteRef",
                               "oldOid", "newOid", "connectionSessionId", "expectedConnectionRevision"))
    require(row["kind"] == "push")
    selected = packets.Selection(row["localRef"], row["remoteRef"], row["oldOid"], row["newOid"])
    return Action(fields._hex(row["expectedRevision"]), fields._hex(row["expectedReferenceRevision"]),
        push.remote_name(row["remote"]), selected, fields._id(row["connectionSessionId"]),
        fields._integer(row["expectedConnectionRevision"], 1, (1 << 32) - 2))


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    phase: str
    action: Action
    review_digest: str | None
    journal_revision: int | None
    project_id: str
    generation: int
    revision: str
    uid: int
    gid: int
    root: Path
    directories: tuple
    tool: fields.FileSnapshot
    files: tuple[fields.FileSnapshot, ...]
    index_absent: bool
    work_end_ns: int
    hard_end_ns: int
    digest: str
    target: transport.Target


def parse_request(raw):
    try:
        row = fields._keys(fields._decode(raw, REQUEST_LIMIT), ("protocol", "id", "phase", "action", "reviewDigest",
            "journalRevision", "context", "native", "clock", "target"))
        require(row["protocol"] == PROTOCOL and row["phase"] in ("prepare", "apply"))
        selected = action(row["action"])
        target = fields._keys(row["target"], ("repository", "login", "accountId", "repositoryId"))
        target = transport.Target(target["repository"], target["login"], target["accountId"], target["repositoryId"], selected.selected)
        if row["phase"] == "prepare":
            require(row["reviewDigest"] is None and row["journalRevision"] is None)
        else:
            fields._hex(row["reviewDigest"])
            fields._integer(row["journalRevision"], 1, (1 << 64) - 2)
        context = fields._keys(row["context"], ("projectId", "generation", "revision"))
        native = fields._keys(row["native"], ("uid", "gid", "root", "directories", "tool", "files"))
        uid, gid = fields._integer(native["uid"], 1, (1 << 32) - 1), fields._integer(native["gid"], 0, (1 << 32) - 1)
        root = fields._path(native["root"])
        directories = fields._keys(native["directories"], ("root", "git", "objects"))
        directories = tuple((root / relative, fields._directory(directories[name], uid))
            for name, relative in (("root", ""), ("git", ".git"), ("objects", ".git/objects")))
        tool = fields._snapshot(TOOL_PATH, native["tool"], 0, TOOL_LIMIT, executable=True)
        files = fields._keys(native["files"], ("HEAD", "config", "index"))
        snapshots = tuple(fields._snapshot(root / ".git" / name, files[name], uid, maximum)
            for name, maximum in (("HEAD", 2048), ("config", 65536), ("index", core.MAX_INDEX_BYTES))
            if name != "index" or files[name] is not None)
        require(snapshots[0].identity[6] > 0)
        clock = fields._keys(row["clock"], ("workEndNs", "hardEndNs"))
        work, hard = (fields._integer(clock[name], 1, (1 << 63) - 1) for name in ("workEndNs", "hardEndNs"))
        require(hard - work == 10_000_000_000)
        return Request(fields._id(row["id"]), row["phase"], selected, row["reviewDigest"], row["journalRevision"],
            fields._id(context["projectId"]), fields._integer(context["generation"], 0, (1 << 32) - 1),
            fields._id(context["revision"]), uid, gid, root, directories, tool, snapshots, files["index"] is None,
            work, hard, hashlib.sha256(raw).hexdigest(), target)
    except (fields.ProtocolError, core.GitError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def _encode(value, limit):
    try:
        return fields._encode(value, limit)
    except fields.ProtocolError:
        raise ProtocolError(_ERROR) from None


def ready(request):
    require(type(request) is Request)
    return _encode({"protocol": PROTOCOL, "id": request.id, "digest": request.digest}, READY_LIMIT)


def private_go(request, raw):
    require(type(request) is Request)
    try:
        row = fields._keys(fields._decode(raw, GO_LIMIT), ("protocol", "kind", "id", "digest", "token"))
        require((row["protocol"], row["kind"], row["id"], row["digest"]) == (PROTOCOL, "go", request.id, request.digest))
        return private.token(row["token"])
    except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def matches_review(request, review):
    require(type(request) is Request and type(review) is push.PushReview and type(review.plan) is push.PushPlan
            and review.digest == push._review_digest(review.plan))
    plan = review.plan
    require(plan.remote == request.action.remote and plan.reference_revision == request.action.expected_reference_revision
            and plan._snapshot.public.revision == request.action.expected_revision and plan.target == request.target)
    if request.phase == "apply":
        require(review.digest == request.review_digest)


@dataclass(frozen=True, slots=True, repr=False)
class Candidate:
    request: Request
    intent: push.PushIntent
    raw: bytes
    digest: str


def candidate(request, review, intent):
    matches_review(request, review)
    require(request.phase == "apply" and type(intent) is push.PushIntent
            and intent == push.PushIntent.from_plan(review.plan, review.digest))
    raw = _encode({"protocol": PROTOCOL, "kind": "candidate", "id": request.id, "digest": request.digest,
                   "reviewDigest": review.digest, "intent": intent.as_dict()}, CANDIDATE_LIMIT)
    return Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


def acknowledged(request, sent, raw):
    require(type(request) is Request and type(sent) is Candidate and sent.request is request and request.phase == "apply")
    try:
        row = fields._keys(fields._decode(raw, ACK_LIMIT), ("protocol", "kind", "id", "digest", "candidateDigest", "journalRevision"))
        require((row["protocol"], row["kind"], row["id"], row["digest"], row["candidateDigest"]) ==
                (PROTOCOL, "ack", request.id, request.digest, sent.digest))
        revision = fields._integer(row["journalRevision"], 1, (1 << 64) - 1)
        require(revision == request.journal_revision + 1)
        return revision
    except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def transmission_data(request, value):
    """Actual returned helper DATA only; native parent still proves finality."""
    require(type(value) is transaction.Returned and value.mode == "apply" and value.selected == request.target.selected)
    return {"body": private.body_value(value.body), "advertisement": value.advertisement_sha256,
            "response": private.status_value(value.status, value.selected), "after": value.after_sha256}


def _matches_intent(request, intent):
    """Closed request comparisons; not another candidate or send permission."""
    require(type(intent) is push.PushIntent)
    selected, target = request.action.selected, request.target
    require((intent.review_digest, intent.expected_revision, intent.expected_reference_revision,
             intent.remote, intent.repository, intent.account_id, intent.repository_id,
             intent.local_ref, intent.remote_ref, intent.old_oid, intent.new_oid)
            == (request.review_digest, request.action.expected_revision, request.action.expected_reference_revision,
                request.action.remote, target.repository, target.account_id, target.repository_id,
                selected.local_ref, selected.remote_ref, selected.old_oid, selected.new_oid))
    require(type(intent.expected_index) is str and core._REVISION.fullmatch(intent.expected_index) is not None)
    require(type(intent.commits_sha256) is str and core._REVISION.fullmatch(intent.commits_sha256) is not None)


def terminal(request, status, *, reason, review=None, result=None, transmission=None,
             effect_phase="not-sent", retained_paths=(), first_failure_ns, cleanup_end_ns, control=None):
    require(type(request) is Request and status in STATUSES and (reason is None or valid_reason(reason)))
    try:
        fields._integer(cleanup_end_ns, 1, request.hard_end_ns)
        if first_failure_ns is not None:
            fields._integer(first_failure_ns, 1, cleanup_end_ns)
            require(cleanup_end_ns - first_failure_ns <= 10_000_000_000)
        safe_control = controls.checked(controls.empty() if control is None else control)
    except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None
    data = receipt = None
    if status == "ok":
        require(reason is None)
        if request.phase == "prepare":
            matches_review(request, review)
            require(result is transmission is None and effect_phase == "not-sent" and not retained_paths
                    and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns
                    and safe_control["reason"] == "none")
            data = {"review": review.as_dict(), "diff": None}
        else:
            require(review is None and type(result) is core.MutationResult and result.operation_id == request.id
                    and result.action == "push" and result.settlement == "settled" and result.observation is None
                    and result.state in ("succeeded", "failed", "recovery-required") and effect_phase in EFFECTS
                    and type(retained_paths) is tuple and len(retained_paths) <= 1
                    and all(type(path) is str and re.fullmatch(r"(?:mrk-git-[a-z0-9_]{1,32}/)?mrk-git-push-[a-z0-9_]{1,32}", path) is not None
                            for path in retained_paths))
            intent = result.intent
            if intent is not None:
                _matches_intent(request, intent)
            if transmission is not None:
                require(intent is not None)
                receipt = transmission_data(request, transmission)
            if result.state == "succeeded":
                require(result.reason is None and intent is not None and transmission is not None
                        and effect_phase == "remote-returned" and not retained_paths and safe_control["reason"] == "none"
                        and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
            else:
                require(valid_reason(result.reason) and result.reason not in ("unknown", "cleanup-unknown")
                        and first_failure_ns is not None and (intent is not None or effect_phase == "not-sent"))
            data = {**result.as_dict(), "effectPhase": effect_phase, "retainedPaths": list(retained_paths)}
    else:
        require(review is result is transmission is None and reason is not None
                and effect_phase == "not-sent" and not retained_paths
                and (first_failure_ns is not None or status == "cleanup-unknown"))
    return _encode({"protocol": PROTOCOL, "kind": "terminal", "id": request.id, "digest": request.digest,
        "phase": request.phase, "action": "push", "status": status, "reason": reason, "result": data,
        "transmission": receipt, "firstFailureNs": first_failure_ns, "cleanupEndNs": cleanup_end_ns, "control": safe_control},
        RESPONSE_LIMIT - READY_LIMIT - CANDIDATE_LIMIT)
