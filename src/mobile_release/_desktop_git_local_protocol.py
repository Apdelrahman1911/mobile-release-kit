"""Finite private GitLocal frames, not a source/consent/journal capability.

The installed original owner supplies fixed source snapshots and clock endpoints.
GitRead's pure field validators are reused; no GitRead operation or authorization
is constructed. Only one candidate handoff is possible in the actual input owner.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from . import _desktop_git_read_protocol as source_fields
from . import _desktop_git_branches as branch
from . import git_fast_forward_worker as ff
from . import _desktop_git_switch as switch
from . import _desktop_git_rename as rename
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .errors import ValidationError

PROTOCOL = "mrk-git-local/1"
WORK_SECONDS, FINALITY_SECONDS, COMMAND_SECONDS = 45, 55, 10
REQUEST_LIMIT, READY_LIMIT, CANDIDATE_LIMIT, RESPONSE_LIMIT = 96 * 1024, 512, 4 * 1024, 2 * 1024 * 1024
TOOL_PATH, TOOL_LIMIT = source_fields.TOOL_PATH, source_fields.TOOL_LIMIT
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")
_ERROR = "The original local Git request or result was refused."


class ProtocolError(ValidationError):
    pass


def require(value: bool) -> None:
    if not value:
        raise ProtocolError(_ERROR)


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    expected_revision: str
    paths: tuple[str, ...]
    message: str | None
    identity: core.CommitIdentity | None

    def as_dict(self) -> dict:
        # Private request only. Public projections must omit message/identity.
        return {"kind": self.kind, "expectedRevision": self.expected_revision, "paths": list(self.paths),
                "message": self.message, "identity": None if self.identity is None else
                {"name": self.identity.name, "email": self.identity.email}}


def action(value) -> Action | branch.Action | switch.Action | rename.Action | ff.Action:
    if type(value) is dict and value.get("kind") == "fast-forward":
        return ff.action(value)
    if type(value) is dict and value.get("kind") == "branch-rename":
        return rename.action(value)
    if type(value) is dict and value.get("kind") == "branch-switch":
        return switch.action(value)
    if type(value) is dict and value.get("kind") == "branch-create":
        return branch.action(value)
    row = source_fields._keys(value, ("kind", "expectedRevision", "paths", "message", "identity"))
    require(type(row["kind"]) is str and row["kind"] in ("stage", "unstage", "commit"))
    revision = source_fields._hex(row["expectedRevision"])
    paths, message, identity = (), row["message"], row["identity"]
    if row["kind"] == "commit":
        require(type(row["paths"]) is list and row["paths"] == [] and type(message) is str
                and 1 <= len(message.encode("utf-8")) <= 4096 and bool(message.strip())
                and not any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in message)
                and core._SECRET.search(message.encode("utf-8")) is None)
        names = source_fields._keys(identity, ("name", "email"))
        identity = core.CommitIdentity(names["name"], names["email"])
        identity.validate()
    else:
        require(message is None and identity is None and type(row["paths"]) is list)
        paths = core._paths(row["paths"])
        require(list(paths) == row["paths"] and all(len(path.split("/")) <= read.MAX_REF_DEPTH for path in paths))
    return Action(row["kind"], revision, paths, message, identity)


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    phase: str
    action: Action | branch.Action | switch.Action | rename.Action
    review_digest: str | None
    journal_revision: int | None
    project_id: str  # Runtime context alias; NOT the durable service project ID.
    generation: int
    revision: str
    uid: int
    gid: int
    root: Path
    directories: tuple
    tool: source_fields.FileSnapshot
    files: tuple[source_fields.FileSnapshot, ...]
    index_absent: bool
    work_end_ns: int
    hard_end_ns: int
    digest: str
    switch_sources: switch.Sources | None = None
    rename_sources: rename.Sources | None = None
    fast_forward_sources: ff.Sources | None = None


def parse_request(raw: bytes) -> Request:
    try:
        decoded = source_fields._decode(raw, REQUEST_LIMIT)
        is_ff = (type(decoded) is dict and type(decoded.get("action")) is dict and decoded["action"].get("kind") == "fast-forward")
        is_switch = (type(decoded) is dict and type(decoded.get("action")) is dict
                     and decoded["action"].get("kind") == "branch-switch")
        is_rename = (type(decoded) is dict and type(decoded.get("action")) is dict
                     and decoded["action"].get("kind") == "branch-rename")
        keys = ("protocol", "id", "phase", "action", "reviewDigest", "journalRevision", "context", "native", "clock")
        row = source_fields._keys(decoded, (*keys, "fastForward") if is_ff else (*keys, "switch") if is_switch else (*keys, "rename") if is_rename else keys)
        require(row["protocol"] == PROTOCOL and row["phase"] in ("prepare", "apply"))
        if row["phase"] == "prepare":
            require(row["reviewDigest"] is None and row["journalRevision"] is None)
        else:
            source_fields._hex(row["reviewDigest"])
            source_fields._integer(row["journalRevision"], 1, (1 << 64) - 2)
        context = source_fields._keys(row["context"], ("projectId", "generation", "revision"))
        native = source_fields._keys(row["native"], ("uid", "gid", "root", "directories", "tool", "files"))
        uid, gid = source_fields._integer(native["uid"], 1, (1 << 32) - 1), source_fields._integer(native["gid"], 0, (1 << 32) - 1)
        root = source_fields._path(native["root"])
        directories = source_fields._keys(native["directories"], ("root", "git", "objects"))
        directories = tuple((root / relative, source_fields._directory(directories[name], uid))
            for name, relative in (("root", ""), ("git", ".git"), ("objects", ".git/objects")))
        tool = source_fields._snapshot(TOOL_PATH, native["tool"], 0, TOOL_LIMIT, executable=True)
        files = source_fields._keys(native["files"], ("HEAD", "config", "index"))
        snapshots = tuple(source_fields._snapshot(root / ".git" / name, files[name], uid, maximum)
            for name, maximum in (("HEAD", 2048), ("config", 65536), ("index", core.MAX_INDEX_BYTES))
            if name != "index" or files[name] is not None)
        require(snapshots[0].identity[6] > 0)
        clock = source_fields._keys(row["clock"], ("workEndNs", "hardEndNs"))
        work, hard = (source_fields._integer(clock[name], 1, (1 << 63) - 1) for name in ("workEndNs", "hardEndNs"))
        require(hard - work == 10_000_000_000)
        selected = action(row["action"])
        compared = switch.sources(row["switch"], phase=row["phase"], root=root, uid=uid, selected=selected) if is_switch else None
        renamed = rename.sources(row["rename"], phase=row["phase"], root=root, uid=uid, selected=selected) if is_rename else None
        forwarded = ff.sources(row["fastForward"], phase=row["phase"], root=root, uid=uid, selected=selected) if is_ff else None
        require(not (is_ff or is_switch or is_rename) or row["phase"] != "apply" or files["index"] is not None)
        return Request(source_fields._id(row["id"]), row["phase"], selected,
            row["reviewDigest"], row["journalRevision"], source_fields._id(context["projectId"]),
            source_fields._integer(context["generation"], 0, (1 << 32) - 1), source_fields._id(context["revision"]),
            uid, gid, root, directories, tool, snapshots, files["index"] is None, work, hard, hashlib.sha256(raw).hexdigest(), compared, renamed, forwarded)
    except (source_fields.ProtocolError, core.GitError, UnicodeError, ValueError, TypeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def _encode(value: dict, limit: int) -> bytes:
    try:
        return source_fields._encode(value, limit)
    except source_fields.ProtocolError:
        raise ProtocolError(_ERROR) from None


def ready(request: Request) -> bytes:
    require(type(request) is Request)
    return _encode({"protocol": PROTOCOL, "id": request.id, "digest": request.digest}, READY_LIMIT)


def go(request: Request) -> bytes:
    require(type(request) is Request)
    return b"MRK-GIT-LOCAL-GO/1 " + request.digest.encode("ascii") + b"\n"


def matches_review(request: Request, review: local.LocalReview | branch.BranchReview) -> None:
    if type(request) is Request and type(request.action) is ff.Action:
        return ff.matches_review(request, review)
    if type(request) is Request and type(request.action) is rename.Action:
        return rename.matches_review(request, review)
    if type(request) is Request and type(request.action) is switch.Action:
        return switch.matches_review(request, review)
    if type(request) is Request and type(request.action) is branch.Action:
        return branch.matches_review(request, review)
    require(type(request) is Request and type(review) is local.LocalReview and type(review.plan) is core.GitPlan
            and review.digest == local._review_digest(review.plan))
    plan = review.plan
    require(plan.action == request.action.kind and plan._snapshot.public.revision == request.action.expected_revision
            and plan._message == request.action.message and plan._identity == request.action.identity)
    require(plan.paths == request.action.paths if plan.action != "commit" else bool(plan.paths))
    if request.phase == "apply":
        require(review.digest == request.review_digest)


@dataclass(frozen=True, slots=True, repr=False)
class Candidate:
    request: Request
    intent: core.PublicationIntent | branch.BranchIntent
    raw: bytes
    digest: str


def candidate(request: Request, review: local.LocalReview | branch.BranchReview,
              intent: core.PublicationIntent | branch.BranchIntent) -> Candidate:
    if type(request) is Request and type(request.action) is ff.Action:
        return ff.candidate(request, review, intent)
    if type(request) is Request and type(request.action) is rename.Action:
        return rename.candidate(request, review, intent)
    if type(request) is Request and type(request.action) is switch.Action:
        return switch.candidate(request, review, intent)
    if type(request) is Request and type(request.action) is branch.Action:
        return branch.candidate(request, review, intent)
    matches_review(request, review)
    require(request.phase == "apply" and type(intent) is core.PublicationIntent)
    before = review.plan._snapshot
    require((intent.action, intent.expected_revision, intent.expected_ref, intent.expected_head, intent.expected_index) ==
            (review.plan.action, before.public.revision, before.public.branch, before.public.head, before.index_stamp.digest))
    if intent.action == "commit":
        require(intent.candidate_index is None and type(intent.candidate_commit) is str
                and core._OID.fullmatch(intent.candidate_commit) is not None
                and (intent.expected_head is None or len(intent.candidate_commit) == len(intent.expected_head)))
    else:
        require(intent.candidate_commit is None and type(intent.candidate_index) is str
                and core._REVISION.fullmatch(intent.candidate_index) is not None)
    raw = _encode({"protocol": PROTOCOL, "kind": "candidate", "id": request.id, "digest": request.digest,
                   "reviewDigest": review.digest, "intent": intent.as_dict()}, CANDIDATE_LIMIT)
    return Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


def acknowledged(request: Request, sent: Candidate, raw: bytes) -> int:
    """Exact ACK syntax. The original input's consumed latch is indispensable."""
    require(type(request) is Request and type(sent) is Candidate and sent.request is request
            and request.phase == "apply" and type(raw) is bytes and len(raw) <= READY_LIMIT)
    prefix = b"MRK-GIT-LOCAL-ACK/1 " + request.digest.encode("ascii") + b" " + sent.digest.encode("ascii") + b" "
    require(raw.startswith(prefix))
    number = raw[len(prefix):]
    require(re.fullmatch(rb"[1-9][0-9]{0,19}\n", number) is not None)
    revision = int(number[:-1])
    require(request.journal_revision is not None and revision == request.journal_revision + 1 and revision < 1 << 64)
    return revision


def terminal(request: Request, status: str, *, reason: str | None,
             review: local.LocalReview | branch.BranchReview | None = None,
             diff: core.Diff | None = None, result: core.MutationResult | None = None,
             publication: str = "not-reported", progress: switch.Progress | None = None,
             first_failure_ns: int | None, cleanup_end_ns: int) -> bytes:
    is_ff = type(request) is Request and type(request.action) is ff.Action
    is_switch = type(request) is Request and type(request.action) is switch.Action
    is_rename = type(request) is Request and type(request.action) is rename.Action
    is_branch = type(request) is Request and type(request.action) is branch.Action
    require(type(request) is Request and status in STATUSES
            and (reason is None or (ff.valid_reason(reason) if is_ff else rename.valid_reason(reason) if is_rename else switch.valid_reason(reason) if is_switch else
                                  branch.valid_reason(reason) if is_branch else reason in core._REASONS))
            and (is_ff or is_switch or is_rename or progress is None)
            and publication in (ff.PUBLICATIONS if is_ff else rename.PUBLICATIONS if is_rename else switch.PUBLICATIONS if is_switch else ("not-reported", branch.PUBLICATION) if is_branch else
                                ("not-reported", "index-returned", "ref-returned")))
    try:
        source_fields._integer(cleanup_end_ns, 1, request.hard_end_ns)
        if first_failure_ns is not None:
            source_fields._integer(first_failure_ns, 1, cleanup_end_ns)
            require(cleanup_end_ns - first_failure_ns <= 10_000_000_000)
    except source_fields.ProtocolError:
        raise ProtocolError(_ERROR) from None
    data = None
    if is_ff:
        data = ff.terminal_data(request, status, reason=reason, review=review, diff=diff, result=result,
            publication=publication, progress=progress, first_failure_ns=first_failure_ns, cleanup_end_ns=cleanup_end_ns)
    elif is_rename:
        data = rename.terminal_data(request, status, reason=reason, review=review, diff=diff, result=result,
            publication=publication, progress=progress, first_failure_ns=first_failure_ns, cleanup_end_ns=cleanup_end_ns)
    elif is_switch:
        data = switch.terminal_data(request, status, reason=reason, review=review, diff=diff, result=result,
            publication=publication, progress=progress, first_failure_ns=first_failure_ns, cleanup_end_ns=cleanup_end_ns)
    elif is_branch:
        data = branch.terminal_data(request, status, reason=reason, review=review, diff=diff,
            result=result, publication=publication, first_failure_ns=first_failure_ns, cleanup_end_ns=cleanup_end_ns)
    elif status == "ok":
        require(reason is None)
        if request.phase == "prepare":
            require(result is None and publication == "not-reported" and first_failure_ns is None
                    and cleanup_end_ns == request.hard_end_ns)
            matches_review(request, review)
            require(type(diff) is core.Diff and diff.revision == request.action.expected_revision
                    and diff.paths == review.plan.paths and diff.staged is (request.action.kind != "stage"))
            data = {"review": review.as_dict(), "diff": diff.as_dict()}
        else:
            require(review is None and diff is None and type(result) is core.MutationResult
                    and result.operation_id == request.id and result.action == request.action.kind
                    and result.settlement == "settled" and result.state in ("succeeded", "failed", "recovery-required"))
            if publication != "not-reported":
                require(result.intent is not None and result.settlement == "settled"
                        and publication == ("ref-returned" if result.action == "commit" else "index-returned"))
            if result.state == "succeeded":
                require(publication != "not-reported" and result.reason is None and result.observation is not None
                        and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
            else:
                require(result.reason in core._REASONS and first_failure_ns is not None and result.observation is None)
            data = result.as_dict()
    else:
        require(review is None and diff is None and result is None and publication == "not-reported"
                and reason is not None and (first_failure_ns is not None or status == "cleanup-unknown"))
    return _encode({"protocol": PROTOCOL, "kind": "terminal", "id": request.id, "digest": request.digest,
        "phase": request.phase, "action": request.action.kind, "status": status, "reason": reason,
        "result": data, "publication": publication, "firstFailureNs": first_failure_ns,
        "cleanupEndNs": cleanup_end_ns}, RESPONSE_LIMIT - READY_LIMIT - CANDIDATE_LIMIT)
