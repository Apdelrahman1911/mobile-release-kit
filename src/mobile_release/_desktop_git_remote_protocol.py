"""Closed private Fetch request/GO/candidate-ACK/terminal comparisons.

Only the original GitLocal native owner supplies source/Connection/consent and
the SAME Preparing row. No frame grants that authority, opens the Store, or
selects a command, token source, HTTP role or arbitrary output destination.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from . import _desktop_git_read_protocol as fields
from . import _git_remote_private_protocol as private
from . import git_repository_fetch as fetch
from . import git_remote_control as controls
from . import git_fetch_transaction as transaction
from . import git_service as core
from . import git_remote_transport as transport
from .git_remote_wire import Selection
from .errors import ValidationError

PROTOCOL = "mrk-git-remote/1"
WORK_SECONDS, FINALITY_SECONDS, COMMAND_SECONDS = 45, 55, 45
REQUEST_LIMIT, READY_LIMIT, GO_LIMIT, CANDIDATE_LIMIT, ACK_LIMIT, RESPONSE_LIMIT = 96 * 1024, 512, 8192, 4096, 4096, 32 * 1024
TOOL_PATH, TOOL_LIMIT = fields.TOOL_PATH, fields.TOOL_LIMIT
STATUSES = ("ok", "refused", "cancelled", "timed-out", "cleanup-unknown")
EFFECTS = ("not-published", "pack-link-entered", "pack-linked", "index-link-entered", "objects-linked", "ref-send-entered", "ref-published")
_ERROR = "The original Git Fetch request or result was refused."


class ProtocolError(ValidationError):
    pass


def require(condition):
    if not condition:
        raise ProtocolError(_ERROR)


def valid_reason(value):
    return type(value) is str and value in core._REASONS | fetch._FETCH_REASONS | transport._REASONS


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    expected_revision: str
    expected_reference_revision: str
    remote: str
    reference: str
    connection_session_id: str
    expected_connection_revision: int

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "remote": self.remote,
                "reference": self.reference, "connectionSessionId": self.connection_session_id,
                "expectedConnectionRevision": self.expected_connection_revision}


def action(value):
    row = fields._keys(value, ("kind", "expectedRevision", "expectedReferenceRevision", "remote", "reference",
                               "connectionSessionId", "expectedConnectionRevision"))
    require(row["kind"] == "fetch")
    reference = fetch.selected_branch(row["reference"])
    require(reference.isascii() and len(reference) <= 255)
    return Action("fetch", fields._hex(row["expectedRevision"]), fields._hex(row["expectedReferenceRevision"]),
        fetch.remote_name(row["remote"]), reference, fields._id(row["connectionSessionId"]),
        fields._integer(row["expectedConnectionRevision"], 1, (1 << 32) - 2))


@dataclass(frozen=True, slots=True, repr=False)
class Request:
    id: str
    phase: str
    action: Action
    review_digest: str | None
    journal_revision: int | None
    project_id: str  # Runtime alias; never the durable service ProjectBinding.
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
        target = fields._keys(row["target"], ("repository", "login", "accountId", "repositoryId", "reference", "oid"))
        target = transport.Target(target["repository"], target["login"], target["accountId"], target["repositoryId"],
                                  Selection(target["reference"], target["oid"]))
        require(target.selected.reference == selected.reference)
        if row["phase"] == "prepare":
            require(row["reviewDigest"] is None and row["journalRevision"] is None and target.selected.oid is None)
        else:
            fields._hex(row["reviewDigest"])
            fields._integer(row["journalRevision"], 1, (1 << 64) - 2)
            require(target.selected.oid is not None)
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
    """Native-private consume only. Never place this return in a result/log."""
    require(type(request) is Request)
    try:
        row = fields._keys(fields._decode(raw, GO_LIMIT), ("protocol", "kind", "id", "digest", "token"))
        require((row["protocol"], row["kind"], row["id"], row["digest"]) == (PROTOCOL, "go", request.id, request.digest))
        return private.token(row["token"])
    except (fields.ProtocolError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def matches_review(request, review):
    require(type(request) is Request and type(review) is fetch.FetchReview and type(review.plan) is fetch.FetchPlan
            and review.digest == fetch._review_digest(review.plan))
    plan, target = review.plan, request.target
    require(plan.remote == request.action.remote and plan.reference_revision == request.action.expected_reference_revision
            and plan._snapshot.public.revision == request.action.expected_revision
            and plan.target.repository == target.repository and plan.target.login == target.login
            and plan.target.account_id == target.account_id and plan.target.repository_id == target.repository_id
            and plan.target.selected.reference == target.selected.reference and plan.target.selected.oid is not None)
    if request.phase == "apply":
        require(review.digest == request.review_digest and plan.target.selected == target.selected)


@dataclass(frozen=True, slots=True, repr=False)
class Candidate:
    request: Request
    intent: fetch.FetchIntent
    raw: bytes
    digest: str


def candidate(request, review, intent):
    matches_review(request, review)
    require(request.phase == "apply" and type(intent) is fetch.FetchIntent)
    before, plan = review.plan._snapshot, review.plan
    require((intent.review_digest, intent.expected_revision, intent.expected_reference_revision, intent.expected_ref,
             intent.expected_head, intent.expected_index, intent.target_ref, intent.expected_target, intent.candidate_ref_oid) ==
            (review.digest, before.public.revision, plan.reference_revision, before.public.branch, before.public.head,
             before.index_stamp.digest, plan.target_ref, plan.expected_target, plan.target.selected.oid))
    require(intent.expected_target != intent.candidate_ref_oid and re.fullmatch(r"[a-f0-9]{40}", intent.pack_oid) is not None
            and intent.pack_oid != "0" * 40)
    try:
        fields._hex(intent.pack_sha256); fields._hex(intent.index_sha256)
        fields._integer(intent.pack_bytes, 1, transaction.FILE_LIMIT); fields._integer(intent.index_bytes, 1, transaction.FILE_LIMIT)
    except fields.ProtocolError:
        raise ProtocolError(_ERROR) from None
    raw = _encode({"protocol": PROTOCOL, "kind": "candidate", "id": request.id, "digest": request.digest,
                   "reviewDigest": review.digest, "intent": intent.as_dict()}, CANDIDATE_LIMIT)
    return Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


def acknowledged(request, sent, raw):
    require(type(request) is Request and type(sent) is Candidate and sent.request is request and request.phase == "apply")
    try:
        row = fields._keys(fields._decode(raw, ACK_LIMIT), ("protocol", "kind", "id", "digest", "candidateDigest",
                                                          "journalRevision", "keep"))
        require((row["protocol"], row["kind"], row["id"], row["digest"], row["candidateDigest"]) ==
                (PROTOCOL, "ack", request.id, request.digest, sent.digest))
        revision = fields._integer(row["journalRevision"], 1, (1 << 64) - 1)
        require(revision == request.journal_revision + 1)
        keep = fields._keys(row["keep"], ("packOid", "reviewDigest", "identity", "parentBefore", "parentAfter"))
        require(all(type(keep[name]) is list for name in ("identity", "parentBefore", "parentAfter")))
        keep = transaction.BorrowedKeep(keep["packOid"], keep["reviewDigest"], tuple(keep["identity"]),
                                       tuple(keep["parentBefore"]), tuple(keep["parentAfter"]))
        require(keep.pack_oid == sent.intent.pack_oid and keep.review_digest == sent.intent.review_digest)
        return revision, keep
    except (fields.ProtocolError, core.GitError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None


def publication_data(value):
    """Positive child return comparison; original SourceBook still owns proof."""
    require(type(value) is transaction.Publication and value.phase in EFFECTS and value.pack is not None)
    ref = value.ref
    if ref is not None:
        require(value.phase == "ref-published" and ref.name == value.intent.target_ref and ref.oid == value.intent.candidate_ref_oid)
    log = value.log
    return {"phase": value.phase, "pack": value.pack, "index": value.index,
            "reference": None if ref is None else {"name": ref.name, "oid": ref.oid,
                "identity": ref.stamp.identity, "parent": ref.parent},
            "log": None if log is None else {"kind": log.kind, "identity": log.identity, "sha256": log.digest},
            "logParent": value.log_parent}


def terminal(request, status, *, reason: str | None, review=None, result=None, publication=None,
             effect_phase="not-published", retained_paths=(), first_failure_ns, cleanup_end_ns, control=None):
    require(type(request) is Request and status in STATUSES and (reason is None or valid_reason(reason)))
    try:
        fields._integer(cleanup_end_ns, 1, request.hard_end_ns)
        if first_failure_ns is not None:
            fields._integer(first_failure_ns, 1, cleanup_end_ns)
            require(cleanup_end_ns - first_failure_ns <= 10_000_000_000)
    except fields.ProtocolError:
        raise ProtocolError(_ERROR) from None
    try:
        safe_control = controls.checked(controls.empty() if control is None else control)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise ProtocolError(_ERROR) from None
    data, receipt = None, None
    if status == "ok":
        require(reason is None)
        if request.phase == "prepare":
            require(safe_control["reason"] == "none")
            matches_review(request, review)
            require(result is None and publication is None and effect_phase == "not-published" and not retained_paths
                    and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
            data = {"review": review.as_dict(), "diff": None}
        else:
            require(review is None and type(result) is core.MutationResult and result.operation_id == request.id
                    and result.action == "fetch" and result.settlement == "settled" and result.observation is None
                    and result.state in ("succeeded", "failed", "recovery-required") and effect_phase in EFFECTS
                    and type(retained_paths) is tuple and len(retained_paths) <= 5
                    and tuple(sorted(set(retained_paths))) == retained_paths)
            intent = result.intent
            require(intent is None or type(intent) is fetch.FetchIntent and intent.review_digest == request.review_digest)
            for path in retained_paths:
                require(type(path) is str and (re.fullmatch(r"mrk-git-fetch-[a-z0-9_]{1,32}", path) is not None
                    or intent is not None and path in tuple("objects/pack/pack-" + intent.pack_oid + "." + suffix
                                                           for suffix in ("pack", "idx", "keep"))))
            if publication is not None:
                require(type(publication) is transaction.Publication and publication.intent is intent)
                receipt = publication_data(publication)
            if result.state == "succeeded":
                require(safe_control["reason"] == "none")
                require(result.reason is None and intent is not None and publication is not None
                        and publication.ref is not None and effect_phase == "ref-published" and not retained_paths
                        and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
            else:
                require(valid_reason(result.reason) and result.reason not in ("unknown", "cleanup-unknown")
                        and first_failure_ns is not None and (intent is not None or effect_phase == "not-published"))
            data = {**result.as_dict(), "effectPhase": effect_phase, "retainedPaths": list(retained_paths)}
    else:
        require(review is None and result is None and publication is None and reason is not None
                and effect_phase == "not-published" and not retained_paths
                and (first_failure_ns is not None or status == "cleanup-unknown"))
    return _encode({"protocol": PROTOCOL, "kind": "terminal", "id": request.id, "digest": request.digest,
        "phase": request.phase, "action": "fetch", "status": status, "reason": reason, "result": data,
        "publication": receipt, "firstFailureNs": first_failure_ns, "cleanupEndNs": cleanup_end_ns, "control": safe_control},
        RESPONSE_LIMIT - READY_LIMIT - CANDIDATE_LIMIT)
