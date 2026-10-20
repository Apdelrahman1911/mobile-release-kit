"""Initialize-only DATA/dispatch in the existing GitLocal Input and Engine."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path

from . import _desktop_git_read_protocol as fields
from . import git_repository_init as init
from . import git_service as core


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str = field(default=init.ACTION, init=False)

    def as_dict(self):
        return {"kind": self.kind}


def action(value):
    from . import _desktop_git_local_protocol as wire
    row = fields._keys(value, ("kind",))
    wire.require(row["kind"] == init.ACTION)
    return Action()


@dataclass(frozen=True, slots=True, repr=False)
class Sources:
    name: str
    paths: tuple


def native(value, phase):
    from . import _desktop_git_local_protocol as wire
    row = fields._keys(value, ("uid", "gid", "root", "directory", "tool", "candidate"))
    uid, gid = fields._integer(row["uid"], 1, (1 << 32) - 1), fields._integer(row["gid"], 0, (1 << 32) - 1)
    root = fields._path(row["root"])
    original = fields._directory(row["directory"], uid)
    wire.require(original[4] == gid)
    tool = fields._snapshot(fields.TOOL_PATH, row["tool"], 0, fields.TOOL_LIMIT, executable=True)
    directories, sources = [(root, original)], None
    if phase == "prepare":
        wire.require(row["candidate"] is None)
    else:
        candidate = fields._keys(row["candidate"], ("name", "outer", "worktree", "git", "template"))
        name = candidate["name"]
        wire.require(type(name) is str and init.re.fullmatch(init.re.escape(init.PRIVATE_PREFIX) + r"[0-9a-f]{32}", name) is not None)
        outer = root / name
        paths = (outer, outer / "worktree", outer / "worktree/.git", outer / "empty-template")
        identities = tuple(fields._directory(candidate[key], uid) for key in ("outer", "worktree", "git", "template"))
        wire.require(all(v[0] == original[0] and v[1] != original[1] and v[2] & 0o7777 == 0o700 for v in identities)
                     and len({v[:2] for v in identities}) == 4)
        directories.extend(zip(paths, identities))
        sources = Sources(name, paths)
    return uid, gid, root, tuple(directories), tool, (), sources


def matches_review(request, review):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and type(review) is init.InitReview and type(review.plan) is init.InitPlan
                 and review.digest == init.review_digest(review.plan)
                 and (request.phase == "prepare" and request.init_sources is None
                      or request.phase == "apply" and type(request.init_sources) is Sources
                      and request.review_digest == review.digest))


def candidate(request, review, intent):
    from . import _desktop_git_local_protocol as wire
    matches_review(request, review)
    wire.require(request.phase == "apply" and type(intent) is init.InitIntent
                 and intent.expected_revision == review.plan.expected_revision
                 and intent.candidate_head == hashlib.sha256(b"ref: refs/heads/main\n").hexdigest()
                 and all(core._REVISION.fullmatch(v) for v in (intent.candidate_manifest, intent.candidate_head, intent.candidate_config)))
    raw = wire._encode({"protocol": wire.PROTOCOL, "kind": "candidate", "id": request.id,
        "digest": request.digest, "reviewDigest": review.digest, "intent": intent.as_dict()}, wire.CANDIDATE_LIMIT)
    return wire.Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


def terminal_data(request, status, *, reason, review, diff, result, publication, first_failure_ns, cleanup_end_ns):
    from . import _desktop_git_local_protocol as wire
    wire.require(diff is None)
    if status != "ok":
        return None
    wire.require(reason is None)
    if request.phase == "prepare":
        wire.require(result is None and publication == "not-reported" and first_failure_ns is None
                     and cleanup_end_ns == request.hard_end_ns)
        matches_review(request, review)
        return {"review": review.as_dict()}
    wire.require(review is None and type(result) is core.MutationResult and result.action == init.ACTION
                 and result.operation_id == request.id and result.settlement == "settled" and result.observation is None)
    if result.state == "succeeded":
        wire.require(type(result.intent) is init.InitIntent and publication == "init-returned"
                     and result.reason is None and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
    else:
        wire.require(result.state in ("failed", "recovery-required") and valid_reason(result.reason)
                     and first_failure_ns is not None and (publication == "not-reported" or type(result.intent) is init.InitIntent))
    return result.as_dict()


def valid_reason(value):
    return type(value) is str and value in core._REASONS | init.REASONS


def command_spec(operation, argv):
    """Called by the same command gate; the final run_owned gate checks again."""
    from . import _desktop_git_local_protocol as wire
    repository = operation.repository
    wire.require(type(repository) is init.GitInitRepository and len(repository._active_sessions) == 1)
    session = repository._active_sessions[0]
    wire.require(type(session) is init.InitSession and session.repository is repository
                 and session.candidate is operation.init_state.borrowed and session.frozen is None
                 and repository.git_executable == wire.TOOL_PATH and type(argv) is list)
    args = (["config", "--file", str(session.candidate.git.path / "config"), "--no-includes", "--null", "--list"]
            if session.generated else ["init", "--quiet", "--initial-branch=main", "--object-format=sha1",
                                       "--template=" + str(session.candidate.template.path)])
    expected, environment, cwd = session.command_spec(args)
    wire.require(argv == expected and (session.calls, operation.calls) in ((1, 0), (2, 1)))
    return environment, cwd


def expected_revision(operation):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(operation.review) is init.InitReview)
    return operation.review.plan.expected_revision


def prepare_or_apply(operation):
    from . import _desktop_git_local_protocol as wire
    candidate_source = operation.init_state.candidate()
    operation.repository = init.GitInitRepository(operation.request.root, git_executable=wire.TOOL_PATH,
        work_end=operation.source.work_end, tool_digest=operation.request.tool.sha256,
        candidate=candidate_source, cancellation=operation.guard, _run=operation.command)
    operation.review = operation.repository.prepare_init()
    matches_review(operation.request, operation.review)
    if operation.request.phase == "apply":
        operation.result = operation.repository.apply_init(operation.review, operation,
            expected_digest=operation.request.review_digest)
