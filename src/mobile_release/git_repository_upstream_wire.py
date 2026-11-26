"""Closed set-upstream DATA in the existing GitLocal worker protocol."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import stat

from . import _desktop_git_read_protocol as fields
from . import git_repository_upstream as upstream
from . import git_repository_upstream_transaction as tx
from . import git_service as core

ACTION_KEYS = ("kind", "expectedRevision", "expectedReferenceRevision", "branch", "head", "remote", "repository", "identity")
REVIEW_KEYS = ("action", "remote", "repository", "expectedRevision", "expectedReferenceRevision", "branch", "head",
               "expectedIndex", "originalConfig", "additions", "missingDirectories", "unchanged", "reviewDigest")
INTENT_KEYS = ("action", "expectedRevision", "expectedReferenceRevision", "expectedRef", "expectedHead", "expectedIndex",
               "originalConfig", "candidateConfig", "remote", "repository", "missingDirectories", "working", "configChanged")
RESULT_KEYS = ("operationId", "action", "state", "settlement", "reason", "observation", "intent", "effectPhase", "retainedPaths")
PHASES = ("not-published", "directories-returned", "config-returned")
PUBLICATIONS = ("not-reported", "upstream-directories-returned", "upstream-config-returned")


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    expected_revision: str
    expected_reference_revision: str
    branch: str
    head: str
    remote: str
    repository: str
    identity: core.CommitIdentity | None
    kind: str = field(default=upstream.KIND, init=False)

    def as_dict(self):
        return {"kind": self.kind, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision, "branch": self.branch,
                "head": self.head, "remote": self.remote, "repository": self.repository,
                "identity": None if self.identity is None else {"name": self.identity.name, "email": self.identity.email}}


def action(value):
    from . import _desktop_git_local_protocol as wire
    try:
        v = fields._keys(value, ACTION_KEYS)
        wire.require(v["kind"] == upstream.KIND)
        upstream.selection(v["remote"], v["repository"], v["branch"], v["head"])
        identity = None
        if v["identity"] is not None:
            i = fields._keys(v["identity"], ("name", "email"))
            identity = upstream.approved_identity(core.CommitIdentity(i["name"], i["email"]))
        return Action(fields._hex(v["expectedRevision"]), fields._hex(v["expectedReferenceRevision"]),
                      v["branch"], v["head"], v["remote"], v["repository"], identity)
    except (fields.ProtocolError, core.GitError, TypeError, ValueError, UnicodeError, AttributeError):
        raise wire.ProtocolError(wire._ERROR) from None


def parent(value, uid):
    fields.require(type(value) is list and len(value) == 9)
    result = tuple(fields._integer(v, 0 if i < 7 else -(1 << 63), (1 << (64 if i < 7 else 63)) - 1)
                   for i, v in enumerate(value))
    fields.require(result[0] > 0 and result[1] > 0 and stat.S_ISDIR(result[2]) and result[3] == uid
                   and result[5] > 0 and not result[2] & 0o7022)
    return result


@dataclass(frozen=True, slots=True, repr=False)
class Sources:
    parents: tuple[upstream.Parent, ...]
    missing: tuple[str, ...]
    reference: fields.FileSnapshot | None
    log: fields.FileSnapshot | None


def sources(value, *, root, uid, selected):
    from . import _desktop_git_local_protocol as wire
    try:
        wire.require(type(selected) is Action)
        v = fields._keys(value, ("parents", "missing", "reference", "log"))
        _, _, target = upstream.selection(selected.remote, selected.repository, selected.branch, selected.head)
        paths = upstream.parent_paths(target)
        fields.require(type(v["parents"]) is list and len(v["parents"]) <= len(paths)
                       and type(v["missing"]) is list and len(v["missing"]) <= upstream.MAX_MISSING)
        rows, count, length = [], 0, 0
        for row in v["parents"]:
            row = fields._keys(row, ("name", "identity", "names"))
            fields.require(type(row["name"]) is str and row["name"] in paths and type(row["names"]) is list)
            names = row["names"]
            fields.require(all(type(n) is str and n not in ("", ".", "..") and "/" not in n and "\0" not in n
                               and len(n.encode("utf-8")) <= 255 for n in names)
                           and names == sorted(set(names)))
            count += len(names)
            length += sum(len(n.encode("utf-8")) for n in names)
            fields.require(count <= upstream.MAX_NAMES and length <= upstream.MAX_NAME_BYTES)
            rows.append(upstream.Parent(row["name"], parent(row["identity"], uid), tuple(names)))
        missing = tuple(v["missing"])
        fields.require(all(type(n) is str and n != "." and n in paths for n in missing)
                       and sum(len(n) for n in missing) <= upstream.MAX_PATH_BYTES
                       and tuple(p.name for p in rows) == tuple(n for n in paths if n not in missing)
                       and missing == tuple(n for n in paths if n in missing)
                       and len(set(missing)) == len(missing) and rows and rows[0].name == ".")
        by_name = {p.name: p for p in rows}
        for name in paths[1:]:
            p, leaf = Path(name).parent.as_posix(), Path(name).name
            if p in missing:
                fields.require(name in missing)
            else:
                fields.require(not any(n.casefold() == leaf.casefold() and n != leaf for n in by_name[p].names))
                fields.require((leaf not in by_name[p].names) == (name in missing))
        snapshots = tuple(None if v[key] is None else fields._snapshot(root / ".git" / name, v[key], uid, limit)
                          for key, name, limit in (("reference", target, 65), ("log", "logs/" + target, 128 * 1024)))
        for snap, name in zip(snapshots, (target, "logs/" + target)):
            parent_name, leaf = Path(name).parent.as_posix(), Path(name).name
            if parent_name in missing:
                fields.require(snap is None)
            else:
                names = by_name[parent_name].names
                fields.require(not any(n.casefold() == leaf.casefold() and n != leaf for n in names))
                fields.require((leaf in names) == (snap is not None))
        return Sources(tuple(rows), missing, *snapshots)
    except (fields.ProtocolError, core.GitError, TypeError, ValueError, UnicodeError, OverflowError):
        raise wire.ProtocolError(wire._ERROR) from None


def matches_review(request, review):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action
                 and type(review) is upstream.UpstreamReview and type(review.plan) is upstream.UpstreamPlan
                 and type(request.upstream_sources) is Sources and review.digest == upstream.review_digest(review.plan))
    p, a, s = review.plan, request.action, request.upstream_sources
    wire.require((p.remote, p.repository, p.reference_revision, p._snapshot.public.revision, p._snapshot.public.branch,
                  p._snapshot.public.head, p.supplied_identity) ==
                 (a.remote, a.repository, a.expected_reference_revision, a.expected_revision, a.branch, a.head, a.identity)
                 and (s.parents, s.missing) == (p._controls.parents, p._controls.missing)
                 and (request.phase == "prepare" or request.review_digest == review.digest))
    for snapshot, (_, stamp) in zip((s.reference, s.log), p._controls.leaves):
        wire.require(stamp.kind == "absent" if snapshot is None else stamp.kind == "file"
                     and tx.core_identity(snapshot.identity) == stamp.identity and snapshot.sha256 == stamp.digest)


def valid_intent(request, intent):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(intent) is upstream.UpstreamIntent and type(request.action) is Action)
    a = request.action
    wire.require((intent.expected_revision, intent.expected_reference_revision, intent.expected_ref, intent.expected_head,
                  intent.remote, intent.repository) ==
                 (a.expected_revision, a.expected_reference_revision, a.branch, a.head, a.remote, a.repository)
                 and intent.missing_directories == request.upstream_sources.missing
                 and type(intent.config_changed) is bool and (intent.config_changed or intent.missing_directories))
    for v in (intent.expected_index, intent.original_config, intent.candidate_config):
        fields._hex(v)
    wire.require(intent.config_changed or intent.original_config == intent.candidate_config)
    w = fields._keys(intent.working, ("root", "locks", "scratch", "scratchIdentity", "indexIdentity"))
    wire.require(type(w["locks"]) is list and len(w["locks"]) == 3
                 and type(w["scratch"]) is str and re.fullmatch(r"mrk-git-[a-z0-9_]{8}", w["scratch"])
                 and parent(list(w["root"]), request.uid)[:5] == request.upstream_sources.parents[0].identity[:5]
                 and stat.S_IMODE(parent(w["scratchIdentity"], request.uid)[2]) == 0o700)
    for name, i in zip(("config.lock", "index.lock", "HEAD.lock"), w["locks"]):
        snap = fields._snapshot(request.root / ".git" / name, {"identity": i, "sha256": "0" * 64}, request.uid, 0)
        wire.require(stat.S_IMODE(snap.identity[2]) == 0o600)
    fields._snapshot(request.root / ".git" / w["scratch"] / "index",
                     {"identity": w["indexIdentity"], "sha256": intent.expected_index}, request.uid, 1024 * 1024)


def valid_reason(value):
    return type(value) is str and value in core._REASONS | upstream.REASONS


def publication(operation):
    t = None if operation.repository is None else operation.repository._transaction
    if t is None or not t.directory_returned:
        return "not-reported"
    from . import _desktop_git_local_protocol as wire
    wire.require(type(t) is tx.UpstreamTransaction and t.owner.original is operation
                 and t.intent is operation.source.candidate.intent and operation.source.candidate_returned
                 and t.owner.acknowledged)
    return "upstream-config-returned" if t.config_returned is not None else "upstream-directories-returned"


def applied(operation, result):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(result) is core.MutationResult and result.action == upstream.KIND
                 and result.observation is None and result.intent is operation.repository._transaction.intent)
    phase = PHASES[PUBLICATIONS.index(publication(operation))]
    if result.intent is not None:
        valid_intent(operation.request, result.intent)
    wire.require(result.state != "succeeded" or phase == ("config-returned" if result.intent.config_changed else "directories-returned"))
    value = result.as_dict()
    value.update(effectPhase=phase, retainedPaths=retained_paths(operation.repository._transaction))
    return value


def retained_paths(t):
    if not t.retained:
        return []
    # Fixed relative, nonsecret custody hints. Never delete/retry instructions.
    names = [".git/" + n for n in t.plan._controls.missing]
    if t.config_attempted:
        names.append(".git/config")
    if t.scratch is not None:
        names += [".git/" + t.scratch.name, ".git/" + t.scratch.name + "/index"]
    return sorted(set(names))


def candidate(request, review, intent):
    from . import _desktop_git_local_protocol as wire
    import hashlib
    matches_review(request, review)
    wire.require(request.phase == "apply" and not review.plan.public()["unchanged"])
    valid_intent(request, intent)
    wire.require(intent.original_config == review.plan._controls.config.digest
                 and intent.expected_index == review.plan._snapshot.index_stamp.digest
                 and intent.config_changed == bool(review.plan._controls.additions))
    raw = wire._encode({"protocol": wire.PROTOCOL, "kind": "candidate", "id": request.id,
        "digest": request.digest, "reviewDigest": review.digest, "intent": intent.as_dict()}, wire.CANDIDATE_LIMIT)
    return wire.Candidate(request, intent, raw, hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True, slots=True, repr=False)
class Progress:
    phase: str
    retained: tuple[str, ...]

    def valid(self, publication, selected):
        if publication not in PUBLICATIONS or self.phase != PHASES[PUBLICATIONS.index(publication)]:
            return False
        _, _, target = upstream.selection(selected.remote, selected.repository, selected.branch, selected.head)
        allowed = {".git/config", *(".git/" + n for n in upstream.parent_paths(target) if n != ".")}
        scratch = [n for n in self.retained if re.fullmatch(r"\.git/mrk-git-[a-z0-9_]{8}(?:/index)?", n)]
        return (type(self.retained) is tuple and len(self.retained) <= upstream.MAX_MISSING + 3
                and self.retained == tuple(sorted(set(self.retained)))
                and all(n in allowed or n in scratch for n in self.retained)
                and (not scratch or len(scratch) == 2 and scratch[1] == scratch[0] + "/index"))


def terminal_data(request, status, *, reason, review, diff, result, publication, progress,
                  first_failure_ns, cleanup_end_ns):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(request) is wire.Request and type(request.action) is Action and publication in PUBLICATIONS)
    if status != "ok":
        wire.require(review is None and diff is None and result is None and progress is None
                     and publication == "not-reported" and reason is not None
                     and (first_failure_ns is not None or status == "cleanup-unknown"))
        return None
    wire.require(reason is None and diff is None)
    if request.phase == "prepare":
        matches_review(request, review)
        wire.require(result is None and progress is None and publication == "not-reported"
                     and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
        return {"review": review.as_dict()}
    wire.require(review is None and type(result) is core.MutationResult and result.operation_id == request.id
                 and result.action == upstream.KIND and result.settlement == "settled"
                 and result.state in ("succeeded", "failed", "recovery-required") and result.observation is None
                 and type(progress) is Progress and progress.valid(publication, request.action))
    if result.intent is not None:
        valid_intent(request, result.intent)
    wire.require(publication == "not-reported" or result.intent is not None)
    if result.state == "succeeded":
        wire.require(result.intent is not None and not progress.retained and result.reason is None
                     and publication == ("upstream-config-returned" if result.intent.config_changed else "upstream-directories-returned")
                     and first_failure_ns is None and cleanup_end_ns == request.hard_end_ns)
    else:
        wire.require(valid_reason(result.reason) and first_failure_ns is not None
                     and (result.state == "recovery-required" and result.intent is not None or
                          result.state == "failed" and publication == "not-reported" and not progress.retained))
    return {**result.as_dict(), "effectPhase": progress.phase, "retainedPaths": list(progress.retained)}


def local_session(operation, session):
    return (type(operation.request.action) is Action and type(operation.repository) is upstream.GitUpstreamRepository
            and type(session) is upstream._UpstreamSession and session.repository is operation.repository)


def returned_command(operation, session, args, result):
    from . import _desktop_git_local_protocol as wire
    wire.require(local_session(operation, session))
    if session.execution_command is None:
        return
    t = operation.repository._transaction
    wire.require(type(t) is tx.UpstreamTransaction and t.session is session and t.owner.original is operation
                 and operation.pending is not None and operation.pending.claimed)
    if result.returncode == 0:
        t.command_did_return(args, result)


def prepare_or_apply(operation):
    from . import _desktop_git_local_protocol as wire
    wire.require(type(operation.request.action) is Action and operation.entered and operation.source.go_returned)
    a = operation.request.action
    operation.repository = upstream.GitUpstreamRepository(operation.request.root, git_executable=wire.TOOL_PATH,
        work_end=operation.source.work_end, cancellation=operation.guard, _run=operation.command)
    kwargs = dict(identity=a.identity, expected_revision=a.expected_revision,
                  expected_reference_revision=a.expected_reference_revision)
    if operation.request.phase == "prepare":
        operation.review = operation.repository.prepare_upstream(a.remote, a.repository, a.branch, a.head, **kwargs)
        matches_review(operation.request, operation.review)
        return
    wire.require(operation.request.phase == "apply")

    @core._session_boundary
    def apply_current(repository):
        wire.require(not repository._apply_entered)
        repository._apply_entered = True
        session = repository._session()
        p = repository._capture_upstream(session, a.remote, a.repository, a.branch, a.head, a.identity,
                                          a.expected_revision, a.expected_reference_revision)
        operation.review = upstream.UpstreamReview(p, upstream.review_digest(p))
        matches_review(operation.request, operation.review)
        wire.require(not p.public()["unchanged"])
        p._used = True
        return repository._apply_captured(session, operation.review, operation)

    operation.result = apply_current(operation.repository)
    operation.upstream_state.capture_progress()
