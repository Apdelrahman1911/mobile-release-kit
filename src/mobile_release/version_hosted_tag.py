"""Fixed future-tag binding on the existing hosted Source/HTTP/Contents owners.

The ordinary source is still a branch. This action proves B→F, retains one
immutable claim in the SAME ledger, then may create exactly one absent T→F.
A loaded claim is comparison-only and can never authorize another POST.
"""
from __future__ import annotations

import base64
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from . import version_allocation as a
from . import version_ci as ci
from . import version_enrollment as enrollment
from . import version_future_tag as tag
from . import version_hosted as host
from . import version_policy as p
from . import workflow
from .cancellation import CleanupScope, cancellation_owner
from .github_preflight import HttpRequest
from .owned_process import ProcessCleanupError

READ = "hosted-version-tag-read"
CLAIM = "hosted-version-tag-claim"
CREATE = "hosted-version-tag-create"
ROLES = frozenset((READ, CLAIM, CREATE))
MAX_GIT_CALLS = 16
MAX_HTTP_CALLS = 25
_MESSAGE = "Bind Mobile Release Kit reserved future tag"
_PLATFORMS = {"android": ("android",), "ios": ("ios",), "both": ("android", "ios")}
_CONFIRMATION = re.compile(r"bind-version-tag:(android|ios|both):([0-9a-f-]{36}):([0-9a-f]{64}):([0-9a-f]{40})\Z", re.ASCII)


def need(condition, reason="tag-unconfirmed"):
    if not condition:
        raise host.Refused(reason)


@dataclass(frozen=True, slots=True)
class Intent:
    platform: str
    candidate_id: str
    row_sha256: str
    final: str

    @classmethod
    def parse(cls, confirmation):
        need(type(confirmation) is str and len(confirmation) <= 256, "admission")
        match = _CONFIRMATION.fullmatch(confirmation)
        need(match is not None, "admission")
        platform, candidate, digest, final = match.groups()
        a._uuid(candidate)
        return cls(platform, candidate, digest, final)

    def confirmation(self):
        return f"bind-version-tag:{self.platform}:{self.candidate_id}:{self.row_sha256}:{self.final}"


def validate_endpoint(role, method, path):
    _, tail = host.wire._path(path)
    if role == READ:
        need(method == "GET" and tail.startswith("git/ref/tags/"))
        tag.reference("refs/" + tail.removeprefix("git/ref/"))
    elif role == CLAIM:
        need(method == "PUT" and tail == "contents/" + a.LEDGER_PATH)
    elif role == CREATE:
        need(method == "POST" and tail == "git/refs")
    else:
        need(False)


def claim_body(before, after):
    need(type(before) is a.Ledger and type(after) is a.Ledger
         and before.genesis == after.genesis and before.reservations == after.reservations
         and len(after.tag_bindings) == len(before.tag_bindings) + 1
         and after.tag_bindings[:-1] == before.tag_bindings)
    raw = p.canonical({"branch": a.LEDGER_BRANCH, "message": _MESSAGE,
        "sha": a.blob_sha(before.to_bytes()), "content": base64.b64encode(after.to_bytes()).decode("ascii")})
    need(len(raw) <= a.MAX_HTTP_BYTES)
    return raw


def validate_body(role, body, *, path):
    if role == READ:
        validate_endpoint(role, "GET", path)
        need(body is None)
        return
    validate_endpoint(role, "PUT" if role == CLAIM else "POST", path)
    need(type(body) is bytes and 0 < len(body) <= (a.MAX_HTTP_BYTES if role == CLAIM else 512))
    row = a._decode_json(body, limit=a.MAX_HTTP_BYTES if role == CLAIM else 512,
                         nodes=16, depth=2, exact=True)
    need(p.canonical(row) == body)
    if role == CREATE:
        p._object(row, {"ref", "sha"})
        tag.reference(row["ref"])
        p._match(row["sha"], p._SHA)
        return
    p._object(row, {"branch", "message", "sha", "content"})
    need(row["branch"] == a.LEDGER_BRANCH and row["message"] == _MESSAGE)
    p._match(row["sha"], p._SHA)
    encoded = row["content"]
    need(type(encoded) is str and len(encoded) <= 4 * ((a.MAX_LEDGER_BYTES + 2) // 3))
    raw = base64.b64decode(encoded, validate=True)
    need(base64.b64encode(raw).decode("ascii") == encoded)
    value = a._decode_json(raw, limit=a.MAX_LEDGER_BYTES, nodes=20_000, depth=16)
    p._object(value, {"schemaVersion", "protocol", "genesis", "reservations", "tagBindings"})
    genesis = a.Genesis.parse(value["genesis"])
    repository, _ = host.wire._path(path)
    structural = a.AuthorityRegistration(genesis.project_id, repository, genesis.repository_id,
                                         genesis.ledger_id, genesis.sha256, True)
    after = a.Ledger.parse(raw, structural)
    need(bool(after.tag_bindings))
    before = a.Ledger(after.genesis, after.reservations, after.tag_bindings[:-1])
    need(claim_body(before, after) == body)


class _Source(host._Source):
    """The original owned read path with one CLOSED bind-only ceiling."""
    _git_limit = MAX_GIT_CALLS

    def __init__(self, root, context, guard):
        super().__init__(root, context, guard)
        self.remote = None
        self.bind_entered = False
        self.claim_entered = self.claim_acknowledged = self.post_entered = False
        self.claim = None

    def json(self, suffix):
        need(self.remote is not None)
        return self.remote.read(suffix)


class _Remote(host._Remote):
    _limit = MAX_HTTP_CALLS


class _ReservationRemote(host._Remote):
    _limit = 45

    def __init__(self, authority, source, send):
        need(getattr(source, "future_tag", None) is not None, "admission")
        super().__init__(authority, source, send)
        self.max_calls = 38 if source.enabled == ("ios",) else 45


def _branch(remote, reference, final):
    need(reference.startswith("refs/heads/"), "source")
    body = remote.read("git/ref/" + reference.removeprefix("refs/"))
    need(body.get("ref") == reference and type(body.get("object")) is dict
         and body["object"].get("type") == "commit" and body["object"].get("sha") == final, "source")


def _tag(remote, target):
    return remote.read("git/ref/" + target.removeprefix("refs/"), role=READ, missing=True)


def _result(status, row, intent, tree, claim):
    return {"schemaVersion": 1, "status": status, "candidateId": row.request.candidate_id,
        "rowSha256": row.sha256, "futureTag": row.request.future_tag,
        "sourceBranch": row.request.source.ref, "sourceCommit": row.request.source.commit,
        "finalCommit": intent.final, "finalTree": tree, "version": p.version_value(row.version),
        "bindingAttemptId": claim.attempt_id, "tagTriggeredBuild": False,
        "build": "not-performed", "store": "not-entered"}


def _bind(source, settings, intent, remote):
    """One claimed original, with a read-only branch for loaded permanent DATA."""
    need(type(source) is _Source and type(remote) is _Remote and not source.bind_entered)
    source.bind_entered = True  # Never reenter/restart this source after failure.
    source.remote = remote
    context, authority = source.context, settings.authority
    reference, final = context.authority["ref"], context.authority["headSha"]
    need(final == intent.final and context.platform == intent.platform
         and authority.repository == context.repository["fullName"]
         and authority.repository_id == context.repository["id"], "source")
    # CA used the same first three Git reads in _live, before this method.
    source.head(final)
    tree, parents, message = source.commit(final)
    trailer = ci.commit_selection(message)
    need(trailer is not None and trailer.candidate_id == intent.candidate_id
         and trailer.row_sha256 == intent.row_sha256, "source")
    a._repository_identity(remote.read(""), authority)                         # 1
    enrollment._protection(remote.read("branches/" + a.LEDGER_BRANCH + "/protection")) # 2
    original_commit = remote.ref()                                           # 3
    remote.ancestry(settings.checkpoint.commit, original_commit)              # 4
    before = a._snapshot(remote.read("contents/" + a.LEDGER_PATH + "?ref=" + original_commit),
                         original_commit, authority, settings.checkpoint)    # 5
    matches = [r for r in before.ledger.reservations if r.request.candidate_id == intent.candidate_id]
    need(len(matches) == 1 and matches[0].sha256 == intent.row_sha256, "candidate")
    row = matches[0]
    target = row.request.future_tag
    need(target is not None, "candidate")
    tag.reference(target)
    host._attempt(remote, context)                                           # 6
    _branch(remote, reference, final)                                        # 7
    # SAME ordinary CI proof. Its two remote commit checks are 8–9, and all
    # ten local proof reads include real final HEAD/tree. No filtered diff.
    source._prove(authority, row, final, reference, _PLATFORMS[intent.platform], tree, parents)
    present = _tag(remote, target)                                           # 10
    need(remote.ref() == original_commit, "authority")                       # 11
    a._repository_identity(remote.read(""), authority)                        # 12
    existing = [b for b in before.ledger.tag_bindings if b.candidate_id == intent.candidate_id]
    if existing:
        claim = tag.check_bound(before.ledger, row, final, tree)
        if present is None:
            source.remaining()
            return _result("unresolved", row, intent, tree, claim)
        tag.check_ref(present, target, final)
        source.head(final, tree)
        source.remaining()
        return _result("observed", row, intent, tree, claim)
    need(present is None, "tag-exists")  # Never adopt even an unclaimed T→F.
    run = context.authority
    claim = tag.Binding(row.request.candidate_id, row.sha256, final, tree,
                        str(uuid4()), run["runId"], run["attempt"])
    after = tag.append_binding(before.ledger, claim)
    raw = after.to_bytes()
    source.claim = claim  # Original intent held BEFORE possible write.
    source.claim_entered = True
    response = remote.exchange(CLAIM, HttpRequest("PUT", remote.prefix + "/contents/" + a.LEDGER_PATH,
                                                claim_body(before.ledger, after))) # 13
    ack = response.observation
    need(ack["status"] == 200 and type(ack["body"]) is dict)
    ack = ack["body"]
    need(type(ack.get("content")) is dict and ack["content"].get("path") == a.LEDGER_PATH
         and ack["content"].get("sha") == a.blob_sha(raw) and type(ack.get("commit")) is dict)
    committed = p._match(ack["commit"].get("sha"), p._SHA)
    back = a._snapshot(remote.read("contents/" + a.LEDGER_PATH + "?ref=" + committed),
                       committed, authority, before.checkpoint)              # 14
    need(back.ledger == after)
    remote.ancestry(original_commit, committed)                               # 15
    source.claim_acknowledged = True  # Not POST authority without cuts below.
    _branch(remote, reference, final)                                        # 16
    need(_tag(remote, target) is None, "tag-exists")                           # 17
    need(remote.ref() == committed, "authority")                             # 18 exact fully read claim revision
    source.head(final)  # Git 14, not a fresh source clock.
    source.remaining()
    need(source.claim is claim and source.claim_acknowledged and not source.post_entered)
    source.post_entered = True
    sent = remote.exchange(CREATE, HttpRequest("POST", remote.prefix + "/git/refs",
                                               p.canonical({"ref": target, "sha": final}))) # 19
    need(sent.observation["status"] == 201 and type(sent.observation["body"]) is dict)
    tag.check_ref(sent.observation["body"], target, final)
    tag.check_ref(_tag(remote, target), target, final)                          # 20
    final_counter = remote.ref()                                             # 21
    remote.ancestry(committed, final_counter)                                 # 22
    final_snapshot = a._snapshot(remote.read("contents/" + a.LEDGER_PATH + "?ref=" + final_counter),
                                final_counter, authority, back.checkpoint)   # 23
    need(tag.preserves(after, final_snapshot.ledger))
    need(tag.check_bound(final_snapshot.ledger, row, final, tree) == claim)
    a._repository_identity(remote.read(""), authority)                        # 24
    _branch(remote, reference, final)                                        # 25
    source.head(final, tree)  # Git 15–16; result stays private until outer cleanup.
    source.remaining()
    return _result("bound", row, intent, tree, claim)


def bind(app_root: Path, tooling_root: Path):
    selected = os.environ.get("MOBILE_RELEASE_SELECTED_PLATFORM", "")
    need(selected in _PLATFORMS, "admission")
    context = workflow.Context.current("candidate", selected)
    intent = Intent.parse(context.confirmation)
    need(os.environ.get("MOBILE_RELEASE_OPERATION") == "bind-version-tag"
         and context.stage == "candidate" and context.current_job == "version_reserve"
         and context.platform == intent.platform == context.selected_platform
         and context.authority["headSha"] == intent.final, "admission")
    settings = host._settings(context)
    root, tooling = workflow._safe_path(app_root), workflow._safe_path(tooling_root)
    need(root.is_dir() and tooling.is_dir() and (root / ".git").is_dir()
         and not (root / ".git").is_symlink(), "source")
    guard, owns = cancellation_owner(None, ProcessCleanupError, "Hosted future tag cleanup is unconfirmed")
    scope = CleanupScope(guard, lambda: None, owns_cancellation=owns, first_primary=True)
    result = None
    try:
        with scope:
            if owns:
                guard.install()
                guard.activate()
            source = _Source(root, context, guard)
            remote = _Remote(settings.authority, source,
                host._live(source, tooling, os.environ[host.TOKEN_ENV], operation="bind-version-tag"))
            result = _bind(source, settings, intent, remote)
    finally:
        scope.__exit__(*sys.exc_info())
    guard.check()
    return result
