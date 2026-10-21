"""Local upstream configuration on the original GitLocal transaction.

No network, credential lookup, remote success claim, ref/OID publication or
global configuration is available here. Candidate/config/parent comparisons
supplement the original native SourceBook and durable candidate handoff.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat

from . import git_repository_branches as branches
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_repository_rename as rename
from . import git_repository_switch as switch
from . import git_service as core
from .api._github_connection import _coordinate
from ._desktop_git_read_protocol import identity as full_identity
from .owned_process import ProcessError

KIND = "set-upstream"
MAX_CONFIG = 60 * 1024
MAX_MISSING = 64
MAX_PATH_BYTES = 2048  # Also bounded by the unchanged 4KiB candidate frame.
MAX_NAMES = 1024
MAX_NAME_BYTES = 32768
REASONS = frozenset(("upstream-config", "upstream-conflict", "upstream-identity-required",
                     "upstream-layout", "upstream-unchanged", "upstream-parent-changed"))


class UpstreamError(core.GitError):
    def __init__(self, reason):
        core._need(reason in REASONS, "invalid-input")
        super().__init__("invalid-input")
        self.reason = reason


def require(value, reason="upstream-layout"):
    if not value:
        raise UpstreamError(reason)


def selection(remote, repository, branch, head):
    require(type(remote) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", remote),
            "upstream-config")
    try:
        require(_coordinate(repository) == repository and repository.isascii(), "upstream-config")
    except (ValueError, UnicodeError, AttributeError):
        raise UpstreamError("upstream-config") from None
    require(type(branch) is str and branch.startswith("refs/heads/"), "upstream-layout")
    name = branches.branch_name(branch[len("refs/heads/"):])
    require(type(head) is str and re.fullmatch(r"[a-f0-9]{40}", head) and head != "0" * 40)
    core._need(core._SECRET.search((remote + repository).encode("ascii")) is None, "sensitive-content")
    return name, "https://github.com/" + repository + ".git", "refs/remotes/" + remote + "/" + name


def approved_identity(identity):
    require(type(identity) is core.CommitIdentity, "upstream-identity-required")
    try:
        selected = branches._local_identity({"user.name": (identity.name.encode("utf-8"),),
                                              "user.email": (identity.email.encode("utf-8"),)})
        require(not any(c in selected.name for c in "#;"), "upstream-identity-required")
        return selected
    except (branches.BranchError, UnicodeError, AttributeError):
        raise UpstreamError("upstream-identity-required") from None


def configuration(raw, config, remote, repository, branch, head, identity):
    """Return only explicitly approved additions, never a replacement map.

    The supported missing-section spelling permits stock config to append
    without editing any old byte. Existing identical complete sections remain
    unchanged; partial/conflicting/case-alias/duplicate sections are refusals.
    """
    name, url, target = selection(remote, repository, branch, head)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CONFIG and raw.endswith(b"\n")
            and b"\0" not in raw and b"\r" not in raw, "upstream-config")
    require(type(config) is dict, "upstream-config")
    rp, bp = "remote." + remote + ".", "branch." + name + "."
    pairs = ((rp, ((rp + "url", url), (rp + "fetch", "+refs/heads/*:refs/remotes/" + remote + "/*"))),
             (bp, ((bp + "remote", remote), (bp + "merge", branch))))
    additions = []
    sections = {"remote": [], "branch": [], "user": []}
    for line in raw.splitlines(keepends=True):
        start = line.lstrip(b" \t")
        matched = re.match(rb"\[(remote|branch|user)(?:[ .\t\]])", start, re.I)
        if matched is None:
            continue
        kind = matched[1].decode("ascii").lower()
        pattern = rb'\[user\]\n' if kind == "user" else rb'\[' + kind.encode("ascii") + rb' "([A-Za-z0-9][A-Za-z0-9._/-]*)"\]\n'
        header = re.fullmatch(pattern, line)
        require(header is not None, "upstream-config")
        sections[kind].append("user" if kind == "user" else header[1].decode("ascii"))
    for kind, selected, prefix in (("remote", remote, rp), ("branch", name, bp)):
        matching = [v for v in sections[kind] if v.casefold() == selected.casefold()]
        require(matching in ([], [selected]), "upstream-conflict")
        require(not any(k.casefold().startswith(prefix.casefold()) and not k.startswith(prefix) for k in config),
                "upstream-conflict")
    for prefix, expected in pairs:
        present = [key in config for key, _ in expected]
        require(all(present) or not any(present), "upstream-conflict")
        if all(present):
            require(all(config[key] == (value.encode("ascii"),) for key, value in expected), "upstream-conflict")
        else:
            kind, selected = ("remote", remote) if prefix == rp else ("branch", name)
            require(selected not in sections[kind] and not any(k.startswith(prefix) for k in config), "upstream-conflict")
            additions.extend(expected)
    present = [key in config for key in ("user.name", "user.email")]
    require(all(present) or not any(present), "upstream-identity-required")
    require(len(sections["user"]) <= 1, "upstream-identity-required")
    if all(present):
        try:
            existing = branches._local_identity(config)
        except branches.BranchError:
            raise UpstreamError("upstream-identity-required") from None
        require(identity is None or approved_identity(identity) == existing, "upstream-conflict")
        selected_identity = existing
    else:
        require(not sections["user"] and not any(k.startswith(("user.", "author.", "committer.")) for k in config),
                "upstream-identity-required")
        selected_identity = approved_identity(identity)
        additions.extend((("user.name", selected_identity.name), ("user.email", selected_identity.email)))
    # Do not configure a tuple which the existing local Fetch policy refuses.
    require(config.get("core.logallrefupdates", (b"true",)) == (b"true",), "upstream-config")
    require(config.get("core.sharedrepository", (b"false",)) in ((b"false",), (b"0",)), "upstream-config")
    require(config.get("extensions.objectformat", (b"sha1",)) == (b"sha1",)
            and config.get("core.repositoryformatversion", (b"0",)) == (b"0",), "upstream-config")
    require(not any(k.startswith(("url.", "http.", "credential.", "protocol.", "core.ssh", "lfs.", "submodule.", "fetch."))
                    or k in ("core.gitproxy", "core.askpass", "core.alternaterefscommand") for k in config), "upstream-config")
    allowed_remote = {rp + key for key in ("url", "fetch", "pushurl", "tagopt")}
    require(all(k in allowed_remote for k in config if k.startswith(rp)), "upstream-config")
    require(config.get(rp + "pushurl", (url.encode("ascii"),)) == (url.encode("ascii"),)
            and config.get(rp + "tagopt", (b"--no-tags",)) == (b"--no-tags",), "upstream-config")
    require(len(additions) <= 6, "upstream-config")
    return tuple(additions), selected_identity, target


def configured(config, additions):
    result = dict(config)
    for key, value in additions:
        require(key not in result, "upstream-conflict")
        result[key] = (value.encode("utf-8"),)
    return result


def parent_paths(target):
    require(type(target) is str and target.startswith("refs/remotes/") and read._full_ref(target))
    paths = {"."}
    for leaf in (target, "logs/" + target):
        path = Path(leaf).parent
        while str(path) != ".":
            paths.add(path.as_posix())
            path = path.parent
    return tuple(sorted(paths, key=lambda v: (v.count("/") + (v != "."), v)))


def directory(path):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid() and not value.st_mode & 0o7022)
    return full_identity(value)


@dataclass(frozen=True, slots=True, repr=False)
class Parent:
    name: str
    identity: tuple
    names: tuple


@dataclass(frozen=True, slots=True, repr=False)
class Controls:
    config: core._Stamp
    raw: bytes
    additions: tuple
    identity: core.CommitIdentity
    parents: tuple[Parent, ...]
    missing: tuple[str, ...]
    leaves: tuple

    def comparison(self):
        return (self.config.identity, self.config.digest, self.additions,
                self.identity.name, self.identity.email,
                [(p.name, p.identity, p.names) for p in self.parents], self.missing,
                [(n, s.kind, s.identity, s.digest) for n, s in self.leaves])


def append_config(raw, additions):
    """Exact comparison for stock Git's newly appended, approved sections."""
    result, previous = raw, None
    for key, value in additions:
        pieces = key.split(".")
        if pieces[0] == "user":
            require(len(pieces) == 2 and pieces[1] in ("name", "email"), "upstream-config")
            header, variable = b"[user]\n", pieces[1]
        else:
            require(pieces[0] in ("remote", "branch") and len(pieces) >= 3, "upstream-config")
            section, variable = ".".join(pieces[1:-1]), pieces[-1]
            header = ('[' + pieces[0] + ' "' + section + '"]\n').encode("ascii")
        # All strings have already passed the closed URL/ref/local-identity
        # validators. No config escape, include, shell or newline is admitted.
        require(type(value) is str and value and not any(c in value for c in '\r\n\0"\\#;'), "upstream-config")
        if header != previous:
            result += header
        result += ("\t" + variable + " = " + value + "\n").encode("utf-8")
        previous = header
    require(len(result) <= MAX_CONFIG, "upstream-config")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class UpstreamIntent:
    expected_revision: str
    expected_reference_revision: str
    expected_ref: str
    expected_head: str
    expected_index: str
    original_config: str
    candidate_config: str
    remote: str
    repository: str
    missing_directories: tuple[str, ...]
    working: dict
    config_changed: bool
    action: str = field(default=KIND, init=False)

    def as_dict(self):
        return {"action": self.action, "expectedRevision": self.expected_revision,
                "expectedReferenceRevision": self.expected_reference_revision,
                "expectedRef": self.expected_ref, "expectedHead": self.expected_head,
                "expectedIndex": self.expected_index, "originalConfig": self.original_config,
                "candidateConfig": self.candidate_config, "remote": self.remote,
                "repository": self.repository, "missingDirectories": list(self.missing_directories),
                "working": self.working, "configChanged": self.config_changed}


def capture_controls(session, before, remote, repository, branch, head, identity):
    config_stamp, raw = rename.regular(session.git_dir / "config", MAX_CONFIG)
    additions, selected_identity, target = configuration(raw, before.config, remote, repository, branch, head, identity)
    require((session.git_dir / "config").lstat().st_gid == session.git_dir.lstat().st_gid == os.getegid())
    parents, missing, used_names, used_bytes = {}, [], 0, 0
    for name in parent_paths(target):
        parent, leaf = (".", ".") if name == "." else (Path(name).parent.as_posix(), Path(name).name)
        if parent in missing:
            missing.append(name)
            continue
        if name != ".":
            original = parents[parent]
            require(directory(session.git_dir / parent) == original.identity, "upstream-parent-changed")
            require(not any(v.casefold() == leaf.casefold() and v != leaf for v in original.names), "upstream-conflict")
            if leaf not in original.names:
                try:
                    (session.git_dir / name).lstat()
                except FileNotFoundError:
                    missing.append(name)
                    continue
                raise UpstreamError("upstream-parent-changed")
        path = session.git_dir / name
        stamp = directory(path)
        names = tuple(session.names(path))
        require(directory(path) == stamp, "upstream-parent-changed")
        used_names += len(names)
        used_bytes += sum(len(v.encode("utf-8")) for v in names)
        core._need(used_names <= MAX_NAMES and used_bytes <= MAX_NAME_BYTES, "limit")
        parents[name] = Parent(name, stamp, names)
    core._need(len(missing) <= MAX_MISSING and sum(len(v) for v in missing) <= MAX_PATH_BYTES, "limit")
    leaves = []
    for name, limit in ((target, 65), ("logs/" + target, 128 * 1024)):
        if Path(name).parent.as_posix() in missing:
            stamp = core._ABSENT
        else:
            stamp, _ = core._read(session.git_dir / name, limit)
            require(stamp.kind in ("file", "absent"))
            if stamp.kind == "file":
                rename.regular(session.git_dir / name, limit)
        leaves.append((name, stamp))
    return Controls(config_stamp, raw, additions, selected_identity, tuple(parents.values()), tuple(missing), tuple(leaves))


@dataclass(slots=True, repr=False)
class UpstreamPlan:
    remote: str
    repository: str
    reference_revision: str
    supplied_identity: core.CommitIdentity | None
    _key: object
    _snapshot: core._Snapshot
    _controls: Controls
    _used: bool = False
    action: str = field(default=KIND, init=False)

    def public(self):
        source, c = self._snapshot.public, self._controls
        return {"action": KIND, "remote": self.remote, "repository": self.repository,
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "branch": source.branch, "head": source.head, "expectedIndex": self._snapshot.index_stamp.digest,
                "originalConfig": c.config.digest, "additions": [{"key": k, "value": v} for k, v in c.additions],
                "missingDirectories": list(c.missing), "unchanged": not c.additions and not c.missing}


def review_digest(plan):
    require(type(plan) is UpstreamPlan)
    return switch._hash({"domain": "mrk-git-set-upstream/1", "review": plan.public(), "private": plan._controls.comparison()})


@dataclass(frozen=True, slots=True, repr=False)
class UpstreamReview:
    plan: UpstreamPlan
    digest: str

    def as_dict(self):
        return {**self.plan.public(), "reviewDigest": self.digest}


class _UpstreamSession(rename._RenameSession):
    def guard_current(self):
        local._LocalSession.guard_current(self)

    def check_original(self):
        current = read._inventory(self.git_dir, self.checkpoint, self.names)
        transaction = self.repository._transaction
        expected = transaction.expected_inventory(self.originals) if transaction is not None else self.originals
        core._need(current == expected, "stale-observation")
        hooks = self._hooks()
        if self.hooks is None:
            self.hooks = hooks
        core._need(hooks == self.hooks, "stale-observation")
        self.check_object_parents()
        if transaction is not None:
            transaction.check_controls()


class GitUpstreamRepository(local.GitLocalRepository):
    _ref_locks = None

    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _UpstreamSession(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture_upstream(self, session, remote, repository, branch, head, identity,
                          expected_revision, expected_reference_revision):
        selection(remote, repository, branch, head)
        core._need(type(expected_reference_revision) is str and core._REVISION.fullmatch(expected_reference_revision), "invalid-input")
        before = session.snapshot()
        self._expected(before, expected_revision)
        core._need(session.reference_revision(before.public) == expected_reference_revision
                   and (before.public.branch, before.public.head) == (branch, head), "stale-observation")
        self._policy(before, KIND)
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        require(before.index_stamp.kind == "file" and len(before.index_bytes) <= 1024 * 1024)
        controls = capture_controls(session, before, remote, repository, branch, head, identity)
        plan = UpstreamPlan(remote, repository, expected_reference_revision, identity, self._key, before, controls)
        session.check_original()
        session._check_frozen()
        return plan

    @core._session_boundary
    def prepare_upstream(self, remote, repository, branch, head, *, identity,
                         expected_revision, expected_reference_revision):
        core._need(not self._retained and not self._apply_entered, "recovery-required")
        plan = self._capture_upstream(self._session(), remote, repository, branch, head, identity,
                                      expected_revision, expected_reference_revision)
        return UpstreamReview(plan, review_digest(plan))

    @core._session_boundary
    def apply_upstream(self, review, owner, *, expected_digest):
        core._need(type(review) is UpstreamReview and type(review.plan) is UpstreamPlan and review.plan._key is self._key
                   and not review.plan._used and not self._apply_entered and not self._retained, "already-used")
        core._need(review.digest == expected_digest == review_digest(review.plan), "stale-observation")
        require(not review.plan.public()["unchanged"], "upstream-unchanged")
        self._apply_entered = True
        session, old = self._session(), review.plan
        plan = self._capture_upstream(session, old.remote, old.repository, old._snapshot.public.branch,
                                      old._snapshot.public.head, old.supplied_identity,
                                      old._snapshot.public.revision, old.reference_revision)
        core._need(review_digest(plan) == review.digest, "stale-observation")
        review.plan._used = True
        return self._apply_captured(session, UpstreamReview(plan, review.digest), owner)

    def _apply_captured(self, session, review, owner):
        from .git_repository_upstream_transaction import Handoff, UpstreamTransaction
        core._need(self._apply_entered and self._active_sessions == [session] and type(session) is _UpstreamSession
                   and self._transaction is None and review.plan._key is self._key, "authorization")
        plan = review.plan
        handoff = Handoff(self, plan, owner)
        self._active_plan, self._active_owner = plan, handoff
        transaction = self._transaction = UpstreamTransaction(session, plan._snapshot, plan, handoff)
        intent = None
        state, settlement, reason = "failed", "settled", None
        try:
            handoff.check_current(self.root, KIND, plan._snapshot.public.revision)
            transaction.acquire()
            transaction.prepare_candidate()
            intent = transaction.intent
            handoff.record_intent(intent)
            transaction.publish_config()
            state = "succeeded"
        except ProcessError as error:
            if error.fatal:
                self._unknown = True
                state, settlement, reason = "unknown", "unknown", "unknown"
            else:
                state, reason = ("recovery-required", "recovery-required") if intent else ("failed", "command-failed")
        except (core.GitError, OSError) as error:
            state = "recovery-required" if intent is not None else "failed"
            reason = error.reason if isinstance(error, core.GitError) else "command-failed"
        except BaseException:
            self._unknown = transaction.retained = True
            self._retained.append(transaction)
            raise
        try:
            if self._unknown:
                transaction.retained = True
            elif not transaction.close(preserve_scratch=intent is not None and state != "succeeded"):
                transaction.retained = True
                state, reason = "recovery-required", "recovery-required"
            if transaction.retained:
                self._retained.append(transaction)
            if transaction.uncertain_closes or transaction.directory_closes or transaction.config_lock.unknown:
                self._unknown = True
            if self._unknown:
                state, settlement, reason = "unknown", "unknown", "unknown"
        except BaseException:
            self._unknown = transaction.retained = True
            if transaction not in self._retained:
                self._retained.append(transaction)
            raise
        finally:
            if not self._unknown:
                self._active_plan = self._active_owner = None
        # No synthesized Observe/tracking OID. Refresh remains an explicit read.
        return core.MutationResult(handoff.operation_id, KIND, state, settlement, reason, None, intent)

    def _refuse_other_write(self, *args, **kwargs):
        raise core.GitError("invalid-input")

    prepare_local = apply_review = _refuse_other_write
