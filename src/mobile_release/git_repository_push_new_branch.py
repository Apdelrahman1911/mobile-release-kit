"""First publication through the SAME Push transaction and native owner.

No configured remote, tracking ref or existing OLD is manufactured. Every
reachable commit is reviewed, and both upstream keys must be genuinely absent
in the original frozen config. This facet never configures upstream, stages,
commits, fetches, overwrites a remote branch, or resolves credentials.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import git_push_new_branch as first
from . import git_repository_push as push
from . import git_service as core
from .git_push_transport import Target


@dataclass(slots=True, repr=False)
class PushNewBranchPlan(push.PushPlan):
    action: str = field(default=first.KIND, init=False)

    def __post_init__(self):
        core._need(self.remote is None and type(self.target) is Target
                   and type(self.target.selected) is first.Selection, "invalid-input")

    def public(self):
        selected, source = self.target.selected, self._snapshot.public
        return {"action": first.KIND, "remote": None, "repository": self.target.repository,
                "accountId": self.target.account_id, "repositoryId": self.target.repository_id,
                "login": self.target.login, "branch": selected.local_ref, "head": selected.new_oid,
                "upstreamRef": selected.remote_ref, "expectedRemoteOid": first.ZERO,
                "trackingRef": None, "commits": list(self.commits),
                "expectedRevision": source.revision, "expectedReferenceRevision": self.reference_revision,
                "expectedIndex": self._snapshot.index_stamp.digest, "basis": first.BASIS,
                "withheld": ["messages", "authors", "emails", "signatures", "objects"]}


@dataclass(frozen=True, slots=True, repr=False)
class PushNewBranchIntent(push.PushIntent):
    action: str = field(default=first.KIND, init=False)


def configuration(config, selected):
    core._need(type(selected) is first.Selection, "invalid-input")
    prefix = "branch." + selected.local_ref[len("refs/heads/"):] + "."
    # Neither an empty value nor one missing half is an unconfigured branch.
    # Config comes from the SAME bounded original --no-includes parser.
    push.require(prefix + "remote" not in config and prefix + "merge" not in config,
                 "push-upstream")
    push.require(prefix + "pushremote" not in config and "remote.pushdefault" not in config,
                 "push-upstream")
    push._configuration_policy(config)


class _Session(push._Session):
    def _extra_arguments(self, args, index, identity):
        selected = self.push_selection
        if type(selected) is first.Selection and index is None and identity is None:
            if args == ["rev-list", "--reverse", "--topo-order", "--max-count=" + str(push.MAX_COMMITS + 1),
                        selected.new_oid, "--"]:
                return True
            return self.push_tree is not None and args == ["ls-tree", "-r", "-z", "--full-tree", self.push_tree]
        return super()._extra_arguments(args, index, identity)

    def outgoing(self, selected):
        core._need(type(selected) is first.Selection and self.push_selection is None, "invalid-input")
        self.push_selection = selected
        _, raw = self.git(["rev-list", "--reverse", "--topo-order", "--max-count=" + str(push.MAX_COMMITS + 1),
                           selected.new_oid, "--"], limit=(push.MAX_COMMITS + 1) * 41)
        push.require(raw.endswith(b"\n") and b"\r" not in raw, "push-history")
        try:
            commits = tuple(raw[:-1].decode("ascii").split("\n"))
        except UnicodeError:
            raise push.PushError("push-history") from None
        push.require(1 <= len(commits) <= push.MAX_COMMITS and len(set(commits)) == len(commits)
                     and commits[-1] == selected.new_oid
                     and all(push._OID.fullmatch(oid) is not None and oid != first.ZERO for oid in commits),
                     "push-history")
        return commits, self._inspect_trees(commits)


class GitPushNewBranchRepository(push.GitPushRepository):
    """Closed capture only; prepare/apply/close remain the original Push flow."""
    def _session(self):
        core._need(not self._unknown, "unknown")
        session = _Session(self)
        self._active_sessions.append(session)
        session.discover()
        return session

    def _capture(self, session, target, revision, reference_revision):
        core._need(type(session) is _Session and type(target) is Target
                   and type(target.selected) is first.Selection, "invalid-input")
        before = session.snapshot()
        self._expected(before, revision)
        core._need(session.reference_revision(before.public) == reference_revision, "stale-observation")
        self._policy(before, first.KIND)
        core._need("required-signing" not in before.public.restrictions, "required-signing")
        selected = target.selected
        push.require((before.public.branch, before.public.head) == (selected.local_ref, selected.new_oid),
                     "push-upstream")
        push.require(not session.originals.shallow, "push-history")
        configuration(before.config, selected)
        # Check the real read algorithm too, but never treat a renderer's
        # 'not-configured' label as either upstream or remote-absence proof.
        push.require(session.tracking(before.public).state == "not-configured", "push-upstream")
        commits, trees = session.outgoing(selected)
        self._expected(session.snapshot(), revision)
        core._need(session.reference_revision(before.public) == reference_revision, "stale-observation")
        session.check_original(); session.guard_current()
        return PushNewBranchPlan(None, target, reference_revision, commits, trees, session.hooks,
                                 self._key, before)
