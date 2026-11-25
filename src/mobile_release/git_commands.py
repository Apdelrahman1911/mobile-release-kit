"""Closed Desktop/CLI domain adapter over one registered GitRepository.

Root owns command registration, authenticated session binding, durable operation
status and the shared project coordinator. This module is not a standalone CLI,
an authorization issuer or a generic command/HTTP/process endpoint.
"""
from __future__ import annotations

import secrets
from typing import Any

from .git_service import CommitIdentity, GitError, GitPlan, GitRepository, MutationOwner


def _shape(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise GitError("invalid-input")
    return value


class GitCommands:
    def __init__(self, repository: GitRepository):
        self.repository = repository
        self._plans: dict[str, GitPlan] = {}

    def _retain(self, plan: GitPlan) -> dict[str, Any]:
        if len(self._plans) >= 16:
            raise GitError("limit")
        identifier = "git-plan-" + secrets.token_hex(16)
        self._plans[identifier] = plan
        return {"planId": identifier, **plan.as_dict()}

    def invoke(self, name: str, params: dict[str, Any], *, owner: MutationOwner | None = None) -> dict[str, Any]:
        """Finite operation names; no caller root, tool, env, argv or patch bytes.

        The host holds this instance with its registered project. In-memory
        plans are intentionally nonportable: after restart re-prepare unsent work
        or use the host's durable original operation recovery; never reconstruct
        an apply capability from a previous public plan description.
        """
        if name == "git_observe":
            _shape(params, set())
            return self.repository.observe().as_dict()
        if name == "git_diff":
            _shape(params, {"paths", "staged", "expectedRevision"})
            return self.repository.diff(params["paths"], staged=params["staged"],
                                        expected_revision=params["expectedRevision"]).as_dict()
        if name in ("git_stage_prepare", "git_unstage_prepare"):
            _shape(params, {"paths", "expectedRevision"})
            if len(self._plans) >= 16:
                raise GitError("limit")
            prepare = self.repository.prepare_stage if name == "git_stage_prepare" else self.repository.prepare_unstage
            return self._retain(prepare(params["paths"], expected_revision=params["expectedRevision"]))
        if name == "git_commit_prepare":
            _shape(params, {"message", "authorName", "authorEmail", "expectedRevision"})
            if len(self._plans) >= 16:
                raise GitError("limit")
            identity = CommitIdentity(params["authorName"], params["authorEmail"])
            return self._retain(self.repository.prepare_commit(params["message"], identity,
                                                               expected_revision=params["expectedRevision"]))
        if name in ("git_stage_apply", "git_unstage_apply", "git_commit_apply", "git_plan_discard"):
            _shape(params, {"planId"})
            identifier = params["planId"]
            if type(identifier) is not str or len(identifier) > 64 or identifier not in self._plans:
                raise GitError("invalid-input")
            plan = self._plans[identifier]
            if name == "git_plan_discard":
                if plan._used:
                    raise GitError("already-used")
                del self._plans[identifier]
                return {"discarded": True}
            if owner is None:
                raise GitError("authorization")
            if name != "git_" + plan.action + "_apply":
                raise GitError("invalid-input")
            # Retain the consumed plan as a tombstone. A lost response is not
            # permission to repeat a mutation or to adopt its public description.
            return self.repository.apply(plan, owner).as_dict()
        raise GitError("invalid-input")
