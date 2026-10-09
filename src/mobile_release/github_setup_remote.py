"""Closed DATA and request sequences for repository settings and environments.

No credential, clock, consent, socket, child or local-finality owner lives here.
A Schedule is not network authority. Live Setup admission and native one-use
consent are separate, required integrations; existing engine routes stay closed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from ._desktop_github_engine import _ID, _check_control, _check_values, _decode_json
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _account, _coordinate, _id, _read, _repository, _utc
from .github_preflight import HttpRequest, Reader, _DIGEST, _match, _object, _require
from .credential_requirements import ENVIRONMENT_NAMES

PROTOCOL = "mrk-github-setup/1"
API_VERSION = "2026-03-10"
MAX_REQUESTS = 6
MAX_BODY_BYTES = 8 * 1024
MAX_INITIAL_BYTES = 8 * 1024
MAX_GO_BYTES = 8 * 1024
MAX_READY_BYTES = 512
MAX_RESULT_BYTES = 64 * 1024
KINDS = frozenset({"actions_enabled", "workflow_token_policy"})
REASONS = frozenset({"none", "no-change", "policy-unsupported", "policy-changed",
                     "organization-restricted", "repository-archived", "unauthorized", "forbidden",
                     "not-found-or-inaccessible", "target-changed", "rate-limited", "network-unavailable",
                     "tls-failed", "response-invalid", "response-limit", "expired", "cancelled"})


class Refused(ValueError):
    def __init__(self, reason: str) -> None:
        _require(type(reason) is str and reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed GitHub setup observation was refused")


def _same(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


@dataclass(frozen=True, slots=True)
class Selection:
    kind: str
    desired: tuple[Any, ...]

    @classmethod
    def parse(cls, value: object) -> Selection:
        _require(type(value) is dict and type(value.get("kind")) is str and value["kind"] in KINDS)
        if value["kind"] == "actions_enabled":
            row = _object(value, {"kind", "enabled"})
            _require(type(row["enabled"]) is bool)
            return cls(row["kind"], (row["enabled"],))
        row = _object(value, {"kind", "defaultWorkflowPermissions", "canApprovePullRequestReviews"})
        _require(type(row["defaultWorkflowPermissions"]) is str
                 and row["defaultWorkflowPermissions"] in {"read", "write"}
                 and type(row["canApprovePullRequestReviews"]) is bool)
        return cls(row["kind"], (row["defaultWorkflowPermissions"], row["canApprovePullRequestReviews"]))

    def value(self) -> dict[str, Any]:
        if self.kind == "actions_enabled":
            return {"kind": self.kind, "enabled": self.desired[0]}
        return {"kind": self.kind, "defaultWorkflowPermissions": self.desired[0],
                "canApprovePullRequestReviews": self.desired[1]}


@dataclass(frozen=True, slots=True)
class Target:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    selection: Selection

    @classmethod
    def parse(cls, value: object) -> Target:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "selection"})
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _id(row["accountId"]), _id(row["repositoryId"]), Selection.parse(row["selection"]))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "selection": self.selection.value()}


@dataclass(frozen=True, slots=True)
class Policy:
    kind: str
    fields: tuple[Any, ...]

    @classmethod
    def parse(cls, kind: str, value: object, *, upstream: bool = False) -> Policy:
        _require(type(kind) is str and kind in KINDS and type(value) is dict)
        if kind == "actions_enabled":
            required = {"enabled", "allowed_actions", "sha_pinning_required"}
            if upstream:
                # Optional documented policy fields cannot become defaults.
                # Extra semantic policy fields require a reviewed preservation rule.
                _same(required <= set(value) <= required | {"selected_actions_url"}, "policy-unsupported")
                if "selected_actions_url" in value:
                    text = value["selected_actions_url"]
                    _require(type(text) is str and 1 <= len(text) <= 2048
                             and all(0x21 <= ord(char) <= 0x7e for char in text))
                    # Never follow, emit or use this URL as an endpoint.
            else:
                _object(value, required)
            _require(type(value["enabled"]) is bool and type(value["sha_pinning_required"]) is bool
                     and type(value["allowed_actions"]) is str
                     and value["allowed_actions"] in {"all", "local_only", "selected"})
            return cls(kind, (value["enabled"], value["allowed_actions"], value["sha_pinning_required"]))
        _object(value, {"default_workflow_permissions", "can_approve_pull_request_reviews"})
        _require(type(value["default_workflow_permissions"]) is str
                 and value["default_workflow_permissions"] in {"read", "write"}
                 and type(value["can_approve_pull_request_reviews"]) is bool)
        return cls(kind, (value["default_workflow_permissions"], value["can_approve_pull_request_reviews"]))

    def value(self) -> dict[str, Any]:
        if self.kind == "actions_enabled":
            return dict(zip(("enabled", "allowed_actions", "sha_pinning_required"), self.fields))
        return dict(zip(("default_workflow_permissions", "can_approve_pull_request_reviews"), self.fields))

    def changed(self, selection: Selection) -> Policy:
        _require(self.kind == selection.kind)
        if self.kind == "actions_enabled":
            return Policy(self.kind, (selection.desired[0], self.fields[1], self.fields[2]))
        return Policy(self.kind, selection.desired)


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    before: Policy
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> Prepared:
        row = _object(value, {"target", "before", "after", "observedAt", "confirmation"})
        target = Target.parse(row["target"])
        before = Policy.parse(target.selection.kind, row["before"])
        result = cls(target, before, _utc(row["observedAt"]))
        _require(Policy.parse(target.selection.kind, row["after"]) == result.after)
        _require(result.before != result.after and row == result.value())
        return result

    @property
    def after(self) -> Policy:
        return self.before.changed(self.target.selection)

    def value(self) -> dict[str, Any]:
        notice = ("Change " + self.target.selection.kind + " for " + self.target.repository
                  + "? Review the exact before and after values. Enabling Actions can allow configured workflows "
                  "to run; write tokens or review approvals grant additional privileges. GitHub does not provide "
                  "an atomic compare-and-set here: another administrator can change settings after this review. "
                  "This does not configure secrets, change local workflows, or qualify a release.")
        return {"target": self.target.value(), "before": self.before.value(), "after": self.after.value(),
                "observedAt": self.observed_at, "confirmation": notice}


@dataclass(frozen=True, slots=True, repr=False)
class Action:
    kind: str
    target: Target
    prepared: Prepared | None = None

    @classmethod
    def parse(cls, value: object) -> Action:
        row = _object(value, {"kind", "target", "prepared"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "apply"})
        target = Target.parse(row["target"])
        prepared = None if row["prepared"] is None else Prepared.parse(row["prepared"])
        _require((row["kind"] == "prepare") == (prepared is None))
        _require(prepared is None or prepared.target == target)
        return cls(row["kind"], target, prepared)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value()}


class Schedule:
    """DATA-only fixed endpoint cursor, claimed before any possible send."""
    def __init__(self, action: Action) -> None:
        self.action = Action.parse(action.value())
        self.steps: list[str] = []

    def claim(self, step: str, reference: str | None = None) -> HttpRequest:
        schedule = (("account", "repository-before", "resource-before", "repository-after")
                    if self.action.kind == "prepare" else
                    ("account", "repository-before", "resource-before", "write", "resource-after", "repository-after"))
        _require(reference is None and len(self.steps) < len(schedule) <= MAX_REQUESTS
                 and step == schedule[len(self.steps)])
        self.steps.append(step)  # Includes failed attempts; no retry or rollback.
        if step == "account":
            return HttpRequest("GET", "/user", None)
        prefix = "/repos/" + self.action.target.repository
        if step in {"repository-before", "repository-after"}:
            return HttpRequest("GET", prefix, None)
        path = prefix + "/actions/permissions"
        if self.action.target.selection.kind == "workflow_token_policy":
            path += "/workflow"
        if step == "write":
            _require(self.action.prepared is not None)
            raw = _canonical(self.action.prepared.after.value())
            _require(len(raw) <= MAX_BODY_BYTES)
            return HttpRequest("PUT", path, raw)
        return HttpRequest("GET", path, None)


# Environment DATA remains outside old KINDS/execute. The closed Initial
# dispatcher and private reader separately admit these exact roles and budgets.
ENVIRONMENT_MAX_REQUESTS = 8
ENVIRONMENT_POLICY_BYTES = 1024
ENVIRONMENT_FACTS_BYTES = 1536
ENVIRONMENT_PREPARED_BYTES = 4096
_ENVIRONMENT_NAMES = tuple(ENVIRONMENT_NAMES.items())
_ENVIRONMENT_FIELDS = {"id", "node_id", "name", "url", "html_url", "created_at", "updated_at",
                       "protection_rules", "deployment_branch_policy"}
_USER_METADATA = {"name", "email", "login", "id", "node_id", "avatar_url", "gravatar_id", "url",
                  "html_url", "followers_url", "following_url", "gists_url", "starred_url",
                  "subscriptions_url", "organizations_url", "repos_url", "events_url",
                  "received_events_url", "type", "site_admin", "starred_at", "user_view_type"}
_TEAM_METADATA = {"id", "node_id", "name", "slug", "description", "privacy", "notification_setting",
                  "permission", "permissions", "url", "html_url", "members_url", "repositories_url",
                  "type", "access_source", "organization_id", "enterprise_id", "parent"}


def _environment_id(value: object, *, upstream: bool = False) -> str:
    if upstream:
        _require(type(value) is int and 0 < value <= 2**63 - 1)
        return str(value)
    result = _id(value)
    _require(int(result) <= 2**63 - 1)
    return result


def _environment_text(value: object, maximum: int = 2048) -> str:
    _require(type(value) is str and 1 <= len(value) <= maximum
             and all(0x20 <= ord(char) <= 0x7e for char in value))
    return value


def _environment_login(value: object) -> str:
    text = _environment_text(value, 39)
    _require(text[0].isalnum() and text[-1].isalnum()
             and all(char.isalnum() or char == "-" for char in text) and "--" not in text)
    return text


def _environment_bounded(value: object, maximum: int) -> None:
    # Only call on the bounded normalized forms, never on an unbounded raw body.
    _require(len(_canonical(value)) <= maximum)


@dataclass(frozen=True, slots=True)
class EnvironmentSelection:
    mode: str
    stage: str
    wait_timer: int
    prevent_self_review: bool | None
    reviewer_login: str | None
    branches: str | None

    @classmethod
    def parse(cls, value: object) -> EnvironmentSelection:
        row = _object(value, {"kind", "mode", "stage", "waitTimerMinutes", "preventSelfReview",
                              "reviewerLogin", "branches"})
        _require(row["kind"] == "environment_protection" and type(row["mode"]) is str
                 and row["mode"] in {"configure", "create"} and type(row["stage"]) is str
                 and row["stage"] in dict(_ENVIRONMENT_NAMES)
                 and type(row["waitTimerMinutes"]) is int and 0 <= row["waitTimerMinutes"] <= 43200)
        review = row["preventSelfReview"]
        _require(review is None or type(review) is bool)
        if row["mode"] == "create":
            _require(review is True and type(row["branches"]) is str and row["branches"] in {"all", "protected"})
            login = _environment_login(row["reviewerLogin"])
        else:
            _require(row["reviewerLogin"] is None and row["branches"] is None)
            login = None
        return cls(row["mode"], row["stage"], row["waitTimerMinutes"], review, login, row["branches"])

    @property
    def name(self) -> str:
        return dict(_ENVIRONMENT_NAMES)[self.stage]

    def value(self) -> dict[str, Any]:
        return {"kind": "environment_protection", "mode": self.mode, "stage": self.stage,
                "waitTimerMinutes": self.wait_timer, "preventSelfReview": self.prevent_self_review,
                "reviewerLogin": self.reviewer_login, "branches": self.branches}


@dataclass(frozen=True, slots=True)
class EnvironmentTarget:
    project_binding: str
    repository: str
    account_id: str
    repository_id: str
    selection: EnvironmentSelection

    @classmethod
    def parse(cls, value: object) -> EnvironmentTarget:
        row = _object(value, {"projectBinding", "repository", "accountId", "repositoryId", "selection"})
        return cls(_match(row["projectBinding"], _DIGEST), _coordinate(row["repository"]),
                   _environment_id(row["accountId"]), _environment_id(row["repositoryId"]),
                   EnvironmentSelection.parse(row["selection"]))

    def value(self) -> dict[str, Any]:
        return {"projectBinding": self.project_binding, "repository": self.repository,
                "accountId": self.account_id, "repositoryId": self.repository_id,
                "selection": self.selection.value()}


@dataclass(frozen=True, slots=True)
class EnvironmentPolicy:
    wait_timer: int
    prevent_self_review: bool | None
    reviewers: tuple[tuple[str, str], ...]
    protected_branches: bool

    @classmethod
    def parse(cls, value: object) -> EnvironmentPolicy:
        row = _object(value, {"waitTimerMinutes", "requiredReviewers", "protectedBranches"})
        _require(type(row["waitTimerMinutes"]) is int and 0 <= row["waitTimerMinutes"] <= 43200
                 and type(row["protectedBranches"]) is bool)
        rule = row["requiredReviewers"]
        review, identities = None, []
        if rule is not None:
            rule = _object(rule, {"preventSelfReview", "reviewers"})
            _require(type(rule["preventSelfReview"]) is bool and type(rule["reviewers"]) is list
                     and 1 <= len(rule["reviewers"]) <= 6)
            review = rule["preventSelfReview"]
            for item in rule["reviewers"]:
                item = _object(item, {"type", "id"})
                _require(type(item["type"]) is str and item["type"] in {"User", "Team"})
                pair = (item["type"], _environment_id(item["id"]))
                _require(pair not in identities)
                identities.append(pair)
        # Reviewer array order has no policy significance; normalize before comparing.
        result = cls(row["waitTimerMinutes"], review, tuple(sorted(identities)), row["protectedBranches"])
        _environment_bounded(result.value(), ENVIRONMENT_POLICY_BYTES)
        return result

    def value(self) -> dict[str, Any]:
        return {"waitTimerMinutes": self.wait_timer, "protectedBranches": self.protected_branches,
                "requiredReviewers": None if self.prevent_self_review is None else
                {"preventSelfReview": self.prevent_self_review,
                 "reviewers": [{"type": kind, "id": identity} for kind, identity in self.reviewers]}}

    def put_value(self) -> dict[str, Any]:
        checked = EnvironmentPolicy.parse(self.value())
        return {"wait_timer": checked.wait_timer,
                "prevent_self_review": False if checked.prevent_self_review is None else checked.prevent_self_review,
                "reviewers": [{"type": kind, "id": int(identity)} for kind, identity in checked.reviewers] or None,
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}
                if checked.protected_branches else None}

    @classmethod
    def upstream(cls, body: object) -> EnvironmentPolicy:
        _require(type(body) is dict and set(body) == _ENVIRONMENT_FIELDS)
        rules, branch = body["protection_rules"], body["deployment_branch_policy"]
        _require(type(rules) is list and len(rules) <= 3)
        protected = branch is not None
        if protected:
            branch = _object(branch, {"protected_branches", "custom_branch_policies"})
            _same(branch["protected_branches"] is True and branch["custom_branch_policies"] is False,
                  "policy-unsupported")
        seen: set[str] = set()
        wait, reviewers = 0, None
        for rule in rules:
            _require(type(rule) is dict and type(rule.get("type")) is str)
            kind = rule["type"]
            _same(kind in {"wait_timer", "required_reviewers", "branch_policy"}, "policy-unsupported")
            _require(kind not in seen)
            seen.add(kind)
            keys = {"id", "node_id", "type"}
            if kind == "wait_timer":
                keys |= {"wait_timer"}
            elif kind == "required_reviewers":
                keys |= {"prevent_self_review", "reviewers"}
            _object(rule, keys)
            _environment_id(rule["id"], upstream=True)
            _environment_text(rule["node_id"])
            if kind == "wait_timer":
                wait = rule["wait_timer"]
            elif kind == "required_reviewers":
                _require(type(rule["reviewers"]) is list and 1 <= len(rule["reviewers"]) <= 6)
                identities = []
                for item in rule["reviewers"]:
                    item = _object(item, {"type", "reviewer"})
                    kind_of_reviewer, principal = item["type"], item["reviewer"]
                    _require(type(kind_of_reviewer) is str and kind_of_reviewer in {"User", "Team"}
                             and type(principal) is dict and "id" in principal)
                    _same(set(principal) <= (_USER_METADATA if kind_of_reviewer == "User" else _TEAM_METADATA),
                          "policy-unsupported")
                    if kind_of_reviewer == "User":
                        _require(principal.get("type") == "User")
                    identities.append({"type": kind_of_reviewer,
                                       "id": _environment_id(principal["id"], upstream=True)})
                reviewers = {"preventSelfReview": rule["prevent_self_review"], "reviewers": identities}
        _require(("branch_policy" in seen) == protected)
        return cls.parse({"waitTimerMinutes": wait, "requiredReviewers": reviewers, "protectedBranches": protected})


@dataclass(frozen=True, slots=True)
class EnvironmentFacts:
    name: str
    identity: str | None
    policy: EnvironmentPolicy | None

    @classmethod
    def parse(cls, value: object) -> EnvironmentFacts:
        row = _object(value, {"name", "id", "policy"})
        _require(type(row["name"]) is str and row["name"] in dict(_ENVIRONMENT_NAMES).values())
        _require((row["id"] is None) == (row["policy"] is None))
        result = cls(row["name"], None if row["id"] is None else _environment_id(row["id"]),
                     None if row["policy"] is None else EnvironmentPolicy.parse(row["policy"]))
        _environment_bounded(result.value(), ENVIRONMENT_FACTS_BYTES)
        return result

    def value(self) -> dict[str, Any]:
        return {"name": self.name, "id": self.identity, "policy": None if self.policy is None else self.policy.value()}

    @classmethod
    def upstream(cls, body: object, name: str) -> EnvironmentFacts:
        _object(body, _ENVIRONMENT_FIELDS)
        _same(body["name"] == name, "target-changed")
        for field in ("node_id", "url", "html_url"):
            _environment_text(body[field])  # Display metadata only; never followed.
        _utc(body["created_at"])
        _utc(body["updated_at"])
        return cls.parse({"name": name, "id": _environment_id(body["id"], upstream=True),
                          "policy": EnvironmentPolicy.upstream(body).value()})

    @classmethod
    def absent(cls, body: object, name: str) -> EnvironmentFacts:
        _require(type(name) is str and name in dict(_ENVIRONMENT_NAMES).values())
        row = _object(body, {"total_count", "environments"})
        _require(type(row["total_count"]) is int and type(row["environments"]) is list
                 and 0 <= row["total_count"] == len(row["environments"]) <= 100)
        names, identities = set(), set()
        for item in row["environments"]:
            _require(type(item) is dict and {"id", "name"} <= set(item) <= _ENVIRONMENT_FIELDS)
            other = _environment_text(item["name"], 255).lower()
            identity = _environment_id(item["id"], upstream=True)
            _require(other not in names and identity not in identities)
            names.add(other)
            identities.add(identity)
        _same(name.lower() not in names, "policy-changed")
        return cls.parse({"name": name, "id": None, "policy": None})


def environment_custom_rules_empty(body: object) -> None:
    row = _object(body, {"total_count", "custom_deployment_protection_rules"})
    _same(type(row["total_count"]) is int and row["total_count"] == 0
          and type(row["custom_deployment_protection_rules"]) is list
          and len(row["custom_deployment_protection_rules"]) == 0, "policy-unsupported")


@dataclass(frozen=True, slots=True)
class EnvironmentReviewer:
    identity: str
    login: str
    permission: str

    @classmethod
    def parse(cls, value: object) -> EnvironmentReviewer:
        row = _object(value, {"id", "login", "permission"})
        _require(type(row["permission"]) is str and row["permission"] in {"read", "write", "admin"})
        return cls(_environment_id(row["id"]), _environment_login(row["login"]), row["permission"])

    def value(self) -> dict[str, Any]:
        return {"id": self.identity, "login": self.login, "permission": self.permission}

    @classmethod
    def upstream(cls, body: object, login: str) -> EnvironmentReviewer:
        row = _object(body, {"permission", "role_name", "user"})
        user = row["user"]
        _require(type(user) is dict and {"id", "login", "type"} <= set(user)
                 and set(user) <= _USER_METADATA | {"permissions", "role_name"} and user["type"] == "User")
        _environment_text(row["role_name"], 100)  # Not authority; only base permission is admitted.
        result = cls.parse({"id": _environment_id(user["id"], upstream=True),
                            "login": user["login"], "permission": row["permission"]})
        _same(result.login.lower() == _environment_login(login).lower(), "target-changed")
        return result


@dataclass(frozen=True, slots=True)
class EnvironmentPrepared:
    target: EnvironmentTarget
    before: EnvironmentFacts
    reviewer: EnvironmentReviewer | None
    observed_at: str

    @classmethod
    def parse(cls, value: object) -> EnvironmentPrepared:
        row = _object(value, {"target", "before", "after", "reviewer", "observedAt", "confirmation"})
        target, before = EnvironmentTarget.parse(row["target"]), EnvironmentFacts.parse(row["before"])
        reviewer = None if row["reviewer"] is None else EnvironmentReviewer.parse(row["reviewer"])
        _require(before.name == target.selection.name)
        if target.selection.mode == "create":
            _require(before.identity is None and reviewer is not None
                     and reviewer.login.lower() == target.selection.reviewer_login.lower())
        else:
            _require(before.policy is not None and reviewer is None)
            _same(target.selection.prevent_self_review is None or before.policy.prevent_self_review is not None,
                  "policy-unsupported")
        result = cls(target, before, reviewer, _utc(row["observedAt"]))
        _require(EnvironmentPolicy.parse(row["after"]) == result.after)
        _same(before.policy != result.after, "no-change")
        _require(row == result.value())
        _environment_bounded(result.value(), ENVIRONMENT_PREPARED_BYTES)
        return result

    @property
    def after(self) -> EnvironmentPolicy:
        selected = self.target.selection
        if selected.mode == "create":
            _require(self.reviewer is not None)
            policy = EnvironmentPolicy(selected.wait_timer, True, (("User", self.reviewer.identity),),
                                       selected.branches == "protected")
        else:
            _require(self.before.policy is not None)
            old = self.before.policy
            policy = EnvironmentPolicy(selected.wait_timer, old.prevent_self_review if selected.prevent_self_review is None
                                       else selected.prevent_self_review, old.reviewers, old.protected_branches)
        return EnvironmentPolicy.parse(policy.value())

    def value(self) -> dict[str, Any]:
        return {"target": self.target.value(), "before": self.before.value(), "after": self.after.value(),
                "reviewer": None if self.reviewer is None else self.reviewer.value(), "observedAt": self.observed_at,
                "confirmation": "Send these exact GitHub create-or-update environment fields? A concurrent edit can be "
                "overwritten, a deleted environment recreated, or a newly created environment updated. There is no "
                "atomic compare-and-set. Protected-branches mode allows all branches if none are protected. "
                "Administrator bypass is not observed or configured here; review it on GitHub. This does not "
                "provision secrets or prove complete environment protection. Cancel does not undo a sent request."}

    def check_fresh(self, facts: EnvironmentFacts, reviewer: EnvironmentReviewer | None) -> None:
        checked = EnvironmentPrepared.parse(self.value())
        actual = EnvironmentFacts.parse(facts.value())
        _same(actual == checked.before, "policy-changed")
        actual_reviewer = None if reviewer is None else EnvironmentReviewer.parse(reviewer.value())
        _same(actual_reviewer == checked.reviewer, "policy-changed")
        # Caller must also admit the scheduled zero-custom response for existing mode.

    def check_readback(self, acknowledged: EnvironmentFacts, observed: EnvironmentFacts) -> None:
        checked = EnvironmentPrepared.parse(self.value())
        ack, post = EnvironmentFacts.parse(acknowledged.value()), EnvironmentFacts.parse(observed.value())
        _same(ack.name == post.name == checked.before.name and ack.identity is not None
              and ack.identity == post.identity and ack.policy == post.policy == checked.after, "policy-changed")
        _same(checked.before.identity is None or post.identity == checked.before.identity, "target-changed")
        # This DATA correlation is not finality or creation causality. Scheduled custom
        # rules/repository POST and original transport/native settlement remain required.


@dataclass(frozen=True, slots=True)
class EnvironmentAction:
    kind: str
    target: EnvironmentTarget
    prepared: EnvironmentPrepared | None = None

    @classmethod
    def parse(cls, value: object) -> EnvironmentAction:
        row = _object(value, {"kind", "target", "prepared"})
        _require(type(row["kind"]) is str and row["kind"] in {"prepare", "apply"})
        target = EnvironmentTarget.parse(row["target"])
        prepared = None if row["prepared"] is None else EnvironmentPrepared.parse(row["prepared"])
        _require((row["kind"] == "prepare") == (prepared is None) and (prepared is None or prepared.target == target))
        return cls(row["kind"], target, prepared)

    def value(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target.value(),
                "prepared": None if self.prepared is None else self.prepared.value()}


class EnvironmentSchedule:
    """Finite DATA cursor; the live Setup reader claims each fixed exchange."""
    def __init__(self, action: EnvironmentAction) -> None:
        self.action = EnvironmentAction.parse(action.value())
        self.steps: list[str] = []

    def claim(self, step: str, reference: str | None = None) -> HttpRequest:
        selected = self.action.target.selection
        pre = ("environment-before", "custom-before") if selected.mode == "configure" else ("absence-before", "reviewer-before")
        sequence = ("account", "repository-before") + pre
        if self.action.kind == "apply":
            sequence += ("write", "environment-after", "custom-after")
        sequence += ("repository-after",)
        _require(reference is None and len(self.steps) < len(sequence) <= ENVIRONMENT_MAX_REQUESTS
                 and step == sequence[len(self.steps)])
        self.steps.append(step)  # Failed attempts are never retried or rolled back.
        if step == "account":
            return HttpRequest("GET", "/user", None)
        root = "/repos/" + self.action.target.repository
        if step in {"repository-before", "repository-after"}:
            return HttpRequest("GET", root, None)
        if step == "absence-before":
            return HttpRequest("GET", root + "/environments?per_page=100&page=1", None)
        if step == "reviewer-before":
            _require(selected.reviewer_login is not None)
            return HttpRequest("GET", root + "/collaborators/" + selected.reviewer_login + "/permission", None)
        path = root + "/environments/" + selected.name
        if step in {"custom-before", "custom-after"}:
            path += "/deployment_protection_rules"
        if step == "write":
            _require(self.action.prepared is not None)
            raw = _canonical(self.action.prepared.after.put_value())
            _require(len(raw) <= MAX_BODY_BYTES)
            return HttpRequest("PUT", path, raw)
        return HttpRequest("GET", path, None)


def _identity(body: dict[str, Any], target: Target) -> None:
    _require(type(body.get("id")) is int)
    selected = _repository(body)
    _same(selected["id"] == target.repository_id
          and selected["fullName"].lower() == target.repository.lower(), "target-changed")
    _same(not selected["archived"], "repository-archived")


def execute(action: Action, reader: Reader, *, observed_at: str) -> dict[str, Any]:
    """One original's finite sequence, not a claim of native settlement.

    The existing owned reader must clip all exchanges and closes to the SAME
    original endpoint and enforce existing response/aggregate/header bounds.
    Only the private Setup factory below may construct that owned reader.
    """
    action = Action.parse(action.value())
    _utc(observed_at)
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
                              "effect": "not-started", "writeClaimed": False, "writeAcknowledged": False,
                              "prepared": None, "observed": None, "control": _control()}

    def take(step: str) -> dict[str, Any] | None:
        if step == "write":
            # This means loss of no-send proof, not proof bytes reached GitHub.
            result["writeClaimed"], result["effect"] = True, "unknown"
        reply = reader.read(step)
        _require(type(reply) is ReadResult)
        control = dict(_check_control(reply.control))
        result["control"] = control
        _check_values(reply.observation, nodes=20_000, depth=24)
        row = _object(reply.observation, {"status", "body", "failure"})
        if control["reason"] != "none":
            raise Refused(control["reason"])
        if step == "write" and type(row["status"]) is int and row["status"] == 204:
            _require(row["body"] is None and row["failure"] == "none")
            result["writeAcknowledged"] = True
            return None
        body, reason = _read(row)
        if step == "write":
            if row["status"] == 409 and action.target.selection.kind == "workflow_token_policy":
                raise Refused("organization-restricted")
            raise Refused(reason if reason != "none" else "response-invalid")
        if body is None:
            raise Refused(reason)
        return body

    try:
        account = take("account")
        _require(account is not None and type(account.get("id")) is int)
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        _identity(take("repository-before"), action.target)  # type: ignore[arg-type]
        before = Policy.parse(action.target.selection.kind, take("resource-before"), upstream=True)
        if action.kind == "prepare":
            _identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            result["observed"] = before.value()
            if before == before.changed(action.target.selection):
                result["reason"] = "no-change"
            else:
                result["prepared"] = Prepared(action.target, before, observed_at).value()
        else:
            _require(action.prepared is not None)
            _same(before == action.prepared.before, "policy-changed")
            take("write")
            after = Policy.parse(action.target.selection.kind, take("resource-after"), upstream=True)
            _same(after == action.prepared.after, "policy-changed")
            _identity(take("repository-after"), action.target)  # type: ignore[arg-type]
            result["observed"], result["effect"] = after.value(), "readback-confirmed"
    except Refused as error:
        result["reason"] = error.reason
    except ReadFailure as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    return result


def environment_put_policy(value: object) -> EnvironmentPolicy:
    """Decode only the supported four-field body; never forward arbitrary JSON."""
    row = _object(value, {"wait_timer", "prevent_self_review", "reviewers", "deployment_branch_policy"})
    _require(type(row["prevent_self_review"]) is bool)
    reviewers = row["reviewers"]
    if reviewers is None:
        _require(row["prevent_self_review"] is False)
        required = None
    else:
        _require(type(reviewers) is list and 1 <= len(reviewers) <= 6)
        identities = []
        for reviewer in reviewers:
            reviewer = _object(reviewer, {"type", "id"})
            identities.append({"type": reviewer["type"], "id": _environment_id(reviewer["id"], upstream=True)})
        required = {"preventSelfReview": row["prevent_self_review"], "reviewers": identities}
    branch = row["deployment_branch_policy"]
    if branch is not None:
        branch = _object(branch, {"protected_branches", "custom_branch_policies"})
        _require(branch["protected_branches"] is True and branch["custom_branch_policies"] is False)
    policy = EnvironmentPolicy.parse({"waitTimerMinutes": row["wait_timer"], "requiredReviewers": required,
                                      "protectedBranches": branch is not None})
    _require(policy.put_value() == row)
    return policy


def execute_environment(action: EnvironmentAction, reader: Reader, *, observed_at: str) -> dict[str, Any]:
    """Same-original fixed5/8 effects, not consent or proof of native settlement."""
    action = EnvironmentAction.parse(action.value())
    _utc(observed_at)
    result: dict[str, Any] = {"schemaVersion": 1, "action": action.kind, "reason": "none",
        "effect": "not-started", "writeClaimed": False, "writeAcknowledged": False,
        "prepared": None, "observed": None, "control": _control()}

    def take(step: str) -> dict[str, Any]:
        if step == "write":
            result["writeClaimed"], result["effect"] = True, "unknown"
        reply = reader.read(step)
        _require(type(reply) is ReadResult)
        control = dict(_check_control(reply.control))
        result["control"] = control
        _check_values(reply.observation, nodes=20_000, depth=24)
        row = _object(reply.observation, {"status", "body", "failure"})
        if control["reason"] != "none":
            raise Refused(control["reason"])
        body, reason = _read(row)
        if body is None:
            if step == "write" and row["status"] == 422:
                raise Refused("policy-unsupported")
            raise Refused(reason)
        if step == "write":
            result["writeAcknowledged"] = True  # Actual200, not causality/finality.
        return body

    try:
        account = take("account")
        _require(type(account.get("id")) is int)
        _same(_account(account)["id"] == action.target.account_id, "target-changed")
        account = None  # Do not retain the full remote profile over later reads.
        _identity(take("repository-before"), action.target)
        name = action.target.selection.name
        reviewer = None
        if action.target.selection.mode == "configure":
            before = EnvironmentFacts.upstream(take("environment-before"), name)
            environment_custom_rules_empty(take("custom-before"))
        else:
            before = EnvironmentFacts.absent(take("absence-before"), name)
            reviewer = EnvironmentReviewer.upstream(take("reviewer-before"), action.target.selection.reviewer_login)
        if action.kind == "prepare":
            candidate = EnvironmentPrepared(action.target, before, reviewer, observed_at)
            # Validation precedes the final repository observation and any consent.
            no_change = False
            try:
                prepared = EnvironmentPrepared.parse(candidate.value())
            except Refused as error:
                if error.reason != "no-change":
                    raise
                no_change = True
            _identity(take("repository-after"), action.target)
            result["observed"] = before.value()
            if no_change:
                result["reason"] = "no-change"
            else:
                result["prepared"] = prepared.value()
        else:
            _require(action.prepared is not None)
            action.prepared.check_fresh(before, reviewer)
            acknowledged = EnvironmentFacts.upstream(take("write"), name)
            after = EnvironmentFacts.upstream(take("environment-after"), name)
            environment_custom_rules_empty(take("custom-after"))
            action.prepared.check_readback(acknowledged, after)
            _identity(take("repository-after"), action.target)
            result["observed"], result["effect"] = after.value(), "readback-confirmed"
    except (Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        result["reason"] = "response-invalid"
    return result


def _parse_action(value: object) -> Action | EnvironmentAction:
    _require(type(value) is dict and type(value.get("target")) is dict
             and type(value["target"].get("selection")) is dict)
    if value["target"]["selection"].get("kind") == "environment_protection":
        return EnvironmentAction.parse(value)
    return Action.parse(value)  # Still closed to exactly KINDS, not a fallback grant.


def _make_live_reader(action: Action | EnvironmentAction, token: str, *, started: float, runtime_dir: str) -> Reader:
    """Private Setup-only factory, called after the genuine native final GO."""
    from ._github_connection_transport import _ExchangeProfile, _ResponseRole, _make_live_exchange

    _require(type(action) in {Action, EnvironmentAction})
    environment = type(action) is EnvironmentAction
    schedule = EnvironmentSchedule(action) if environment else Schedule(action)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir,
                                   api_version=API_VERSION, _profile=_ExchangeProfile.SETUP)

    class FixedReader:
        def read(self, step: str, reference: str | None = None) -> ReadResult:
            request = schedule.claim(step, reference)
            role = _ResponseRole.STANDARD
            if environment:
                if step in {"environment-before", "environment-after"}:
                    role = _ResponseRole.SETUP_ENVIRONMENT_READ
                elif step == "absence-before":
                    role = _ResponseRole.SETUP_ENVIRONMENT_LIST
                elif step in {"custom-before", "custom-after"}:
                    role = _ResponseRole.SETUP_ENVIRONMENT_CUSTOM_READ
                elif step == "reviewer-before":
                    role = _ResponseRole.SETUP_ENVIRONMENT_REVIEWER_READ
                elif step == "write":
                    role = _ResponseRole.SETUP_ENVIRONMENT_WRITE
            elif step == "write":
                role = (_ResponseRole.SETUP_ACTIONS_WRITE if schedule.action.target.selection.kind == "actions_enabled"
                        else _ResponseRole.SETUP_WORKFLOW_WRITE)
            return exchange(request.method, request.path, request.body, _role=role)

    return FixedReader()


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    action: Action | EnvironmentAction
    digest: str


def _frame(raw: bytes, maximum: int, *, nodes: int, depth: int) -> Any:
    _require(type(raw) is bytes and 1 < len(raw) <= maximum and raw.endswith(b"\n")
             and raw.count(b"\n") == 1 and b"\r" not in raw)
    return _decode_json(raw[:-1], limit=maximum - 1, nodes=nodes, depth=depth, exact=True)


def parse_initial(raw: bytes) -> Initial:
    row = _object(_frame(raw, MAX_INITIAL_BYTES, nodes=256, depth=8), {"protocol", "id", "action"})
    _require(row["protocol"] == PROTOCOL)
    return Initial(_match(row["id"], _ID), _parse_action(row["action"]), hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    raw = _canonical({"protocol": PROTOCOL, "id": request.id,
                      "ready": {"requestSha256": request.digest}}) + b"\n"
    _require(len(raw) <= MAX_READY_BYTES)
    return raw


def parse_go(raw: bytes, request: Initial) -> str:
    # Actual native context/consent checks precede this private token handoff.
    row = _object(_frame(raw, MAX_GO_BYTES, nodes=32, depth=4), {"protocol", "id", "go"})
    _require(row["protocol"] == PROTOCOL and row["id"] == request.id)
    go = _object(row["go"], {"requestSha256", "token"})
    _require(go["requestSha256"] == request.digest)
    token = go["token"]
    _require(type(token) is str and 1 <= len(token) <= 4096
             and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def _encode_environment_result(request: Initial, value: object) -> bytes:
    action = EnvironmentAction.parse(request.action.value())
    row = _object(value, {"schemaVersion", "action", "reason", "effect", "writeClaimed",
                          "writeAcknowledged", "prepared", "observed", "control"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and row["action"] == action.kind and type(row["reason"]) is str and row["reason"] in REASONS
             and type(row["writeClaimed"]) is bool and type(row["writeAcknowledged"]) is bool)
    _check_control(row["control"])
    observed = None if row["observed"] is None else EnvironmentFacts.parse(row["observed"])
    _require(observed is None or observed.name == action.target.selection.name and row["observed"] == observed.value())
    _require(not row["writeAcknowledged"] or row["writeClaimed"])
    if row["control"]["reason"] != "none":
        _require(row["reason"] == row["control"]["reason"])
    if action.kind == "prepare":
        _require(row["effect"] == "not-started" and not row["writeClaimed"] and not row["writeAcknowledged"])
        _require((row["reason"] == "none") == (row["prepared"] is not None)
                 and (row["reason"] in {"none", "no-change"}) == (observed is not None))
        if row["prepared"] is not None:
            prepared = EnvironmentPrepared.parse(row["prepared"])
            _require(prepared.target == action.target and observed == prepared.before)
        if row["reason"] == "no-change":
            _require(action.target.selection.mode == "configure" and observed is not None and observed.policy is not None)
            selected = action.target.selection
            _require(observed.policy.wait_timer == selected.wait_timer
                     and (selected.prevent_self_review is None
                          or observed.policy.prevent_self_review is selected.prevent_self_review))
    else:
        _require(row["prepared"] is None and row["reason"] != "no-change")
        if row["effect"] == "readback-confirmed":
            _require(row["reason"] == "none" and row["writeAcknowledged"] and action.prepared is not None
                     and observed is not None and observed.identity is not None and observed.policy == action.prepared.after)
            _require(action.prepared.before.identity is None or observed.identity == action.prepared.before.identity)
        else:
            _require(row["effect"] == ("unknown" if row["writeClaimed"] else "not-started")
                     and row["reason"] != "none" and observed is None)
    envelope = {"protocol": PROTOCOL, "id": request.id, "result": row}
    _check_values(envelope, nodes=1024, depth=12)
    raw = _canonical(envelope) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw


def encode_result(request: Initial, value: object) -> bytes:
    if type(request.action) is EnvironmentAction:
        return _encode_environment_result(request, value)
    row = _object(value, {"schemaVersion", "action", "reason", "effect", "writeClaimed",
                          "writeAcknowledged", "prepared", "observed", "control"})
    _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
             and row["action"] == request.action.kind and type(row["reason"]) is str
             and row["reason"] in REASONS and type(row["writeClaimed"]) is bool
             and type(row["writeAcknowledged"]) is bool)
    _check_control(row["control"])
    if row["observed"] is not None:
        Policy.parse(request.action.target.selection.kind, row["observed"])
    _require(not row["writeAcknowledged"] or row["writeClaimed"])
    if row["control"]["reason"] != "none":
        _require(row["reason"] == row["control"]["reason"])
    if request.action.kind == "prepare":
        _require(row["effect"] == "not-started" and not row["writeClaimed"] and not row["writeAcknowledged"])
        _require((row["reason"] == "none") == (row["prepared"] is not None))
        _require((row["reason"] in {"none", "no-change"}) == (row["observed"] is not None))
        if row["prepared"] is not None:
            prepared = Prepared.parse(row["prepared"])
            _require(prepared.target == request.action.target and row["observed"] == prepared.before.value())
        if row["reason"] == "no-change":
            policy = Policy.parse(request.action.target.selection.kind, row["observed"])
            _require(policy == policy.changed(request.action.target.selection))
    else:
        _require(row["prepared"] is None and row["reason"] != "no-change")
        if row["effect"] == "readback-confirmed":
            _require(row["reason"] == "none" and row["writeAcknowledged"]
                     and request.action.prepared is not None
                     and row["observed"] == request.action.prepared.after.value())
        else:
            _require(row["effect"] == ("unknown" if row["writeClaimed"] else "not-started")
                     and row["reason"] != "none" and row["observed"] is None)
    envelope = {"protocol": PROTOCOL, "id": request.id, "result": row}
    _check_values(envelope, nodes=1024, depth=12)
    raw = _canonical(envelope) + b"\n"
    _require(len(raw) <= MAX_RESULT_BYTES)
    return raw
