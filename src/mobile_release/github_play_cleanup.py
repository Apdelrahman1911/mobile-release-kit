"""One explicit hosted known-Play-edit cleanup dispatch, not a release engine.

The current configured branch B is the dispatch target. The selected hosted
candidate retains its original source A. These are deliberately different:
GitHub does not atomically pin a workflow_dispatch to the reviewed commit.
Only the protected workflow can decrypt, claim and delete the known edit.
Neither a 204 nor a later journal read establishes that cleanup succeeded.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from . import android_store_versions as android
from . import github_activity as activity
from . import github_release as release
from . import ios_store_versions as ios
from . import version_allocation as allocation
from . import version_enrollment as enrollment
from . import version_hosted as hosted
from . import version_policy as policy
from . import version_text
from ._desktop_github_engine import _check_control
from ._github_connection_transport import ReadFailure, ReadResult, _control
from .api._github_connection import _id
from .api._github_setup import _resource
from .api._json import bounded_json_text
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES, ReleaseVersion, parse_config_text
from .errors import ConfigurationError, ValidationError
from .github_preflight import HttpRequest, TOOLING_REPOSITORY, branch, _quote
from .github_repository_create import coordinate, hex_text, login, obj, require
from .workflow_payloads import render_workflow_caller

PROTOCOL = "mrk-github-play-cleanup/1"
WORKFLOW_PATH = ".github/workflows/mobile-candidate.yml"
WORKFLOW_NAME = "Mobile internal candidate"
MAX_REQUESTS = 19
MAX_DISPATCH_REQUESTS = 13
MAX_RECORDS = 32
MAX_RECORD_BYTES = 8192
MAX_PREPARED_BYTES = 4096
MAX_RESULT_BYTES = 192 * 1024
BODY_LIMIT = 256 * 1024
CONFIG_BODY_LIMIT = 768 * 1024
TOTAL_BODY_LIMIT = 2 * 1024 * 1024
LOCAL_CONFIG_LIMIT = 64 * 1024  # Unchanged held publication-config loan.
MAX_CALLER_BYTES = 16 * 1024
REASONS = activity.REASONS | frozenset({"source-changed", "source-tree-unavailable", "source-unsupported",
    "configuration-invalid", "caller-mismatch", "workflow-unavailable", "permission-unconfirmed",
    "counter-unavailable", "protection-unsupported", "authority-changed", "authority-rewound",
    "ledger-invalid", "journal-invalid", "cleanup-unavailable", "cleanup-claimed", "review-changed",
    "journal-unavailable", "journal-full", "previous-attempt", "unresolved", "tag-exists"})
canonical = policy.canonical


class Refused(ValueError):
    def __init__(self, reason: str):
        require(reason in REASONS and reason != "none")
        self.reason = reason
        super().__init__("The fixed hosted Play cleanup request is unavailable")


def need(condition: bool, reason: str = "response-invalid") -> None:
    if not condition:
        raise Refused(reason)


@dataclass(frozen=True, slots=True)
class Target:
    scope: activity.Target
    tooling_sha: str
    marker: str
    version_tag: object | None = None
    pending_purpose: str | None = None

    @classmethod
    def parse(cls, value: object) -> Target:
        from .github_version_tag import Selection
        tag = Selection.parse(value["versionTag"]) if type(value) is dict and "versionTag" in value else None
        pending = value.get("purpose") if type(value) is dict else None
        require(pending is None or pending == "version-tag" and tag is None)
        row = obj(value, {"scope", "toolingRepository", "toolingSha", "marker"} | ({"versionTag"} if tag is not None else set()) | ({"purpose"} if pending is not None else set()))
        require(row["toolingRepository"] == TOOLING_REPOSITORY)
        return cls(activity.Target.parse(row["scope"]), hex_text(row["toolingSha"], 40),
                   hex_text(row["marker"], 32), tag, pending)

    def value(self) -> dict:
        return {"scope": self.scope.value(), "toolingRepository": TOOLING_REPOSITORY,
                "toolingSha": self.tooling_sha, "marker": self.marker,
                **({"versionTag": self.version_tag.value()} if self.version_tag is not None else {}),
                **({"purpose": self.pending_purpose} if self.pending_purpose is not None else {})}

    @property
    def purpose(self):
        return "version-tag" if self.version_tag is not None or self.pending_purpose is not None else "play-cleanup"

    @property
    def repository(self) -> str:
        return self.scope.repository

    def same_scope(self, other: Target) -> bool:
        return (self.scope.project_binding == other.scope.project_binding
            and self.scope.account_id == other.scope.account_id
            and self.scope.repository_id == other.scope.repository_id
            and self.repository.lower() == other.repository.lower()
            and self.purpose == other.purpose)


def canonical_caller(target: Target) -> bytes:
    _, resource = _resource()
    return render_workflow_caller(resource["workflows"]["candidate"].encode("utf-8"),
                                  TOOLING_REPOSITORY, target.tooling_sha)


@dataclass(frozen=True, slots=True)
class Source:
    """Comparison DATA from the SAME still-held publication configuration."""
    branch: str
    saved_sha256: str
    platform: str
    identity_revision: str

    @classmethod
    def from_saved(cls, raw: bytes) -> Source:
        need(type(raw) is bytes and 0 < len(raw) <= LOCAL_CONFIG_LIMIT, "configuration-invalid")
        try:
            # Use the established sensitive/path checks as well as the real
            # config validator. No reader or path is constructed here.
            version_text.public_version_selection(raw.decode("utf-8"))
            config = parse_config_text(raw.decode("utf-8"))
            enabled = tuple(k for k in ("android", "ios") if config[k].get("enabled") is True)
            need(enabled in (("android",), ("android", "ios")), "cleanup-unavailable")
            platform = "android" if len(enabled) == 1 else "both"
            identity = identity_data(config, platform)
            return cls(branch(config["source"]["candidateBranch"]), hashlib.sha256(raw).hexdigest(),
                       platform, policy.digest(identity))
        except Refused:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, ConfigurationError, ValidationError):
            raise Refused("configuration-invalid") from None


def identity_data(config: dict, platform: str) -> dict:
    need(platform in ("android", "both"), "cleanup-unavailable")
    enabled = tuple(k for k in ("android", "ios") if config[k].get("enabled") is True)
    need(enabled == (("android",) if platform == "android" else ("android", "ios")), "source-changed")
    package = config["android"].get("applicationId")
    android.package_identity(package)
    identity = {"platform": platform, "packageName": package}
    if platform == "both":
        app, bundle = config["ios"].get("appStoreAppId"), config["ios"].get("bundleId")
        ios.app_identity(app, bundle)
        identity.update(appId=app, bundleId=bundle)
    return identity


def confirmation(prepared: Prepared) -> str:
    if prepared.target.version_tag is not None:
        from .github_version_tag import confirmation as tag_confirmation
        return tag_confirmation(prepared)
    return ("Dispatch one hosted Play edit cleanup for candidate " + prepared.candidate["candidateId"]
        + " in " + prepared.target.repository + "? This is nonpublishing but mutating: the protected workflow "
        "may decrypt its retained edit ID, consume its one-use cleanup claim and delete that Play edit. "
        "It does not reserve a version or build, sign or release. The configured branch " + prepared.branch
        + " is mutable; authorized writers can replace its workflow after review. Its actual dispatch head may "
        "differ from the reviewed head; the workflow must separately validate the original candidate source. "
        "A dispatch acknowledgement does not prove cleanup or identify a run. Stopping cannot undo a sent request.")


def candidate_data(value: object) -> dict:
    row = obj(value, {"candidateId", "attemptId", "requestSha256", "localProjectId", "platform",
                      "source", "identityRevision", "baseVersion", "capsuleSha256"})
    allocation._uuid(row["candidateId"]); allocation._uuid(row["attemptId"])
    for key in ("requestSha256", "identityRevision", "capsuleSha256"):
        hex_text(row[key], 64)
    local = hex_text(row["localProjectId"], 32)
    require(local != "0" * 32 and row["platform"] in ("android", "both"))
    source = policy.SourceBinding.parse(row["source"])
    require(source.ref.startswith("refs/heads/"))
    policy.parse_version(row["baseVersion"], ("android",) if row["platform"] == "android" else ("android", "ios"))
    return dict(row)


@dataclass(frozen=True, slots=True)
class Prepared:
    target: Target
    account_login: str
    branch: str
    source_sha: str
    source_tree: str
    saved_config_sha256: str
    workflow_id: str
    caller_sha256: str
    authority: allocation.AuthorityRegistration
    checkpoint: allocation.Checkpoint
    ledger_blob: str
    journal_blob: str | None
    journal_sha256: str | None
    journal_revision: int | None
    candidate: dict

    def value(self) -> dict:
        return {"target": self.target.value(), "accountLogin": self.account_login,
            "branch": self.branch, "sourceSha": self.source_sha, "sourceTree": self.source_tree,
            "savedConfigSha256": self.saved_config_sha256, "workflowId": self.workflow_id,
            "callerSha256": self.caller_sha256, "authority": self.authority.value(),
            "checkpoint": self.checkpoint.value(), "ledgerBlob": self.ledger_blob,
             **({"journalBlob": self.journal_blob, "journalSha256": self.journal_sha256,
                "journalRevision": self.journal_revision} if self.target.version_tag is None else {}), "candidate": dict(self.candidate),
            "confirmation": confirmation(self)}

    @classmethod
    def parse(cls, value: object) -> Prepared:
        if type(value) is dict and type(value.get("target")) is dict and "versionTag" in value["target"]:
            from .github_version_tag import parse_prepared
            return parse_prepared(value)
        row = obj(value, {"target", "accountLogin", "branch", "sourceSha", "sourceTree", "savedConfigSha256",
            "workflowId", "callerSha256", "authority", "checkpoint", "ledgerBlob", "journalBlob",
            "journalSha256", "journalRevision", "candidate", "confirmation"})
        target = Target.parse(row["target"])
        require(target.pending_purpose is None)
        authority = allocation.AuthorityRegistration.parse(row["authority"])
        checkpoint = allocation.Checkpoint.parse(row["checkpoint"])
        candidate = candidate_data(row["candidate"])
        require(authority.protected_branch and authority.repository_id == target.scope.repository_id
            and authority.repository.lower() == target.repository.lower()
            and candidate["source"]["ref"] == "refs/heads/" + branch(row["branch"]))
        for key in ("sourceSha", "sourceTree", "ledgerBlob", "journalBlob"):
            hex_text(row[key], 40)
        for key in ("savedConfigSha256", "callerSha256", "journalSha256"):
            hex_text(row[key], 64)
        policy._integer(row["journalRevision"], (1 << 64) - 1, 1)
        result = cls(target, login(row["accountLogin"]), row["branch"], row["sourceSha"], row["sourceTree"],
            row["savedConfigSha256"], _id(row["workflowId"]), row["callerSha256"], authority, checkpoint,
            row["ledgerBlob"], row["journalBlob"], row["journalSha256"], row["journalRevision"], candidate)
        require(row == result.value() and len(canonical(row)) <= MAX_PREPARED_BYTES
            and hashlib.sha256(canonical_caller(target)).hexdigest() == result.caller_sha256)
        return result


def digest(prepared: Prepared) -> str:
    return policy.digest(Prepared.parse(prepared.value()).value())


def once_key(prepared: Prepared) -> tuple[str, ...]:
    """No account name, local-project alias, branch or marker can evade this."""
    Prepared.parse(prepared.value())
    if prepared.target.version_tag is not None:
        # Stable exclusion; F/row/T are the immutable BODY, never another key.
        return ("version-tag", prepared.target.scope.repository_id, prepared.authority.project_id,
            prepared.authority.ledger_id, prepared.authority.genesis_sha256, prepared.candidate["candidateId"])
    return (prepared.target.scope.repository_id, prepared.authority.project_id,
        prepared.authority.ledger_id, prepared.authority.genesis_sha256,
        prepared.candidate["candidateId"], prepared.candidate["attemptId"])


def dispatch_body(prepared: Prepared) -> bytes:
    if prepared.target.version_tag is not None:
        from .github_version_tag import dispatch_body as tag_body
        raw = tag_body(prepared)
        require(len(raw) <= 1024)
        return raw
    c = prepared.candidate
    raw = canonical({"ref": prepared.branch, "inputs": {"operation": "recover-play-edit",
        "platform": c["platform"], "confirmation": "recover-play-edit:" + c["candidateId"] + ":" + c["attemptId"]}})
    require(len(raw) <= 1024)
    return raw


class Exchange(Protocol):
    control: dict
    def __call__(self, request: HttpRequest) -> ReadResult: ...


class Journal(Protocol):
    def create_intent(self, value: dict) -> None: ...
    def claim(self) -> None: ...
    def record_accepted(self) -> None: ...


class Operation:
    def __init__(self, target: Target, source: Source | None, exchange: Exchange, *, dispatch: bool = False):
        self.target = Target.parse(target.value())
        require(source is None or type(source) is Source)
        self.source, self.exchange = source, exchange
        self.base = "/repos/" + self.target.repository
        self.steps: set[str] = set()
        self.maximum = MAX_DISPATCH_REQUESTS if dispatch else MAX_REQUESTS
        self.bytes = 0
        self.control = _control()

    def guard_document(self, raw: bytes) -> None:
        # SAME prospective guard as the original saved-config reader. Embedded
        # Contents documents need it too, before the established semantic parsers.
        from .github_setup_secret_inputs import _json_prelude_checked, SecretConfigurationError
        check = getattr(self.exchange, "decode_checkpoint", lambda: None)
        try:
            _json_prelude_checked(raw, check)
        except SecretConfigurationError as error:
            raise Refused("response-limit" if error.reason == "resources-unavailable" else "response-invalid") from None

    def take(self, step: str, suffix: str, *, body: bytes | None = None, config: bool = False, missing: bool = False):
        if missing:
            from .version_future_tag import reference
            need(self.target.version_tag is not None and body is None and suffix.startswith("git/ref/tags/"))
            reference("refs/" + suffix.removeprefix("git/ref/"))
        need(step not in self.steps and len(self.steps) < self.maximum, "response-limit")
        self.steps.add(step)  # Original attempt is consumed before the call.
        request = HttpRequest("POST" if body is not None else "GET",
            "/user" if suffix == "/user" else self.base + ("/" + suffix if suffix else ""), body)
        try:
            reply = self.exchange(request)
        except ReadFailure:
            self.control = dict(_check_control(getattr(self.exchange, "control", self.control)))
            raise
        need(type(reply) is ReadResult)
        self.control = dict(_check_control(reply.control))
        row = obj(reply.observation, {"status", "body", "failure"})
        if self.control["reason"] != "none":
            raise Refused(self.control["reason"] if self.control["reason"] in REASONS else "response-invalid")
        if row["failure"] != "none":
            raise Refused(row["failure"] if row["failure"] in REASONS else "response-invalid")
        need(type(row["status"]) is int)
        if missing and row["status"] == 404:
            need(row["body"] is None)
            return None
        if row["status"] != (204 if body is not None else 200):
            raise Refused({401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible",
                409: "review-changed", 422: "cleanup-unavailable", 429: "rate-limited"}.get(row["status"],
                    "network-unavailable" if row["status"] >= 500 else "response-invalid"))
        if body is not None:
            need(row["body"] is None)  # No run-ID assumption or status-based adoption.
            return None
        need(type(row["body"]) is dict)
        limit = CONFIG_BODY_LIMIT if config else BODY_LIMIT
        bounded_json_text(row["body"], max_bytes=limit, max_nodes=20_000, max_depth=24)
        size = len(canonical(row["body"])); self.bytes += size
        need(size <= limit and self.bytes <= TOTAL_BODY_LIMIT, "response-limit")
        return row["body"]

    def repository(self, step: str) -> None:
        value = self.take(step, "")
        need(activity.upstream_id(value.get("id")) == self.target.scope.repository_id
            and coordinate(value.get("full_name")).lower() == self.target.repository.lower()
            and value.get("archived") is False and value.get("disabled") is False, "target-changed")
        permissions = value.get("permissions")
        need(type(permissions) is dict and permissions.get("push") is True, "permission-unconfirmed")

    def identity(self) -> str:
        value = self.take("account", "/user")
        need(activity.upstream_id(value.get("id")) == self.target.scope.account_id
            and value.get("type") == "User", "target-changed")
        name = login(value.get("login"))
        self.repository("repository-before")
        return name

    def branch(self, step: str, name: str) -> tuple[str, str]:
        value = self.take(step, "branches/" + _quote(branch(name)))
        need(value.get("name") == name and type(value.get("commit")) is dict, "source-changed")
        commit = value["commit"]
        need(type(commit.get("commit")) is dict and type(commit["commit"].get("tree")) is dict)
        sha = hex_text(commit.get("sha"), 40)
        tree = commit["commit"]["tree"]
        tree_sha = hex_text(tree.get("sha"), 40)
        need(tree.get("url") == "https://api.github.com" + self.base + "/git/trees/" + tree_sha, "source-changed")
        return sha, tree_sha

    def workflow(self) -> str:
        value = self.take("workflow", "actions/workflows/mobile-candidate.yml")
        need(value.get("path") == WORKFLOW_PATH and value.get("name") == WORKFLOW_NAME
            and value.get("state") == "active", "workflow-unavailable")
        return activity.upstream_id(value.get("id"))

    def protection(self, step: str) -> None:
        enrollment._protection(self.take(step, "branches/" + allocation.LEDGER_BRANCH + "/protection"))

    def ref(self, step: str) -> str:
        return allocation._ref_commit(self.take(step, "git/ref/heads/" + allocation.LEDGER_BRANCH))

    def snapshot(self, current: str) -> allocation.LedgerSnapshot:
        target = enrollment.Target(self.target.scope.project_binding, self.target.repository,
                                   self.target.scope.account_id, self.target.scope.repository_id)
        value = self.take("ledger", "contents/" + allocation.LEDGER_PATH + "?ref=" + current)
        self.guard_document(release._contents(value, allocation.LEDGER_PATH, allocation.MAX_LEDGER_BYTES, "ledger-invalid"))
        return enrollment._snapshot(value, current, target)

    def envelope(self, current: str) -> tuple[hosted.Envelope, str, str]:
        value = self.take("journal", "contents/" + hosted.JOURNAL_PATH + "?ref=" + current)
        raw = hosted._journal_content(value)
        self.guard_document(raw)
        return hosted.Envelope.parse(raw), value["sha"], hashlib.sha256(raw).hexdigest()

    @staticmethod
    def selected(snapshot: allocation.LedgerSnapshot, original: hosted.Envelope,
                 target: Target, *, claim_free: bool = True):
        genesis = snapshot.ledger.genesis
        authority = allocation.AuthorityRegistration(genesis.project_id, target.repository,
            target.scope.repository_id, genesis.ledger_id, genesis.sha256, True)
        need(original.schema_version == 3 and len(original.state.authorities) == 1, "journal-invalid")
        retained = original.state.selected(authority)
        # This is a CURRENT published-counter review, not a forged previous
        # native enrollment. Validate the complete retained ledger prefix.
        snapshot.ledger.admit(authority, retained.checkpoint)
        pending = original.play_query
        need(pending is not None and pending.recovery is not None, "cleanup-unavailable")
        if claim_free:
            need(pending.recovery.claim is None, "cleanup-claimed")
        pending.require_state(original.state)
        rows = [r for r in original.state.candidates if r.request.candidate_id == pending.candidate_id]
        need(len(rows) == 1, "journal-invalid")
        row = rows[0]
        need(row.request.project_id == authority.project_id and row.request.sha256 == pending.request_sha256
            and any(e.local_project_id == row.local_project_id and e.authority_project_id == authority.project_id
                for e in original.state.enrollments), "journal-invalid")
        from .version_hosted_play_recovery import PURPOSE
        capsule = pending.recovery.capsule
        # Public AAD consistency only: this neither decrypts the capsule nor
        # establishes that the protected workflow possesses its key version.
        aad = {"schemaVersion": 1, "purpose": PURPOSE, "keyVersion": capsule.key_version,
            "authority": authority.value(), "localProjectId": row.local_project_id,
            "candidateId": pending.candidate_id, "requestSha256": pending.request_sha256,
            "attemptId": pending.attempt_id, "source": row.request.source.value(),
            "contextSha256": row.request.store_context_revision, "identityRevision": row.request.identity_revision}
        need(policy.digest(aad) == capsule.aad_sha256, "cleanup-unavailable")
        enabled = row.request.enabled_platforms
        need(enabled in (("android",), ("android", "ios")), "cleanup-unavailable")
        projected = {"candidateId": pending.candidate_id, "attemptId": pending.attempt_id,
            "requestSha256": pending.request_sha256, "localProjectId": row.local_project_id,
            "platform": "android" if len(enabled) == 1 else "both", "source": row.request.source.value(),
            "identityRevision": row.request.identity_revision, "baseVersion": policy.version_value(row.request.base_version),
            "capsuleSha256": policy.digest(pending.recovery.capsule.value())}
        return authority, row, candidate_data(projected)

    def original_source(self, row, candidate: dict) -> None:
        request = row.request
        value = self.take("original-commit", "git/commits/" + request.source.commit)
        need(value.get("sha") == request.source.commit and type(value.get("tree")) is dict, "source-changed")
        tree_sha = hex_text(value["tree"].get("sha"), 40)
        need(tree_sha == request.source.tree and value["tree"].get("url")
            == "https://api.github.com" + self.base + "/git/trees/" + tree_sha, "source-changed")
        config_raw = release._contents(self.take("original-config", "contents/" + version_text.CONFIG_PATH
            + "?ref=" + request.source.commit, config=True), version_text.CONFIG_PATH, MAX_CONFIG_BYTES, "config-invalid")
        self.guard_document(config_raw)
        selection = version_text.public_version_selection(config_raw.decode("utf-8"))
        config = parse_config_text(config_raw.decode("utf-8"))
        identity_revision = policy.digest(identity_data(config, candidate["platform"]))
        del config  # The complete validated identity has been copied; no source/IO owner is retired.
        # Existing complete tree/mode validator. Only the exact two selected
        # paths are projected; no caller-supplied path traversal or downloader.
        entries = release._source_tree(self.take("original-tree", "git/trees/" + tree_sha + "?recursive=1"),
            self.target, tree_sha, (version_text.CONFIG_PATH, selection.source))
        raw = release._contents(self.take("original-version", "contents/" + release._quote_path(selection.source)
            + "?ref=" + request.source.commit), selection.source, MAX_VERSION_BYTES, "version-invalid")
        release._match_blob(entries[version_text.CONFIG_PATH], config_raw)
        release._match_blob(entries[selection.source], raw)
        parsed = version_text.original_text(selection, raw)
        actual = policy.SourceBinding(request.source.commit, tree_sha, request.source.ref,
            hashlib.sha256(config_raw).hexdigest(), hashlib.sha256(raw).hexdigest())
        need(actual == request.source and identity_revision == request.identity_revision
            and ReleaseVersion(parsed.values[0], int(parsed.values[1])) == request.base_version, "source-changed")

    def prepare(self) -> Prepared:
        need(self.source is not None, "configuration-invalid")
        source = self.source
        name = self.identity()
        head, tree = self.branch("branch-before", source.branch)
        workflow_id = self.workflow()
        caller = release._contents(self.take("caller", "contents/" + WORKFLOW_PATH + "?ref=" + head),
                                   WORKFLOW_PATH, MAX_CALLER_BYTES, "caller-mismatch")
        need(caller == canonical_caller(self.target), "caller-mismatch")
        entries = release._source_tree(self.take("current-tree", "git/trees/" + tree + "?recursive=1"),
            self.target, tree, (WORKFLOW_PATH,))
        release._match_blob(entries[WORKFLOW_PATH], caller)
        self.protection("protection-before")
        current = self.ref("ref-before")
        snapshot = self.snapshot(current)
        envelope, blob, envelope_sha = self.envelope(current)
        authority, row, candidate = self.selected(snapshot, envelope, self.target)
        need(candidate["source"]["ref"] == "refs/heads/" + source.branch
            and candidate["platform"] == source.platform
            and candidate["identityRevision"] == source.identity_revision, "source-changed")
        checkpoint, ledger_blob, journal_revision = snapshot.checkpoint, snapshot.blob, envelope.revision
        # Complete current-counter/capsule validation finished. Keep only its
        # exact bounded proof DATA; the original operation/source/IO remains held.
        del snapshot, envelope
        self.original_source(row, candidate)
        allocation._ancestry(self.take("source-ancestry", "compare/" + row.request.source.commit + "..." + head
            + "?per_page=1&page=1"), row.request.source.commit, head)
        need(self.branch("branch-after", source.branch) == (head, tree), "source-changed")
        need(self.ref("ref-after") == current, "authority-changed")
        self.protection("protection-after")
        self.repository("repository-after")
        need(len(self.steps) == MAX_REQUESTS)
        return Prepared.parse(Prepared(self.target, name, source.branch, head, tree, source.saved_sha256, workflow_id,
            hashlib.sha256(caller).hexdigest(), authority, checkpoint, ledger_blob, blob,
            envelope_sha, journal_revision, candidate).value())

    def current_for_dispatch(self, prepared: Prepared) -> None:
        source = self.source
        need(source is not None and source.saved_sha256 == prepared.saved_config_sha256
            and source.branch == prepared.branch and source.platform == prepared.candidate["platform"]
            and source.identity_revision == prepared.candidate["identityRevision"], "review-changed")
        need(self.identity() == prepared.account_login, "target-changed")
        need(self.branch("branch-before", source.branch) == (prepared.source_sha, prepared.source_tree), "source-changed")
        need(self.workflow() == prepared.workflow_id, "workflow-unavailable")
        self.protection("protection-before")
        current = self.ref("ref-before")
        need(current == prepared.checkpoint.commit, "review-changed")
        original, blob, sha = self.envelope(current)
        # C addresses immutable ledger/caller objects read by Prepare. Recheck
        # the full original journal, not a display row or candidate UUID alone.
        need(blob == prepared.journal_blob and sha == prepared.journal_sha256
            and original.revision == prepared.journal_revision, "review-changed")
        retained = original.state.selected(prepared.authority)
        pending = original.play_query
        need(pending is not None and pending.recovery is not None and pending.recovery.claim is None, "cleanup-unavailable")
        rows = [r for r in original.state.candidates if r.request.candidate_id == prepared.candidate["candidateId"]]
        need(len(rows) == 1 and rows[0].local_project_id == prepared.candidate["localProjectId"]
            and rows[0].request.sha256 == prepared.candidate["requestSha256"]
            and pending.candidate_id == prepared.candidate["candidateId"]
            and pending.attempt_id == prepared.candidate["attemptId"]
            and pending.request_sha256 == prepared.candidate["requestSha256"]
            and policy.digest(pending.recovery.capsule.value()) == prepared.candidate["capsuleSha256"]
            and retained.authority == prepared.authority, "review-changed")
        need(self.ref("ref-after") == current, "review-changed")
        need(self.branch("branch-after", source.branch) == (prepared.source_sha, prepared.source_tree), "source-changed")
        self.protection("protection-after")
        self.repository("repository-after")


def reason(error: BaseException) -> str:
    if isinstance(error, OSError):
        return "journal-unavailable"
    value = getattr(error, "reason", "response-invalid")
    aliases = {"config-invalid": "configuration-invalid", "version-invalid": "source-changed",
        "protection-unavailable": "counter-unavailable", "counter-missing": "counter-unavailable",
        "journal": "journal-invalid", "size": "response-limit"}
    value = aliases.get(value, value)
    return value if value in REASONS else "response-invalid"


def _operation(target, source, exchange, *, dispatch=False):
    if target.version_tag is not None:
        from .github_version_tag import Operation as TagOperation
        return TagOperation(target, source, exchange, dispatch=dispatch)
    return Operation(target, source, exchange, dispatch=dispatch)


def prepare(target: Target, source: Source, exchange: Exchange) -> tuple[Prepared, dict]:
    require(target.pending_purpose is None)
    op = _operation(target, source, exchange)
    try:
        return op.prepare(), op.control
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError, ConfigurationError, ValidationError, ReadFailure) as error:
        raise Refused(reason(error)) from None


def dispatch(prepared: Prepared, source: Source, exchange: Exchange, journal: Journal) -> dict:
    prepared = Prepared.parse(prepared.value())
    op = _operation(prepared.target, source, exchange, dispatch=True)
    result = {"effect": "not-sent", "reason": "none", "claimed": False, "acknowledged": False,
              "observed": None, "control": _control()}
    try:
        op.current_for_dispatch(prepared)
        journal.create_intent(prepared.value())
        # Both immutable records must be durably read back by the original
        # custodian. A failed/unknown create consumes that marker forever.
        journal.claim()
        result.update(effect="potentially-applied", claimed=True)
        op.take("dispatch", "actions/workflows/" + prepared.workflow_id + "/dispatches", body=dispatch_body(prepared))
        # Save actual receipt facts before later journal/clock/close checks.
        result.update(effect="acknowledged-unconfirmed", acknowledged=True)
        journal.record_accepted()
        need(len(op.steps) <= MAX_DISPATCH_REQUESTS)
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError, OSError, ReadFailure) as error:
        result["reason"] = reason(error)
    result["control"] = dict(op.control)
    return result


def pending_record(value: object) -> dict:
    row = obj(value, {"prepared", "claimed", "acknowledged"})
    prepared = Prepared.parse(row["prepared"])
    require(type(row["claimed"]) is bool and type(row["acknowledged"]) is bool
        and (not row["acknowledged"] or row["claimed"]))
    return {"prepared": prepared.value(), "claimed": row["claimed"], "acknowledged": row["acknowledged"]}


def observation(value: object) -> dict:
    if type(value) is dict and value.get("assurance") == "later-binding-read-not-creation-proof":
        from .github_version_tag import observation as tag_observation
        return tag_observation(value)
    row = obj(value, {"counterCommit", "journalSha256", "journalRevision", "pendingTuple", "assurance"})
    hex_text(row["counterCommit"], 40); hex_text(row["journalSha256"], 64)
    policy._integer(row["journalRevision"], (1 << 64) - 1, 1)
    require(row["pendingTuple"] in ("same-unclaimed", "same-claimed", "different", "not-present")
        and row["assurance"] == "later-journal-read-not-cleanup-proof")
    return dict(row)


def observe(record: dict, exchange: Exchange) -> dict:
    original = pending_record(record)
    prepared = Prepared.parse(original["prepared"])
    if prepared.target.version_tag is not None:
        from .github_version_tag import observe as tag_observe
        return tag_observe(original, exchange)
    op = Operation(prepared.target, None, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": original["claimed"],
        "acknowledged": original["acknowledged"], "observed": None, "control": _control()}
    try:
        op.identity(); op.protection("protection-before")
        current = op.ref("ref-before")
        snapshot = op.snapshot(current)
        snapshot.ledger.admit(prepared.authority, prepared.checkpoint)
        if current != prepared.checkpoint.commit:
            allocation._ancestry(op.take("counter-ancestry", "compare/" + prepared.checkpoint.commit + "..." + current
                + "?per_page=1&page=1"), prepared.checkpoint.commit, current)
        envelope, _, sha = op.envelope(current)
        selected = envelope.state.selected(prepared.authority)
        snapshot.ledger.admit(prepared.authority, selected.checkpoint)
        pending = envelope.play_query
        state = "not-present" if pending is None else "different"
        if pending is not None and pending.candidate_id == prepared.candidate["candidateId"] and pending.attempt_id == prepared.candidate["attemptId"]:
            need(pending.request_sha256 == prepared.candidate["requestSha256"] and pending.recovery is not None
                and policy.digest(pending.recovery.capsule.value()) == prepared.candidate["capsuleSha256"], "journal-invalid")
            state = "same-claimed" if pending.recovery.claim is not None else "same-unclaimed"
        need(op.ref("ref-after") == current, "authority-changed")
        op.protection("protection-after"); op.repository("repository-after")
        result.update(effect="observed-unconfirmed", reason="none", observed=observation({"counterCommit": current,
            "journalSha256": sha, "journalRevision": envelope.revision, "pendingTuple": state,
            "assurance": "later-journal-read-not-cleanup-proof"}))
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError, ReadFailure) as error:
        result["reason"] = reason(error)
    result["control"] = dict(op.control)
    return result


def action_result(value: object, prepared: Prepared, kind: str) -> dict:
    require(kind in ("dispatch", "observe")); Prepared.parse(prepared.value())
    row = obj(value, {"effect", "reason", "claimed", "acknowledged", "observed", "control"})
    require(row["reason"] in REASONS and type(row["claimed"]) is bool and type(row["acknowledged"]) is bool
        and (not row["acknowledged"] or row["claimed"]))
    _check_control(row["control"])
    seen = None if row["observed"] is None else observation(row["observed"])
    if seen is not None:
        require((seen["assurance"] == "later-binding-read-not-creation-proof") == (prepared.target.version_tag is not None))
    effect = row["effect"]
    if effect == "not-sent":
        require(kind == "dispatch" and not row["claimed"] and not row["acknowledged"] and seen is None and row["reason"] != "none")
    elif effect == "potentially-applied":
        require(kind == "dispatch" and row["claimed"] and not row["acknowledged"] and seen is None and row["reason"] != "none")
    elif effect == "acknowledged-unconfirmed":
        require(kind == "dispatch" and row["claimed"] and row["acknowledged"] and seen is None)
    elif effect == "unresolved":
        require(kind == "observe" and seen is None and row["reason"] != "none")
    elif effect == "observed-unconfirmed":
        require(kind == "observe" and seen is not None and row["reason"] == "none")
    else:
        require(False)
    return dict(row)
